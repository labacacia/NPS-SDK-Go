// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

package nwp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/labacacia/NPS-sdk-go/core"
)

const (
	LlmCompleteRequestAnchor       = "nps:system:llm.complete:request"
	LlmContextStatusRequestAnchor  = "nps:system:llm.context.status:request"
	LlmContextReleaseRequestAnchor = "nps:system:llm.context.release:request"
)

// LlmAuthorizationStage distinguishes admission from the mandatory pre-commit recheck.
type LlmAuthorizationStage string

const (
	LlmAuthorizationAdmission LlmAuthorizationStage = "admission"
	LlmAuthorizationCommit    LlmAuthorizationStage = "commit"
)

// LlmContextAuthorizer performs deployment-owned NIP/capability checks.
type LlmContextAuthorizer func(
	ctx context.Context,
	owner LlmContextOwner,
	actionID string,
	stage LlmAuthorizationStage,
	actionContext ActionContext,
) error

// StatefulLlmActionOptions contains deployment-owned settings, never payload inputs.
type StatefulLlmActionOptions struct {
	SecurityScope       string
	RuntimeRevision     string
	ProviderName        string
	DefaultModel        string
	SupportsTools       bool
	SupportsJSONMode    bool
	ReasoningVisibility string
	Authorizer          LlmContextAuthorizer
}

// StatefulLlmActionProvider wraps an ordinary provider with the NWP 0.21 context lifecycle.
type StatefulLlmActionProvider struct {
	inner   IActionNodeProvider
	store   *InMemoryLlmContextStore
	options StatefulLlmActionOptions
}

func NewStatefulLlmActionProvider(
	inner IActionNodeProvider,
	store *InMemoryLlmContextStore,
	options StatefulLlmActionOptions,
) (*StatefulLlmActionProvider, error) {
	if inner == nil {
		return nil, errors.New("inner provider is required")
	}
	if store == nil {
		return nil, errors.New("context store is required")
	}
	if strings.TrimSpace(options.SecurityScope) == "" {
		return nil, errors.New("security scope must not be empty")
	}
	if strings.TrimSpace(options.RuntimeRevision) == "" {
		return nil, errors.New("runtime revision must not be empty")
	}
	return &StatefulLlmActionProvider{inner: inner, store: store, options: options}, nil
}

// Store exposes the provider-neutral context store for operations and diagnostics.
func (p *StatefulLlmActionProvider) Store() *InMemoryLlmContextStore { return p.store }

// ConfigureNode registers the exact actions and truthful process-local NWM profile.
func (p *StatefulLlmActionProvider) ConfigureNode(node *ActionNodeOptions) {
	if node.Actions == nil {
		node.Actions = map[string]ActionSpec{}
	}
	complete := node.Actions[LlmCompleteActionID]
	if complete.Description == "" {
		complete.Description = "Complete an LLM request"
	}
	complete.ParamsAnchor = LlmCompleteRequestAnchor
	complete.ResultAnchor = LlmCompleteResponseAnchor
	if _, exists := node.Actions[LlmCompleteActionID]; !exists {
		complete.Async = true
	}
	complete.Idempotent = llmBoolPtr(true)
	complete.RequiredCapability = CapabilityLlmComplete
	node.Actions[LlmCompleteActionID] = complete
	node.Actions[LlmContextStatusActionID] = ActionSpec{
		Description:  "Inspect an LLM context or retained create outcome",
		ParamsAnchor: LlmContextStatusRequestAnchor, ResultAnchor: LlmContextStatusResponseAnchor,
		RequiredCapability: CapabilityLlmContext,
	}
	node.Actions[LlmContextReleaseActionID] = ActionSpec{
		Description: "Release an LLM context", ParamsAnchor: LlmContextReleaseRequestAnchor,
		ResultAnchor: LlmContextReleaseResponseAnchor, Idempotent: llmBoolPtr(true),
		RequiredCapability: CapabilityLlmContext,
	}

	descriptor := p.store.Descriptor()
	profile := map[string]any{
		"profile_version": "0.2",
		"actions":         []string{LlmCompleteActionID, LlmContextStatusActionID, LlmContextReleaseActionID},
		"supports_stream": false, "supports_tools": p.options.SupportsTools,
		"supports_json_mode": p.options.SupportsJSONMode,
		"context": map[string]any{
			"supported": true, "operations": descriptor.Operations,
			"persistence":                descriptor.Persistence,
			"max_contexts_per_principal": descriptor.MaxContextsPerPrincipal,
			"max_ttl_seconds":            descriptor.MaxTTLSeconds,
			"tombstone_seconds":          descriptor.TombstoneSeconds,
		},
	}
	if p.options.ProviderName != "" {
		profile["provider"] = p.options.ProviderName
	}
	if p.options.DefaultModel != "" {
		profile["default_model"] = p.options.DefaultModel
	}
	if p.options.ReasoningVisibility != "" {
		profile["reasoning_visibility"] = p.options.ReasoningVisibility
	}
	if node.Profiles == nil {
		node.Profiles = map[string]any{}
	}
	node.Profiles["llm"] = profile
}

// Authorize runs before generic Action Server replay lookup.
func (p *StatefulLlmActionProvider) Authorize(
	ctx context.Context,
	frame *ActionFrame,
	actionContext ActionContext,
) error {
	if authorizer, ok := p.inner.(IActionNodeAuthorizer); ok {
		if err := authorizer.Authorize(ctx, frame, actionContext); err != nil {
			return err
		}
	}
	requiresContext := frame.Action == LlmContextStatusActionID || frame.Action == LlmContextReleaseActionID
	if frame.Action == LlmCompleteActionID {
		params, _ := frame.Params.(map[string]any)
		_, requiresContext = params["context"]
	}
	if !requiresContext {
		return nil
	}
	owner, err := p.owner(actionContext)
	if err != nil {
		return err
	}
	return p.checkAuthorization(ctx, owner, frame.Action, LlmAuthorizationAdmission, actionContext)
}

// Execute dispatches lifecycle actions or delegates ordinary actions to the wrapped provider.
func (p *StatefulLlmActionProvider) Execute(
	ctx context.Context,
	frame *ActionFrame,
	actionContext ActionContext,
) (*ActionExecutionResult, error) {
	switch frame.Action {
	case LlmCompleteActionID:
		return p.complete(ctx, frame, actionContext)
	case LlmContextStatusActionID:
		return p.status(frame, actionContext)
	case LlmContextReleaseActionID:
		return p.release(frame, actionContext)
	default:
		return p.inner.Execute(ctx, frame, actionContext)
	}
}

func (p *StatefulLlmActionProvider) complete(
	ctx context.Context,
	frame *ActionFrame,
	actionContext ActionContext,
) (*ActionExecutionResult, error) {
	request, err := decodeCompleteRequest(frame)
	if err != nil {
		return nil, paramsExecutionError(err.Error())
	}
	if !p.options.SupportsTools && len(request.Tools) > 0 {
		return nil, paramsExecutionError("this node does not advertise LLM tool-definition support")
	}
	if request.Context == nil {
		return p.inner.Execute(ctx, frame, actionContext)
	}
	if request.Stream {
		return nil, paramsExecutionError(
			"the Action Server context coordinator supports unary/async completion, not streaming")
	}
	if (request.Context.Operation == LlmContextAppend || request.Context.Operation == LlmContextFork ||
		request.Context.Operation == LlmContextReset) &&
		(request.Context.ContextID == nil || request.Context.BaseVersion == nil) {
		return nil, paramsExecutionError("append/fork/reset require context_id and base_version")
	}
	owner, err := p.owner(actionContext)
	if err != nil {
		return nil, err
	}
	binding, err := p.resolveBinding(owner, request)
	if err != nil {
		return nil, err
	}
	reservation, err := p.store.Reserve(LlmContextMutationRequest{
		Operation: request.Context.Operation, Owner: owner, ContextID: request.Context.ContextID,
		BaseVersion: request.Context.BaseVersion, Binding: binding, Messages: request.Messages,
		TTLSeconds: request.Context.TTLSeconds, IdempotencyKey: valueString(frame.IdempotencyKey),
		RequestID: valueString(frame.RequestID),
	})
	if err != nil {
		return nil, mapLlmStoreError(err)
	}
	reservationDone := make(chan struct{})
	defer close(reservationDone)
	go func() {
		select {
		case <-ctx.Done():
			p.abort(reservation, ErrNodeUnavailable)
		case <-reservationDone:
		}
	}()

	providerResult, err := p.inner.Execute(ctx, frame, actionContext)
	if err != nil {
		p.abort(reservation, executionErrorCode(err))
		return nil, err
	}
	if ctx.Err() != nil {
		p.abort(reservation, ErrNodeUnavailable)
		return nil, ctx.Err()
	}
	if providerResult == nil || len(providerResult.Result) == 0 {
		p.abort(reservation, ErrNodeUnavailable)
		return nil, internalExecutionError("stateful llm.complete returned no official response object")
	}
	var response LlmCompleteActionResponse
	if err := json.Unmarshal(providerResult.Result, &response); err != nil || !validStopReason(response.StopReason) {
		p.abort(reservation, ErrNodeUnavailable)
		if err == nil {
			err = fmt.Errorf("invalid stop_reason %q", response.StopReason)
		}
		return nil, internalExecutionError("stateful llm.complete returned an invalid official response: " + err.Error())
	}
	if response.StopReason == LlmStopError {
		p.abort(reservation, ErrNodeUnavailable)
		response.Context = nil
		return completionResult(response, providerResult)
	}
	if err := p.checkAuthorization(ctx, owner, frame.Action, LlmAuthorizationCommit, actionContext); err != nil {
		p.abort(reservation, executionErrorCode(err))
		return nil, err
	}
	if ctx.Err() != nil {
		p.abort(reservation, ErrNodeUnavailable)
		return nil, ctx.Err()
	}
	receipt, err := p.store.Commit(reservation, LlmMessageDto{
		Role: "assistant", Content: cloneString(response.Content), ToolCalls: cloneToolCalls(response.ToolCalls),
	})
	if err != nil {
		return nil, mapLlmStoreError(err)
	}
	response.Context = &receipt
	return completionResult(response, providerResult)
}

func (p *StatefulLlmActionProvider) status(
	frame *ActionFrame,
	actionContext ActionContext,
) (*ActionExecutionResult, error) {
	var request LlmContextStatusRequestDto
	if err := decodeFrameParams(frame, &request); err != nil {
		return nil, paramsExecutionError(err.Error())
	}
	owner, err := p.owner(actionContext)
	if err != nil {
		return nil, err
	}
	result, err := p.store.Status(owner, request.ContextID, request.IdempotencyKey)
	if err != nil {
		return nil, mapLlmStoreError(err)
	}
	return marshalActionResult(result, LlmContextStatusResponseAnchor)
}

func (p *StatefulLlmActionProvider) release(
	frame *ActionFrame,
	actionContext ActionContext,
) (*ActionExecutionResult, error) {
	var request LlmContextReleaseRequestDto
	if err := decodeFrameParams(frame, &request); err != nil || request.ContextID == "" {
		if err == nil {
			err = errors.New("context_id is required")
		}
		return nil, paramsExecutionError(err.Error())
	}
	owner, err := p.owner(actionContext)
	if err != nil {
		return nil, err
	}
	receipt, err := p.store.Release(owner, request.ContextID, request.BaseVersion, valueString(frame.IdempotencyKey))
	if err != nil {
		return nil, mapLlmStoreError(err)
	}
	return marshalActionResult(receipt, LlmContextReleaseResponseAnchor)
}

func (p *StatefulLlmActionProvider) resolveBinding(
	owner LlmContextOwner,
	request *LlmCompleteActionRequest,
) (LlmContextBinding, error) {
	if request.Context.Operation == LlmContextAppend || request.Context.Operation == LlmContextFork {
		if request.Context.ContextID == nil {
			return LlmContextBinding{}, paramsExecutionError("append/fork require context_id and base_version")
		}
		snapshot, err := p.store.Snapshot(owner, *request.Context.ContextID)
		if err != nil {
			return LlmContextBinding{}, mapLlmStoreError(err)
		}
		tools := request.Tools
		if tools == nil {
			tools = snapshot.Binding.Tools
		}
		return LlmContextBinding{
			Model: request.Model, SystemMessages: snapshot.Binding.SystemMessages,
			Tools: tools, RuntimeRevision: p.options.RuntimeRevision,
		}, nil
	}
	systemMessages := make([]LlmMessageDto, 0)
	for _, message := range request.Messages {
		if strings.EqualFold(message.Role, "system") {
			systemMessages = append(systemMessages, message)
		}
	}
	return LlmContextBinding{
		Model: request.Model, SystemMessages: systemMessages,
		Tools: request.Tools, RuntimeRevision: p.options.RuntimeRevision,
	}, nil
}

func (p *StatefulLlmActionProvider) owner(actionContext ActionContext) (LlmContextOwner, error) {
	if strings.TrimSpace(actionContext.AgentNid) == "" {
		return LlmContextOwner{}, &ActionExecutionError{
			HTTPStatus: 401, NpsStatus: core.NpsAuthUnauthenticated,
			ErrorCode: ErrAuthNidScopeViolation,
			Message:   "stateful LLM context actions require an authenticated agent NID",
		}
	}
	return LlmContextOwner{NID: actionContext.AgentNid, SecurityScope: p.options.SecurityScope}, nil
}

func (p *StatefulLlmActionProvider) checkAuthorization(
	ctx context.Context,
	owner LlmContextOwner,
	actionID string,
	stage LlmAuthorizationStage,
	actionContext ActionContext,
) error {
	if p.options.Authorizer == nil {
		return nil
	}
	return p.options.Authorizer(ctx, owner, actionID, stage, actionContext)
}

func (p *StatefulLlmActionProvider) abort(reservation *LlmContextMutationReservation, errorCode string) {
	_ = p.store.Abort(reservation, errorCode)
}

func decodeCompleteRequest(frame *ActionFrame) (*LlmCompleteActionRequest, error) {
	params, ok := frame.Params.(map[string]any)
	if !ok {
		return nil, errors.New("llm.complete requires an object params payload")
	}
	request, err := LlmCompleteRequestFromMap(params)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.Model) == "" {
		return nil, errors.New("llm.complete requires a non-empty model")
	}
	if request.Messages == nil {
		return nil, errors.New("messages must be an array")
	}
	for _, message := range request.Messages {
		if strings.TrimSpace(message.Role) == "" {
			return nil, errors.New("each message requires a non-empty role")
		}
	}
	if request.Context != nil && !validContextOperation(request.Context.Operation) {
		return nil, fmt.Errorf("invalid context operation %q", request.Context.Operation)
	}
	return request, nil
}

func decodeFrameParams(frame *ActionFrame, target any) error {
	if _, ok := frame.Params.(map[string]any); !ok {
		return errors.New("action requires an object params payload")
	}
	encoded, err := json.Marshal(frame.Params)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}

func completionResult(
	response LlmCompleteActionResponse,
	providerResult *ActionExecutionResult,
) (*ActionExecutionResult, error) {
	anchor := providerResult.AnchorRef
	if anchor == "" {
		anchor = LlmCompleteResponseAnchor
	}
	return marshalActionResultWithTokens(response, anchor, providerResult.TokenEst)
}

func marshalActionResult(value any, anchor string) (*ActionExecutionResult, error) {
	return marshalActionResultWithTokens(value, anchor, 0)
}

func marshalActionResultWithTokens(value any, anchor string, tokenEst uint) (*ActionExecutionResult, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, internalExecutionError(err.Error())
	}
	return &ActionExecutionResult{Result: payload, AnchorRef: anchor, TokenEst: tokenEst}, nil
}

func paramsExecutionError(message string) *ActionExecutionError {
	return &ActionExecutionError{
		HTTPStatus: 422, NpsStatus: core.NpsClientUnprocessable,
		ErrorCode: ErrActionParamsInvalid, Message: message,
	}
}

func internalExecutionError(message string) *ActionExecutionError {
	return &ActionExecutionError{
		HTTPStatus: 500, NpsStatus: core.NpsServerInternal,
		ErrorCode: ErrNodeUnavailable, Message: message,
	}
}

func mapLlmStoreError(err error) error {
	var storeErr *LlmContextStoreError
	if !errors.As(err, &storeErr) {
		return internalExecutionError(err.Error())
	}
	status := NwpErrorToNpsStatus[storeErr.ErrorCode]
	if status == "" {
		status = core.NpsServerInternal
	}
	return &ActionExecutionError{
		HTTPStatus: core.ToHttpStatus(status), NpsStatus: status,
		ErrorCode: storeErr.ErrorCode, Message: storeErr.Message,
	}
}

func executionErrorCode(err error) string {
	var execErr *ActionExecutionError
	if errors.As(err, &execErr) {
		return execErr.ErrorCode
	}
	return ErrNodeUnavailable
}

func validStopReason(value LlmStopReason) bool {
	switch value {
	case LlmStopEndTurn, LlmStopToolUse, LlmStopToolCalls, LlmStopMaxTokens, LlmStopLength, LlmStopError:
		return true
	default:
		return false
	}
}

func validContextOperation(value LlmContextOperation) bool {
	switch value {
	case LlmContextCreate, LlmContextAppend, LlmContextFork, LlmContextReset, LlmContextRelease:
		return true
	default:
		return false
	}
}

func llmBoolPtr(value bool) *bool { return &value }

func valueString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func cloneToolCalls(value []LlmToolCallDto) []LlmToolCallDto {
	if value == nil {
		return nil
	}
	return append([]LlmToolCallDto(nil), value...)
}
