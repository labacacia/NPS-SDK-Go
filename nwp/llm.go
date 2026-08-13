// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"encoding/json"
	"fmt"
)

const (
	LlmCompleteActionID             = "llm.complete"
	LlmContextStatusActionID        = "llm.context.status"
	LlmContextReleaseActionID       = "llm.context.release"
	LlmCompleteResponseAnchor       = "nps:system:llm.complete:response"
	LlmCompleteStreamAnchor         = "nps:system:llm.complete:stream"
	LlmContextStatusResponseAnchor  = "nps:system:llm.context.status:response"
	LlmContextReleaseResponseAnchor = "nps:system:llm.context.release:response"
	CapabilityLlmComplete           = "llm:complete"
	CapabilityLlmContext            = "llm:context"
	CapabilityLlmStream             = "llm:stream"
	CapabilityLlmToolCall           = "llm:tool_call"
)

type LlmStopReason string

const (
	LlmStopEndTurn   LlmStopReason = "end_turn"
	LlmStopToolUse   LlmStopReason = "tool_use"
	LlmStopToolCalls LlmStopReason = "tool_calls"
	LlmStopMaxTokens LlmStopReason = "max_tokens"
	LlmStopLength    LlmStopReason = "length"
	LlmStopError     LlmStopReason = "error"
)

type LlmContextOperation string

const (
	LlmContextCreate  LlmContextOperation = "create"
	LlmContextAppend  LlmContextOperation = "append"
	LlmContextFork    LlmContextOperation = "fork"
	LlmContextReset   LlmContextOperation = "reset"
	LlmContextRelease LlmContextOperation = "release"
)

type LlmContextState string

const (
	LlmContextBusy     LlmContextState = "busy"
	LlmContextActive   LlmContextState = "active"
	LlmContextReleased LlmContextState = "released"
	LlmContextExpired  LlmContextState = "expired"
	LlmContextFailed   LlmContextState = "failed"
)

type LlmToolCallDto struct {
	CallID        string `json:"call_id"`
	ToolName      string `json:"tool_name"`
	ArgumentsJSON string `json:"arguments_json"`
}

type ToolParameterDto struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Description *string `json:"description,omitempty"`
	Required    bool    `json:"required"`
}

type LlmToolDefinitionDto struct {
	Name        string             `json:"name"`
	Description *string            `json:"description,omitempty"`
	Parameters  []ToolParameterDto `json:"parameters,omitempty"`
}

type LlmMessageDto struct {
	Role       string           `json:"role"`
	Content    *string          `json:"content,omitempty"`
	ToolCallID *string          `json:"tool_call_id,omitempty"`
	ToolName   *string          `json:"tool_name,omitempty"`
	ToolCalls  []LlmToolCallDto `json:"tool_calls,omitempty"`
}

type LlmContextRequestDto struct {
	Operation   LlmContextOperation `json:"operation"`
	ContextID   *string             `json:"context_id,omitempty"`
	BaseVersion *uint64             `json:"base_version,omitempty"`
	TTLSeconds  *uint32             `json:"ttl_seconds,omitempty"`
}

type LlmContextReceiptDto struct {
	ContextID       string              `json:"context_id"`
	Version         uint64              `json:"version"`
	Operation       LlmContextOperation `json:"operation"`
	State           LlmContextState     `json:"state"`
	ExpiresAt       *string             `json:"expires_at,omitempty"`
	ParentContextID *string             `json:"parent_context_id,omitempty"`
	ParentVersion   *uint64             `json:"parent_version,omitempty"`
}

type LlmContextStatusRequestDto struct {
	ContextID      *string `json:"context_id,omitempty"`
	IdempotencyKey *string `json:"idempotency_key,omitempty"`
}

type LlmContextReleaseRequestDto struct {
	ContextID   string `json:"context_id"`
	BaseVersion uint64 `json:"base_version"`
}

type LlmContextStatusDto struct {
	State     LlmContextState `json:"state"`
	ContextID *string         `json:"context_id,omitempty"`
	Version   *uint64         `json:"version,omitempty"`
	ExpiresAt *string         `json:"expires_at,omitempty"`
	RequestID *string         `json:"request_id,omitempty"`
	ErrorCode *string         `json:"error_code,omitempty"`
}

type LlmUsageDto struct {
	InputTokens     *uint32 `json:"input_tokens,omitempty"`
	OutputTokens    *uint32 `json:"output_tokens,omitempty"`
	CacheHit        *bool   `json:"cache_hit,omitempty"`
	ReusedTokens    *uint32 `json:"reused_tokens,omitempty"`
	EvaluatedTokens *uint32 `json:"evaluated_tokens,omitempty"`
	WireInputBytes  *uint64 `json:"wire_input_bytes,omitempty"`
}

type LlmCompleteActionRequest struct {
	Kind      string                 `json:"kind"`
	Model     string                 `json:"model"`
	MaxTokens *uint32                `json:"max_tokens,omitempty"`
	Stream    bool                   `json:"stream"`
	Messages  []LlmMessageDto        `json:"messages"`
	Tools     []LlmToolDefinitionDto `json:"tools,omitempty"`
	Context   *LlmContextRequestDto  `json:"context,omitempty"`
}

type LlmCompleteActionResponse struct {
	StopReason LlmStopReason         `json:"stop_reason"`
	Content    *string               `json:"content,omitempty"`
	ToolCalls  []LlmToolCallDto      `json:"tool_calls,omitempty"`
	Error      *string               `json:"error,omitempty"`
	Usage      *LlmUsageDto          `json:"usage,omitempty"`
	Context    *LlmContextReceiptDto `json:"context,omitempty"`
}

type LlmCompleteStreamChunkDto struct {
	ContentDelta *string               `json:"content_delta,omitempty"`
	ToolCalls    []LlmToolCallDto      `json:"tool_calls,omitempty"`
	StopReason   *LlmStopReason        `json:"stop_reason,omitempty"`
	Error        *string               `json:"error,omitempty"`
	Usage        *LlmUsageDto          `json:"usage,omitempty"`
	Context      *LlmContextReceiptDto `json:"context,omitempty"`
}

type LlmActionFrameOptions struct {
	IdempotencyKey *string
	TimeoutMs      *uint32
	Async          bool
	RequestID      *string
}

func (r LlmCompleteActionRequest) ToMap() (map[string]any, error) {
	if r.Kind == "" {
		r.Kind = LlmCompleteActionID
	}
	return structToMap(r)
}

func LlmCompleteRequestFromMap(value map[string]any) (*LlmCompleteActionRequest, error) {
	var result LlmCompleteActionRequest
	if err := mapToStruct(value, &result); err != nil {
		return nil, err
	}
	if result.Kind == "" {
		result.Kind = LlmCompleteActionID
	}
	if result.Kind != LlmCompleteActionID {
		return nil, fmt.Errorf("unexpected LLM payload kind %q", result.Kind)
	}
	return &result, nil
}

func LlmCompleteActionFrame(request LlmCompleteActionRequest, options LlmActionFrameOptions) (*ActionFrame, error) {
	params, err := request.ToMap()
	if err != nil {
		return nil, err
	}
	return &ActionFrame{
		Action: LlmCompleteActionID, Params: params, Async: options.Async,
		IdempotencyKey: options.IdempotencyKey, TimeoutMs: options.TimeoutMs,
		RequestID: options.RequestID,
	}, nil
}

func LlmContextStatusActionFrame(request LlmContextStatusRequestDto, requestID *string) (*ActionFrame, error) {
	params, err := structToMap(request)
	if err != nil {
		return nil, err
	}
	return &ActionFrame{Action: LlmContextStatusActionID, Params: params, RequestID: requestID}, nil
}

func LlmContextReleaseActionFrame(request LlmContextReleaseRequestDto, idempotencyKey string, requestID *string) (*ActionFrame, error) {
	params, err := structToMap(request)
	if err != nil {
		return nil, err
	}
	return &ActionFrame{
		Action: LlmContextReleaseActionID, Params: params,
		IdempotencyKey: &idempotencyKey, RequestID: requestID,
	}, nil
}

func structToMap(value any) (map[string]any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func mapToStruct(value map[string]any, target any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}
