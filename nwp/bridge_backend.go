// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/labacacia/NPS-sdk-go/core"
)

// NPS-CR-0010 §1 — the backend abstraction.
//
// The consolidation of compat/*-ingress into the Bridge is a backend
// ABSTRACTION, not a deletion. Two deployment shapes, one interface; the
// protocol servers are written against the interface alone and are unaware of
// which shape is behind it:
//
//	NwpBackend ──┬── InProcessNwpBackend  (delegate dispatch — the SDK's shape)
//	             └── HttpNwpBackend       (HTTP to a remote node — the ingress shape)
//	                    ▲
//	   one McpInboundServer / A2aInboundServer / GrpcInboundService
//	   serving the full method set over either backend

// NwpNodeRole is the role of a fronted NWP node.
type NwpNodeRole int

const (
	NwpRoleUnknown NwpNodeRole = iota
	NwpRoleMemory
	NwpRoleAction
	NwpRoleComplex
	NwpRoleAnchor
	NwpRoleBridge
)

func (r NwpNodeRole) String() string {
	switch r {
	case NwpRoleMemory:
		return "memory"
	case NwpRoleAction:
		return "action"
	case NwpRoleComplex:
		return "complex"
	case NwpRoleAnchor:
		return "anchor"
	case NwpRoleBridge:
		return "bridge"
	default:
		return "unknown"
	}
}

// ParseNwpRole lower-cases nodeType and maps the five known names; anything else
// is NwpRoleUnknown, which projects onto nothing rather than failing the Bridge.
func ParseNwpRole(nodeType string) NwpNodeRole {
	switch strings.ToLower(strings.TrimSpace(nodeType)) {
	case "memory":
		return NwpRoleMemory
	case "action":
		return NwpRoleAction
	case "complex":
		return NwpRoleComplex
	case "anchor":
		return NwpRoleAnchor
	case "bridge":
		return NwpRoleBridge
	default:
		return NwpRoleUnknown
	}
}

// NwpNodeDescriptor identifies one NWP node fronted by the Bridge.
type NwpNodeDescriptor struct {
	// Name must be unique per Bridge — it namespaces resource URIs and tool names.
	Name        string
	Role        NwpNodeRole
	DisplayName string
	Description string
}

// IsQueryable reports whether resources/* and QueryAsync apply to this node.
func (d NwpNodeDescriptor) IsQueryable() bool {
	return d.Role == NwpRoleMemory || d.Role == NwpRoleComplex
}

// IsInvokable reports whether tools/* and InvokeAsync apply to this node.
func (d NwpNodeDescriptor) IsInvokable() bool {
	return d.Role == NwpRoleAction || d.Role == NwpRoleComplex
}

// NwpActionDescriptor describes one invokable action.
type NwpActionDescriptor struct {
	ActionID    string
	Description string
	// InputSchema is a JSON Schema object. Absent means the Bridge advertises the
	// open object schema {"type":"object","additionalProperties":true}.
	InputSchema json.RawMessage
	Async       bool
	Tags        []string
}

// OpenObjectSchema is the schema advertised for an action with no declared one.
func OpenObjectSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","additionalProperties":true}`)
}

// EffectiveInputSchema returns InputSchema, or the open object schema when unset.
func (a NwpActionDescriptor) EffectiveInputSchema() json.RawMessage {
	if len(a.InputSchema) > 0 {
		return a.InputSchema
	}
	return OpenObjectSchema()
}

// NwpResult is a backend outcome.
//
// This type is WHY the §16.3 mapping works: it carries the NPS status forward
// instead of an opaque body, so the protocol servers can pick the right foreign
// code instead of guessing from an HTTP number or a stringly-typed body.
type NwpResult struct {
	Ok        bool
	Payload   json.RawMessage
	NpsStatus string
	NwpError  string
	Message   string
}

// NwpSuccess wraps a successful payload.
func NwpSuccess(payload json.RawMessage) NwpResult {
	return NwpResult{Ok: true, Payload: payload}
}

// NwpFailure wraps a failure carrying its NPS status forward.
func NwpFailure(npsStatus, nwpError, message string) NwpResult {
	return NwpResult{Ok: false, NpsStatus: npsStatus, NwpError: nwpError, Message: message}
}

// NwpDispatchFailed is the catch-all for an unexpected dispatch fault.
func NwpDispatchFailed(message string) NwpResult {
	return NwpFailure(core.NpsServerInternal, ErrBridgeServerDispatchFailed, message)
}

// NwpBackend is the surface every inbound protocol server is written against.
type NwpBackend interface {
	GetDescriptor(ctx context.Context) (NwpNodeDescriptor, error)
	// GetManifest returns the raw /.nwm document.
	GetManifest(ctx context.Context) NwpResult
	GetActions(ctx context.Context) ([]NwpActionDescriptor, error)
	Query(ctx context.Context, query json.RawMessage) NwpResult
	Invoke(ctx context.Context, actionID string, arguments json.RawMessage, async bool) NwpResult
}

// ── InProcessNwpBackend ──────────────────────────────────────────────────────

// BridgeDispatch executes an ActionFrame against the local node.
type BridgeDispatch func(ctx context.Context, frame *ActionFrame) (core.FrameDict, error)

// BridgeQuery executes a QueryFrame against the local node.
type BridgeQuery func(ctx context.Context, frame *QueryFrame) (core.FrameDict, error)

// InProcessNwpBackend dispatches to delegates in this process — the SDK's shape.
type InProcessNwpBackend struct {
	descriptor NwpNodeDescriptor
	actions    []NwpActionDescriptor
	invoke     BridgeDispatch
	query      BridgeQuery
}

// NewInProcessNwpBackend builds an in-process backend. Either delegate may be nil;
// a nil delegate makes the corresponding call fail LOUDLY with
// NWP-BRIDGE-SERVER-DISPATCHER-MISSING rather than looking like "this node
// exposes nothing".
func NewInProcessNwpBackend(
	descriptor NwpNodeDescriptor,
	actions []NwpActionDescriptor,
	invoke BridgeDispatch,
	query BridgeQuery,
) *InProcessNwpBackend {
	return &InProcessNwpBackend{descriptor: descriptor, actions: actions, invoke: invoke, query: query}
}

func (b *InProcessNwpBackend) GetDescriptor(context.Context) (NwpNodeDescriptor, error) {
	return b.descriptor, nil
}

func (b *InProcessNwpBackend) GetManifest(context.Context) NwpResult {
	m := map[string]any{"node_type": b.descriptor.Role.String()}
	if b.descriptor.DisplayName != "" {
		m["display_name"] = b.descriptor.DisplayName
	}
	if b.descriptor.Description != "" {
		m["description"] = b.descriptor.Description
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return NwpDispatchFailed(err.Error())
	}
	return NwpSuccess(raw)
}

func (b *InProcessNwpBackend) GetActions(context.Context) ([]NwpActionDescriptor, error) {
	if !b.descriptor.IsInvokable() {
		return nil, nil
	}
	return b.actions, nil
}

func (b *InProcessNwpBackend) Query(ctx context.Context, query json.RawMessage) (res NwpResult) {
	if !b.descriptor.IsQueryable() {
		return NwpFailure(core.NpsServerUnsupported, ErrBridgeServerToolNotFound,
			fmt.Sprintf("Node '%s' is not queryable (role: %s).", b.descriptor.Name, b.descriptor.Role))
	}
	if b.query == nil {
		return NwpFailure(core.NpsServerInternal, ErrBridgeServerDispatcherMissing,
			fmt.Sprintf("Node '%s' has no query dispatcher configured.", b.descriptor.Name))
	}
	defer func() {
		if r := recover(); r != nil {
			res = NwpDispatchFailed(fmt.Sprint(r))
		}
	}()

	var filter any
	if len(query) > 0 {
		if err := json.Unmarshal(query, &filter); err != nil {
			return NwpFailure(core.NpsClientBadParam, ErrQueryFilterInvalid, err.Error())
		}
	}
	frame, err := b.query(ctx, &QueryFrame{Filter: filter})
	if err != nil {
		return NwpDispatchFailed(err.Error())
	}
	return bridgeFrameToResult(frame)
}

func (b *InProcessNwpBackend) Invoke(ctx context.Context, actionID string, arguments json.RawMessage, async bool) (res NwpResult) {
	if b.invoke == nil {
		return NwpFailure(core.NpsServerInternal, ErrBridgeServerDispatcherMissing,
			fmt.Sprintf("Node '%s' has no action dispatcher configured.", b.descriptor.Name))
	}
	defer func() {
		if r := recover(); r != nil {
			res = NwpDispatchFailed(fmt.Sprint(r))
		}
	}()

	var params any
	if len(arguments) > 0 {
		if err := json.Unmarshal(arguments, &params); err != nil {
			return NwpFailure(core.NpsClientBadParam, ErrActionParamsInvalid, err.Error())
		}
	}
	frame, err := b.invoke(ctx, &ActionFrame{Action: actionID, Params: params, Async: async})
	if err != nil {
		return NwpDispatchFailed(err.Error())
	}
	return bridgeFrameToResult(frame)
}

// bridgeFrameToResult projects a returned frame onto an NwpResult. An ErrorFrame
// shape (a dict carrying `error`) becomes a Failure that PRESERVES its NPS
// status; anything else is a success carrying the serialized frame.
func bridgeFrameToResult(frame core.FrameDict) NwpResult {
	if frame == nil {
		return NwpSuccess(json.RawMessage("null"))
	}
	if code, ok := frame["error"].(string); ok && code != "" {
		status, _ := frame["status"].(string)
		if status == "" {
			status = core.NpsServerInternal
		}
		msg, _ := frame["message"].(string)
		return NwpFailure(status, code, msg)
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		return NwpDispatchFailed(err.Error())
	}
	return NwpSuccess(raw)
}

// ── HttpNwpBackend ───────────────────────────────────────────────────────────

// NwpUpstream configures an HTTP-fronted NWP node.
type NwpUpstream struct {
	Name       string
	BaseURL    string
	AgentNid   string
	AuthHeader string
	// ReadLimit is the row cap applied to a resources/read query. 0 means 100.
	ReadLimit int
}

// HttpNwpBackend proxies to a remote NWP node over HTTP — the compat/*-ingress shape.
type HttpNwpBackend struct {
	up     NwpUpstream
	client *http.Client

	mu         sync.Mutex
	descriptor *NwpNodeDescriptor
}

// NewHttpNwpBackend builds an HTTP backend. client must not be nil.
func NewHttpNwpBackend(up NwpUpstream, client *http.Client) *HttpNwpBackend {
	if client == nil {
		client = http.DefaultClient
	}
	return &HttpNwpBackend{up: up, client: client}
}

func (b *HttpNwpBackend) baseURL() string { return strings.TrimRight(b.up.BaseURL, "/") }

// GetDescriptor fetches and CACHES /.nwm. An unreachable upstream caches
// Role = Unknown: a dead upstream must not take down the Bridge, it is simply
// projected onto nothing.
func (b *HttpNwpBackend) GetDescriptor(ctx context.Context) (NwpNodeDescriptor, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.descriptor != nil {
		return *b.descriptor, nil
	}

	d := NwpNodeDescriptor{Name: b.up.Name, Role: NwpRoleUnknown}
	if res := b.get(ctx, "/.nwm"); res.Ok {
		var m struct {
			NodeType    string `json:"node_type"`
			DisplayName string `json:"display_name"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(res.Payload, &m); err == nil {
			d.Role = ParseNwpRole(m.NodeType)
			d.DisplayName = m.DisplayName
			d.Description = m.Description
		}
	}
	b.descriptor = &d
	return d, nil
}

func (b *HttpNwpBackend) GetManifest(ctx context.Context) NwpResult { return b.get(ctx, "/.nwm") }

func (b *HttpNwpBackend) GetActions(ctx context.Context) ([]NwpActionDescriptor, error) {
	d, _ := b.GetDescriptor(ctx)
	if !d.IsInvokable() {
		return nil, nil
	}
	res := b.get(ctx, "/actions")
	if !res.Ok {
		return nil, errors.New(res.Message)
	}
	var body struct {
		Actions map[string]struct {
			Description  string          `json:"description"`
			ParamsSchema json.RawMessage `json:"params_schema"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(res.Payload, &body); err != nil {
		return nil, err
	}
	out := make([]NwpActionDescriptor, 0, len(body.Actions))
	for id, a := range body.Actions {
		out = append(out, NwpActionDescriptor{
			ActionID: id, Description: a.Description, InputSchema: a.ParamsSchema,
		})
	}
	sortActions(out)
	return out, nil
}

func (b *HttpNwpBackend) Query(ctx context.Context, query json.RawMessage) NwpResult {
	d, _ := b.GetDescriptor(ctx)
	if !d.IsQueryable() {
		return NwpFailure(core.NpsServerUnsupported, ErrBridgeServerToolNotFound,
			fmt.Sprintf("Node '%s' is not queryable (role: %s).", d.Name, d.Role))
	}
	if len(query) == 0 {
		query = json.RawMessage("{}")
	}
	return b.post(ctx, "/query", query)
}

func (b *HttpNwpBackend) Invoke(ctx context.Context, actionID string, arguments json.RawMessage, async bool) NwpResult {
	if len(arguments) == 0 {
		arguments = json.RawMessage("{}")
	}
	body, err := json.Marshal(map[string]any{
		"action_id": actionID,
		"params":    arguments,
		"async":     async,
	})
	if err != nil {
		return NwpDispatchFailed(err.Error())
	}
	return b.post(ctx, "/invoke", body)
}

func (b *HttpNwpBackend) get(ctx context.Context, path string) NwpResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL()+path, nil)
	if err != nil {
		return NwpDispatchFailed(err.Error())
	}
	return b.do(req)
}

func (b *HttpNwpBackend) post(ctx context.Context, path string, body []byte) NwpResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return NwpDispatchFailed(err.Error())
	}
	req.Header.Set("Content-Type", MimeFrame)
	return b.do(req)
}

func (b *HttpNwpBackend) do(req *http.Request) NwpResult {
	req.Header.Set("Accept", "application/json")
	if b.up.AgentNid != "" {
		req.Header.Set(HeaderAgent, b.up.AgentNid)
	}
	if b.up.AuthHeader != "" {
		req.Header.Set("Authorization", b.up.AuthHeader)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		// §16.3 inverse direction: a timeout and a connection error are distinct
		// NPS classes and must not be collapsed.
		if isTimeoutErr(err) {
			return NwpFailure(core.NpsServerTimeout, ErrBridgeUpstreamFailed, err.Error())
		}
		return NwpFailure(core.NpsDownstreamUnavailable, ErrBridgeUpstreamFailed, err.Error())
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code := ""
		var errBody struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &errBody) == nil {
			code = errBody.Error
		}
		return NwpFailure(BridgeFromHttpStatus(resp.StatusCode), code, string(raw))
	}
	if !json.Valid(raw) {
		return NwpFailure(core.NpsDownstreamUnavailable, ErrBridgeUpstreamFailed,
			"upstream returned a non-JSON 2xx body.")
	}
	return NwpSuccess(raw)
}

func isTimeoutErr(err error) bool {
	var t interface{ Timeout() bool }
	if errors.As(err, &t) && t.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func sortActions(a []NwpActionDescriptor) {
	// Stable, deterministic ordering so tools/list and the AgentCard do not
	// reshuffle between calls (Go map iteration is randomized).
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].ActionID < a[j-1].ActionID; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
