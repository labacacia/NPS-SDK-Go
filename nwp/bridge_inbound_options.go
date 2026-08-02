// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"context"
	"net/http"
	"strings"
	"unicode"
)

// BridgeInboundOptions is the TRANSPORT-INDEPENDENT half of the inbound Bridge
// configuration: backends, declared protocols and server identity.
//
// Layering rule to preserve: this is a SEPARATE type from the hosting options
// (BridgeServerOptions: paths, HTTP-bound verifier, limits). The protocol
// servers are written against this type only, so they never touch an
// *http.Request and can be driven from stdio or a unit test with no web server.
type BridgeInboundOptions struct {
	// Backends are the NWP nodes this Bridge fronts.
	Backends []NwpBackend
	// InboundProtocols is the NDP `bridge_inbound_protocols` set. Leave nil to get
	// the default {"mcp","a2a"} — note gRPC is deliberately NOT in the default
	// set, so the gRPC service refuses until "grpc" is added explicitly.
	InboundProtocols []string
	// OutboundProtocols is the NDP `bridge_protocols` set, carried only so the
	// direction-refusal `hint` can name both declared arrays.
	OutboundProtocols []string

	ServerName    string // default "nps-bridge-server"
	ServerVersion string // default "0.1.0"
	// ResourceReadLimit caps rows per resources/read. 0 means 100.
	ResourceReadLimit int
	// RequireAuth is advertised on the A2A AgentCard, so it is part of the
	// protocol surface and not merely host config. nil means true.
	RequireAuth *bool
}

// DefaultInboundProtocols is the .NET default set. gRPC is intentionally absent.
var DefaultInboundProtocols = []string{BridgeProtocolMCP, BridgeProtocolA2A}

// InboundProtocolSet returns the declared inbound protocols, defaulted.
func (o *BridgeInboundOptions) InboundProtocolSet() []string {
	if o == nil || o.InboundProtocols == nil {
		return DefaultInboundProtocols
	}
	return o.InboundProtocols
}

// OutboundProtocolSet returns the declared outbound protocols (never nil).
func (o *BridgeInboundOptions) OutboundProtocolSet() []string {
	if o == nil || o.OutboundProtocols == nil {
		return []string{}
	}
	return o.OutboundProtocols
}

// ServesInbound is a case-insensitive membership test over the declared inbound set.
func (o *BridgeInboundOptions) ServesInbound(protocol string) bool {
	for _, p := range o.InboundProtocolSet() {
		if strings.EqualFold(p, protocol) {
			return true
		}
	}
	return false
}

func (o *BridgeInboundOptions) serverName() string {
	if o != nil && o.ServerName != "" {
		return o.ServerName
	}
	return "nps-bridge-server"
}

func (o *BridgeInboundOptions) serverVersion() string {
	if o != nil && o.ServerVersion != "" {
		return o.ServerVersion
	}
	return "0.1.0"
}

func (o *BridgeInboundOptions) readLimit() int {
	if o != nil && o.ResourceReadLimit > 0 {
		return o.ResourceReadLimit
	}
	return 100
}

func (o *BridgeInboundOptions) requireAuth() bool {
	return o == nil || o.RequireAuth == nil || *o.RequireAuth
}

// directionHint is the §16.1.2 MUST-5 SHOULD-clause payload: the response
// SHOULD carry BOTH declared arrays. The .NET impl emits only data.error;
// this port adds the arrays (TC-N2-BridgeIn-06's second-pass criterion).
func (o *BridgeInboundOptions) directionHint() map[string]any {
	return map[string]any{
		"bridge_inbound_protocols": o.InboundProtocolSet(),
		"bridge_protocols":         o.OutboundProtocolSet(),
	}
}

// directionUnsupported builds the JSON-RPC error a server returns when the
// request's protocol is absent from bridge_inbound_protocols (§16.1.2 MUST-5).
func (o *BridgeInboundOptions) directionUnsupported(protocol string) *BridgeJsonRpcError {
	return &BridgeJsonRpcError{
		Code:    JsonRpcMethodNotFound,
		Message: `This Bridge Node does not declare "` + protocol + `" in bridge_inbound_protocols.`,
		Data: map[string]any{
			"error": ErrBridgeDirectionUnsupported,
			"hint":  o.directionHint(),
		},
	}
}

// ── Tool-name encoding (§4, CR §5.1) ─────────────────────────────────────────

// McpToolNameEncode builds the qualified MCP tool name for (node, action).
//
// CR §5.1 — canonical on output, forgiving on input. tools/list and the
// AgentCard ALWAYS emit qualified `node__action` names: MCP tool names are a
// flat namespace and a Bridge may front several nodes. Qualifying only when
// more than one backend exists was REJECTED — adding a second node later would
// silently rename every tool.
func McpToolNameEncode(node, action string) string {
	return mcpSanitize(node) + "__" + McpToolNameEncodeActionSegment(action)
}

// McpToolNameEncodeActionSegment encodes just the action half. Dots become
// underscores, which is part of what makes the transform lossy.
func McpToolNameEncodeActionSegment(action string) string {
	return strings.ReplaceAll(mcpSanitize(action), ".", "_")
}

// mcpSanitize trims, replaces every char outside [A-Za-z0-9_.-] with '_', then
// trims leading/trailing underscores; an empty result becomes "node".
//
// There is deliberately NO decode. The transform is lossy — '.' and '_' both map
// to '_', and a node name may itself contain "__" — so resolution MUST be by
// RE-ENCODING each candidate and comparing, never by splitting the incoming
// string. See BridgeResolveTool.
func mcpSanitize(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "node"
	}
	return out
}

// ── Tool resolution (§4) ─────────────────────────────────────────────────────

// BridgeToolMatch is a resolved (backend, action) pair.
type BridgeToolMatch struct {
	Backend    NwpBackend
	Descriptor NwpNodeDescriptor
	Action     NwpActionDescriptor
	// QualifiedName is the canonical `node__action` name for this match.
	QualifiedName string
}

// BridgeResolveTool resolves a tool name to exactly one exposed action.
//
//  1. Iterate all backends, skipping non-invokable ones.
//  2. A qualified match — Encode(name, actionID) equal ignoring case — WINS
//     and returns immediately.
//  3. Otherwise a bare `actionID` or `EncodeActionSegment(actionID)` match
//     (ignoring case) becomes an unqualified candidate.
//  4. After the full scan, return the single candidate iff exactly one exists.
//
// Two nodes exposing the same action id must be disambiguated BY THE CALLER,
// not guessed at here — so the candidate list is returned alongside so the
// error can name both qualified candidates (TC-N2-BridgeIn-04).
func BridgeResolveTool(ctx context.Context, backends []NwpBackend, toolName string) (*BridgeToolMatch, []string) {
	var unqualified []BridgeToolMatch

	for _, b := range backends {
		d, err := b.GetDescriptor(ctx)
		if err != nil || !d.IsInvokable() {
			continue
		}
		actions, err := b.GetActions(ctx)
		if err != nil {
			continue
		}
		for _, a := range actions {
			qualified := McpToolNameEncode(d.Name, a.ActionID)
			if strings.EqualFold(qualified, toolName) {
				return &BridgeToolMatch{Backend: b, Descriptor: d, Action: a, QualifiedName: qualified}, nil
			}
			if strings.EqualFold(a.ActionID, toolName) ||
				strings.EqualFold(McpToolNameEncodeActionSegment(a.ActionID), toolName) {
				unqualified = append(unqualified,
					BridgeToolMatch{Backend: b, Descriptor: d, Action: a, QualifiedName: qualified})
			}
		}
	}

	if len(unqualified) == 1 {
		m := unqualified[0]
		return &m, nil
	}
	candidates := make([]string, 0, len(unqualified))
	for _, m := range unqualified {
		candidates = append(candidates, m.QualifiedName)
	}
	return nil, candidates
}

// bridgeAllInvokableActions collects every action of every invokable backend.
func bridgeAllInvokableActions(ctx context.Context, backends []NwpBackend) []BridgeToolMatch {
	var out []BridgeToolMatch
	for _, b := range backends {
		d, err := b.GetDescriptor(ctx)
		if err != nil || !d.IsInvokable() {
			continue
		}
		actions, err := b.GetActions(ctx)
		if err != nil {
			continue
		}
		for _, a := range actions {
			out = append(out, BridgeToolMatch{
				Backend: b, Descriptor: d, Action: a,
				QualifiedName: McpToolNameEncode(d.Name, a.ActionID),
			})
		}
	}
	return out
}

// bridgeQueryableBackends returns the backends whose role is queryable.
func bridgeQueryableBackends(ctx context.Context, backends []NwpBackend) []struct {
	Backend    NwpBackend
	Descriptor NwpNodeDescriptor
} {
	var out []struct {
		Backend    NwpBackend
		Descriptor NwpNodeDescriptor
	}
	for _, b := range backends {
		d, err := b.GetDescriptor(ctx)
		if err != nil || !d.IsQueryable() {
			continue
		}
		out = append(out, struct {
			Backend    NwpBackend
			Descriptor NwpNodeDescriptor
		}{b, d})
	}
	return out
}

// ── Backend materialisation ──────────────────────────────────────────────────

// BridgeServerBackendSpec declares the backends a Bridge deployment fronts.
type BridgeServerBackendSpec struct {
	// In-process node.
	Descriptor NwpNodeDescriptor
	Actions    []NwpActionDescriptor
	Dispatch   BridgeDispatch
	Query      BridgeQuery
	// Remote HTTP nodes.
	Upstreams []NwpUpstream
}

// BridgeCreateBackends materialises the configured backends.
//
// An in-process backend is added iff Dispatch != nil || Query != nil ||
// len(Actions) > 0. That last clause is deliberate: a deployment that declares
// actions but forgets the dispatcher still gets the backend, so its tools appear
// in tools/list and the call fails LOUDLY with
// NWP-BRIDGE-SERVER-DISPATCHER-MISSING rather than looking like
// "this node exposes nothing".
//
// Both shapes may coexist in one Bridge.
func BridgeCreateBackends(spec BridgeServerBackendSpec, client *http.Client) ([]NwpBackend, error) {
	var out []NwpBackend
	if spec.Dispatch != nil || spec.Query != nil || len(spec.Actions) > 0 {
		out = append(out, NewInProcessNwpBackend(spec.Descriptor, spec.Actions, spec.Dispatch, spec.Query))
	}
	if len(spec.Upstreams) > 0 && client == nil {
		return nil, errNoHTTPClient
	}
	for _, up := range spec.Upstreams {
		out = append(out, NewHttpNwpBackend(up, client))
	}
	return out, nil
}

var errNoHTTPClient = &BridgeConfigError{
	Message: "upstreams are configured but no HTTP client was supplied to BridgeCreateBackends.",
}

// BridgeConfigError is a Bridge deployment misconfiguration.
type BridgeConfigError struct{ Message string }

func (e *BridgeConfigError) Error() string { return e.Message }
