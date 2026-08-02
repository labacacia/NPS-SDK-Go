// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// NPS-CR-0010 §2.2 — the inbound A2A (JSON-RPC 2.0) Bridge server.

// A2A provider identity carried on the AgentCard.
const (
	A2aProviderOrganization = "LabAcacia / INNO LOTUS PTY LTD"
	A2aProviderURL          = "https://github.com/labacacia/nps"
)

// a2aSkillKeys are the metadata keys searched, IN THIS ORDER, to identify the
// NPS action a task targets.
var a2aSkillKeys = []string{"action_id", "actionId", "skill_id", "skillId", "skill"}

// A2aMessagePart is one part of an A2A message.
type A2aMessagePart struct {
	Type     string          `json:"type,omitempty"`
	Text     string          `json:"text,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// A2aMessage is an A2A message.
type A2aMessage struct {
	Role     string           `json:"role,omitempty"`
	Parts    []A2aMessagePart `json:"parts,omitempty"`
	Metadata json.RawMessage  `json:"metadata,omitempty"`
}

// A2aTaskSendParams are the `tasks/send` parameters.
type A2aTaskSendParams struct {
	ID        string          `json:"id"`
	SessionID string          `json:"sessionId,omitempty"`
	Message   *A2aMessage     `json:"message,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// A2aInboundServer translates inbound A2A JSON-RPC into NWP backend calls.
type A2aInboundServer struct {
	opts *BridgeInboundOptions
}

// NewA2aInboundServer constructs the inbound A2A server.
func NewA2aInboundServer(opts *BridgeInboundOptions) *A2aInboundServer {
	return &A2aInboundServer{opts: opts}
}

// BuildAgentCard renders the AgentCard served at /.well-known/agent.json.
func (s *A2aInboundServer) BuildAgentCard(ctx context.Context, endpointURL string) map[string]any {
	skills := []any{}
	for _, m := range bridgeAllInvokableActions(ctx, s.opts.Backends) {
		name := m.Action.Description
		if name == "" {
			name = m.Action.ActionID
		}
		skill := map[string]any{
			"id":          m.QualifiedName,
			"name":        name,
			"description": m.Action.Description,
			"inputModes":  []string{"text", "data"},
			"outputModes": []string{"data"},
		}
		if len(m.Action.Tags) > 0 {
			skill["tags"] = m.Action.Tags
		}
		skills = append(skills, skill)
	}

	card := map[string]any{
		"name":        s.opts.serverName(),
		"description": "NPS Bridge Node — inbound A2A surface over the fronted NWP nodes.",
		"url":         endpointURL,
		"provider": map[string]any{
			"organization": A2aProviderOrganization,
			"url":          A2aProviderURL,
		},
		"version": s.opts.serverVersion(),
		"capabilities": map[string]any{
			"streaming":              false,
			"pushNotifications":      false,
			"stateTransitionHistory": false,
		},
		"skills": skills,
	}
	// RequireAuth is advertised here on purpose: it is part of the protocol
	// surface, not merely host config.
	if s.opts.requireAuth() {
		card["authentication"] = map[string]any{
			"schemes":     []string{"apikey"},
			"credentials": HeaderAgent,
		}
	} else {
		card["authentication"] = nil
	}
	return card
}

// Dispatch handles one A2A JSON-RPC request. Only "tasks/send" is served.
func (s *A2aInboundServer) Dispatch(ctx context.Context, req *BridgeJsonRpcRequest) BridgeJsonRpcResponse {
	if req == nil {
		return jsonRpcErr(nullID, JsonRpcInvalidRequest, "JSON-RPC request is required.", nil)
	}
	id := requestID(req)

	// §16.1.2 MUST-5: the direction gate is the FIRST thing in dispatch.
	if !s.opts.ServesInbound(BridgeProtocolA2A) {
		return jsonRpcErrObj(id, s.opts.directionUnsupported(BridgeProtocolA2A))
	}

	if req.Method != "tasks/send" {
		return jsonRpcErr(id, JsonRpcMethodNotFound,
			fmt.Sprintf("A2A method '%s' is not supported by this Bridge Node.", req.Method),
			map[string]any{"error": ErrBridgeDirectionUnsupported})
	}

	var p A2aTaskSendParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return jsonRpcErr(id, JsonRpcInvalidParams, err.Error(), nil)
		}
	}
	if strings.TrimSpace(p.ID) == "" {
		return jsonRpcErr(id, JsonRpcInvalidParams, "A2A tasks/send params.id is required.", nil)
	}

	match, candidates := s.resolveSkill(ctx, &p)
	if match == nil {
		data := map[string]any{"error": ErrBridgeServerToolNotFound}
		if len(candidates) > 0 {
			data["candidates"] = candidates
		}
		return jsonRpcErr(id, JsonRpcInvalidParams,
			"A2A task metadata must identify an exposed NPS action when more than one is available.", data)
	}

	args := a2aExtractArguments(&p)
	res := match.Backend.Invoke(ctx, match.Action.ActionID, args, false)

	// §16.3: an infrastructure-class failure becomes a JSON-RPC ERROR, not a task
	// object. Reporting it as a task — even a failed one — hands the peer a task
	// where it should have received a transport error, and A2A peers retry failed
	// tasks. §16.3 also forbids silently downgrading an error to a `completed` task.
	if !res.Ok && BridgeMustBeProtocolError(res.NpsStatus) {
		return jsonRpcErr(id, BridgeToJsonRpc(res.NpsStatus, false), res.Message,
			map[string]any{"error": res.NwpError, "status": res.NpsStatus})
	}
	return jsonRpcOK(id, a2aToTask(&p, res))
}

// resolveSkill finds the NPS action the task targets.
//
// The named-skill path searches task.metadata, then task.message.metadata, then
// per-part metadata and per-part data, for the first of the a2aSkillKeys. A
// found value matches either the qualified `node__action` name or the raw
// action_id, case-insensitively.
//
// With no skill named, resolution succeeds only when EXACTLY ONE action is
// exposed across all invokable backends — the same "disambiguated by the
// caller, not guessed at here" principle as MCP §4.
func (s *A2aInboundServer) resolveSkill(ctx context.Context, p *A2aTaskSendParams) (*BridgeToolMatch, []string) {
	all := bridgeAllInvokableActions(ctx, s.opts.Backends)

	if named := a2aFindSkillName(p); named != "" {
		for _, m := range all {
			if strings.EqualFold(m.QualifiedName, named) || strings.EqualFold(m.Action.ActionID, named) {
				return &m, nil
			}
		}
		candidates := make([]string, 0, len(all))
		for _, m := range all {
			candidates = append(candidates, m.QualifiedName)
		}
		return nil, candidates
	}

	if len(all) == 1 {
		return &all[0], nil
	}
	candidates := make([]string, 0, len(all))
	for _, m := range all {
		candidates = append(candidates, m.QualifiedName)
	}
	return nil, candidates
}

func a2aFindSkillName(p *A2aTaskSendParams) string {
	if v := a2aLookupKeys(p.Metadata, a2aSkillKeys); v != "" {
		return v
	}
	if p.Message != nil {
		if v := a2aLookupKeys(p.Message.Metadata, a2aSkillKeys); v != "" {
			return v
		}
		for _, part := range p.Message.Parts {
			if v := a2aLookupKeys(part.Metadata, a2aSkillKeys); v != "" {
				return v
			}
			if v := a2aLookupKeys(part.Data, a2aSkillKeys); v != "" {
				return v
			}
		}
	}
	return ""
}

func a2aLookupKeys(raw json.RawMessage, keys []string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// a2aExtractArguments recovers the action arguments, in this order:
// task.metadata.params|arguments -> task.message.metadata.params|arguments ->
// per-part data.params|arguments -> a type:"data" part's whole data ->
// a type:"text" part becomes {"text": <the text>} -> else nil.
func a2aExtractArguments(p *A2aTaskSendParams) json.RawMessage {
	if v := a2aLookupObject(p.Metadata); v != nil {
		return v
	}
	if p.Message == nil {
		return nil
	}
	if v := a2aLookupObject(p.Message.Metadata); v != nil {
		return v
	}
	for _, part := range p.Message.Parts {
		if v := a2aLookupObject(part.Data); v != nil {
			return v
		}
	}
	for _, part := range p.Message.Parts {
		if strings.EqualFold(part.Type, "data") && len(part.Data) > 0 {
			return part.Data
		}
	}
	for _, part := range p.Message.Parts {
		if strings.EqualFold(part.Type, "text") && part.Text != "" {
			raw, _ := json.Marshal(map[string]any{"text": part.Text})
			return raw
		}
	}
	return nil
}

func a2aLookupObject(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	for _, k := range []string{"params", "arguments"} {
		if v, ok := m[k]; ok && len(v) > 0 && string(v) != "null" {
			return v
		}
	}
	return nil
}

// a2aToTask projects a backend result onto an A2A task object.
func a2aToTask(p *A2aTaskSendParams, res NwpResult) map[string]any {
	state := "completed"
	artifactName := "nps-result"
	payload := res.Payload
	var statusMessage any

	if !res.Ok {
		state = "failed"
		artifactName = "nps-error"
		detail := res.Message
		if detail == "" {
			detail = res.NwpError
		}
		if detail == "" {
			detail = res.NpsStatus
		}
		// The NPS code is preserved VERBATIM in the failure detail.
		statusMessage = map[string]any{
			"role":  "agent",
			"parts": []any{map[string]any{"type": "text", "text": detail}},
		}
		payload, _ = json.Marshal(bridgeFailurePayload(res))
	}

	var payloadValue any
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &payloadValue)
	}

	task := map[string]any{
		"id": p.ID,
		"status": map[string]any{
			"state":     state,
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"message":   statusMessage,
		},
		"artifacts": []any{map[string]any{
			"name":  artifactName,
			"parts": []any{map[string]any{"type": "data", "data": payloadValue}},
			"index": 0,
		}},
	}
	if p.SessionID != "" {
		task["sessionId"] = p.SessionID
	}
	if p.Message != nil {
		task["history"] = []any{p.Message}
	} else {
		task["history"] = []any{}
	}
	return task
}
