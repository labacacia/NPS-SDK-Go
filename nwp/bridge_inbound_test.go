// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labacacia/NPS-sdk-go/core"
	"github.com/labacacia/NPS-sdk-go/nwp"
)

// ── Fixtures ──────────────────────────────────────────────────────────────────

func jrpc(method string, params any) *nwp.BridgeJsonRpcRequest {
	raw, _ := json.Marshal(params)
	if params == nil {
		raw = nil
	}
	return &nwp.BridgeJsonRpcRequest{JsonRpc: "2.0", ID: json.RawMessage(`1`), Method: method, Params: raw}
}

// actionBackend fronts one Action Node named `name` exposing the given action ids.
func actionBackend(name string, actionIDs ...string) *nwp.InProcessNwpBackend {
	actions := make([]nwp.NwpActionDescriptor, 0, len(actionIDs))
	for _, id := range actionIDs {
		actions = append(actions, nwp.NwpActionDescriptor{ActionID: id, Description: "does " + id})
	}
	return nwp.NewInProcessNwpBackend(
		nwp.NwpNodeDescriptor{Name: name, Role: nwp.NwpRoleAction},
		actions,
		func(_ context.Context, f *nwp.ActionFrame) (core.FrameDict, error) {
			return core.FrameDict{"anchor_ref": "nps:test:result", "action": f.Action, "params": f.Params}, nil
		},
		nil,
	)
}

// memoryBackend fronts one Memory Node named `name`.
func memoryBackend(name string) *nwp.InProcessNwpBackend {
	return nwp.NewInProcessNwpBackend(
		nwp.NwpNodeDescriptor{Name: name, Role: nwp.NwpRoleMemory},
		nil, nil,
		func(_ context.Context, f *nwp.QueryFrame) (core.FrameDict, error) {
			return core.FrameDict{"anchor_ref": "nps:test:rows", "count": 1, "filter": f.Filter}, nil
		},
	)
}

// errorBackend fronts an Action Node whose dispatch returns an ErrorFrame shape.
func errorBackend(name, npsStatus, code, message string) *nwp.InProcessNwpBackend {
	return nwp.NewInProcessNwpBackend(
		nwp.NwpNodeDescriptor{Name: name, Role: nwp.NwpRoleAction},
		[]nwp.NwpActionDescriptor{{ActionID: "boom"}},
		func(context.Context, *nwp.ActionFrame) (core.FrameDict, error) {
			return core.FrameDict{"status": npsStatus, "error": code, "message": message}, nil
		},
		nil,
	)
}

func mcpFixture(backends ...nwp.NwpBackend) *nwp.McpInboundServer {
	return nwp.NewMcpInboundServer(&nwp.BridgeInboundOptions{
		Backends: backends, InboundProtocols: []string{"mcp"},
	})
}

func resultMap(t *testing.T, resp nwp.BridgeJsonRpcResponse) map[string]any {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("expected a result, got error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	raw, _ := json.Marshal(resp.Result)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func errData(t *testing.T, resp nwp.BridgeJsonRpcResponse) map[string]any {
	t.Helper()
	if resp.Error == nil {
		t.Fatal("expected an error response")
	}
	raw, _ := json.Marshal(resp.Error.Data)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

// ── BridgeIn-01: MCP serves the full required method set ─────────────────────

func TestMcpInbound_ServesTheFullRequiredMethodSet(t *testing.T) {
	s := mcpFixture(memoryBackend("mem"), actionBackend("bridge-inbound-test", "orders.lookup"))
	ctx := context.Background()

	want := []string{"initialize", "ping", "tools/list", "tools/call", "resources/list", "resources/read"}
	if len(nwp.McpRequiredMethods) != len(want) {
		t.Fatalf("McpRequiredMethods must be exported as data and normative: %v", nwp.McpRequiredMethods)
	}
	for i, m := range want {
		if nwp.McpRequiredMethods[i] != m {
			t.Errorf("McpRequiredMethods[%d] = %s, want %s", i, nwp.McpRequiredMethods[i], m)
		}
	}

	for _, m := range want {
		var params any
		switch m {
		case "tools/call":
			params = map[string]any{"name": "bridge-inbound-test__orders_lookup", "arguments": map[string]any{}}
		case "resources/read":
			params = map[string]any{"uri": "nwp://mem/"}
		}
		resp := s.Dispatch(ctx, jrpc(m, params))
		if resp.Error != nil {
			t.Errorf("%s returned an error %d: %s", m, resp.Error.Code, resp.Error.Message)
		}
	}
}

func TestMcpInbound_InitializeAdvertisesBothCapabilities(t *testing.T) {
	// No Memory Node behind at all.
	s := mcpFixture(actionBackend("act", "do"))
	r := resultMap(t, s.Dispatch(context.Background(), jrpc("initialize", nil)))

	caps, _ := r["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Error("capabilities.tools must always be advertised")
	}
	if _, ok := caps["resources"]; !ok {
		t.Error("capabilities.resources must always be advertised, even with no Memory Node behind")
	}
	info, _ := r["serverInfo"].(map[string]any)
	if info["name"] != "nps-bridge-server" {
		t.Errorf("serverInfo.name default: %v", info["name"])
	}
}

func TestMcpInbound_ServesResourcesMethodsEvenWithNoMemoryNode(t *testing.T) {
	s := mcpFixture(actionBackend("act", "do"))
	r := resultMap(t, s.Dispatch(context.Background(), jrpc("resources/list", nil)))

	res, ok := r["resources"].([]any)
	if !ok {
		t.Fatalf("resources/list must return an array, got %#v", r["resources"])
	}
	if len(res) != 0 {
		t.Errorf("expected an empty (but conformant) set, got %v", res)
	}
}

func TestMcpInbound_ServesResourcesOverAQueryableNode(t *testing.T) {
	complexNode := nwp.NewInProcessNwpBackend(
		nwp.NwpNodeDescriptor{Name: "bridge-inbound-test", Role: nwp.NwpRoleComplex},
		[]nwp.NwpActionDescriptor{{ActionID: "orders.lookup"}},
		func(context.Context, *nwp.ActionFrame) (core.FrameDict, error) { return core.FrameDict{}, nil },
		func(context.Context, *nwp.QueryFrame) (core.FrameDict, error) {
			return core.FrameDict{"anchor_ref": "nps:test:rows"}, nil
		},
	)
	s := mcpFixture(complexNode)
	ctx := context.Background()

	r := resultMap(t, s.Dispatch(ctx, jrpc("resources/list", nil)))
	res := r["resources"].([]any)
	if len(res) != 1 {
		t.Fatalf("a Complex node is queryable and must be listed: %v", res)
	}
	entry := res[0].(map[string]any)
	if entry["uri"] != "nwp://bridge-inbound-test/" {
		t.Errorf("uri = %v", entry["uri"])
	}
	if entry["mimeType"] != "application/json" {
		t.Errorf("mimeType = %v", entry["mimeType"])
	}
	if !strings.Contains(entry["description"].(string), "read to query") {
		t.Errorf("default description: %v", entry["description"])
	}

	r = resultMap(t, s.Dispatch(ctx, jrpc("resources/read", map[string]any{"uri": "nwp://bridge-inbound-test/"})))
	contents := r["contents"].([]any)
	if len(contents) != 1 {
		t.Fatalf("contents: %v", contents)
	}
	c := contents[0].(map[string]any)
	if !strings.Contains(c["text"].(string), "nps:test:rows") {
		t.Errorf("resources/read must carry the payload raw JSON: %v", c["text"])
	}
}

func TestMcpInbound_ToolsListSurfacesQualifiedNames(t *testing.T) {
	s := mcpFixture(actionBackend("bridge-inbound-test", "orders.lookup"))
	r := resultMap(t, s.Dispatch(context.Background(), jrpc("tools/list", nil)))

	tools := r["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools: %v", tools)
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "bridge-inbound-test__orders_lookup" {
		t.Errorf("tools/list must emit QUALIFIED node__action names, got %v", tool["name"])
	}
	schema, _ := json.Marshal(tool["inputSchema"])
	if !strings.Contains(string(schema), `"additionalProperties":true`) {
		t.Errorf("an absent schema must be advertised as the open object schema: %s", schema)
	}
}

func TestMcpInbound_ListsToolsAndDispatchesToolCall(t *testing.T) {
	s := mcpFixture(actionBackend("bridge-inbound-test", "orders.lookup"))
	r := resultMap(t, s.Dispatch(context.Background(), jrpc("tools/call", map[string]any{
		"name":      "bridge-inbound-test__orders_lookup",
		"arguments": map[string]any{"id": 7},
	})))

	if r["isError"] != false {
		t.Errorf("a successful dispatch must have isError == false, got %v", r["isError"])
	}
	text := r["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"action":"orders.lookup"`) {
		t.Errorf("the raw action id must reach the backend: %s", text)
	}
}

func TestMcpInbound_StillResolvesUnqualifiedToolNames(t *testing.T) {
	s := mcpFixture(actionBackend("bridge-inbound-test", "orders.lookup"))

	// The bare, dot-form action id.
	r := resultMap(t, s.Dispatch(context.Background(), jrpc("tools/call", map[string]any{"name": "orders.lookup"})))
	if r["isError"] != false {
		t.Errorf("a bare action id must resolve: %v", r)
	}
	// The encoded action segment.
	r = resultMap(t, s.Dispatch(context.Background(), jrpc("tools/call", map[string]any{"name": "orders_lookup"})))
	if r["isError"] != false {
		t.Errorf("the encoded bare segment must resolve: %v", r)
	}
}

func TestMcpInbound_MissingToolNameIsInvalidParams(t *testing.T) {
	s := mcpFixture(actionBackend("act", "do"))
	resp := s.Dispatch(context.Background(), jrpc("tools/call", map[string]any{"name": "  "}))
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("expected -32602, got %v", resp.Error)
	}
	if resp.Error.Message != "MCP tools/call requires params.name." {
		t.Errorf("message: %s", resp.Error.Message)
	}
}

func TestMcpInbound_UnknownMethodIsMethodNotFound(t *testing.T) {
	s := mcpFixture(actionBackend("act", "do"))
	resp := s.Dispatch(context.Background(), jrpc("prompts/list", nil))
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("expected -32601, got %v", resp.Error)
	}
	if errData(t, resp)["error"] != "NWP-BRIDGE-DIRECTION-UNSUPPORTED" {
		t.Errorf("data: %v", errData(t, resp))
	}
}

// ── BridgeIn-04: bare id resolves, ambiguity is rejected ─────────────────────

func TestMcpInbound_BareIdResolvesWhileAmbiguityIsRejected(t *testing.T) {
	// Two nodes; exactly one defines orders_lookup, both define status.
	s := mcpFixture(
		actionBackend("node-a", "orders.lookup", "status"),
		actionBackend("node-b", "status"),
	)
	ctx := context.Background()

	if r := resultMap(t, s.Dispatch(ctx, jrpc("tools/call", map[string]any{"name": "orders_lookup"}))); r["isError"] != false {
		t.Errorf("an unambiguous bare id must resolve and succeed: %v", r)
	}

	resp := s.Dispatch(ctx, jrpc("tools/call", map[string]any{"name": "status"}))
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("an ambiguous bare id must be rejected with -32601, got %v", resp.Error)
	}
	if resp.Result != nil {
		t.Error("an error response must not also carry a result")
	}
	data := errData(t, resp)
	if data["error"] != "NWP-BRIDGE-SERVER-TOOL-NOT-FOUND" {
		t.Errorf("data.error = %v", data["error"])
	}
	// TC-N2-BridgeIn-04 requires the error to NAME BOTH qualified candidates.
	cands, _ := data["candidates"].([]any)
	if len(cands) != 2 {
		t.Fatalf("the rejection must name both qualified candidates, got %v", data["candidates"])
	}
	joined := strings.Join([]string{cands[0].(string), cands[1].(string)}, ",")
	if !strings.Contains(joined, "node-a__status") || !strings.Contains(joined, "node-b__status") {
		t.Errorf("candidates: %v", cands)
	}
}

func TestMcpInbound_UnknownToolIsMinus32601AndNever32002(t *testing.T) {
	s := mcpFixture(actionBackend("act", "do"))
	resp := s.Dispatch(context.Background(), jrpc("tools/call", map[string]any{"name": "nope"}))

	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("an unknown tool is -32601, got %v", resp.Error)
	}
	if resp.Error.Code == -32002 {
		t.Fatal("-32002 is RETIRED by CR-0010 and MUST NOT be emitted")
	}
	if !strings.Contains(resp.Error.Message, "is not exposed by this Bridge Node") {
		t.Errorf("message: %s", resp.Error.Message)
	}
}

// ── resources/read URI handling ──────────────────────────────────────────────

func TestMcpInbound_ResourcesReadUriValidation(t *testing.T) {
	s := mcpFixture(memoryBackend("mem"))
	ctx := context.Background()

	for _, tc := range []struct{ name, uri string }{
		{"missing", ""},
		{"relative", "mem/"},
		{"wrong scheme", "https://mem/"},
	} {
		resp := s.Dispatch(ctx, jrpc("resources/read", map[string]any{"uri": tc.uri}))
		if resp.Error == nil || resp.Error.Code != -32602 {
			t.Errorf("%s: expected -32602, got %v", tc.name, resp.Error)
		}
	}

	// An unknown HOST is -32602 (NOT -32601): the URI is a parameter.
	resp := s.Dispatch(ctx, jrpc("resources/read", map[string]any{"uri": "nwp://ghost/"}))
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("an unknown resource host is -32602, got %v", resp.Error)
	}
	data := errData(t, resp)
	if data["error"] != "NWP-BRIDGE-SERVER-TOOL-NOT-FOUND" || data["uri"] != "nwp://ghost/" {
		t.Errorf("data: %v", data)
	}
}

func TestMcpInbound_ResourcesReadHostIsCaseInsensitive(t *testing.T) {
	s := mcpFixture(memoryBackend("Mem"))
	resp := s.Dispatch(context.Background(), jrpc("resources/read", map[string]any{"uri": "nwp://mem/"}))
	if resp.Error != nil {
		t.Fatalf("the host must resolve case-insensitively: %v", resp.Error)
	}
}

// ── BridgeIn-05: §16.3 error mapping ─────────────────────────────────────────

func TestMcpInbound_AuthFailureIsAProtocolErrorNotAnIsErrorResult(t *testing.T) {
	s := mcpFixture(errorBackend("act", core.NpsAuthForbidden, "NWP-AUTH-NID-SCOPE-VIOLATION", "nope"))
	resp := s.Dispatch(context.Background(), jrpc("tools/call", map[string]any{"name": "boom"}))

	if resp.Error == nil {
		t.Fatal("an auth-class failure MUST be a JSON-RPC error, never isError: true")
	}
	if resp.Error.Code != -32003 {
		t.Errorf("NPS-AUTH-FORBIDDEN maps to -32003, got %d", resp.Error.Code)
	}
	if resp.Result != nil {
		t.Error("result must be nil on a protocol error")
	}
}

func TestMcpInbound_DomainFailureStaysAnIsErrorResult(t *testing.T) {
	s := mcpFixture(errorBackend("act", core.NpsClientBadParam, "NWP-ACTION-PARAMS-INVALID", "bad id"))
	r := resultMap(t, s.Dispatch(context.Background(), jrpc("tools/call", map[string]any{"name": "boom"})))

	if r["isError"] != true {
		t.Fatal("a tool-DOMAIN failure is what MCP's isError flag is for")
	}
	text := r["content"].([]any)[0].(map[string]any)["text"].(string)
	for _, want := range []string{"NPS-CLIENT-BAD-PARAM", "NWP-ACTION-PARAMS-INVALID", "bad id"} {
		if !strings.Contains(text, want) {
			t.Errorf("the failure payload must carry %s: %s", want, text)
		}
	}
}

func TestMcpInbound_MissingDispatcherFailsLoudlyWithARegisteredCode(t *testing.T) {
	// A deployment that declares actions but forgets the dispatcher.
	backends, err := nwp.BridgeCreateBackends(nwp.BridgeServerBackendSpec{
		Descriptor: nwp.NwpNodeDescriptor{Name: "act", Role: nwp.NwpRoleAction},
		Actions:    []nwp.NwpActionDescriptor{{ActionID: "do"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(backends) != 1 {
		t.Fatalf("declaring actions alone must still materialise a backend, got %d", len(backends))
	}
	s := mcpFixture(backends...)
	ctx := context.Background()

	// The tool still APPEARS — that is the point.
	r := resultMap(t, s.Dispatch(ctx, jrpc("tools/list", nil)))
	if len(r["tools"].([]any)) != 1 {
		t.Fatal("the tool must still appear in tools/list")
	}

	resp := s.Dispatch(ctx, jrpc("tools/call", map[string]any{"name": "act__do"}))
	if resp.Error == nil || resp.Error.Code != -32603 {
		t.Fatalf("expected -32603, got %v", resp.Error)
	}
	blob, _ := json.Marshal(resp.Error)
	if !strings.Contains(string(blob), "NWP-BRIDGE-SERVER-DISPATCHER-MISSING") {
		t.Errorf("expected the registered code: %s", blob)
	}
	if strings.Contains(string(blob), "NPS-SERVER-NOT-IMPLEMENTED") {
		t.Error("NPS-SERVER-NOT-IMPLEMENTED is not an NPS status and must not be reintroduced")
	}
}

func TestMcpInbound_QueryOnANonQueryableNodeIsToolNotFound(t *testing.T) {
	b := actionBackend("act", "do")
	res := b.Query(context.Background(), nil)
	if res.Ok {
		t.Fatal("an Action Node is not queryable")
	}
	if res.NpsStatus != core.NpsServerUnsupported || res.NwpError != "NWP-BRIDGE-SERVER-TOOL-NOT-FOUND" {
		t.Errorf("got %s / %s", res.NpsStatus, res.NwpError)
	}
	if !strings.Contains(res.Message, "is not queryable (role: action)") {
		t.Errorf("message: %s", res.Message)
	}
}

// ── BridgeIn-06: undeclared direction is refused ─────────────────────────────

func TestBridgeInbound_UndeclaredProtocolIsRefusedWithBothArraysInHint(t *testing.T) {
	opts := &nwp.BridgeInboundOptions{
		Backends:          []nwp.NwpBackend{actionBackend("act", "do")},
		InboundProtocols:  []string{"mcp"},
		OutboundProtocols: []string{"http"},
	}
	a2a := nwp.NewA2aInboundServer(opts)

	resp := a2a.Dispatch(context.Background(), jrpc("tasks/send", map[string]any{"id": "t1"}))
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("expected -32601, got %v", resp.Error)
	}
	data := errData(t, resp)
	if data["error"] != "NWP-BRIDGE-DIRECTION-UNSUPPORTED" {
		t.Fatalf("data.error = %v", data["error"])
	}
	if !strings.Contains(resp.Error.Message, `does not declare "a2a" in bridge_inbound_protocols`) {
		t.Errorf("message: %s", resp.Error.Message)
	}
	// §16.1.2 MUST-5 SHOULD-clause: BOTH declared arrays in `hint`.
	hint, _ := data["hint"].(map[string]any)
	if hint == nil {
		t.Fatal("the response SHOULD carry both declared arrays in hint")
	}
	if _, ok := hint["bridge_inbound_protocols"]; !ok {
		t.Error("hint.bridge_inbound_protocols missing")
	}
	if _, ok := hint["bridge_protocols"]; !ok {
		t.Error("hint.bridge_protocols missing")
	}

	// The direction gate is the FIRST thing in dispatch — even a bogus method
	// gets the direction error, not "method not supported".
	resp = a2a.Dispatch(context.Background(), jrpc("garbage", nil))
	if errData(t, resp)["error"] != "NWP-BRIDGE-DIRECTION-UNSUPPORTED" {
		t.Error("the direction gate must run before method routing")
	}
}

func TestBridgeInbound_DefaultInboundSetIsMcpAndA2aButNotGrpc(t *testing.T) {
	opts := &nwp.BridgeInboundOptions{} // InboundProtocols left nil
	if !opts.ServesInbound("mcp") || !opts.ServesInbound("a2a") {
		t.Error("the default inbound set is {mcp, a2a}")
	}
	if opts.ServesInbound("grpc") {
		t.Error("gRPC is deliberately NOT in the default set")
	}
	if !opts.ServesInbound("MCP") {
		t.Error("ServesInbound is a case-insensitive membership test")
	}
	// An explicitly empty set serves nothing (an outbound-only Bridge).
	empty := &nwp.BridgeInboundOptions{InboundProtocols: []string{}}
	if empty.ServesInbound("mcp") {
		t.Error("an explicitly empty inbound set must serve nothing")
	}
}

// ── BridgeIn-03: A2A round-trip ──────────────────────────────────────────────

func a2aFixture(backends ...nwp.NwpBackend) *nwp.A2aInboundServer {
	return nwp.NewA2aInboundServer(&nwp.BridgeInboundOptions{
		Backends: backends, InboundProtocols: []string{"a2a"},
	})
}

func TestA2aInbound_AgentCardListsQualifiedSkills(t *testing.T) {
	s := a2aFixture(actionBackend("bridge-inbound-test", "orders.lookup"))
	card := s.BuildAgentCard(context.Background(), "https://bridge.test/a2a")

	provider := card["provider"].(map[string]any)
	if provider["organization"] != "LabAcacia / INNO LOTUS PTY LTD" {
		t.Errorf("provider.organization = %v", provider["organization"])
	}
	caps := card["capabilities"].(map[string]any)
	for _, k := range []string{"streaming", "pushNotifications", "stateTransitionHistory"} {
		if caps[k] != false {
			t.Errorf("capabilities.%s must be false, got %v", k, caps[k])
		}
	}
	// RequireAuth defaults to true, and it is advertised.
	auth, _ := card["authentication"].(map[string]any)
	if auth == nil || auth["credentials"] != "X-NWP-Agent" {
		t.Errorf("authentication = %v", card["authentication"])
	}

	skills := card["skills"].([]any)
	if len(skills) != 1 {
		t.Fatalf("skills: %v", skills)
	}
	sk := skills[0].(map[string]any)
	if sk["id"] != "bridge-inbound-test__orders_lookup" {
		t.Errorf("the AgentCard must list QUALIFIED skill ids, got %v", sk["id"])
	}
	if !equalStrings(sk["inputModes"], []string{"text", "data"}) {
		t.Errorf("inputModes = %v", sk["inputModes"])
	}
	if !equalStrings(sk["outputModes"], []string{"data"}) {
		t.Errorf("outputModes = %v", sk["outputModes"])
	}
}

func equalStrings(got any, want []string) bool {
	raw, _ := json.Marshal(got)
	var g []string
	if json.Unmarshal(raw, &g) != nil || len(g) != len(want) {
		return false
	}
	for i := range want {
		if g[i] != want[i] {
			return false
		}
	}
	return true
}

func TestA2aInbound_TasksSendDispatchesActionFrame(t *testing.T) {
	s := a2aFixture(actionBackend("bridge-inbound-test", "orders.lookup"))
	r := resultMap(t, s.Dispatch(context.Background(), jrpc("tasks/send", map[string]any{
		"id":        "task-1",
		"sessionId": "sess-1",
		"metadata":  map[string]any{"action_id": "bridge-inbound-test__orders_lookup"},
		"message": map[string]any{
			"role":  "user",
			"parts": []any{map[string]any{"type": "data", "data": map[string]any{"params": map[string]any{"id": 7}}}},
		},
	})))

	if r["id"] != "task-1" || r["sessionId"] != "sess-1" {
		t.Errorf("task identity: %v", r)
	}
	status := r["status"].(map[string]any)
	if status["state"] != "completed" {
		t.Fatalf("state = %v", status["state"])
	}
	if status["message"] != nil {
		t.Errorf("status.message must be null on success, got %v", status["message"])
	}
	arts := r["artifacts"].([]any)
	if len(arts) != 1 {
		t.Fatal("expected one artifact")
	}
	art := arts[0].(map[string]any)
	if art["name"] != "nps-result" {
		t.Errorf("artifact name = %v", art["name"])
	}
	// The action result reaches the peer as the task ARTIFACT.
	data := art["parts"].([]any)[0].(map[string]any)["data"].(map[string]any)
	if data["anchor_ref"] != "nps:test:result" {
		t.Errorf("the artifact must carry the NWP result body: %v", data)
	}
	if data["params"].(map[string]any)["id"] != float64(7) {
		t.Errorf("arguments did not reach the backend: %v", data["params"])
	}
	if len(r["history"].([]any)) != 1 {
		t.Errorf("history must echo the request message: %v", r["history"])
	}
}

func TestA2aInbound_OnlyTasksSendIsServed(t *testing.T) {
	s := a2aFixture(actionBackend("act", "do"))
	resp := s.Dispatch(context.Background(), jrpc("tasks/get", map[string]any{"id": "t1"}))
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("expected -32601, got %v", resp.Error)
	}
	if errData(t, resp)["error"] != "NWP-BRIDGE-DIRECTION-UNSUPPORTED" {
		t.Errorf("data: %v", errData(t, resp))
	}
}

func TestA2aInbound_MissingIdIsInvalidParams(t *testing.T) {
	s := a2aFixture(actionBackend("act", "do"))
	resp := s.Dispatch(context.Background(), jrpc("tasks/send", map[string]any{"id": " "}))
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("expected -32602, got %v", resp.Error)
	}
	if resp.Error.Message != "A2A tasks/send params.id is required." {
		t.Errorf("message: %s", resp.Error.Message)
	}
}

func TestA2aInbound_UnnamedSkillResolvesOnlyWhenExactlyOneExists(t *testing.T) {
	single := a2aFixture(actionBackend("act", "do"))
	if resp := single.Dispatch(context.Background(), jrpc("tasks/send", map[string]any{"id": "t1"})); resp.Error != nil {
		t.Fatalf("with exactly one exposed action, no skill need be named: %v", resp.Error)
	}

	many := a2aFixture(actionBackend("a", "do"), actionBackend("b", "other"))
	resp := many.Dispatch(context.Background(), jrpc("tasks/send", map[string]any{"id": "t1"}))
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("expected -32602, got %v", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "must identify an exposed NPS action") {
		t.Errorf("message: %s", resp.Error.Message)
	}
	if errData(t, resp)["error"] != "NWP-BRIDGE-SERVER-TOOL-NOT-FOUND" {
		t.Errorf("data: %v", errData(t, resp))
	}
}

func TestA2aInbound_SkillKeyAliasesAndTextPartArguments(t *testing.T) {
	s := a2aFixture(actionBackend("a", "do"), actionBackend("b", "other"))
	ctx := context.Background()

	for _, key := range []string{"action_id", "actionId", "skill_id", "skillId", "skill"} {
		resp := s.Dispatch(ctx, jrpc("tasks/send", map[string]any{
			"id": "t1", "metadata": map[string]any{key: "a__do"},
		}))
		if resp.Error != nil {
			t.Errorf("%s must be accepted as a skill key: %v", key, resp.Error)
		}
	}

	// A raw action_id also matches, and a text part becomes {"text": ...}.
	r := resultMap(t, s.Dispatch(ctx, jrpc("tasks/send", map[string]any{
		"id": "t1",
		"message": map[string]any{
			"role": "user",
			"parts": []any{
				map[string]any{"type": "text", "text": "hello", "metadata": map[string]any{"skill": "do"}},
			},
		},
	})))
	art := r["artifacts"].([]any)[0].(map[string]any)
	data := art["parts"].([]any)[0].(map[string]any)["data"].(map[string]any)
	if data["params"].(map[string]any)["text"] != "hello" {
		t.Errorf("a text part must become {\"text\": ...}: %v", data["params"])
	}
}

func TestA2aInbound_InfrastructureFailureIsAJsonRpcErrorNotAFailedTask(t *testing.T) {
	s := a2aFixture(errorBackend("act", core.NpsAuthUnauthenticated, "NWP-AUTH-NID-EXPIRED", "expired"))
	resp := s.Dispatch(context.Background(), jrpc("tasks/send", map[string]any{"id": "t1"}))

	if resp.Error == nil {
		t.Fatal("an infrastructure-class failure MUST become a JSON-RPC error, not a task object")
	}
	if resp.Error.Code != -32001 {
		t.Errorf("NPS-AUTH-UNAUTHENTICATED maps to -32001, got %d", resp.Error.Code)
	}
	if resp.Result != nil {
		t.Error("no task object may accompany the error")
	}
}

func TestA2aInbound_DomainFailureTerminatesTheTaskAsFailedNotCompleted(t *testing.T) {
	s := a2aFixture(errorBackend("act", core.NpsClientNotFound, "NWP-ACTION-NOT-FOUND", "no such order"))
	r := resultMap(t, s.Dispatch(context.Background(), jrpc("tasks/send", map[string]any{"id": "t1"})))

	status := r["status"].(map[string]any)
	if status["state"] != "failed" {
		t.Fatalf("a client-class failure terminates the task as failed, never `completed`: %v", status["state"])
	}
	msg := status["message"].(map[string]any)
	if msg["role"] != "agent" {
		t.Errorf("failure message role = %v", msg["role"])
	}
	if msg["parts"].([]any)[0].(map[string]any)["text"] != "no such order" {
		t.Errorf("the NPS detail must be preserved verbatim: %v", msg["parts"])
	}
	art := r["artifacts"].([]any)[0].(map[string]any)
	if art["name"] != "nps-error" {
		t.Errorf("artifact name on failure = %v", art["name"])
	}
	data := art["parts"].([]any)[0].(map[string]any)["data"].(map[string]any)
	if data["status"] != "NPS-CLIENT-NOT-FOUND" || data["error"] != "NWP-ACTION-NOT-FOUND" {
		t.Errorf("failure payload: %v", data)
	}
}

// ── BridgeIn-02: gRPC inbound service logic ──────────────────────────────────

func grpcFixture(inbound []string, backends ...nwp.NwpBackend) *nwp.GrpcInboundService {
	return nwp.NewGrpcInboundService(&nwp.BridgeInboundOptions{
		Backends: backends, InboundProtocols: inbound,
	})
}

func TestGrpcInbound_InvokeRoundTrip(t *testing.T) {
	s := grpcFixture([]string{"grpc"}, actionBackend("bridge-inbound-test", "orders.lookup"))
	args, _ := json.Marshal(map[string]any{"id": 7})

	resp, gerr := s.Invoke(context.Background(), nwp.GrpcUpstreamContext{}, "orders.lookup", args)
	if gerr != nil {
		t.Fatalf("unexpected error: %v", gerr)
	}
	if resp.HTTPStatus != 200 {
		t.Errorf("http_status = %d", resp.HTTPStatus)
	}
	if !strings.Contains(string(resp.BodyJSON), "nps:test:result") {
		t.Errorf("the response payload must equal the Action Node's NWP result body: %s", resp.BodyJSON)
	}
	if resp.TaskID != "" {
		t.Errorf("task_id must be \"\" when the payload carries none, got %q", resp.TaskID)
	}
}

func TestGrpcInbound_EmptyActionIdIsInvalidArgument(t *testing.T) {
	s := grpcFixture([]string{"grpc"}, actionBackend("act", "do"))
	_, gerr := s.Invoke(context.Background(), nwp.GrpcUpstreamContext{}, " ", nil)
	if gerr == nil || gerr.Code != nwp.GrpcInvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %v", gerr)
	}
	if gerr.Message != "action_id is required" {
		t.Errorf("message: %s", gerr.Message)
	}
}

func TestGrpcInbound_BackendResolution(t *testing.T) {
	ctx := context.Background()

	// Empty upstream + exactly one backend => that one.
	one := grpcFixture([]string{"grpc"}, actionBackend("only", "do"))
	if _, _, gerr := one.ResolveBackend(ctx, nwp.GrpcUpstreamContext{}); gerr != nil {
		t.Errorf("a single backend must resolve with an empty upstream: %v", gerr)
	}

	many := grpcFixture([]string{"grpc"}, actionBackend("a", "do"), actionBackend("b", "do"))
	// Case-insensitive name match.
	if _, d, gerr := many.ResolveBackend(ctx, nwp.GrpcUpstreamContext{Upstream: "B"}); gerr != nil || d.Name != "b" {
		t.Errorf("names must match case-insensitively: %v / %v", d, gerr)
	}
	// Empty upstream with >1 backend => NOT_FOUND.
	_, _, gerr := many.ResolveBackend(ctx, nwp.GrpcUpstreamContext{})
	if gerr == nil || gerr.Code != nwp.GrpcNotFound {
		t.Fatalf("expected NOT_FOUND, got %v", gerr)
	}
	for _, want := range []string{"NPS-CLIENT-NOT-FOUND", "NWP-BRIDGE-SERVER-TOOL-NOT-FOUND"} {
		if !strings.Contains(gerr.Message, want) {
			t.Errorf("the detail must let a caller recover the exact NPS fault (%s): %s", want, gerr.Message)
		}
	}
}

func TestGrpcInbound_UndeclaredDirectionIsUnimplemented(t *testing.T) {
	// The default set omits grpc, so an unset InboundProtocols refuses.
	s := nwp.NewGrpcInboundService(&nwp.BridgeInboundOptions{
		Backends: []nwp.NwpBackend{actionBackend("act", "do")},
	})
	_, gerr := s.Invoke(context.Background(), nwp.GrpcUpstreamContext{}, "do", nil)
	if gerr == nil || gerr.Code != nwp.GrpcUnimplemented {
		t.Fatalf("expected UNIMPLEMENTED, got %v", gerr)
	}
	for _, want := range []string{"NPS-SERVER-UNSUPPORTED", "NWP-BRIDGE-DIRECTION-UNSUPPORTED", `"grpc"`} {
		if !strings.Contains(gerr.Message, want) {
			t.Errorf("detail missing %s: %s", want, gerr.Message)
		}
	}
}

func TestGrpcInbound_ManifestQueryAndListActions(t *testing.T) {
	s := grpcFixture([]string{"grpc"},
		nwp.NewInProcessNwpBackend(
			nwp.NwpNodeDescriptor{Name: "node", Role: nwp.NwpRoleComplex, DisplayName: "Node"},
			[]nwp.NwpActionDescriptor{{ActionID: "do", Description: "does it"}},
			func(context.Context, *nwp.ActionFrame) (core.FrameDict, error) { return core.FrameDict{}, nil },
			func(context.Context, *nwp.QueryFrame) (core.FrameDict, error) {
				return core.FrameDict{"count": 0}, nil
			},
		))
	ctx := context.Background()

	m, gerr := s.GetManifest(ctx, nwp.GrpcUpstreamContext{})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if m.NodeType != "complex" {
		t.Errorf("node_type = %q", m.NodeType)
	}
	if !strings.Contains(string(m.NwmJSON), `"display_name":"Node"`) {
		t.Errorf("nwm_json: %s", m.NwmJSON)
	}

	q, gerr := s.Query(ctx, nwp.GrpcUpstreamContext{}, nil)
	if gerr != nil || q.HTTPStatus != 200 {
		t.Fatalf("query: %v / %v", q, gerr)
	}

	a, gerr := s.ListActions(ctx, nwp.GrpcUpstreamContext{})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if !strings.Contains(string(a.ActionsJSON), `{"actions":{"do":{"description":"does it"}}}`) {
		t.Errorf("actions_json: %s", a.ActionsJSON)
	}
}

func TestGrpcInbound_FailureSurfacingUsesTheStatusMap(t *testing.T) {
	s := grpcFixture([]string{"grpc"}, errorBackend("act", core.NpsAuthForbidden, "NWP-AUTH-NID-SCOPE-VIOLATION", "nope"))
	_, gerr := s.Invoke(context.Background(), nwp.GrpcUpstreamContext{}, "boom", nil)

	if gerr == nil || gerr.Code != nwp.GrpcPermissionDenied {
		t.Fatalf("NPS-AUTH-FORBIDDEN maps to PERMISSION_DENIED, got %v", gerr)
	}
	if gerr.Message != "NPS-AUTH-FORBIDDEN NWP-AUTH-NID-SCOPE-VIOLATION: nope" {
		t.Errorf("detail shape: %s", gerr.Message)
	}
}

// ── stdio transport ──────────────────────────────────────────────────────────

func TestMcpInbound_StdioHandlesLineDelimitedJsonRpc(t *testing.T) {
	s := mcpFixture(actionBackend("bridge-inbound-test", "orders.lookup"))
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		``, // blank lines are skipped
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{ not json`,
		`{"jsonrpc":"2.0","id":4,"method":"ping"}`,
	}, "\n")

	var out bytes.Buffer
	if err := s.RunStdio(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected one response line per request (blank lines skipped), got %d:\n%s", len(lines), out.String())
	}

	var initialize, list, parse, ping nwp.BridgeJsonRpcResponse
	mustUnmarshal(t, lines[0], &initialize)
	mustUnmarshal(t, lines[1], &list)
	mustUnmarshal(t, lines[2], &parse)
	mustUnmarshal(t, lines[3], &ping)

	if initialize.Error != nil || string(initialize.ID) != "1" {
		t.Errorf("initialize: %+v", initialize)
	}
	if list.Error != nil || !strings.Contains(lines[1], "bridge-inbound-test__orders_lookup") {
		t.Errorf("tools/list: %s", lines[1])
	}
	if parse.Error == nil || parse.Error.Code != -32700 {
		t.Errorf("a parse error must be -32700, got %+v", parse.Error)
	}
	if string(parse.ID) != "null" {
		t.Errorf("a parse error carries id: null, got %s", parse.ID)
	}
	if ping.Error != nil || string(ping.ID) != "4" {
		t.Errorf("ping: %+v", ping)
	}
}

func mustUnmarshal(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("bad response line %q: %v", s, err)
	}
}

// ── Tool-name encoding ───────────────────────────────────────────────────────

func TestMcpToolName_EncodeIsLossyAndHasNoDecode(t *testing.T) {
	if got := nwp.McpToolNameEncode("bridge-inbound-test", "orders.lookup"); got != "bridge-inbound-test__orders_lookup" {
		t.Errorf("Encode = %s", got)
	}
	if got := nwp.McpToolNameEncodeActionSegment("orders.lookup"); got != "orders_lookup" {
		t.Errorf("EncodeActionSegment = %s", got)
	}
	// Sanitization: non-[A-Za-z0-9_.-] becomes '_', then leading/trailing '_' trimmed.
	if got := nwp.McpToolNameEncode(" my node! ", "a b"); got != "my_node__a_b" {
		t.Errorf("sanitize = %s", got)
	}
	// An empty sanitized node name becomes "node".
	if got := nwp.McpToolNameEncode("!!!", "x"); got != "node__x" {
		t.Errorf("empty node name = %s", got)
	}
	// Lossiness: '.' and '_' both map to '_', so encoding is not injective.
	if nwp.McpToolNameEncodeActionSegment("a.b") != nwp.McpToolNameEncodeActionSegment("a_b") {
		t.Error("the transform is expected to be lossy — this is why there is no decode")
	}
}

// ── HTTP hosting layer ───────────────────────────────────────────────────────

func bridgeApp(t *testing.T, opt nwp.BridgeServerOptions, backends ...nwp.NwpBackend) *nwp.BridgeServerApp {
	t.Helper()
	return nwp.NewBridgeServerApp(&nwp.BridgeInboundOptions{
		Backends: backends, InboundProtocols: []string{"mcp", "a2a"},
	}, opt)
}

func allowAll(context.Context, string, *http.Request) bool { return true }

func postBridge(app *nwp.BridgeServerApp, path, agent, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if agent != "" {
		req.Header.Set("X-NWP-Agent", agent)
	}
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	return w
}

const testAgentNid = "urn:nps:agent:example.com:client-1"

func TestBridgeServer_AuthFailuresAre401(t *testing.T) {
	backend := actionBackend("act", "do")

	// Missing verifier: fail-closed, every request denied.
	noVerifier := bridgeApp(t, nwp.BridgeServerOptions{}, backend)
	if w := postBridge(noVerifier, "/mcp", testAgentNid, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); w.Code != 401 {
		t.Errorf("no verifier configured must fail closed, got %d", w.Code)
	}

	app := bridgeApp(t, nwp.BridgeServerOptions{Verifier: allowAll}, backend)
	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	if w := postBridge(app, "/mcp", "", body); w.Code != 401 {
		t.Errorf("a missing X-NWP-Agent must be 401, got %d", w.Code)
	}
	if w := postBridge(app, "/mcp", "not-a-nid", body); w.Code != 401 {
		t.Errorf("a syntactically invalid NID must be 401, got %d", w.Code)
	}

	rejecting := bridgeApp(t, nwp.BridgeServerOptions{
		Verifier: func(context.Context, string, *http.Request) bool { return false },
	}, backend)
	w := postBridge(rejecting, "/mcp", testAgentNid, body)
	if w.Code != 401 {
		t.Errorf("verifier rejection must be 401, got %d", w.Code)
	}
	var resp nwp.BridgeJsonRpcResponse
	mustUnmarshal(t, w.Body.String(), &resp)
	if resp.Error == nil || resp.Error.Code != -32600 {
		t.Errorf("a 401 carries a -32600 JSON-RPC error body, got %+v", resp.Error)
	}
	if string(resp.ID) != "null" {
		t.Errorf("a 401 carries id: null, got %s", resp.ID)
	}

	// A happy path proves the gate is not simply denying everything.
	if w := postBridge(app, "/mcp", testAgentNid, body); w.Code != 200 {
		t.Errorf("an authorized request must succeed, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBridgeIsValidAgentNid(t *testing.T) {
	valid := []string{
		"urn:nps:agent:example.com:client-1",
		"urn:nps:agent:ex-1.test:a_b~c@d/e:f",
	}
	invalid := []string{
		"", "urn:nps:node:example.com:x", "urn:nps:agent:example.com",
		"urn:nps:agent::x", "urn:nps:agent:example.com:", "urn:nps:agent:ex ample.com:x",
		"urn:nps:agent:example.com:" + strings.Repeat("a", 512),
	}
	for _, v := range valid {
		if !nwp.BridgeIsValidAgentNid(v) {
			t.Errorf("expected valid: %q", v)
		}
	}
	for _, v := range invalid {
		if nwp.BridgeIsValidAgentNid(v) {
			t.Errorf("expected invalid: %q", v)
		}
	}
}

func TestBridgeServer_BodyOverLimitIs413(t *testing.T) {
	app := bridgeApp(t, nwp.BridgeServerOptions{Verifier: allowAll, MaxRequestBodyBytes: 64}, actionBackend("act", "do"))
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","pad":"` + strings.Repeat("x", 200) + `"}`

	w := postBridge(app, "/mcp", testAgentNid, big)
	if w.Code != 413 {
		t.Fatalf("expected 413, got %d", w.Code)
	}
	var resp nwp.BridgeJsonRpcResponse
	mustUnmarshal(t, w.Body.String(), &resp)
	if resp.Error == nil || resp.Error.Code != -32600 {
		t.Errorf("a 413 carries -32600, got %+v", resp.Error)
	}

	// A LYING Content-Length must not bypass the cap — the streaming accumulate
	// is the second of the two enforcement points.
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(big))
	req.Header.Set("X-NWP-Agent", testAgentNid)
	req.ContentLength = 4
	req.Header.Set("Content-Length", "4")
	w = httptest.NewRecorder()
	app.ServeHTTP(w, req)
	if w.Code != 413 {
		t.Fatalf("a lying Content-Length must not bypass the cap, got %d", w.Code)
	}
}

func TestBridgeServer_AgentCardIsExposedAndGetOnly(t *testing.T) {
	app := bridgeApp(t, nwp.BridgeServerOptions{Verifier: allowAll}, actionBackend("bridge-inbound-test", "orders.lookup"))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/agent.json", nil)
	req.Header.Set("X-NWP-Agent", testAgentNid)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("AgentCard: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "bridge-inbound-test__orders_lookup") {
		t.Errorf("the AgentCard must list the fronted action as a skill: %s", w.Body.String())
	}

	if w := postBridge(app, "/.well-known/agent.json", testAgentNid, "{}"); w.Code != 405 {
		t.Errorf("non-GET on the AgentCard path must be 405, got %d", w.Code)
	}
}

func TestBridgeServer_NonPostOnRpcPathsIs405(t *testing.T) {
	app := bridgeApp(t, nwp.BridgeServerOptions{Verifier: allowAll}, actionBackend("act", "do"))
	for _, p := range []string{"/mcp", "/a2a"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("X-NWP-Agent", testAgentNid)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		if w.Code != 405 {
			t.Errorf("GET %s must be 405, got %d", p, w.Code)
		}
	}
}

func TestBridgeServer_DispatchTimeoutIs504WithMinus32000(t *testing.T) {
	slow := nwp.NewInProcessNwpBackend(
		nwp.NwpNodeDescriptor{Name: "slow", Role: nwp.NwpRoleAction},
		[]nwp.NwpActionDescriptor{{ActionID: "wait"}},
		func(ctx context.Context, _ *nwp.ActionFrame) (core.FrameDict, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		nil,
	)
	app := bridgeApp(t, nwp.BridgeServerOptions{Verifier: allowAll, DispatchTimeoutMs: 30}, slow)

	w := postBridge(app, "/mcp", testAgentNid,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow__wait"}}`)
	if w.Code != 504 {
		t.Fatalf("a dispatch timeout must be 504, got %d: %s", w.Code, w.Body.String())
	}
	var resp nwp.BridgeJsonRpcResponse
	mustUnmarshal(t, w.Body.String(), &resp)
	if resp.Error == nil || resp.Error.Code != -32000 {
		t.Errorf("a dispatch timeout carries -32000, got %+v", resp.Error)
	}
}

func TestBridgeServer_SseAliasAndPathPrefix(t *testing.T) {
	app := bridgeApp(t, nwp.BridgeServerOptions{Verifier: allowAll, PathPrefix: "/bridge"}, actionBackend("act", "do"))
	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	for _, p := range []string{"/bridge/mcp", "/bridge/mcp/sse", "/bridge/a2a"} {
		if w := postBridge(app, p, testAgentNid, body); w.Code != 200 {
			t.Errorf("%s: %d %s", p, w.Code, w.Body.String())
		}
	}
	if w := postBridge(app, "/mcp", testAgentNid, body); w.Code != 404 {
		t.Errorf("an unprefixed path must 404, got %d", w.Code)
	}
}

// ── Backend materialisation ──────────────────────────────────────────────────

func TestBridgeCreateBackends(t *testing.T) {
	// Neither delegate nor actions => no in-process backend.
	b, err := nwp.BridgeCreateBackends(nwp.BridgeServerBackendSpec{
		Descriptor: nwp.NwpNodeDescriptor{Name: "x", Role: nwp.NwpRoleAction},
	}, nil)
	if err != nil || len(b) != 0 {
		t.Errorf("expected no backends, got %d / %v", len(b), err)
	}

	// Upstreams without an HTTP client is a configuration error.
	if _, err := nwp.BridgeCreateBackends(nwp.BridgeServerBackendSpec{
		Upstreams: []nwp.NwpUpstream{{Name: "u", BaseURL: "http://x"}},
	}, nil); err == nil {
		t.Error("upstreams without an HTTP client must be rejected")
	}

	// Both shapes coexist.
	b, err = nwp.BridgeCreateBackends(nwp.BridgeServerBackendSpec{
		Descriptor: nwp.NwpNodeDescriptor{Name: "local", Role: nwp.NwpRoleAction},
		Actions:    []nwp.NwpActionDescriptor{{ActionID: "do"}},
		Upstreams:  []nwp.NwpUpstream{{Name: "remote", BaseURL: "http://x"}},
	}, http.DefaultClient)
	if err != nil || len(b) != 2 {
		t.Fatalf("both shapes must coexist in one Bridge: %d / %v", len(b), err)
	}
}

func TestHttpNwpBackend_DeadUpstreamCachesRoleUnknown(t *testing.T) {
	b := nwp.NewHttpNwpBackend(nwp.NwpUpstream{Name: "dead", BaseURL: "http://127.0.0.1:1"}, http.DefaultClient)

	d, err := b.GetDescriptor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Role != nwp.NwpRoleUnknown {
		t.Errorf("an unreachable /.nwm must cache Role = Unknown, got %v", d.Role)
	}
	// A dead upstream must not take down the Bridge — it projects onto nothing.
	if d.IsQueryable() || d.IsInvokable() {
		t.Error("an Unknown role projects onto nothing")
	}
}

func TestHttpNwpBackend_TranslatesUpstreamFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.nwm":
			w.Write([]byte(`{"node_type":"action"}`))
		case "/invoke":
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"NWP-AUTH-NID-SCOPE-VIOLATION","message":"nope"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	b := nwp.NewHttpNwpBackend(nwp.NwpUpstream{Name: "up", BaseURL: srv.URL}, srv.Client())
	res := b.Invoke(context.Background(), "do", nil, false)

	if res.Ok {
		t.Fatal("expected a failure")
	}
	// The most specific NPS status, never a blanket NPS-SERVER-INTERNAL.
	if res.NpsStatus != core.NpsAuthForbidden {
		t.Errorf("403 must map to NPS-AUTH-FORBIDDEN, got %s", res.NpsStatus)
	}
	if res.NwpError != "NWP-AUTH-NID-SCOPE-VIOLATION" {
		t.Errorf("the ErrorFrame's error prop must be lifted, got %s", res.NwpError)
	}
}

func TestNwpRoleParsingAndProjection(t *testing.T) {
	cases := map[string]nwp.NwpNodeRole{
		"memory": nwp.NwpRoleMemory, "ACTION": nwp.NwpRoleAction, " complex ": nwp.NwpRoleComplex,
		"anchor": nwp.NwpRoleAnchor, "bridge": nwp.NwpRoleBridge, "nonsense": nwp.NwpRoleUnknown, "": nwp.NwpRoleUnknown,
	}
	for in, want := range cases {
		if got := nwp.ParseNwpRole(in); got != want {
			t.Errorf("ParseNwpRole(%q) = %v, want %v", in, got, want)
		}
	}
	for _, tc := range []struct {
		role                 nwp.NwpNodeRole
		queryable, invokable bool
	}{
		{nwp.NwpRoleMemory, true, false},
		{nwp.NwpRoleAction, false, true},
		{nwp.NwpRoleComplex, true, true},
		{nwp.NwpRoleAnchor, false, false},
		{nwp.NwpRoleBridge, false, false},
		{nwp.NwpRoleUnknown, false, false},
	} {
		d := nwp.NwpNodeDescriptor{Role: tc.role}
		if d.IsQueryable() != tc.queryable || d.IsInvokable() != tc.invokable {
			t.Errorf("%v: queryable=%v invokable=%v", tc.role, d.IsQueryable(), d.IsInvokable())
		}
	}
}
