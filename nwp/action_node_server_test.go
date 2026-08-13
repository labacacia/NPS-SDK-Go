// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
)

const (
	anPrefix = "/orders"
	anAgent  = "urn:nps:agent:tester"
)

// ── Test providers ──────────────────────────────────────────────────────────

type echoProvider struct {
	delay time.Duration
}

func (p echoProvider) Execute(ctx context.Context, frame *ActionFrame, actx ActionContext) (*ActionExecutionResult, error) {
	if p.delay > 0 {
		select {
		case <-time.After(p.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	payload, _ := json.Marshal(map[string]any{
		"order_id": "o-123",
		"action":   frame.Action,
		"agent":    actx.AgentNid,
	})
	return &ActionExecutionResult{Result: payload, AnchorRef: actx.Spec.ResultAnchor, TokenEst: 10}, nil
}

type authorizingProvider struct {
	mu         sync.Mutex
	admissions int
	calls      int
	revoke     bool
}

func (p *authorizingProvider) Authorize(context.Context, *ActionFrame, ActionContext) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.admissions++
	if p.revoke && p.admissions > 1 {
		return &ActionExecutionError{
			HTTPStatus: 401, NpsStatus: core.NpsAuthUnauthenticated,
			ErrorCode: ErrAuthNidRevoked, Message: "revoked",
		}
	}
	return nil
}

func (p *authorizingProvider) Execute(_ context.Context, _ *ActionFrame, actx ActionContext) (*ActionExecutionResult, error) {
	p.mu.Lock()
	p.calls++
	call := p.calls
	p.mu.Unlock()
	payload, _ := json.Marshal(map[string]any{"call": call, "owner": actx.AgentNid})
	return &ActionExecutionResult{Result: payload}, nil
}

func anBaseOpts() ActionNodeOptions {
	return ActionNodeOptions{
		NodeID:     "urn:nps:node:api.example.com:orders",
		PathPrefix: anPrefix,
		Actions: map[string]ActionSpec{
			"orders.create": {ResultAnchor: "nps:orders:result", Async: true, TimeoutMsDefault: 3000},
			"orders.peek":   {ResultAnchor: "nps:orders:peek"},
		},
	}
}

func anPost(t *testing.T, srv *httptest.Server, body any, headers map[string]string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req, _ := http.NewRequest("POST", srv.URL+anPrefix+"/invoke", &buf)
	req.Header.Set("X-NWP-Agent", anAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func anDecode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return m
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestActionNodeManifestAndReservedGuard(t *testing.T) {
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{}, anBaseOpts(), nil, nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + anPrefix + "/.nwm")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != MimeManifest {
		t.Fatalf("nwm status %d ct %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get(HeaderNodeType) != "action" {
		t.Fatal("node type header")
	}
	m := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if m["node_type"] != "action" || m["nwp"] != "0.4" {
		t.Fatalf("manifest %+v", m)
	}

	// Reserved action registration must panic.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic on reserved action registration")
			}
		}()
		opt := anBaseOpts()
		opt.Actions[SystemTaskStatus] = ActionSpec{}
		NewActionNodeServer(echoProvider{}, opt, nil, nil)
	}()
}

func TestActionNodeSyncInvoke(t *testing.T) {
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{}, anBaseOpts(), nil, nil))
	defer srv.Close()

	resp := anPost(t, srv, map[string]any{"action_id": "orders.peek", "params": map[string]any{"x": 1}}, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != MimeCapsule {
		t.Fatalf("status %d ct %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get(HeaderNodeType) != "action" {
		t.Fatal("node type")
	}
	m := anDecode(t, resp)
	if m["count"].(float64) != 1 {
		t.Fatalf("count %+v", m)
	}
	data := m["data"].([]any)[0].(map[string]any)
	if data["order_id"] != "o-123" || data["agent"] != anAgent {
		t.Fatalf("data %+v", data)
	}
	if m["anchor_ref"] != "nps:orders:peek" {
		t.Fatal("anchor_ref")
	}
}

func TestActionNodeUnknownAction(t *testing.T) {
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{}, anBaseOpts(), nil, nil))
	defer srv.Close()
	resp := anPost(t, srv, map[string]any{"action_id": "nope.verb"}, nil)
	if resp.StatusCode != 404 || anDecode(t, resp)["error"] != ErrActionNotFound {
		t.Fatal("unknown action")
	}
}

func TestActionNodeAsyncAndTaskStatus(t *testing.T) {
	store := NewInMemoryActionTaskStore()
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{}, anBaseOpts(), store, nil))
	defer srv.Close()

	resp := anPost(t, srv, map[string]any{"action_id": "orders.create", "async": true}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}
	m := anDecode(t, resp)
	taskID, _ := m["task_id"].(string)
	if taskID == "" || m["status"] != "pending" || m["poll_url"] != anPrefix+"/invoke" {
		t.Fatalf("async response %+v", m)
	}

	// Poll until completed.
	var status string
	for i := 0; i < 50; i++ {
		r := anPost(t, srv, map[string]any{"action_id": SystemTaskStatus, "params": map[string]any{"task_id": taskID}}, nil)
		if r.StatusCode != 200 {
			t.Fatalf("status poll %d", r.StatusCode)
		}
		sm := anDecode(t, r)
		st := sm["data"].([]any)[0].(map[string]any)
		status, _ = st["status"].(string)
		if status == "completed" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if status != "completed" {
		t.Fatalf("task never completed, last status %q", status)
	}
}

func TestActionNodeAsyncOnNonAsyncAction(t *testing.T) {
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{}, anBaseOpts(), nil, nil))
	defer srv.Close()
	resp := anPost(t, srv, map[string]any{"action_id": "orders.peek", "async": true}, nil)
	if resp.StatusCode != 400 || anDecode(t, resp)["error"] != ErrActionParamsInvalid {
		t.Fatal("async on non-async action")
	}
}

func TestActionNodeTaskCancel(t *testing.T) {
	store := NewInMemoryActionTaskStore()
	// Slow provider so the task stays running long enough to cancel.
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{delay: 2 * time.Second}, anBaseOpts(), store, nil))
	defer srv.Close()

	resp := anPost(t, srv, map[string]any{"action_id": "orders.create", "async": true}, nil)
	taskID := anDecode(t, resp)["task_id"].(string)

	c := anPost(t, srv, map[string]any{"action_id": SystemTaskCancel, "params": map[string]any{"task_id": taskID}}, nil)
	if c.StatusCode != 200 {
		t.Fatalf("cancel status %d", c.StatusCode)
	}
	st := anDecode(t, c)["data"].([]any)[0].(map[string]any)
	if st["status"] != "cancelled" {
		t.Fatalf("cancel result %+v", st)
	}

	// Second cancel → 409 conflict.
	c2 := anPost(t, srv, map[string]any{"action_id": SystemTaskCancel, "params": map[string]any{"task_id": taskID}}, nil)
	if c2.StatusCode != 409 || anDecode(t, c2)["error"] != ErrTaskAlreadyCancelled {
		t.Fatal("double cancel should conflict")
	}
}

func TestActionNodeTaskStatusNotFound(t *testing.T) {
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{}, anBaseOpts(), nil, nil))
	defer srv.Close()
	r := anPost(t, srv, map[string]any{"action_id": SystemTaskStatus, "params": map[string]any{"task_id": "deadbeef"}}, nil)
	if r.StatusCode != 404 || anDecode(t, r)["error"] != ErrTaskNotFound {
		t.Fatal("unknown task")
	}
}

func TestActionNodeIdempotencyRehitAndConflict(t *testing.T) {
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{}, anBaseOpts(), nil, nil))
	defer srv.Close()

	body := map[string]any{"action_id": "orders.peek", "idempotency_key": "k1", "params": map[string]any{"x": 1}}
	r1 := anPost(t, srv, body, nil)
	if r1.StatusCode != 200 {
		t.Fatalf("first %d", r1.StatusCode)
	}
	m1 := anDecode(t, r1)

	// Re-hit with same params → cached result, same payload.
	r2 := anPost(t, srv, body, nil)
	if r2.StatusCode != 200 {
		t.Fatalf("rehit %d", r2.StatusCode)
	}
	m2 := anDecode(t, r2)
	if m1["data"].([]any)[0].(map[string]any)["order_id"] != m2["data"].([]any)[0].(map[string]any)["order_id"] {
		t.Fatal("cached payload mismatch")
	}

	// Same key, different params → 409 conflict.
	conflict := map[string]any{"action_id": "orders.peek", "idempotency_key": "k1", "params": map[string]any{"x": 2}}
	r3 := anPost(t, srv, conflict, nil)
	if r3.StatusCode != 409 || anDecode(t, r3)["error"] != ErrActionIdempotencyConflict {
		t.Fatal("idempotency conflict")
	}
}

func TestActionNodeIdempotencyAsyncRehit(t *testing.T) {
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{delay: time.Second}, anBaseOpts(), nil, nil))
	defer srv.Close()

	body := map[string]any{"action_id": "orders.create", "async": true, "idempotency_key": "ak"}
	r1 := anPost(t, srv, body, nil)
	t1 := anDecode(t, r1)["task_id"].(string)

	r2 := anPost(t, srv, body, nil)
	if r2.StatusCode != 202 {
		t.Fatalf("async rehit %d", r2.StatusCode)
	}
	t2 := anDecode(t, r2)["task_id"].(string)
	if t1 != t2 {
		t.Fatalf("async rehit should return same task handle: %s vs %s", t1, t2)
	}
}

func TestActionNodeIdempotencyCallerScopeAndReplayAuthorization(t *testing.T) {
	provider := &authorizingProvider{}
	srv := httptest.NewServer(NewActionNodeServer(provider, anBaseOpts(), nil, nil))
	defer srv.Close()
	body := map[string]any{"action_id": "orders.peek", "idempotency_key": "shared", "params": map[string]any{"x": 1}}
	alice := anPost(t, srv, body, nil)
	if alice.StatusCode != 200 {
		t.Fatalf("alice status %d", alice.StatusCode)
	}
	anDecode(t, alice)
	bob := anPost(t, srv, body, map[string]string{HeaderAgent: "urn:nps:agent:bob"})
	if bob.StatusCode != 200 {
		t.Fatalf("bob status %d", bob.StatusCode)
	}
	bobData := anDecode(t, bob)["data"].([]any)[0].(map[string]any)
	if bobData["owner"] != "urn:nps:agent:bob" || provider.calls != 2 {
		t.Fatalf("caller-scoped replay failed: data=%+v calls=%d", bobData, provider.calls)
	}

	provider.revoke = true
	replay := anPost(t, srv, body, nil)
	if replay.StatusCode != 401 || anDecode(t, replay)["error"] != ErrAuthNidRevoked {
		t.Fatal("cached replay must be reauthorized")
	}
}

func TestActionNodeTaskOwnershipAndCancellationPropagation(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	provider := actionProviderFunc(func(ctx context.Context, _ *ActionFrame, _ ActionContext) (*ActionExecutionResult, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	srv := httptest.NewServer(NewActionNodeServer(provider, anBaseOpts(), nil, nil))
	defer srv.Close()
	accepted := anPost(t, srv, map[string]any{"action_id": "orders.create", "async": true}, nil)
	taskID := anDecode(t, accepted)["task_id"].(string)
	<-started

	for _, action := range []string{SystemTaskStatus, SystemTaskCancel} {
		response := anPost(t, srv, map[string]any{
			"action_id": action, "params": map[string]any{"task_id": taskID},
		}, map[string]string{HeaderAgent: "urn:nps:agent:bob"})
		if response.StatusCode != 403 || anDecode(t, response)["error"] != ErrAuthNidScopeViolation {
			t.Fatalf("%s must be owner scoped", action)
		}
	}
	cancel := anPost(t, srv, map[string]any{
		"action_id": SystemTaskCancel, "params": map[string]any{"task_id": taskID},
	}, nil)
	if cancel.StatusCode != 200 {
		t.Fatalf("cancel status %d", cancel.StatusCode)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("provider context was not cancelled")
	}
}

type actionProviderFunc func(context.Context, *ActionFrame, ActionContext) (*ActionExecutionResult, error)

func (f actionProviderFunc) Execute(ctx context.Context, frame *ActionFrame, actx ActionContext) (*ActionExecutionResult, error) {
	return f(ctx, frame, actx)
}

func TestActionNodeSyncTimeout(t *testing.T) {
	opt := anBaseOpts()
	opt.Actions["orders.slow"] = ActionSpec{TimeoutMsMax: 20, TimeoutMsDefault: 20}
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{delay: 500 * time.Millisecond}, opt, nil, nil))
	defer srv.Close()

	resp := anPost(t, srv, map[string]any{"action_id": "orders.slow"}, nil)
	if resp.StatusCode != 504 || anDecode(t, resp)["error"] != ErrNodeUnavailable {
		t.Fatalf("expected 504 timeout, got %d", resp.StatusCode)
	}
}

func TestActionNodeCallbackSSRFRejected(t *testing.T) {
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{}, anBaseOpts(), nil, nil))
	defer srv.Close()

	// Loopback https URL is rejected by the SSRF guard.
	resp := anPost(t, srv, map[string]any{
		"action_id":    "orders.peek",
		"callback_url": "https://127.0.0.1/hook",
	}, nil)
	if resp.StatusCode != 400 || anDecode(t, resp)["error"] != ErrActionParamsInvalid {
		t.Fatalf("expected 400 for SSRF callback, got %d", resp.StatusCode)
	}

	// Non-https scheme is rejected.
	resp2 := anPost(t, srv, map[string]any{
		"action_id":    "orders.peek",
		"callback_url": "http://example.com/hook",
	}, nil)
	if resp2.StatusCode != 400 {
		t.Fatalf("expected 400 for http callback, got %d", resp2.StatusCode)
	}

	// A public https callback passes validation.
	resp3 := anPost(t, srv, map[string]any{
		"action_id":    "orders.peek",
		"callback_url": "https://hooks.example.com/cb",
	}, nil)
	if resp3.StatusCode != 200 {
		t.Fatalf("public callback should pass, got %d", resp3.StatusCode)
	}
}

func TestActionNodeAuthGate(t *testing.T) {
	opt := anBaseOpts()
	opt.RequireAuth = true
	srv := httptest.NewServer(NewActionNodeServer(echoProvider{}, opt, nil, nil))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+anPrefix+"/.nwm", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 || anDecode(t, resp)["error"] != ErrAuthNidScopeViolation {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestActionNodeCallbackValidatorUnit(t *testing.T) {
	cases := []struct {
		url       string
		reject    bool
		wantEmpty bool
	}{
		{"https://example.com/x", true, true},
		{"https://127.0.0.1/x", true, false},
		{"https://localhost/x", true, false},
		{"https://10.0.0.5/x", true, false},
		{"https://192.168.1.1/x", true, false},
		{"http://example.com/x", true, false},
		{"", true, false},
		{"https://127.0.0.1/x", false, true}, // reject disabled → allowed
	}
	for _, c := range cases {
		got := ValidateCallbackURL(c.url, c.reject)
		if (got == "") != c.wantEmpty {
			t.Errorf("ValidateCallbackURL(%q, %v) = %q, wantEmpty=%v", c.url, c.reject, got, c.wantEmpty)
		}
	}
}
