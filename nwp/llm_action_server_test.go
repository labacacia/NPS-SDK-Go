// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
)

const (
	llmPrefix = "/llm"
	llmAlice  = "urn:nps:agent:labacacia:alice"
	llmBob    = "urn:nps:agent:labacacia:bob"
)

type llmTestProvider struct {
	mu       sync.Mutex
	calls    int
	behavior func(context.Context) (*ActionExecutionResult, error)
}

func (p *llmTestProvider) Execute(ctx context.Context, frame *ActionFrame, actionContext ActionContext) (*ActionExecutionResult, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	if p.behavior != nil {
		return p.behavior(ctx)
	}
	params, _ := frame.Params.(map[string]any)
	if stream, _ := params["stream"].(bool); stream {
		return &ActionExecutionResult{Stream: func(
			ctx context.Context, emit func(*ActionStreamFrame) error,
		) error {
			first, _ := json.Marshal(LlmCompleteStreamChunkDto{ContentDelta: llmTestString("Fir")})
			if err := emit(&ActionStreamFrame{
				Seq: 0, Data: []json.RawMessage{first}, AnchorRef: LlmCompleteStreamAnchor,
			}); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			stop := LlmStopEndTurn
			last, _ := json.Marshal(LlmCompleteStreamChunkDto{
				ContentDelta: llmTestString("st"), StopReason: &stop,
			})
			return emit(&ActionStreamFrame{
				Seq: 1, IsLast: true, Data: []json.RawMessage{last},
			})
		}}, nil
	}
	payload, _ := json.Marshal(map[string]any{
		"stop_reason": "end_turn", "content": "First",
		"usage": map[string]any{"input_tokens": 12, "output_tokens": 2, "wire_input_bytes": actionContext.WireInputBytes},
	})
	return &ActionExecutionResult{Result: payload}, nil
}

func (p *llmTestProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func llmTestString(value string) *string { return &value }

type llmTestApp struct {
	server      *httptest.Server
	provider    *llmTestProvider
	coordinator *StatefulLlmActionProvider
	store       *InMemoryLlmContextStore
}

func newLlmTestApp(
	t *testing.T,
	provider *llmTestProvider,
	configure func(*StatefulLlmActionOptions),
) *llmTestApp {
	t.Helper()
	if provider == nil {
		provider = &llmTestProvider{}
	}
	ids := []string{
		"AQIDBAUGBwgJCgsMDQ4PEA", "ERITFBUWFxgZGhscHR4fIA",
		"ISIjJCUmJygpKissLS4vMA", "MTIzNDU2Nzg5Ojs8PT4_QA",
	}
	store := NewInMemoryLlmContextStore(LlmContextStoreOptions{
		ContextIDFactory: func() (string, error) {
			if len(ids) == 0 {
				return "QUJDREVGR0hJSktMTU5PUA", nil
			}
			id := ids[0]
			ids = ids[1:]
			return id, nil
		},
	})
	options := StatefulLlmActionOptions{
		SecurityScope: "workspace-a", RuntimeRevision: "runtime-1",
		SupportsStream: true,
		Authorizer: func(
			context.Context, LlmContextOwner, string, LlmAuthorizationStage, []string, ActionContext,
		) error {
			return nil
		},
	}
	if configure != nil {
		configure(&options)
	}
	coordinator, err := NewStatefulLlmActionProvider(provider, store, options)
	if err != nil {
		t.Fatal(err)
	}
	node := ActionNodeOptions{
		NodeID: "urn:nps:node:labacacia:llm", PathPrefix: llmPrefix,
		RequireAuth: true, Actions: map[string]ActionSpec{},
	}
	coordinator.ConfigureNode(&node)
	server := httptest.NewServer(NewActionNodeServer(coordinator, node, nil, nil))
	t.Cleanup(server.Close)
	return &llmTestApp{server: server, provider: provider, coordinator: coordinator, store: store}
}

func llmInvoke(
	t *testing.T,
	app *llmTestApp,
	actionID string,
	params any,
	key string,
	agent string,
	async bool,
) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"action_id": actionID, "params": params, "idempotency_key": key,
		"request_id": "req-" + key, "async": async,
	})
	request, _ := http.NewRequest(http.MethodPost, app.server.URL+llmPrefix+"/invoke", bytes.NewReader(body))
	if agent == "" {
		agent = llmAlice
	}
	request.Header.Set(HeaderAgent, agent)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func llmDecode(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	defer response.Body.Close()
	var value map[string]any
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func llmData(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	value := llmDecode(t, response)
	return value["data"].([]any)[0].(map[string]any)
}

func llmStreamFrames(t *testing.T, response *http.Response) []map[string]any {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		response.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("stream status=%d content-type=%q", response.StatusCode,
			response.Header.Get("Content-Type"))
	}
	frames := make([]map[string]any, 0)
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		var frame map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return frames
}

func llmCreateParams(content string) map[string]any {
	return map[string]any{
		"kind": LlmCompleteActionID, "model": "willow-small",
		"messages": []any{
			map[string]any{"role": "system", "content": "Be concise."},
			map[string]any{"role": "user", "content": content},
		},
		"context": map[string]any{"operation": "create"},
	}
}

func TestStatefulLlmActionManifestAndLifecycle(t *testing.T) {
	app := newLlmTestApp(t, nil, nil)
	request, _ := http.NewRequest(http.MethodGet, app.server.URL+llmPrefix+"/.nwm", nil)
	request.Header.Set(HeaderAgent, llmAlice)
	manifestResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	manifest := llmDecode(t, manifestResponse)
	profile := manifest["profiles"].(map[string]any)["llm"].(map[string]any)
	contextProfile := profile["context"].(map[string]any)
	if profile["profile_version"] != "0.2" || profile["supports_stream"] != true ||
		contextProfile["persistence"] != "process" || contextProfile["max_contexts_per_principal"] != float64(32) {
		t.Fatalf("unexpected LLM profile: %+v", profile)
	}
	operations := contextProfile["operations"].([]any)
	if len(operations) != 5 || operations[0] != "create" || operations[4] != "release" {
		t.Fatalf("unexpected operations: %+v", operations)
	}

	createdResponse := llmInvoke(t, app, LlmCompleteActionID, llmCreateParams("One"), "create-1", "", false)
	if createdResponse.StatusCode != 200 || createdResponse.Header.Get(HeaderSchema) != LlmCompleteResponseAnchor {
		t.Fatalf("create status=%d schema=%q", createdResponse.StatusCode, createdResponse.Header.Get(HeaderSchema))
	}
	created := llmData(t, createdResponse)
	receipt := created["context"].(map[string]any)
	contextID := receipt["context_id"].(string)
	if receipt["version"] != float64(1) || receipt["state"] != "active" {
		t.Fatalf("unexpected create receipt: %+v", receipt)
	}

	appendParams := map[string]any{
		"kind": LlmCompleteActionID, "model": "willow-small",
		"messages": []any{map[string]any{"role": "user", "content": "Two"}},
		"context":  map[string]any{"operation": "append", "context_id": contextID, "base_version": 1},
	}
	appended := llmData(t, llmInvoke(t, app, LlmCompleteActionID, appendParams, "append-1", "", false))
	if appended["context"].(map[string]any)["version"] != float64(2) {
		t.Fatalf("unexpected append: %+v", appended)
	}
	snapshot, err := app.store.Snapshot(LlmContextOwner{NID: llmAlice, SecurityScope: "workspace-a"}, contextID)
	if err != nil || len(snapshot.Transcript) != 5 {
		t.Fatalf("snapshot err=%v len=%d", err, len(snapshot.Transcript))
	}
	status := llmData(t, llmInvoke(t, app, LlmContextStatusActionID,
		map[string]any{"context_id": contextID}, "", "", false))
	if status["state"] != "active" || status["version"] != float64(2) {
		t.Fatalf("unexpected status: %+v", status)
	}
	released := llmData(t, llmInvoke(t, app, LlmContextReleaseActionID,
		map[string]any{"context_id": contextID, "base_version": 2}, "release-1", "", false))
	if released["state"] != "released" || released["version"] != float64(3) {
		t.Fatalf("unexpected release: %+v", released)
	}
}

func TestStatefulLlmReconnectConcurrentAppendAndProcessRestart(t *testing.T) {
	app := newLlmTestApp(t, nil, nil)
	lost := llmInvoke(t, app, LlmCompleteActionID, llmCreateParams("One"), "lost-create", "", false)
	if lost.StatusCode != http.StatusOK {
		t.Fatalf("lost create status=%d", lost.StatusCode)
	}
	lost.Body.Close()
	recovered := llmData(t, llmInvoke(t, app, LlmContextStatusActionID,
		map[string]any{"idempotency_key": "lost-create"}, "", "", false))
	if recovered["state"] != "active" || recovered["version"] != float64(1) {
		t.Fatalf("recovered status: %+v", recovered)
	}
	contextID := recovered["context_id"].(string)
	appendParams := map[string]any{
		"kind": LlmCompleteActionID, "model": "willow-small",
		"messages": []any{map[string]any{"role": "user", "content": "Two"}},
		"context": map[string]any{
			"operation": "append", "context_id": contextID, "base_version": 1,
		},
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	app.provider.behavior = func(context.Context) (*ActionExecutionResult, error) {
		startedOnce.Do(func() { close(started) })
		<-release
		payload, _ := json.Marshal(map[string]any{
			"stop_reason": "end_turn", "content": "First",
		})
		return &ActionExecutionResult{Result: payload}, nil
	}
	winnerResponse := make(chan *http.Response, 1)
	go func() {
		winnerResponse <- llmInvoke(t, app, LlmCompleteActionID,
			appendParams, "append-winner", "", false)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("winner did not enter provider")
	}
	loser := llmInvoke(t, app, LlmCompleteActionID, appendParams, "append-loser", "", false)
	if loser.StatusCode != http.StatusConflict || llmDecode(t, loser)["error"] != ErrLlmContextVersionConflict {
		t.Fatal("concurrent append loser must return version conflict")
	}
	close(release)
	winner := llmData(t, <-winnerResponse)
	if winner["context"].(map[string]any)["version"] != float64(2) || app.provider.callCount() != 2 {
		t.Fatalf("winner=%+v provider calls=%d", winner, app.provider.callCount())
	}

	restarted := newLlmTestApp(t, nil, nil)
	appendParams["context"].(map[string]any)["base_version"] = 2
	missing := llmInvoke(t, restarted, LlmCompleteActionID,
		appendParams, "append-after-restart", "", false)
	if missing.StatusCode != http.StatusNotFound || llmDecode(t, missing)["error"] != ErrLlmContextNotFound {
		t.Fatal("process restart must lose process-local context state")
	}
	if restarted.provider.callCount() != 0 {
		t.Fatal("missing post-restart context must fail before provider dispatch")
	}
}

func TestStatefulLlmActionValidationAndAbortPaths(t *testing.T) {
	app := newLlmTestApp(t, nil, nil)
	malformed := llmInvoke(t, app, LlmCompleteActionID, map[string]any{
		"model": "", "messages": []any{}, "context": map[string]any{"operation": "create"},
	}, "bad", "", false)
	if malformed.StatusCode != 422 || llmDecode(t, malformed)["error"] != ErrActionParamsInvalid {
		t.Fatal("malformed request must be rejected before dispatch")
	}
	tools := llmCreateParams("tools")
	tools["tools"] = []any{map[string]any{"name": "search"}}
	unsupported := llmInvoke(t, app, LlmCompleteActionID, tools, "tools", "", false)
	if unsupported.StatusCode != 422 || app.provider.callCount() != 0 {
		t.Fatal("unsupported tools must be rejected before dispatch")
	}
	reset := llmCreateParams("reset")
	reset["context"] = map[string]any{"operation": "reset"}
	resetWithoutVersion := llmInvoke(t, app, LlmCompleteActionID, reset, "reset-without-version", "", false)
	if resetWithoutVersion.StatusCode != 422 || app.provider.callCount() != 0 {
		t.Fatal("reset without context_id/base_version must be rejected before dispatch")
	}
	streamAsync := llmCreateParams("stream-async")
	streamAsync["stream"] = true
	invalidMode := llmInvoke(
		t, app, LlmCompleteActionID, streamAsync, "stream-async", "", true)
	if invalidMode.StatusCode != 422 || app.provider.callCount() != 0 {
		t.Fatal("stream=true with async=true must be rejected before dispatch")
	}

	for _, tc := range []struct {
		name   string
		result func(context.Context) (*ActionExecutionResult, error)
		status int
	}{
		{"provider", func(context.Context) (*ActionExecutionResult, error) { return nil, errors.New("down") }, 500},
		{"model", func(context.Context) (*ActionExecutionResult, error) {
			payload, _ := json.Marshal(map[string]any{"stop_reason": "error", "error": "refused"})
			return &ActionExecutionResult{Result: payload}, nil
		}, 200},
	} {
		provider := &llmTestProvider{behavior: tc.result}
		test := newLlmTestApp(t, provider, nil)
		response := llmInvoke(t, test, LlmCompleteActionID, llmCreateParams(tc.name), tc.name, "", false)
		if response.StatusCode != tc.status {
			t.Fatalf("%s status %d", tc.name, response.StatusCode)
		}
		response.Body.Close()
		status := llmData(t, llmInvoke(t, test, LlmContextStatusActionID,
			map[string]any{"idempotency_key": tc.name}, "", "", false))
		if status["state"] != "failed" || status["context_id"] != nil {
			t.Fatalf("%s abort outcome: %+v", tc.name, status)
		}
	}
}

func TestStatefulLlmActionStreamingCommitAndReplay(t *testing.T) {
	app := newLlmTestApp(t, nil, nil)
	params := llmCreateParams("stream")
	params["stream"] = true
	first := llmStreamFrames(t, llmInvoke(
		t, app, LlmCompleteActionID, params, "stream-create", "", false))
	replay := llmStreamFrames(t, llmInvoke(
		t, app, LlmCompleteActionID, params, "stream-create", "", false))
	if len(first) != 2 || len(replay) != 2 || first[0]["is_last"] != false ||
		first[1]["is_last"] != true {
		t.Fatalf("unexpected stream frames: %+v", first)
	}
	if first[0]["stream_id"] == replay[0]["stream_id"] {
		t.Fatal("completed replay must use a fresh stream_id")
	}
	firstChunk := first[0]["data"].([]any)[0].(map[string]any)
	terminal := first[1]["data"].([]any)[0].(map[string]any)
	replayTerminal := replay[1]["data"].([]any)[0].(map[string]any)
	if firstChunk["context"] != nil || firstChunk["content_delta"] != "Fir" ||
		terminal["content_delta"] != "st" || terminal["stop_reason"] != "end_turn" {
		t.Fatalf("unexpected chunks: first=%+v terminal=%+v", firstChunk, terminal)
	}
	receipt := terminal["context"].(map[string]any)
	if receipt["version"] != float64(1) ||
		replayTerminal["context"].(map[string]any)["context_id"] != receipt["context_id"] ||
		app.provider.callCount() != 1 {
		t.Fatalf("unexpected replay/receipt: receipt=%+v calls=%d", receipt, app.provider.callCount())
	}
	snapshot, err := app.store.Snapshot(
		LlmContextOwner{NID: llmAlice, SecurityScope: "workspace-a"},
		receipt["context_id"].(string),
	)
	if err != nil || valueString(snapshot.Transcript[len(snapshot.Transcript)-1].Content) != "First" {
		t.Fatalf("unexpected committed transcript: snapshot=%+v err=%v", snapshot, err)
	}
}

func TestStatefulLlmActionStreamingAbnormalEndAborts(t *testing.T) {
	provider := &llmTestProvider{behavior: func(context.Context) (*ActionExecutionResult, error) {
		return &ActionExecutionResult{Stream: func(
			_ context.Context, emit func(*ActionStreamFrame) error,
		) error {
			payload, _ := json.Marshal(LlmCompleteStreamChunkDto{
				ContentDelta: llmTestString("partial"),
			})
			return emit(&ActionStreamFrame{Seq: 0, Data: []json.RawMessage{payload}})
		}}, nil
	}}
	app := newLlmTestApp(t, provider, nil)
	params := llmCreateParams("stream")
	params["stream"] = true
	frames := llmStreamFrames(t, llmInvoke(
		t, app, LlmCompleteActionID, params, "stream-abnormal", "", false))
	if len(frames) != 2 || frames[1]["is_last"] != true ||
		frames[1]["error_code"] != ErrNodeUnavailable {
		t.Fatalf("unexpected abnormal stream: %+v", frames)
	}
	status := llmData(t, llmInvoke(t, app, LlmContextStatusActionID,
		map[string]any{"idempotency_key": "stream-abnormal"}, "", "", false))
	if status["state"] != "failed" || status["context_id"] != nil {
		t.Fatalf("unexpected abort status: %+v", status)
	}
}

func TestStatefulLlmActionCommitAuthorizationAndCallerIsolation(t *testing.T) {
	revoke := false
	denyAdmission := false
	app := newLlmTestApp(t, nil, func(options *StatefulLlmActionOptions) {
		options.Authorizer = func(
			_ context.Context, _ LlmContextOwner, _ string, stage LlmAuthorizationStage,
			_ []string, _ ActionContext,
		) error {
			if (denyAdmission && stage == LlmAuthorizationAdmission) ||
				(revoke && stage == LlmAuthorizationCommit) {
				return &ActionExecutionError{
					HTTPStatus: 401, NpsStatus: core.NpsAuthUnauthenticated,
					ErrorCode: ErrAuthNidRevoked, Message: "revoked before commit",
				}
			}
			return nil
		}
	})
	alice := llmData(t, llmInvoke(t, app, LlmCompleteActionID, llmCreateParams("One"), "shared", llmAlice, false))
	replay := llmData(t, llmInvoke(t, app, LlmCompleteActionID, llmCreateParams("One"), "shared", llmAlice, false))
	bob := llmData(t, llmInvoke(t, app, LlmCompleteActionID, llmCreateParams("One"), "shared", llmBob, false))
	aliceID := alice["context"].(map[string]any)["context_id"]
	if replay["context"].(map[string]any)["context_id"] != aliceID ||
		bob["context"].(map[string]any)["context_id"] == aliceID || app.provider.callCount() != 2 {
		t.Fatal("response idempotency must be caller scoped and must not recommit")
	}
	denyAdmission = true
	rejectedReplay := llmInvoke(t, app, LlmCompleteActionID, llmCreateParams("One"), "shared", llmAlice, false)
	if rejectedReplay.StatusCode != 401 || llmDecode(t, rejectedReplay)["error"] != ErrAuthNidRevoked {
		t.Fatal("cached LLM replay must be reauthorized")
	}
	denyAdmission = false

	revoke = true
	revoked := llmInvoke(t, app, LlmCompleteActionID, llmCreateParams("revoked"), "revoked", "", false)
	if revoked.StatusCode != 401 || llmDecode(t, revoked)["error"] != ErrAuthNidRevoked {
		t.Fatal("commit revocation must preserve the auth envelope")
	}
	status := llmData(t, llmInvoke(t, app, LlmContextStatusActionID,
		map[string]any{"idempotency_key": "revoked"}, "", "", false))
	if status["state"] != "failed" || status["error_code"] != ErrAuthNidRevoked {
		t.Fatalf("revoked outcome: %+v", status)
	}
}

func TestStatefulLlmActionAuthorizationCapabilitiesAndFailClosed(t *testing.T) {
	var checks [][]string
	app := newLlmTestApp(t, nil, func(options *StatefulLlmActionOptions) {
		options.Authorizer = func(
			_ context.Context, _ LlmContextOwner, _ string, _ LlmAuthorizationStage,
			required []string, _ ActionContext,
		) error {
			checks = append(checks, append([]string(nil), required...))
			return nil
		}
	})
	response := llmInvoke(
		t, app, LlmCompleteActionID, llmCreateParams("caps"), "caps", llmAlice, false)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("stateful completion status = %d", response.StatusCode)
	}
	response.Body.Close()
	status := llmInvoke(t, app, LlmContextStatusActionID,
		map[string]any{"idempotency_key": "caps"}, "", llmAlice, false)
	if status.StatusCode != http.StatusOK {
		t.Fatalf("context status = %d", status.StatusCode)
	}
	status.Body.Close()
	extended := llmCreateParams("extended")
	extended["stream"] = true
	extended["tools"] = []any{map[string]any{"name": "lookup"}}
	rejected := llmInvoke(
		t, app, LlmCompleteActionID, extended, "extended", llmAlice, false)
	if rejected.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("extended capability request status = %d", rejected.StatusCode)
	}
	rejected.Body.Close()
	wantComplete := []string{CapabilityLlmComplete, CapabilityLlmContext}
	wantContext := []string{CapabilityLlmContext}
	wantExtended := []string{
		CapabilityLlmComplete, CapabilityLlmContext, CapabilityLlmStream, CapabilityLlmToolCall,
	}
	if len(checks) != 4 || !slices.Equal(checks[0], wantComplete) ||
		!slices.Equal(checks[1], wantComplete) || !slices.Equal(checks[2], wantContext) ||
		!slices.Equal(checks[3], wantExtended) {
		t.Fatalf("authorization capability checks = %v", checks)
	}

	app.coordinator.options.Authorizer = nil
	denied := llmInvoke(
		t, app, LlmCompleteActionID, llmCreateParams("denied"), "denied", llmAlice, false)
	if denied.StatusCode != http.StatusForbidden || llmDecode(t, denied)["error"] != ErrLlmContextForbidden {
		t.Fatal("missing stateful authorizer must fail closed")
	}
	if app.provider.callCount() != 1 {
		t.Fatal("fail-closed authorization must run before provider dispatch")
	}
}

func TestStatefulLlmActionAsyncReceiptIsTerminalOnly(t *testing.T) {
	app := newLlmTestApp(t, nil, nil)
	accepted := llmInvoke(t, app, LlmCompleteActionID, llmCreateParams("async"), "async", "", true)
	if accepted.StatusCode != 202 {
		t.Fatalf("accepted status %d", accepted.StatusCode)
	}
	ack := llmDecode(t, accepted)
	if ack["context"] != nil {
		t.Fatal("async ack must not contain a context receipt")
	}
	taskID := ack["task_id"].(string)
	deadline := time.Now().Add(time.Second)
	for {
		task := llmData(t, llmInvoke(t, app, SystemTaskStatus,
			map[string]any{"task_id": taskID}, "", "", false))
		if task["status"] == "completed" {
			result := task["result"].(map[string]any)
			receipt := result["context"].(map[string]any)
			if receipt["version"] != float64(1) || receipt["state"] != "active" {
				t.Fatalf("terminal receipt: %+v", receipt)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("async task did not complete: %+v", task)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStatefulLlmActionAsyncReceiptAndIgnoredCancellation(t *testing.T) {
	finish := make(chan struct{})
	defer close(finish)
	provider := &llmTestProvider{behavior: func(context.Context) (*ActionExecutionResult, error) {
		<-finish // deliberately ignore ctx cancellation
		payload, _ := json.Marshal(map[string]any{"stop_reason": "end_turn", "content": "too late"})
		return &ActionExecutionResult{Result: payload}, nil
	}}
	app := newLlmTestApp(t, provider, nil)
	accepted := llmInvoke(t, app, LlmCompleteActionID, llmCreateParams("cancel"), "cancel", "", true)
	if accepted.StatusCode != 202 {
		t.Fatalf("accepted status %d", accepted.StatusCode)
	}
	ack := llmDecode(t, accepted)
	if ack["context"] != nil {
		t.Fatal("async ack must not contain a context receipt")
	}
	taskID := ack["task_id"].(string)
	bobStatus := llmInvoke(t, app, SystemTaskStatus, map[string]any{"task_id": taskID}, "", llmBob, false)
	if bobStatus.StatusCode != 403 {
		t.Fatal("task polling must be owner scoped")
	}
	bobStatus.Body.Close()
	cancel := llmInvoke(t, app, SystemTaskCancel, map[string]any{"task_id": taskID}, "", "", false)
	if cancel.StatusCode != 200 {
		t.Fatalf("cancel status %d", cancel.StatusCode)
	}
	cancel.Body.Close()

	deadline := time.Now().Add(time.Second)
	for {
		status := llmData(t, llmInvoke(t, app, LlmContextStatusActionID,
			map[string]any{"idempotency_key": "cancel"}, "", "", false))
		if status["state"] == "failed" {
			if status["context_id"] != nil {
				t.Fatalf("cancelled request allocated context: %+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancelled reservation did not abort: %+v", status)
		}
		time.Sleep(time.Millisecond)
	}
}
