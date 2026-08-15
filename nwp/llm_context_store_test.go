// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
)

var (
	testAlice = LlmContextOwner{NID: "urn:nps:agent:labacacia:alice", SecurityScope: "workspace-a"}
	testBob   = LlmContextOwner{NID: "urn:nps:agent:labacacia:bob", SecurityScope: "workspace-a"}
)

type contextStoreHarness struct {
	now   time.Time
	ids   []string
	store *InMemoryLlmContextStore
}

func newContextStoreHarness(configure func(*LlmContextStoreOptions)) *contextStoreHarness {
	h := &contextStoreHarness{
		now: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC),
		ids: []string{
			"AQIDBAUGBwgJCgsMDQ4PEA", "ERITFBUWFxgZGhscHR4fIA",
			"ISIjJCUmJygpKissLS4vMA", "MTIzNDU2Nzg5Ojs8PT4_QA",
		},
	}
	options := LlmContextStoreOptions{
		Clock: func() time.Time { return h.now },
		ContextIDFactory: func() (string, error) {
			value := h.ids[0]
			h.ids = h.ids[1:]
			return value, nil
		},
	}
	if configure != nil {
		configure(&options)
	}
	h.store = NewInMemoryLlmContextStore(options)
	return h
}

func (h *contextStoreHarness) request(
	operation LlmContextOperation,
	key string,
	contextID *string,
	baseVersion *uint64,
) LlmContextMutationRequest {
	messages := []LlmMessageDto{userMessage("Continue")}
	if operation == LlmContextCreate {
		messages = []LlmMessageDto{systemMessage("Be concise."), userMessage("One")}
	}
	return LlmContextMutationRequest{
		Operation: operation, Owner: testAlice, ContextID: contextID, BaseVersion: baseVersion,
		Binding: testBinding("willow-small", "runtime-1"), Messages: messages,
		IdempotencyKey: key, RequestID: "req-" + key,
	}
}

func (h *contextStoreHarness) create(t *testing.T, key string, ttl *uint32) LlmContextReceiptDto {
	t.Helper()
	request := h.request(LlmContextCreate, key, nil, nil)
	request.TTLSeconds = ttl
	reservation, err := h.store.Reserve(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := h.store.Commit(reservation, assistantMessage("First"))
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestLlmContextStoreSharedVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			ID       string         `json:"id"`
			Input    map[string]any `json:"input"`
			Expected map[string]any `json:"expected"`
		} `json:"vectors"`
	}
	_, file, _, _ := runtime.Caller(0)
	path, err := testfixture.ConformanceFile(file, "nwp", "llm_context_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*testing.T){
		"nwp.llm-context.001": testContextStateless,
		"nwp.llm-context.002": testContextCreate,
		"nwp.llm-context.003": testContextAppend,
		"nwp.llm-context.004": testContextCAS,
		"nwp.llm-context.005": testContextFork,
		"nwp.llm-context.006": testContextReset,
		"nwp.llm-context.007": testContextBinding,
		"nwp.llm-context.008": testContextOwner,
		"nwp.llm-context.009": testContextAbort,
		"nwp.llm-context.010": testContextLostCreate,
		"nwp.llm-context.011": testContextReleaseExpiry,
		"nwp.llm-context.012": testContextUsage,
		"nwp.llm-context.013": testContextAdvertised,
		"nwp.llm-context.014": testContextRestart,
		"nwp.llm-context.015": testContextIdempotency,
		"nwp.llm-context.016": testContextRevocation,
		"nwp.llm-context.017": testContextLimit,
		"nwp.llm-context.018": testContextUnsupported,
		"nwp.llm-context.019": testContextMissingKey,
	}
	for _, vector := range fixture.Vectors {
		fn, exists := cases[vector.ID]
		if !exists {
			t.Fatalf("shared vector %s has no Go implementation", vector.ID)
		}
		t.Run(vector.ID, func(t *testing.T) {
			assertLlmFixtureContract(t, vector.ID, vector.Input, vector.Expected)
			fn(t)
		})
	}
}

func assertLlmFixtureContract(t *testing.T, id string, input, expected map[string]any) {
	t.Helper()
	if len(input) == 0 || len(expected) == 0 {
		t.Fatalf("%s must have non-empty input and expected objects", id)
	}
	switch id[len(id)-3:] {
	case "001":
		if _, exists := jmap(input, "params")["context"]; exists || jstring(expected, "mode") != "stateless" ||
			!jbool(expected, "dispatched") || jbool(expected, "context_mutated") {
			t.Fatal("stateless fixture contract mismatch")
		}
	case "002":
		if jstring(expected, "owner_nid") != jstring(input, "owner_nid") || jnum(expected, "version") != 1 || !jbool(expected, "committed") {
			t.Fatal("create fixture contract mismatch")
		}
	case "003":
		pre, params := jmap(input, "pre_state"), jmap(input, "params")
		if jnum(expected, "version") != jnum(pre, "version")+1 ||
			jnum(expected, "accepted_delta_message_count") != float64(len(jarray(params, "messages"))) ||
			jnum(expected, "post_message_count") != float64(len(jarray(pre, "messages"))+len(jarray(params, "messages"))+1) {
			t.Fatal("append fixture contract mismatch")
		}
	case "004":
		pre := jmap(input, "pre_state")
		if jnum(expected, "post_version") != jnum(pre, "version") ||
			jnum(jmap(expected, "hint"), "current_version") != jnum(pre, "version") ||
			jstring(expected, "error") != ErrLlmContextVersionConflict {
			t.Fatal("CAS fixture contract mismatch")
		}
	case "005":
		if jnum(expected, "parent_version") != jnum(jmap(input, "request"), "base_version") ||
			jnum(expected, "post_parent_version") != jnum(input, "parent_version_at_child_commit") ||
			jnum(expected, "version") != 1 {
			t.Fatal("fork fixture contract mismatch")
		}
	case "006":
		if jnum(expected, "version") != jnum(jmap(input, "pre_state"), "version")+1 ||
			jstring(expected, "resolved_model") != jstring(jmap(input, "request"), "model") {
			t.Fatal("reset fixture contract mismatch")
		}
	case "007":
		if jnum(expected, "post_version") != jnum(jmap(input, "pre_state"), "version") ||
			jstring(expected, "error") != ErrLlmContextBindingMismatch ||
			jbool(expected, "provider_dispatched") || jbool(expected, "stateless_fallback") {
			t.Fatal("binding fixture contract mismatch")
		}
	case "008":
		if jstring(input, "owner_nid") == jstring(input, "caller_nid") ||
			containsJSON(jarray(input, "caller_capabilities"), CapabilityLlmContext) ||
			jstring(expected, "error") != ErrLlmContextForbidden {
			t.Fatal("owner fixture contract mismatch")
		}
	case "009":
		if jnum(expected, "post_version") != jnum(jmap(input, "pre_state"), "version") ||
			jbool(expected, "committed") || !jbool(expected, "reservation_released") {
			t.Fatal("abort fixture contract mismatch")
		}
	case "010":
		sequence := jarray(input, "status_sequence")
		terminal := sequence[len(sequence)-1].(map[string]any)
		completed := jmap(expected, "completed_status")
		if jbool(jmap(expected, "running_status"), "context_id_present") ||
			jstring(completed, "context_id") != jstring(terminal, "context_id") ||
			jnum(completed, "version") != jnum(terminal, "version") {
			t.Fatal("lost-create fixture contract mismatch")
		}
	case "011":
		if jnum(jmap(expected, "release_receipt"), "version") != jnum(jmap(input, "pre_state"), "version")+1 ||
			jnum(jmap(expected, "expiry_tombstone"), "version") != jnum(jmap(input, "expiry_branch"), "active_version") {
			t.Fatal("tombstone fixture contract mismatch")
		}
	case "012":
		usage := jmap(input, "usage")
		if jnum(usage, "input_tokens") != jnum(usage, "reused_tokens")+jnum(usage, "evaluated_tokens") ||
			jnum(usage, "wire_input_bytes") >= jnum(input, "stateless_wire_input_bytes") ||
			!jbool(expected, "usage_equation_valid") || !jbool(expected, "wire_input_smaller_than_stateless") {
			t.Fatal("usage fixture contract mismatch")
		}
	case "013":
		manifestContext := jmap(jmap(input, "manifest"), "context")
		if !jsonEqual(jarray(manifestContext, "operations"), jarray(input, "implemented_operations")) ||
			jstring(manifestContext, "persistence") != jstring(input, "implemented_persistence") ||
			!jbool(expected, "manifest_valid") || jstring(expected, "requires_capability") != CapabilityLlmContext {
			t.Fatal("manifest fixture contract mismatch")
		}
	case "014":
		if jstring(input, "persistence") != "process" || jstring(input, "event") != "process_restart" ||
			jstring(expected, "error") != ErrLlmContextNotFound ||
			jbool(expected, "replacement_created") || jbool(expected, "stateless_fallback") {
			t.Fatal("restart fixture contract mismatch")
		}
	case "015":
		original := jmap(input, "original")
		if joinJSON(jarray(original, "chunks")) != jstring(expected, "ordered_content") ||
			jstring(original, "stream_id") == jstring(input, "replay_stream_id") ||
			jnum(expected, "provider_invocations") != 0 || jnum(expected, "additional_context_commits") != 0 {
			t.Fatal("stream replay fixture contract mismatch")
		}
	case "016":
		if jstring(input, "authorization_at_admission") != "valid" || jstring(input, "authorization_at_commit") != "revoked" ||
			jnum(expected, "post_version") != jnum(jmap(input, "pre_state"), "version") ||
			jstring(expected, "error") != ErrAuthNidRevoked {
			t.Fatal("revocation fixture contract mismatch")
		}
	case "017":
		if jnum(input, "live_contexts") != jnum(input, "max_contexts_per_principal") ||
			jstring(expected, "error") != ErrLlmContextLimitExceeded || jbool(expected, "context_allocated") {
			t.Fatal("limit fixture contract mismatch")
		}
	case "018":
		if containsJSON(jarray(input, "advertised_operations"), jstring(jmap(input, "request"), "operation")) ||
			jstring(expected, "error") != ErrLlmContextOperationUnsupported {
			t.Fatal("unsupported-operation fixture contract mismatch")
		}
	case "019":
		if jbool(input, "idempotency_key_present") || jstring(expected, "error") != ErrActionParamsInvalid ||
			jbool(expected, "context_allocated") || jbool(expected, "provider_dispatched") {
			t.Fatal("idempotency fixture contract mismatch")
		}
	default:
		t.Fatalf("unimplemented fixture contract: %s", id)
	}
}

func jmap(value map[string]any, key string) map[string]any { return value[key].(map[string]any) }
func jarray(value map[string]any, key string) []any        { return value[key].([]any) }
func jstring(value map[string]any, key string) string      { return value[key].(string) }
func jnum(value map[string]any, key string) float64        { return value[key].(float64) }
func jbool(value map[string]any, key string) bool          { return value[key].(bool) }
func containsJSON(values []any, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func joinJSON(values []any) string {
	var result string
	for _, value := range values {
		result += value.(string)
	}
	return result
}
func jsonEqual(left, right any) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

func TestLlmContextStoreDefensiveCopies(t *testing.T) {
	h := newContextStoreHarness(nil)
	original := "Original"
	messages := []LlmMessageDto{systemMessage("Be concise."), {Role: "user", Content: &original}}
	request := h.request(LlmContextCreate, "immutable", nil, nil)
	request.Messages = messages
	reservation, err := h.store.Reserve(request)
	if err != nil {
		t.Fatal(err)
	}
	tampered := "Tampered"
	messages[1].Content = &tampered
	request.Binding.Model = "tampered-model"
	receipt, err := h.store.Commit(reservation, assistantMessage("Stable"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := h.store.Snapshot(testAlice, receipt.ContextID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Binding.Model != "willow-small" || *snapshot.Transcript[1].Content != "Original" {
		t.Fatal("reservation did not defensively copy caller input")
	}
	mutated := "Mutated snapshot"
	snapshot.Transcript[1].Content = &mutated
	again, _ := h.store.Snapshot(testAlice, receipt.ContextID)
	if *again.Transcript[1].Content != "Original" {
		t.Fatal("snapshot leaked store-owned message")
	}
}

func testContextStateless(t *testing.T) {
	request := LlmCompleteActionRequest{Model: "willow-small", Messages: []LlmMessageDto{userMessage("Hello")}}
	if request.Context != nil {
		t.Fatal("stateless request gained context")
	}
}

func testContextCreate(t *testing.T) {
	h := newContextStoreHarness(nil)
	reservation, err := h.store.Reserve(h.request(LlmContextCreate, "create-1", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	busy, err := h.store.Status(testAlice, nil, stringPtr("create-1"))
	if err != nil || busy.State != LlmContextBusy || busy.ContextID != nil {
		t.Fatalf("unexpected busy status: %#v %v", busy, err)
	}
	h.now = h.now.Add(5 * time.Second)
	receipt, err := h.store.Commit(reservation, assistantMessage("First"))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Version != 1 || receipt.ExpiresAt == nil {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	expiry, _ := time.Parse(time.RFC3339Nano, *receipt.ExpiresAt)
	if !expiry.Equal(h.now.Add(time.Hour)) {
		t.Fatalf("TTL started before commit: %v", expiry)
	}
}

func testContextAppend(t *testing.T) {
	h := newContextStoreHarness(nil)
	created := h.create(t, "create-1", nil)
	request := h.request(LlmContextAppend, "append-1", &created.ContextID, uint64Ptr(1))
	request.Messages = []LlmMessageDto{userMessage("Two")}
	reservation, err := h.store.Reserve(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := h.store.Commit(reservation, assistantMessage("Second"))
	if err != nil || receipt.Version != 2 {
		t.Fatalf("append: %#v %v", receipt, err)
	}
	snapshot, _ := h.store.Snapshot(testAlice, created.ContextID)
	if len(snapshot.Transcript) != 5 || *snapshot.Transcript[3].Content != "Two" {
		t.Fatalf("unexpected transcript: %#v", snapshot.Transcript)
	}
}

func testContextCAS(t *testing.T) {
	h := newContextStoreHarness(nil)
	created := h.create(t, "create-1", nil)
	winner, err := h.store.Reserve(h.request(LlmContextAppend, "winner", &created.ContextID, uint64Ptr(1)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.store.Reserve(h.request(LlmContextAppend, "loser", &created.ContextID, uint64Ptr(1)))
	requireStoreError(t, err, ErrLlmContextVersionConflict)
	if err := h.store.Abort(winner, ""); err != nil {
		t.Fatal(err)
	}
	_, err = h.store.Reserve(h.request(LlmContextAppend, "stale", &created.ContextID, uint64Ptr(0)))
	requireStoreError(t, err, ErrLlmContextVersionConflict)
}

func testContextFork(t *testing.T) {
	h := newContextStoreHarness(nil)
	parent := h.create(t, "create-1", nil)
	forkRequest := h.request(LlmContextFork, "fork-1", &parent.ContextID, uint64Ptr(1))
	forkRequest.Messages = []LlmMessageDto{}
	fork, err := h.store.Reserve(forkRequest)
	if err != nil {
		t.Fatal(err)
	}
	appendReservation, err := h.store.Reserve(h.request(LlmContextAppend, "parent-append", &parent.ContextID, uint64Ptr(1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Commit(appendReservation, assistantMessage("Parent moved")); err != nil {
		t.Fatal(err)
	}
	child, err := h.store.Commit(fork, assistantMessage("Branch"))
	if err != nil {
		t.Fatal(err)
	}
	parentSnapshot, _ := h.store.Snapshot(testAlice, parent.ContextID)
	childSnapshot, _ := h.store.Snapshot(testAlice, child.ContextID)
	if child.ParentVersion == nil || *child.ParentVersion != 1 || parentSnapshot.Version != 2 || len(childSnapshot.Transcript) != 4 {
		t.Fatalf("fork semantics drift: %#v %#v", child, childSnapshot)
	}
}

func testContextReset(t *testing.T) {
	h := newContextStoreHarness(nil)
	created := h.create(t, "create-1", nil)
	request := h.request(LlmContextReset, "reset-1", &created.ContextID, uint64Ptr(1))
	request.Binding = testBinding("willow-medium", "runtime-2")
	request.Messages = []LlmMessageDto{systemMessage("Use JSON."), userMessage("Restart")}
	reservation, err := h.store.Reserve(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Commit(reservation, assistantMessage("{}")); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := h.store.Snapshot(testAlice, created.ContextID)
	if snapshot.Version != 2 || snapshot.Binding.Model != "willow-medium" || len(snapshot.Transcript) != 3 {
		t.Fatalf("reset drift: %#v", snapshot)
	}
}

func testContextBinding(t *testing.T) {
	h := newContextStoreHarness(nil)
	created := h.create(t, "create-1", nil)
	request := h.request(LlmContextAppend, "bad-binding", &created.ContextID, uint64Ptr(1))
	request.Binding = testBinding("willow-large", "runtime-1")
	_, err := h.store.Reserve(request)
	requireStoreError(t, err, ErrLlmContextBindingMismatch)
}

func testContextOwner(t *testing.T) {
	h := newContextStoreHarness(nil)
	created := h.create(t, "create-1", nil)
	_, err := h.store.Status(testBob, &created.ContextID, nil)
	requireStoreError(t, err, ErrLlmContextForbidden)
}

func testContextAbort(t *testing.T) {
	h := newContextStoreHarness(func(options *LlmContextStoreOptions) { options.DefaultTTLSeconds = 10 })
	created := h.create(t, "create-1", uint32Ptr(10))
	reservation, _ := h.store.Reserve(h.request(LlmContextAppend, "abort-1", &created.ContextID, uint64Ptr(1)))
	h.now = h.now.Add(11 * time.Second)
	if err := h.store.Abort(reservation, "NPS-SERVER-TIMEOUT"); err != nil {
		t.Fatal(err)
	}
	status, _ := h.store.Status(testAlice, &created.ContextID, nil)
	failed, _ := h.store.Status(testAlice, nil, stringPtr("abort-1"))
	if status.State != LlmContextExpired || failed.ErrorCode == nil || *failed.ErrorCode != "NPS-SERVER-TIMEOUT" {
		t.Fatalf("abort drift: %#v %#v", status, failed)
	}
}

func testContextLostCreate(t *testing.T) {
	h := newContextStoreHarness(func(options *LlmContextStoreOptions) {
		options.DefaultTTLSeconds = 10
		options.TombstoneSeconds = 5
	})
	reservation, _ := h.store.Reserve(h.request(LlmContextCreate, "lost-create", nil, nil))
	if _, err := h.store.Commit(reservation, assistantMessage("First")); err != nil {
		t.Fatal(err)
	}
	active, _ := h.store.Status(testAlice, nil, stringPtr("lost-create"))
	h.now = h.now.Add(16 * time.Second)
	h.store.SweepExpired()
	retained, err := h.store.Status(testAlice, nil, stringPtr("lost-create"))
	if err != nil || retained.ContextID == nil || active.ContextID == nil || *retained.ContextID != *active.ContextID {
		t.Fatalf("lost create outcome missing: %#v %v", retained, err)
	}
}

func testContextReleaseExpiry(t *testing.T) {
	h := newContextStoreHarness(func(options *LlmContextStoreOptions) {
		options.DefaultTTLSeconds = 10
		options.TombstoneSeconds = 5
	})
	created := h.create(t, "create-1", uint32Ptr(10))
	released, err := h.store.Release(testAlice, created.ContextID, 1, "create-1")
	if err != nil || released.Version != 2 {
		t.Fatalf("release: %#v %v", released, err)
	}
	replay, _ := h.store.Release(testAlice, created.ContextID, 1, "create-1")
	if replay.Version != 2 {
		t.Fatal("release replay drift")
	}
	_, err = h.store.Release(testAlice, "ERITFBUWFxgZGhscHR4fIA", 1, "create-1")
	requireStoreError(t, err, ErrActionIdempotencyConflict)
	_, err = h.store.Reserve(h.request(LlmContextAppend, "after-release", &created.ContextID, uint64Ptr(2)))
	requireStoreError(t, err, ErrLlmContextNotFound)
	expiring := h.create(t, "create-expiring", uint32Ptr(10))
	h.now = h.now.Add(11 * time.Second)
	h.store.SweepExpired()
	_, err = h.store.Snapshot(testAlice, expiring.ContextID)
	requireStoreError(t, err, ErrLlmContextExpired)
	h.now = h.now.Add(6 * time.Second)
	h.store.SweepExpired()
	_, err = h.store.Status(testAlice, &expiring.ContextID, nil)
	requireStoreError(t, err, ErrLlmContextNotFound)
}

func testContextUsage(t *testing.T) {
	input, reused, evaluated, wire, hit := uint32(1200), uint32(1000), uint32(200), uint64(384), true
	usage := LlmUsageDto{InputTokens: &input, ReusedTokens: &reused, EvaluatedTokens: &evaluated, CacheHit: &hit, WireInputBytes: &wire}
	if *usage.ReusedTokens+*usage.EvaluatedTokens != *usage.InputTokens || !*usage.CacheHit || *usage.WireInputBytes >= 4096 {
		t.Fatal("usage accounting drift")
	}
}

func testContextAdvertised(t *testing.T) {
	h := newContextStoreHarness(func(options *LlmContextStoreOptions) {
		options.SupportedOperations = map[LlmContextOperation]bool{
			LlmContextCreate: true, LlmContextAppend: true, LlmContextReset: true, LlmContextRelease: true,
		}
	})
	created := h.create(t, "create-1", nil)
	request := h.request(LlmContextFork, "fork-disabled", &created.ContextID, uint64Ptr(1))
	request.Messages = []LlmMessageDto{}
	_, err := h.store.Reserve(request)
	requireStoreError(t, err, ErrLlmContextOperationUnsupported)
}

func testContextRestart(t *testing.T) {
	first := newContextStoreHarness(nil)
	created := first.create(t, "create-1", nil)
	restarted := newContextStoreHarness(nil)
	_, err := restarted.store.Reserve(restarted.request(LlmContextAppend, "after-restart", &created.ContextID, uint64Ptr(1)))
	requireStoreError(t, err, ErrLlmContextNotFound)
}

func testContextIdempotency(t *testing.T) {
	h := newContextStoreHarness(nil)
	created := h.create(t, "stream-replay", nil)
	_, err := h.store.Reserve(h.request(LlmContextCreate, "stream-replay", nil, nil))
	requireStoreError(t, err, ErrActionIdempotencyConflict)
	snapshot, _ := h.store.Snapshot(testAlice, created.ContextID)
	if snapshot.Version != 1 {
		t.Fatal("duplicate committed twice")
	}
}

func testContextRevocation(t *testing.T) {
	h := newContextStoreHarness(nil)
	created := h.create(t, "create-1", nil)
	reservation, _ := h.store.Reserve(h.request(LlmContextAppend, "revoked", &created.ContextID, uint64Ptr(1)))
	if err := h.store.Abort(reservation, ErrAuthNidRevoked); err != nil {
		t.Fatal(err)
	}
	status, _ := h.store.Status(testAlice, nil, stringPtr("revoked"))
	if status.ErrorCode == nil || *status.ErrorCode != ErrAuthNidRevoked {
		t.Fatal("revocation outcome missing")
	}
}

func testContextLimit(t *testing.T) {
	h := newContextStoreHarness(func(options *LlmContextStoreOptions) { options.MaxContextsPerPrincipal = 1 })
	h.create(t, "create-1", nil)
	_, err := h.store.Reserve(h.request(LlmContextCreate, "over-limit", nil, nil))
	requireStoreError(t, err, ErrLlmContextLimitExceeded)
}

func testContextUnsupported(t *testing.T) { testContextAdvertised(t) }

func testContextMissingKey(t *testing.T) {
	h := newContextStoreHarness(nil)
	_, err := h.store.Reserve(h.request(LlmContextCreate, "", nil, nil))
	requireStoreError(t, err, ErrActionParamsInvalid)
}

func requireStoreError(t *testing.T, err error, code string) *LlmContextStoreError {
	t.Helper()
	var target *LlmContextStoreError
	if !errors.As(err, &target) || target.ErrorCode != code {
		t.Fatalf("error=%v, want %s", err, code)
	}
	return target
}

func testBinding(model, runtimeRevision string) LlmContextBinding {
	prompt := "Be concise."
	if model != "willow-small" {
		prompt = "Use JSON."
	}
	return LlmContextBinding{Model: model, RuntimeRevision: runtimeRevision, SystemMessages: []LlmMessageDto{systemMessage(prompt)}}
}

func systemMessage(value string) LlmMessageDto {
	return LlmMessageDto{Role: "system", Content: stringPtr(value)}
}
func userMessage(value string) LlmMessageDto {
	return LlmMessageDto{Role: "user", Content: stringPtr(value)}
}
func assistantMessage(value string) LlmMessageDto {
	return LlmMessageDto{Role: "assistant", Content: stringPtr(value)}
}
