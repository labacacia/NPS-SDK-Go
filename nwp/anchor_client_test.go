// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/nwp"
)

// snapshotServer creates an httptest.Server that serves a topology.snapshot
// CapsFrame response at /query. The handler captures the raw request body.
func snapshotServer(t *testing.T, snap map[string]any, capturedBody *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capturedBody != nil {
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			*capturedBody = m
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"data": []any{snap},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// defaultSnap returns a minimal valid TopologySnapshot map.
func defaultSnap() map[string]any {
	return map[string]any{
		"version":      float64(42),
		"anchor_nid":   "anchor-1",
		"cluster_size": float64(3),
		"members": []any{
			map[string]any{
				"nid":             "node-a",
				"node_roles":      []any{"router"},
				"activation_mode": "active",
			},
		},
	}
}

// subscribeServer creates an httptest.Server that serves an NDJSON stream at /subscribe.
// lines must be JSON-encodable objects; the server writes them one per line.
func subscribeServer(t *testing.T, lines []any, capturedBody *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capturedBody != nil {
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			*capturedBody = m
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, l := range lines {
			b, _ := json.Marshal(l)
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n"))
		}
	}))
}

// ackLine returns the ACK envelope (first line; discarded by client).
func ackLine(streamID string) map[string]any {
	return map[string]any{"ack": true, "stream_id": streamID}
}

// eventLine returns a standard event envelope.
func eventLine(seq uint64, eventType string, payload map[string]any) map[string]any {
	return map[string]any{
		"stream_id":  "sid",
		"seq":        seq,
		"event_type": eventType,
		"payload":    payload,
	}
}

// drainEvents reads up to n events from evCh with a timeout.
func drainEvents(t *testing.T, evCh <-chan nwp.TopologyEvent, n int) []nwp.TopologyEvent {
	t.Helper()
	out := make([]nwp.TopologyEvent, 0, n)
	timeout := time.After(3 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case ev, ok := <-evCh:
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-timeout:
			t.Fatalf("drainEvents: timed out waiting for event %d/%d", i+1, n)
		}
	}
	return out
}

// waitClose waits for evCh to be closed with a timeout.
func waitClose(t *testing.T, evCh <-chan nwp.TopologyEvent) {
	t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-evCh:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("waitClose: event channel was not closed in time")
		}
	}
}

// waitErr waits for an error to appear on errCh.
func waitErr(t *testing.T, errCh <-chan error) error {
	t.Helper()
	timeout := time.After(3 * time.Second)
	select {
	case err := <-errCh:
		return err
	case <-timeout:
		t.Fatal("waitErr: timed out waiting for error")
		return nil
	}
}

// ── GetSnapshot tests ─────────────────────────────────────────────────────────

func TestAnchorNodeClient_GetSnapshot_Success(t *testing.T) {
	var body map[string]any
	srv := snapshotServer(t, defaultSnap(), &body)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	snap, err := client.GetSnapshot(context.Background(), "", nil, 0, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify request wire body.
	if got := body["type"]; got != "topology.snapshot" {
		t.Errorf("wire type = %q, want topology.snapshot", got)
	}
	topo, _ := body["topology"].(map[string]any)
	if topo == nil {
		t.Fatal("topology field missing from wire body")
	}
	if got := topo["scope"]; got != "cluster" {
		t.Errorf("wire scope = %q, want cluster", got)
	}
	includes, _ := topo["include"].([]any)
	if len(includes) == 0 || includes[0] != "members" {
		t.Errorf("wire include = %v, want [members]", includes)
	}
	if got := topo["depth"]; got != float64(1) {
		t.Errorf("wire depth = %v, want 1", got)
	}

	// Verify returned fields.
	if snap.Version != 42 {
		t.Errorf("Version = %d, want 42", snap.Version)
	}
	if snap.AnchorNid != "anchor-1" {
		t.Errorf("AnchorNid = %q, want anchor-1", snap.AnchorNid)
	}
	if snap.ClusterSize != 3 {
		t.Errorf("ClusterSize = %d, want 3", snap.ClusterSize)
	}
	if len(snap.Members) != 1 || snap.Members[0].Nid != "node-a" {
		t.Errorf("Members = %+v, want [{nid:node-a ...}]", snap.Members)
	}
}

func TestAnchorNodeClient_GetSnapshot_MemberScopeWithTargetNid(t *testing.T) {
	var body map[string]any
	srv := snapshotServer(t, defaultSnap(), &body)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	_, err := client.GetSnapshot(context.Background(), "member", []string{"members", "metrics"}, 2, "node-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	topo, _ := body["topology"].(map[string]any)
	if topo == nil {
		t.Fatal("topology field missing")
	}
	if got := topo["scope"]; got != "member" {
		t.Errorf("scope = %q, want member", got)
	}
	if got := topo["target_nid"]; got != "node-xyz" {
		t.Errorf("target_nid = %q, want node-xyz", got)
	}
	includes, _ := topo["include"].([]any)
	if len(includes) != 2 {
		t.Errorf("include len = %d, want 2; got %v", len(includes), includes)
	}
	if got := topo["depth"]; got != float64(2) {
		t.Errorf("depth = %v, want 2", got)
	}
}

func TestAnchorNodeClient_GetSnapshot_DepthOption(t *testing.T) {
	var body map[string]any
	srv := snapshotServer(t, defaultSnap(), &body)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	_, err := client.GetSnapshot(context.Background(), "", nil, 5, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	topo, _ := body["topology"].(map[string]any)
	if got := topo["depth"]; got != float64(5) {
		t.Errorf("depth = %v, want 5", got)
	}
}

func TestAnchorNodeClient_GetSnapshot_Non2xxNPSErrorJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "NOT_FOUND",
			"status":  "nps.not_found",
			"message": "anchor node not found",
		})
	}))
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	_, err := client.GetSnapshot(context.Background(), "", nil, 0, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var ate *nwp.AnchorTopologyError
	if !errors.As(err, &ate) {
		t.Fatalf("expected *AnchorTopologyError, got %T: %v", err, err)
	}
	if ate.NwpErrorCode != "NOT_FOUND" {
		t.Errorf("NwpErrorCode = %q, want NOT_FOUND", ate.NwpErrorCode)
	}
	if ate.NpsStatus != "nps.not_found" {
		t.Errorf("NpsStatus = %q, want nps.not_found", ate.NpsStatus)
	}
	if ate.Message != "anchor node not found" {
		t.Errorf("Message = %q, want 'anchor node not found'", ate.Message)
	}
}

func TestAnchorNodeClient_GetSnapshot_Non2xxPlainBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	_, err := client.GetSnapshot(context.Background(), "", nil, 0, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var ate *nwp.AnchorTopologyError
	if !errors.As(err, &ate) {
		t.Fatalf("expected *AnchorTopologyError, got %T: %v", err, err)
	}
	// Should contain the status code somewhere.
	if !strings.Contains(ate.Message, "503") && !strings.Contains(ate.NpsStatus, "503") {
		t.Errorf("error should reference HTTP 503; got message=%q status=%q", ate.Message, ate.NpsStatus)
	}
}

func TestAnchorNodeClient_GetSnapshot_EmptyDataArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
	}))
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	_, err := client.GetSnapshot(context.Background(), "", nil, 0, "")
	if err == nil {
		t.Fatal("expected error for empty data array, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty data; got: %v", err)
	}
}

// ── Subscribe tests ───────────────────────────────────────────────────────────

func TestAnchorNodeClient_Subscribe_Success_AllEventTypes(t *testing.T) {
	lines := []any{
		ackLine("sid"),
		eventLine(1, "member_joined", map[string]any{
			"nid": "node-b", "node_roles": []any{"relay"}, "activation_mode": "passive",
		}),
		eventLine(2, "member_left", map[string]any{"nid": "node-c"}),
		eventLine(3, "member_updated", map[string]any{
			"nid":     "node-d",
			"changes": map[string]any{"activation_mode": "active"},
		}),
		eventLine(4, "anchor_state", map[string]any{
			"field":   "cluster_health",
			"details": map[string]any{"ok": true},
		}),
	}

	srv := subscribeServer(t, lines, nil)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, errCh := client.Subscribe(context.Background(), "", nil, nil)

	events := drainEvents(t, evCh, 4)

	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	// member_joined
	ev0 := events[0]
	if ev0.Kind != "member_joined" {
		t.Errorf("[0] Kind = %q, want member_joined", ev0.Kind)
	}
	if ev0.MemberJoined == nil {
		t.Fatal("[0] MemberJoined is nil")
	}
	if ev0.MemberJoined.Member.Nid != "node-b" {
		t.Errorf("[0] Member.Nid = %q, want node-b", ev0.MemberJoined.Member.Nid)
	}
	if ev0.Version != 1 {
		t.Errorf("[0] Version = %d, want 1", ev0.Version)
	}

	// member_left
	ev1 := events[1]
	if ev1.Kind != "member_left" {
		t.Errorf("[1] Kind = %q, want member_left", ev1.Kind)
	}
	if ev1.MemberLeft == nil || ev1.MemberLeft.Nid != "node-c" {
		t.Errorf("[1] MemberLeft.Nid = %q, want node-c", ev1.MemberLeft.Nid)
	}

	// member_updated
	ev2 := events[2]
	if ev2.Kind != "member_updated" {
		t.Errorf("[2] Kind = %q, want member_updated", ev2.Kind)
	}
	if ev2.MemberUpdated == nil {
		t.Fatal("[2] MemberUpdated is nil")
	}
	if ev2.MemberUpdated.Nid != "node-d" {
		t.Errorf("[2] MemberUpdated.Nid = %q, want node-d", ev2.MemberUpdated.Nid)
	}
	if ev2.MemberUpdated.Changes.ActivationMode == nil || *ev2.MemberUpdated.Changes.ActivationMode != "active" {
		t.Errorf("[2] ActivationMode = %v, want active", ev2.MemberUpdated.Changes.ActivationMode)
	}

	// anchor_state
	ev3 := events[3]
	if ev3.Kind != "anchor_state" {
		t.Errorf("[3] Kind = %q, want anchor_state", ev3.Kind)
	}
	if ev3.AnchorState == nil {
		t.Fatal("[3] AnchorState is nil")
	}
	if ev3.AnchorState.Field != "cluster_health" {
		t.Errorf("[3] AnchorState.Field = %q, want cluster_health", ev3.AnchorState.Field)
	}

	// No error expected.
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	default:
	}
}

func TestAnchorNodeClient_Subscribe_ResyncRequired_ClosesChannel(t *testing.T) {
	lines := []any{
		ackLine("sid"),
		eventLine(1, "member_joined", map[string]any{
			"nid": "node-e", "node_roles": []any{}, "activation_mode": "active",
		}),
		eventLine(2, "resync_required", map[string]any{"reason": "version_gap"}),
	}

	srv := subscribeServer(t, lines, nil)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, _ := client.Subscribe(context.Background(), "", nil, nil)

	// Collect events until channel closes.
	var events []nwp.TopologyEvent
	timeout := time.After(3 * time.Second)
	for {
		select {
		case ev, ok := <-evCh:
			if !ok {
				goto done
			}
			events = append(events, ev)
		case <-timeout:
			t.Fatal("timeout waiting for channel close after resync_required")
		}
	}
done:
	// Should have member_joined + resync_required.
	if len(events) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(events))
	}
	last := events[len(events)-1]
	if last.Kind != "resync_required" {
		t.Errorf("last event Kind = %q, want resync_required", last.Kind)
	}
	if last.ResyncRequired == nil {
		t.Fatal("ResyncRequired field is nil")
	}
	if last.ResyncRequired.Reason != "version_gap" {
		t.Errorf("ResyncRequired.Reason = %q, want version_gap", last.ResyncRequired.Reason)
	}
}

func TestAnchorNodeClient_Subscribe_MidStreamErrorEnvelope(t *testing.T) {
	lines := []any{
		ackLine("sid"),
		eventLine(1, "member_joined", map[string]any{
			"nid": "node-f", "node_roles": []any{}, "activation_mode": "active",
		}),
		// Error envelope: no event_type, has error/status.
		map[string]any{
			"stream_id": "sid",
			"error":     "STREAM_ERROR",
			"status":    "nps.stream_error",
			"message":   "upstream disruption",
		},
	}

	srv := subscribeServer(t, lines, nil)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, errCh := client.Subscribe(context.Background(), "", nil, nil)

	// Drain the member_joined event.
	_ = drainEvents(t, evCh, 1)

	// Expect an error.
	err := waitErr(t, errCh)
	if err == nil {
		t.Fatal("expected error from mid-stream error envelope, got nil")
	}
	var ate *nwp.AnchorTopologyError
	if !errors.As(err, &ate) {
		t.Fatalf("expected *AnchorTopologyError, got %T: %v", err, err)
	}
	if ate.NwpErrorCode != "STREAM_ERROR" {
		t.Errorf("NwpErrorCode = %q, want STREAM_ERROR", ate.NwpErrorCode)
	}
}

func TestAnchorNodeClient_Subscribe_WithFilterOption(t *testing.T) {
	var body map[string]any
	lines := []any{ackLine("sid")}
	srv := subscribeServer(t, lines, &body)
	defer srv.Close()

	filter := &nwp.TopologyFilter{
		TagsAny:   []string{"tier:edge"},
		NodeRoles: []string{"relay"},
	}
	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, _ := client.Subscribe(context.Background(), "", filter, nil)
	waitClose(t, evCh)

	// Verify wire body.
	if got := body["type"]; got != "topology.stream" {
		t.Errorf("wire type = %q, want topology.stream", got)
	}
	topo, _ := body["topology"].(map[string]any)
	if topo == nil {
		t.Fatal("topology field missing from wire body")
	}
	f, _ := topo["filter"].(map[string]any)
	if f == nil {
		t.Fatal("filter field missing from wire topology")
	}
	tagsAny, _ := f["tags_any"].([]any)
	if len(tagsAny) != 1 || tagsAny[0] != "tier:edge" {
		t.Errorf("tags_any = %v, want [tier:edge]", tagsAny)
	}
	roles, _ := f["node_roles"].([]any)
	if len(roles) != 1 || roles[0] != "relay" {
		t.Errorf("node_roles = %v, want [relay]", roles)
	}
}

func TestAnchorNodeClient_Subscribe_WithSinceVersion(t *testing.T) {
	var body map[string]any
	lines := []any{ackLine("sid")}
	srv := subscribeServer(t, lines, &body)
	defer srv.Close()

	var since uint64 = 99
	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, _ := client.Subscribe(context.Background(), "", nil, &since)
	waitClose(t, evCh)

	topo, _ := body["topology"].(map[string]any)
	if topo == nil {
		t.Fatal("topology missing")
	}
	if got := topo["since_version"]; got != float64(99) {
		t.Errorf("since_version = %v, want 99", got)
	}
}

func TestAnchorNodeClient_Subscribe_Non2xxError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "UNAUTHORIZED",
			"status":  "nps.unauthorized",
			"message": "auth required",
		})
	}))
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	_, errCh := client.Subscribe(context.Background(), "", nil, nil)

	err := waitErr(t, errCh)
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	var ate *nwp.AnchorTopologyError
	if !errors.As(err, &ate) {
		t.Fatalf("expected *AnchorTopologyError, got %T", err)
	}
	if ate.NwpErrorCode != "UNAUTHORIZED" {
		t.Errorf("NwpErrorCode = %q, want UNAUTHORIZED", ate.NwpErrorCode)
	}
}

// ── URL and option tests ──────────────────────────────────────────────────────

func TestAnchorNodeClient_URLNormalisationTrailingSlash(t *testing.T) {
	var requestedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{defaultSnap()}})
	}))
	defer srv.Close()

	// Pass URL with trailing slash.
	client := nwp.NewAnchorNodeClient(srv.URL+"/", nwp.WithHTTPClient(srv.Client()))
	_, err := client.GetSnapshot(context.Background(), "", nil, 0, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestedPath != "/query" {
		t.Errorf("request path = %q, want /query (no double slash)", requestedPath)
	}
}

func TestAnchorNodeClient_PathPrefixPrepended(t *testing.T) {
	var requestedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{defaultSnap()}})
	}))
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(
		srv.URL,
		nwp.WithHTTPClient(srv.Client()),
		nwp.WithPathPrefix("/anchor"),
	)
	_, err := client.GetSnapshot(context.Background(), "", nil, 0, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestedPath != "/anchor/query" {
		t.Errorf("request path = %q, want /anchor/query", requestedPath)
	}
}

func TestAnchorNodeClient_PathPrefixTrailingSlashStripped(t *testing.T) {
	var requestedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{defaultSnap()}})
	}))
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(
		srv.URL,
		nwp.WithHTTPClient(srv.Client()),
		nwp.WithPathPrefix("/anchor/"),
	)
	_, err := client.GetSnapshot(context.Background(), "", nil, 0, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestedPath != "/anchor/query" {
		t.Errorf("request path = %q, want /anchor/query (no double slash from prefix)", requestedPath)
	}
}

// ── Payload field tests ───────────────────────────────────────────────────────

func TestAnchorNodeClient_MemberJoinedPayload(t *testing.T) {
	joined := map[string]any{
		"nid":             "node-joined",
		"node_roles":      []any{"router", "relay"},
		"activation_mode": "active",
		"tags":            []any{"region:us-west"},
		"joined_at":       "2026-01-01T00:00:00Z",
	}
	lines := []any{
		ackLine("sid"),
		eventLine(10, "member_joined", joined),
	}
	srv := subscribeServer(t, lines, nil)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, _ := client.Subscribe(context.Background(), "", nil, nil)
	events := drainEvents(t, evCh, 1)

	if len(events) == 0 {
		t.Fatal("no events received")
	}
	m := events[0].MemberJoined.Member
	if m.Nid != "node-joined" {
		t.Errorf("Nid = %q, want node-joined", m.Nid)
	}
	if len(m.NodeRoles) != 2 || m.NodeRoles[0] != "router" {
		t.Errorf("NodeRoles = %v", m.NodeRoles)
	}
	if m.ActivationMode != "active" {
		t.Errorf("ActivationMode = %q, want active", m.ActivationMode)
	}
	if len(m.Tags) != 1 || m.Tags[0] != "region:us-west" {
		t.Errorf("Tags = %v", m.Tags)
	}
	if m.JoinedAt == nil || *m.JoinedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("JoinedAt = %v", m.JoinedAt)
	}
}

func TestAnchorNodeClient_MemberLeftPayload(t *testing.T) {
	lines := []any{
		ackLine("sid"),
		eventLine(20, "member_left", map[string]any{"nid": "node-left-xyz"}),
	}
	srv := subscribeServer(t, lines, nil)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, _ := client.Subscribe(context.Background(), "", nil, nil)
	events := drainEvents(t, evCh, 1)

	if len(events) == 0 {
		t.Fatal("no events received")
	}
	ml := events[0].MemberLeft
	if ml == nil {
		t.Fatal("MemberLeft is nil")
	}
	if ml.Nid != "node-left-xyz" {
		t.Errorf("Nid = %q, want node-left-xyz", ml.Nid)
	}
	if events[0].Version != 20 {
		t.Errorf("Version = %d, want 20", events[0].Version)
	}
}

func TestAnchorNodeClient_MemberUpdatedPayload(t *testing.T) {
	lines := []any{
		ackLine("sid"),
		eventLine(30, "member_updated", map[string]any{
			"nid": "node-upd",
			"changes": map[string]any{
				"activation_mode": "standby",
				"node_roles":      []any{"observer"},
			},
		}),
	}
	srv := subscribeServer(t, lines, nil)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, _ := client.Subscribe(context.Background(), "", nil, nil)
	events := drainEvents(t, evCh, 1)

	if len(events) == 0 {
		t.Fatal("no events received")
	}
	mu := events[0].MemberUpdated
	if mu == nil {
		t.Fatal("MemberUpdated is nil")
	}
	if mu.Nid != "node-upd" {
		t.Errorf("Nid = %q, want node-upd", mu.Nid)
	}
	if mu.Changes.ActivationMode == nil || *mu.Changes.ActivationMode != "standby" {
		t.Errorf("Changes.ActivationMode = %v, want standby", mu.Changes.ActivationMode)
	}
	if len(mu.Changes.NodeRoles) != 1 || mu.Changes.NodeRoles[0] != "observer" {
		t.Errorf("Changes.NodeRoles = %v, want [observer]", mu.Changes.NodeRoles)
	}
}

func TestAnchorNodeClient_AnchorStatePayload(t *testing.T) {
	lines := []any{
		ackLine("sid"),
		eventLine(40, "anchor_state", map[string]any{
			"field":   "leader_nid",
			"details": map[string]any{"previous": "node-a", "current": "node-b"},
		}),
	}
	srv := subscribeServer(t, lines, nil)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, _ := client.Subscribe(context.Background(), "", nil, nil)
	events := drainEvents(t, evCh, 1)

	if len(events) == 0 {
		t.Fatal("no events received")
	}
	as := events[0].AnchorState
	if as == nil {
		t.Fatal("AnchorState is nil")
	}
	if as.Field != "leader_nid" {
		t.Errorf("Field = %q, want leader_nid", as.Field)
	}
	if len(as.Details) == 0 {
		t.Error("Details should not be empty")
	}
	// Verify Details is parseable JSON containing "previous".
	var d map[string]any
	if err := json.Unmarshal(as.Details, &d); err != nil {
		t.Errorf("Details not valid JSON: %v", err)
	}
	if d["previous"] != "node-a" {
		t.Errorf("Details.previous = %v, want node-a", d["previous"])
	}
}

func TestAnchorNodeClient_UnknownEventTypeSkipped_NextValidFollows(t *testing.T) {
	lines := []any{
		ackLine("sid"),
		// Unknown type — should be skipped.
		eventLine(1, "unknown_future_event", map[string]any{"data": "ignored"}),
		// Valid event follows.
		eventLine(2, "member_left", map[string]any{"nid": "node-after-unknown"}),
	}
	srv := subscribeServer(t, lines, nil)
	defer srv.Close()

	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, _ := client.Subscribe(context.Background(), "", nil, nil)

	events := drainEvents(t, evCh, 1)
	if len(events) != 1 {
		t.Fatalf("expected 1 event (unknown skipped), got %d", len(events))
	}
	if events[0].Kind != "member_left" {
		t.Errorf("Kind = %q, want member_left", events[0].Kind)
	}
	if events[0].MemberLeft.Nid != "node-after-unknown" {
		t.Errorf("MemberLeft.Nid = %q, want node-after-unknown", events[0].MemberLeft.Nid)
	}
}

func TestAnchorNodeClient_ContextCancellationStopsIteration(t *testing.T) {
	// Server streams infinitely: it keeps the connection open and sends no data after
	// the ack, so the client blocks on scanner.Scan() until ctx is cancelled.
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", 500)
			return
		}
		// Write the ack.
		ack, _ := json.Marshal(ackLine("sid"))
		_, _ = w.Write(ack)
		_, _ = w.Write([]byte("\n"))
		flusher.Flush()
		close(started)
		// Block until the client disconnects.
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	client := nwp.NewAnchorNodeClient(srv.URL, nwp.WithHTTPClient(srv.Client()))
	evCh, _ := client.Subscribe(ctx, "", nil, nil)

	// Wait for server to confirm it's serving.
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not start serving in time")
	}

	// Cancel and verify evCh closes.
	cancel()
	waitClose(t, evCh)
}
