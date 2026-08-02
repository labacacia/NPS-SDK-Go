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

	"github.com/labacacia/NPS-sdk-go/nwp"
)

func epoch(v uint64) *uint64 { return &v }

// ── Brief A §5.2 — anchor_failover / anchor_quorum_lost wire shape ────────────

func TestAnchorFailover_EventCarriesSuccessorEpochReason(t *testing.T) {
	ev := nwp.NewAnchorFailoverEvent("urn:nps:node:x:anchor-b", 3, "active_lost", 0)

	if ev.Kind != "anchor_state" {
		t.Fatalf("event_type must be anchor_state, got %q", ev.Kind)
	}
	if ev.AnchorState == nil || ev.AnchorState.Field != "anchor_failover" {
		t.Fatalf("field must be anchor_failover, got %+v", ev.AnchorState)
	}

	var d map[string]any
	if err := json.Unmarshal(ev.AnchorState.Details, &d); err != nil {
		t.Fatal(err)
	}
	if d["successor_nid"] != "urn:nps:node:x:anchor-b" {
		t.Errorf("details.successor_nid = %v", d["successor_nid"])
	}
	if d["cluster_epoch"] != float64(3) {
		t.Errorf("details.cluster_epoch = %v (want 3)", d["cluster_epoch"])
	}
	if d["reason"] != "active_lost" {
		t.Errorf("details.reason = %v", d["reason"])
	}

	// Typed decode agrees with the raw wire keys.
	got, ok := nwp.DecodeAnchorFailover(ev.AnchorState)
	if !ok || got.SuccessorNid != "urn:nps:node:x:anchor-b" || got.ClusterEpoch != 3 || got.Reason != "active_lost" {
		t.Errorf("decode mismatch: %+v (ok=%v)", got, ok)
	}
}

func TestAnchorQuorumLost_EventCarriesCounts(t *testing.T) {
	ev := nwp.NewAnchorQuorumLostEvent(3, 1, 0)

	if ev.AnchorState == nil || ev.AnchorState.Field != "anchor_quorum_lost" {
		t.Fatalf("field must be anchor_quorum_lost, got %+v", ev.AnchorState)
	}
	var d map[string]any
	if err := json.Unmarshal(ev.AnchorState.Details, &d); err != nil {
		t.Fatal(err)
	}
	if d["quorum_size"] != float64(3) {
		t.Errorf("details.quorum_size = %v", d["quorum_size"])
	}
	if d["available"] != float64(1) {
		t.Errorf("details.available = %v", d["available"])
	}

	got, ok := nwp.DecodeAnchorQuorumLost(ev.AnchorState)
	if !ok || got.QuorumSize != 3 || got.Available != 1 {
		t.Errorf("decode mismatch: %+v (ok=%v)", got, ok)
	}
}

func TestAnchorFailover_ReasonDefaultsToPlanned(t *testing.T) {
	// Go has no default arguments: the convenience wrapper supplies "planned"/0.
	ev := nwp.NewAnchorFailoverEventDefaults("urn:nps:node:x:anchor-b", 2)

	got, ok := nwp.DecodeAnchorFailover(ev.AnchorState)
	if !ok {
		t.Fatal("decode failed")
	}
	if got.Reason != "planned" {
		t.Errorf("the defaulted reason MUST be \"planned\", got %q", got.Reason)
	}
	if ev.Version != 0 {
		t.Errorf("the defaulted version MUST be 0, got %d", ev.Version)
	}
}

func TestAnchorState_SubTypeTagConstants(t *testing.T) {
	if nwp.AnchorStateFieldVersionRebased != "version_rebased" ||
		nwp.AnchorStateFieldAnchorFailover != "anchor_failover" ||
		nwp.AnchorStateFieldAnchorQuorumLost != "anchor_quorum_lost" {
		t.Error("anchor_state sub-type tag wire values must not be renamed")
	}
}

// Ports SHOULD add: a JSON round-trip on the full envelope.
func TestAnchorFailover_FullEnvelopeRoundTrips(t *testing.T) {
	ev := nwp.NewAnchorFailoverEvent("urn:nps:node:x:anchor-b", 4, "planned", 12)

	envelope := map[string]any{
		"stream_id":  "s-1",
		"seq":        ev.Version,
		"event_type": ev.Kind,
		"payload":    map[string]any{"field": ev.AnchorState.Field, "details": ev.AnchorState.Details},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`"event_type":"anchor_state"`, `"field":"anchor_failover"`,
		`"successor_nid":"urn:nps:node:x:anchor-b"`, `"cluster_epoch":4`, `"reason":"planned"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("envelope missing %s: %s", want, s)
		}
	}
}

// ── Brief A §5.6 — the epoch fence (no .NET impl; built from §3.2) ────────────

func TestEpochGuard_StartsActiveAtEpochOne(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	if g.OwnEpoch() != 1 || !g.IsActive() || g.IsDegraded() {
		t.Fatalf("guard must start ACTIVE at epoch 1: epoch=%d active=%v degraded=%v",
			g.OwnEpoch(), g.IsActive(), g.IsDegraded())
	}
}

func TestEpochGuard_StandbyRejectsWritesWithNotLeader(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	// Fence it into STANDBY with a higher-epoch inbound frame.
	_ = g.OnInboundFrame(epoch(5), "urn:nps:node:x:anchor-b", false)
	if g.IsActive() {
		t.Fatal("a fenced Anchor must be STANDBY")
	}

	// The fence runs FIRST, so a write must arrive at or below our own epoch to
	// reach the leader check at all. (A higher-epoch write re-fences instead —
	// asserted below.)
	perr := g.OnInboundFrame(epoch(1), "urn:nps:node:x:anchor-b", true)
	if perr == nil {
		t.Fatal("a standby MUST reject topology writes")
	}
	if perr.NwpErrorCode != "NWP-ANCHOR-NOT-LEADER" {
		t.Errorf("wrong code: %s", perr.NwpErrorCode)
	}
	if perr.NpsStatus != "NPS-CLIENT-CONFLICT" {
		t.Errorf("wrong status: %s", perr.NpsStatus)
	}

	// Ordering: the fence takes precedence over the leader check for a write that
	// also supersedes us. Fencing does not advance own_epoch (§3.2 pseudocode), so
	// the standby keeps fencing superseding frames rather than silently adopting them.
	if perr := g.OnInboundFrame(epoch(5), "urn:nps:node:x:anchor-b", true); perr == nil ||
		perr.NwpErrorCode != "NWP-ANCHOR-EPOCH-FENCED" {
		t.Fatalf("the epoch fence must precede the leader check, got %v", perr)
	}
	if g.OwnEpoch() != 1 {
		t.Errorf("fencing must not advance own_epoch, got %d", g.OwnEpoch())
	}
}

func TestEpochGuard_FencedLeaderRejectsHigherEpochInboundFrame(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	var emitted []nwp.TopologyEvent
	closed := 0
	g.EmitEvent = func(ev nwp.TopologyEvent) { emitted = append(emitted, ev) }
	g.CloseStreams = func() { closed++ }

	perr := g.OnInboundFrame(epoch(2), "urn:nps:node:x:anchor-b", false)
	if perr == nil {
		t.Fatal("a strictly greater inbound epoch MUST fence the receiver")
	}
	if perr.NwpErrorCode != "NWP-ANCHOR-EPOCH-FENCED" {
		t.Errorf("wrong code: %s", perr.NwpErrorCode)
	}
	if perr.NpsStatus != "NPS-CLIENT-CONFLICT" {
		t.Errorf("wrong status: %s", perr.NpsStatus)
	}
	if g.IsActive() {
		t.Error("the fenced Anchor must drop to STANDBY")
	}
	if closed != 1 {
		t.Errorf("the fenced Anchor must close its topology streams once, got %d", closed)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected one terminal event, got %d", len(emitted))
	}
	d, ok := nwp.DecodeAnchorFailover(emitted[0].AnchorState)
	if !ok {
		t.Fatal("terminal event must be anchor_failover")
	}
	if d.SuccessorNid != "urn:nps:node:x:anchor-b" || d.ClusterEpoch != 2 || d.Reason != "active_lost" {
		t.Errorf("terminal anchor_failover payload: %+v", d)
	}
}

func TestEpochGuard_EqualOrLowerInboundEpochIsAccepted(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	if _, err := g.TakeOwnership(4, ""); err != nil {
		t.Fatal(err)
	}

	// The asymmetry: at the fence, <= own epoch is NOT an error.
	for _, in := range []*uint64{epoch(4), epoch(1), nil} {
		if perr := g.OnInboundFrame(in, "urn:nps:node:x:anchor-b", false); perr != nil {
			t.Errorf("inbound epoch %v must not fence (own=4): %s", in, perr.NwpErrorCode)
		}
	}
	if !g.IsActive() {
		t.Error("a non-superseding frame must leave the Anchor ACTIVE")
	}
}

func TestEpochGuard_ReadsSucceedOnAStandby(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	_ = g.OnInboundFrame(epoch(9), "urn:nps:node:x:anchor-b", false) // -> STANDBY

	// A subsequent read at or below our own epoch is served, stale, by the standby.
	if perr := g.OnInboundFrame(epoch(1), "urn:nps:node:x:anchor-b", false); perr != nil {
		t.Fatalf("a standby MAY serve stale reads: %s", perr.NwpErrorCode)
	}
	snap := &nwp.TopologySnapshot{Version: 7, AnchorNid: "urn:nps:node:x:anchor-a"}
	g.StampSnapshot(snap)
	if snap.ClusterEpoch == nil || *snap.ClusterEpoch != 1 {
		t.Errorf("a standby stamps its LAST-KNOWN epoch, got %v", snap.ClusterEpoch)
	}
}

func TestEpochGuard_QuorumLostDegradesTheActiveOwner(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	var emitted []nwp.TopologyEvent
	g.EmitEvent = func(ev nwp.TopologyEvent) { emitted = append(emitted, ev) }

	ev := g.OnQuorumLost(3, 1)
	if !g.IsDegraded() {
		t.Fatal("quorum loss must set read-only-degraded")
	}
	if d, ok := nwp.DecodeAnchorQuorumLost(ev.AnchorState); !ok || d.QuorumSize != 3 || d.Available != 1 {
		t.Errorf("emitted payload: %+v", d)
	}
	if len(emitted) != 1 {
		t.Errorf("expected one emitted event, got %d", len(emitted))
	}

	// The active owner is still ACTIVE, but writes are refused while degraded.
	if !g.IsActive() {
		t.Error("quorum loss must not by itself demote to STANDBY")
	}
	perr := g.OnInboundFrame(epoch(1), "urn:nps:node:x:anchor-b", true)
	if perr == nil || perr.NwpErrorCode != "NWP-ANCHOR-NOT-LEADER" {
		t.Fatalf("a quorum-lost owner must refuse writes with NWP-ANCHOR-NOT-LEADER, got %v", perr)
	}
	// ...reads still work.
	if perr := g.OnInboundFrame(epoch(1), "urn:nps:node:x:anchor-b", false); perr != nil {
		t.Errorf("a degraded owner must still serve reads: %s", perr.NwpErrorCode)
	}

	g.OnQuorumRestored()
	if perr := g.OnInboundFrame(epoch(1), "", true); perr != nil {
		t.Errorf("writes must resume after quorum is restored: %s", perr.NwpErrorCode)
	}
}

func TestEpochGuard_TakeOwnershipRequiresAStrictlyGreaterEpoch(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")

	ev, err := g.TakeOwnership(2, "active_lost")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := nwp.DecodeAnchorFailover(ev.AnchorState)
	if d.SuccessorNid != "urn:nps:node:x:anchor-a" || d.ClusterEpoch != 2 || d.Reason != "active_lost" {
		t.Errorf("ownership event: %+v", d)
	}
	if g.OwnEpoch() != 2 || !g.IsActive() {
		t.Error("taking ownership must promote to ACTIVE at the new epoch")
	}

	if _, err := g.TakeOwnership(2, ""); err == nil {
		t.Error("an equal epoch must be rejected — the epoch is a fencing token")
	}
	if _, err := g.TakeOwnership(1, ""); err == nil {
		t.Error("a lower epoch must be rejected")
	}
	if g.OwnEpoch() != 2 {
		t.Errorf("a rejected ownership claim must not mutate state, got %d", g.OwnEpoch())
	}
}

func TestEpochGuard_TakeOwnershipReasonDefaultsToPlanned(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	ev, err := g.TakeOwnership(3, "")
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := nwp.DecodeAnchorFailover(ev.AnchorState); d.Reason != "planned" {
		t.Errorf("reason must default to planned, got %q", d.Reason)
	}
}

func TestEpochGuard_ConcurrentUseIsRaceFree(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				_ = g.OnInboundFrame(epoch(1), "peer", j%2 == 0)
				_ = g.OwnEpoch()
				g.StampSnapshot(&nwp.TopologySnapshot{})
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// ── Server wiring: every snapshot response carries cluster_epoch ─────────────

func newGuardedAnchor(t *testing.T, g *nwp.AnchorEpochGuard) *nwp.AnchorNodeApp {
	t.Helper()
	return nwp.NewAnchorNodeApp(
		nwp.AnchorNodeOptions{
			NodeID:      "urn:nps:node:x:anchor-a",
			RequireAuth: new(bool), // false
		},
		nwp.AnchorNodeAppDeps{
			TopologyService: &nwp.InMemoryAnchorTopologyService{
				Nid:     "urn:nps:node:x:anchor-a",
				Version: 7,
			},
			EpochGuard: g,
		},
	)
}

func postJSON(app *nwp.AnchorNodeApp, path string, body map[string]any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	return w
}

func TestAnchorServer_SnapshotResponseCarriesClusterEpoch(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	if _, err := g.TakeOwnership(6, ""); err != nil {
		t.Fatal(err)
	}
	app := newGuardedAnchor(t, g)

	w := postJSON(app, "/query", map[string]any{
		"type":     "topology.snapshot",
		"topology": map[string]any{"scope": "cluster", "include": []string{"members"}, "depth": 1},
	})
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"cluster_epoch":6`) {
		t.Fatalf("every topology.snapshot response MUST carry cluster_epoch: %s", w.Body.String())
	}
}

func TestAnchorServer_SnapshotOmitsClusterEpochWithoutAGuard(t *testing.T) {
	app := nwp.NewAnchorNodeApp(
		nwp.AnchorNodeOptions{NodeID: "urn:nps:node:x:anchor-a", RequireAuth: new(bool)},
		nwp.AnchorNodeAppDeps{TopologyService: &nwp.InMemoryAnchorTopologyService{Nid: "urn:nps:node:x:anchor-a"}},
	)
	w := postJSON(app, "/query", map[string]any{
		"type":     "topology.snapshot",
		"topology": map[string]any{"scope": "cluster"},
	})
	if strings.Contains(w.Body.String(), "cluster_epoch") {
		t.Fatalf("a single-Anchor deployment with no guard must not start emitting cluster_epoch: %s", w.Body.String())
	}
}

func TestAnchorServer_HigherInboundEpochIsFencedWith409(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	app := newGuardedAnchor(t, g)

	w := postJSON(app, "/query", map[string]any{
		"type":          "topology.snapshot",
		"cluster_epoch": 9,
		"anchor_nid":    "urn:nps:node:x:anchor-b",
		"topology":      map[string]any{"scope": "cluster"},
	})
	if w.Code != 409 {
		t.Fatalf("NPS-CLIENT-CONFLICT must render as HTTP 409, got %d: %s", w.Code, w.Body.String())
	}
	var env map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env["error"] != "NWP-ANCHOR-EPOCH-FENCED" || env["status"] != "NPS-CLIENT-CONFLICT" {
		t.Fatalf("error envelope: %v", env)
	}
}

func TestAnchorServer_StandbyRejectsATopologyWriteWith409(t *testing.T) {
	g := nwp.NewAnchorEpochGuard("urn:nps:node:x:anchor-a")
	_ = g.OnInboundFrame(epoch(4), "urn:nps:node:x:anchor-b", false) // -> STANDBY

	called := false
	app := nwp.NewAnchorNodeApp(
		nwp.AnchorNodeOptions{
			NodeID:      "urn:nps:node:x:anchor-a",
			RequireAuth: new(bool),
			Actions: map[string]nwp.AnchorActionSpec{
				"topology.rebalance": {TopologyWrite: true},
				"echo":               {},
			},
		},
		nwp.AnchorNodeAppDeps{
			EpochGuard: g,
			InvokeHandler: func(_ context.Context, _ string, _ json.RawMessage, _ nwp.InvokeContext) (any, error) {
				called = true
				return map[string]any{"ok": true}, nil
			},
		},
	)

	w := postJSON(app, "/invoke", map[string]any{"action_id": "topology.rebalance", "params": map[string]any{}})
	if w.Code != 409 {
		t.Fatalf("a standby must refuse a topology write with 409, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "NWP-ANCHOR-NOT-LEADER") {
		t.Errorf("expected NWP-ANCHOR-NOT-LEADER: %s", w.Body.String())
	}
	if called {
		t.Error("the handler must not run for a refused write")
	}

	// A non-write action on the same standby still runs.
	w = postJSON(app, "/invoke", map[string]any{"action_id": "echo", "params": map[string]any{}})
	if w.Code != 200 {
		t.Fatalf("reads/non-topology actions must still be served by a standby: %d %s", w.Code, w.Body.String())
	}
}
