// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ndp_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/ndp"
)

// ── Fixtures (brief A §5.1) ───────────────────────────────────────────────────

const testClusterNid = "urn:nps:cluster:api.test:main"

func u64(v uint64) *uint64 { return &v }

// anchorMember builds an Anchor AnnounceFrame in the cluster fixture shape.
// Pass epoch == nil to OMIT cluster_epoch entirely.
func anchorMember(name string, epoch *uint64) *ndp.AnnounceFrame {
	nodeType := "anchor"
	return &ndp.AnnounceFrame{
		NID:           "urn:nps:node:api.test:" + name,
		Addresses:     []map[string]any{{"host": "10.0.0.1", "port": uint64(17433), "protocol": "nwp"}},
		Caps:          []string{"topology.read"},
		TTL:           3600,
		Timestamp:     "2026-07-05T00:00:00Z",
		Signature:     "ed25519:placeholder",
		NodeType:      &nodeType,
		NodeRoles:     []string{"anchor"},
		ClusterAnchor: testClusterNid,
		ClusterEpoch:  epoch,
	}
}

func clusterRegistry(members ...*ndp.AnnounceFrame) *ndp.InMemoryNdpRegistry {
	r := ndp.NewInMemoryNdpRegistry()
	for _, m := range members {
		r.Announce(m)
	}
	return r
}

// ── §5.1 NDP cluster resolution ───────────────────────────────────────────────

func TestResolveCluster_ResolvesTheHighestEpochActiveAnchor(t *testing.T) {
	r := clusterRegistry(anchorMember("anchor-a", u64(1)), anchorMember("anchor-b", u64(3)))

	got, err := ndp.ResolveCluster(r, testClusterNid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a resolved Anchor, got nil")
	}
	if got.NID != "urn:nps:node:api.test:anchor-b" {
		t.Errorf("wrong winner: %s", got.NID)
	}
	if got.ClusterEpochOrDefault() != 3 {
		t.Errorf("wrong epoch: %d", got.ClusterEpochOrDefault())
	}
}

func TestResolveCluster_AbsentEpochIsTreatedAsOne(t *testing.T) {
	r := clusterRegistry(anchorMember("anchor-a", nil))

	got, err := ndp.ResolveCluster(r, testClusterNid)
	if err != nil {
		t.Fatalf("absent cluster_epoch must not be an error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a resolved Anchor")
	}
	if got.ClusterEpochOrDefault() != 1 {
		t.Errorf("absent epoch must compare as 1, got %d", got.ClusterEpochOrDefault())
	}
	if got.ClusterEpoch != nil {
		t.Error("the STORED frame must keep its nil cluster_epoch — coercion is comparison-time only")
	}
}

func TestResolveCluster_SplitBrainAtTheTopEpochThrows(t *testing.T) {
	r := clusterRegistry(anchorMember("anchor-a", u64(2)), anchorMember("anchor-b", u64(2)))

	got, err := ndp.ResolveCluster(r, testClusterNid)
	if got != nil {
		t.Errorf("split-brain must not resolve, got %s", got.NID)
	}
	var split *ndp.ClusterSplitError
	if !errors.As(err, &split) {
		t.Fatalf("expected *ClusterSplitError, got %T (%v)", err, err)
	}
	if split.ErrorCode() != "NDP-CLUSTER-SPLIT" {
		t.Errorf("wrong error code: %s", split.ErrorCode())
	}
	if split.Epoch != 2 {
		t.Errorf("wrong epoch: %d", split.Epoch)
	}
	if split.ClusterAnchor != testClusterNid {
		t.Errorf("wrong cluster: %s", split.ClusterAnchor)
	}
	if split.NpsStatus() != "NPS-CLIENT-CONFLICT" {
		t.Errorf("NDP-CLUSTER-SPLIT must map to NPS-CLIENT-CONFLICT, got %s", split.NpsStatus())
	}
	if !strings.Contains(split.Error(), "multiple live active Anchors at epoch 2") {
		t.Errorf("message shape: %s", split.Error())
	}
}

func TestResolveCluster_NoLiveMembersResolvesToNil(t *testing.T) {
	got, err := ndp.ResolveCluster(ndp.NewInMemoryNdpRegistry(), testClusterNid)
	if err != nil {
		t.Fatalf("an empty cluster must not raise: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %s", got.NID)
	}
}

// Ports SHOULD add (brief A §5.1 tail):

func TestResolveCluster_TwoMembersBothOmittingEpochSplit(t *testing.T) {
	r := clusterRegistry(anchorMember("anchor-a", nil), anchorMember("anchor-b", nil))

	_, err := ndp.ResolveCluster(r, testClusterNid)
	var split *ndp.ClusterSplitError
	if !errors.As(err, &split) {
		t.Fatalf("two absent epochs both coerce to 1 and MUST split; got %v", err)
	}
	if split.Epoch != 1 {
		t.Errorf("split epoch must be the coerced 1, got %d", split.Epoch)
	}
}

func TestResolveCluster_TtlExpiredMemberIsExcludedFromTheElection(t *testing.T) {
	now := time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)
	r := ndp.NewInMemoryNdpRegistry()
	r.Clock = func() time.Time { return now }

	winner := anchorMember("anchor-b", u64(5))
	winner.TTL = 10 // expires first
	r.Announce(winner)
	r.Announce(anchorMember("anchor-a", u64(1)))

	// Before expiry the high-epoch member wins.
	got, err := ndp.ResolveCluster(r, testClusterNid)
	if err != nil || got == nil || got.NID != "urn:nps:node:api.test:anchor-b" {
		t.Fatalf("pre-expiry winner wrong: %v / %v", got, err)
	}

	// After its TTL elapses it is purged and the election changes.
	now = now.Add(30 * time.Second)
	got, err = ndp.ResolveCluster(r, testClusterNid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.NID != "urn:nps:node:api.test:anchor-a" {
		t.Fatalf("a TTL-expired member must not participate; got %v", got)
	}
}

func TestResolveCluster_TtlZeroAnnounceEvictsAndChangesTheWinner(t *testing.T) {
	r := clusterRegistry(anchorMember("anchor-a", u64(1)), anchorMember("anchor-b", u64(3)))

	// Orderly shutdown of the current owner: ttl == 0 evicts immediately.
	shutdown := anchorMember("anchor-b", u64(3))
	shutdown.TTL = 0
	r.Announce(shutdown)

	got, err := ndp.ResolveCluster(r, testClusterNid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.NID != "urn:nps:node:api.test:anchor-a" {
		t.Fatalf("ttl=0 must evict the owner and hand the cluster to anchor-a; got %v", got)
	}
}

func TestResolveCluster_IgnoresOtherClustersAndEmptyAnchor(t *testing.T) {
	other := anchorMember("anchor-z", u64(9))
	other.ClusterAnchor = "urn:nps:cluster:api.test:other"
	r := clusterRegistry(anchorMember("anchor-a", u64(1)), other)

	got, err := ndp.ResolveCluster(r, testClusterNid)
	if err != nil || got == nil || got.NID != "urn:nps:node:api.test:anchor-a" {
		t.Fatalf("cluster membership must be ordinal on cluster_anchor; got %v / %v", got, err)
	}

	if got, err := ndp.ResolveCluster(r, ""); got != nil || err != nil {
		t.Errorf("an empty cluster_anchor resolves to (nil, nil); got %v / %v", got, err)
	}
}

func TestResolveCluster_DoesNotFilterByRole(t *testing.T) {
	// A non-Anchor live entry carrying the same cluster_anchor still participates
	// (the reference impl deliberately does not filter by role).
	memory := anchorMember("memory-1", u64(4))
	nt := "memory"
	memory.NodeType = &nt
	memory.NodeRoles = []string{"memory"}
	r := clusterRegistry(anchorMember("anchor-a", u64(2)), memory)

	got, err := ndp.ResolveCluster(r, testClusterNid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.NID != "urn:nps:node:api.test:memory-1" {
		t.Fatalf("role filtering must NOT be applied; got %v", got)
	}
}

func TestResolveCluster_MethodFormMatchesTheFreeFunction(t *testing.T) {
	r := clusterRegistry(anchorMember("anchor-a", u64(1)), anchorMember("anchor-b", u64(3)))
	viaMethod, err1 := r.ResolveCluster(testClusterNid)
	viaFunc, err2 := ndp.ResolveCluster(r, testClusterNid)
	if err1 != nil || err2 != nil {
		t.Fatalf("errors: %v / %v", err1, err2)
	}
	if viaMethod != viaFunc {
		t.Error("the method form must delegate to the free function, not reimplement the rule")
	}
}

// ── §5.5 signature canonical-form regression ──────────────────────────────────

// preCr0009Canonical is the canonical JSON of the fixture frame as produced
// BEFORE cluster_epoch / bridge_inbound_protocols existed. Byte-identity with
// this literal is what keeps already-signed announcements verifying.
const preCr0009Canonical = `{"activation_mode":"resident","addresses":[{"host":"10.0.0.1","port":17433,` +
	`"protocol":"nwp"}],"capabilities":["topology.read"],"cluster_anchor":"urn:nps:cluster:api.test:main",` +
	`"heartbeat_interval_ms":60000,"nid":"urn:nps:node:api.test:anchor-a","node_roles":["anchor"],` +
	`"node_type":"anchor","timestamp":"2026-07-05T00:00:00Z","ttl":3600}`

func canonicalOf(t *testing.T, f *ndp.AnnounceFrame) string {
	t.Helper()
	// encoding/json sorts map keys ordinal-ascending, recursively — the same
	// canonicalization the signing path (nip.canonicalJSON) applies.
	b, err := json.Marshal(f.UnsignedDict())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func canonicalFixture() *ndp.AnnounceFrame {
	f := anchorMember("anchor-a", nil)
	f.HeartbeatIntervalMs = 60_000
	f.ActivationMode = "resident"
	return f
}

func TestAnnounceCanonical_WithClusterEpochContainsIt(t *testing.T) {
	f := canonicalFixture()
	f.ClusterEpoch = u64(3)

	got := canonicalOf(t, f)
	if !strings.Contains(got, `"cluster_epoch":3`) {
		t.Fatalf("cluster_epoch MUST be inside the signed canonical form: %s", got)
	}
}

func TestAnnounceCanonical_WithoutClusterEpochIsByteIdenticalToPreCr0009(t *testing.T) {
	got := canonicalOf(t, canonicalFixture())

	if strings.Contains(got, "cluster_epoch") {
		t.Fatalf("a nil cluster_epoch MUST be omitted entirely (never null, never 0): %s", got)
	}
	if got != preCr0009Canonical {
		t.Fatalf("canonical bytes changed — already-signed announcements would stop verifying.\n got: %s\nwant: %s",
			got, preCr0009Canonical)
	}
}

func TestAnnounceCanonical_WithoutBridgeInboundProtocolsIsUnchanged(t *testing.T) {
	f := canonicalFixture()
	f.BridgeInboundProtocols = nil

	if got := canonicalOf(t, f); got != preCr0009Canonical {
		t.Fatalf("an unset bridge_inbound_protocols must not alter the canonical bytes:\n%s", got)
	}
}

func TestAnnounceCanonical_BridgeInboundProtocolsIsSignedWhenPresent(t *testing.T) {
	f := canonicalFixture()
	f.BridgeInboundProtocols = []string{"mcp", "a2a"}

	got := canonicalOf(t, f)
	if !strings.Contains(got, `"bridge_inbound_protocols":["mcp","a2a"]`) {
		t.Fatalf("bridge_inbound_protocols MUST be inside the signed canonical form: %s", got)
	}
}

func TestAnnounceCanonical_ExcludesWireOnlyFields(t *testing.T) {
	f := canonicalFixture()
	f.ClusterEpoch = u64(2)
	f.Health = "degraded"
	f.LastSeen = "2026-07-05T00:00:01Z"

	got := canonicalOf(t, f)
	for _, k := range []string{"signature", "health", "last_seen", "frame"} {
		if strings.Contains(got, `"`+k+`"`) {
			t.Errorf("canonical form must exclude %q: %s", k, got)
		}
	}
	// ...but it must still carry the CR-0009 / CR-0010 fields.
	if !strings.Contains(got, `"cluster_epoch":2`) {
		t.Errorf("cluster_epoch went missing: %s", got)
	}
}

// ── Wire round-trip ───────────────────────────────────────────────────────────

func TestAnnounceFrame_ClusterEpochRoundTrips(t *testing.T) {
	f := anchorMember("anchor-b", u64(7))
	f.BridgeInboundProtocols = []string{"mcp"}

	// Through a real JSON hop so float64 coercion is exercised.
	raw, _ := json.Marshal(f.ToDict())
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got := ndp.AnnounceFrameFromDict(back)

	if got.ClusterEpoch == nil || *got.ClusterEpoch != 7 {
		t.Fatalf("cluster_epoch did not round-trip: %v", got.ClusterEpoch)
	}
	if len(got.BridgeInboundProtocols) != 1 || got.BridgeInboundProtocols[0] != "mcp" {
		t.Fatalf("bridge_inbound_protocols did not round-trip: %v", got.BridgeInboundProtocols)
	}
}

func TestAnnounceFrame_AbsentClusterEpochParsesAsNil(t *testing.T) {
	got := ndp.AnnounceFrameFromDict(map[string]any{"nid": "urn:nps:node:api.test:x", "ttl": float64(60)})
	if got.ClusterEpoch != nil {
		t.Fatalf("absent cluster_epoch must parse to nil, got %d", *got.ClusterEpoch)
	}
	if got.ClusterEpochOrDefault() != 1 {
		t.Fatalf("absent cluster_epoch must COMPARE as 1, got %d", got.ClusterEpochOrDefault())
	}
	if len(got.BridgeInboundProtocols) != 0 {
		t.Fatalf("an absent bridge_inbound_protocols must read as empty, got %v", got.BridgeInboundProtocols)
	}
}
