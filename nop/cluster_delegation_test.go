// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nop_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/labacacia/NPS-sdk-go/nop"
)

// ── Fixtures (brief A §5.4) ───────────────────────────────────────────────────

const delegationCluster = "urn:nps:cluster:x:main"

func delegateFrame(clusterAnchor string) *nop.DelegateFrame {
	f := &nop.DelegateFrame{
		TaskID:    "t1",
		SubtaskID: "s1",
		Action:    "do",
		TargetNID: "urn:nps:agent:x:w1",
	}
	if clusterAnchor != "" {
		f.TargetClusterAnchor = &clusterAnchor
	}
	return f
}

// lookupQueue yields a scripted sequence of resolutions, counting invocations.
type lookupQueue struct {
	results []nop.ClusterAnchorInfo
	calls   int
	fail    bool
}

func (q *lookupQueue) resolve(string) (nop.ClusterAnchorInfo, bool, error) {
	if q.fail {
		q.calls++
		return nop.ClusterAnchorInfo{}, false, errors.New("the NDP lookup must not be invoked")
	}
	i := q.calls
	q.calls++
	if i >= len(q.results) {
		i = len(q.results) - 1
	}
	if i < 0 {
		return nop.ClusterAnchorInfo{}, false, nil
	}
	return q.results[i], true, nil
}

func newResolver(t *testing.T, q *lookupQueue) *nop.ClusterDelegationResolver {
	t.Helper()
	r, err := nop.NewClusterDelegationResolver(q.resolve)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ── §5.4 scenarios ────────────────────────────────────────────────────────────

func TestClusterDelegation_WithoutClusterTargetUsesAgentNid(t *testing.T) {
	q := &lookupQueue{fail: true} // any invocation is a failure
	r := newResolver(t, q)

	got, err := r.ResolveDelegateTarget(delegateFrame(""))
	if err != nil {
		t.Fatal(err)
	}
	if got != "urn:nps:agent:x:w1" {
		t.Errorf("target = %s", got)
	}
	if q.calls != 0 {
		t.Error("with no target_cluster_anchor there must be NO NDP lookup at all")
	}
}

func TestClusterDelegation_ClusterTargetResolvesToActiveAnchorAndCaches(t *testing.T) {
	q := &lookupQueue{results: []nop.ClusterAnchorInfo{{ActiveNid: "urn:nps:node:x:anchor-a", ClusterEpoch: 1}}}
	r := newResolver(t, q)

	for i := 0; i < 2; i++ {
		got, err := r.ResolveDelegateTarget(delegateFrame(delegationCluster))
		if err != nil {
			t.Fatal(err)
		}
		if got != "urn:nps:node:x:anchor-a" {
			t.Errorf("resolution %d = %s", i, got)
		}
	}
	if q.calls != 1 {
		t.Errorf("a cache hit must perform NO lookup; expected 1 invocation, got %d", q.calls)
	}
}

func TestClusterDelegation_FailoverEventRedirectsSubsequentDelegations(t *testing.T) {
	q := &lookupQueue{results: []nop.ClusterAnchorInfo{{ActiveNid: "urn:nps:node:x:anchor-a", ClusterEpoch: 1}}}
	r := newResolver(t, q)

	if _, err := r.ResolveDelegateTarget(delegateFrame(delegationCluster)); err != nil {
		t.Fatal(err)
	}

	accepted, err := r.OnAnchorFailover(delegationCluster, "urn:nps:node:x:anchor-b", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !accepted {
		t.Fatal("a strictly-newer anchor_failover must be accepted")
	}

	got, _ := r.ResolveDelegateTarget(delegateFrame(delegationCluster))
	if got != "urn:nps:node:x:anchor-b" {
		t.Errorf("subsequent delegations must go to the successor, got %s", got)
	}
	if q.calls != 1 {
		t.Errorf("the failover event updates the cache in place — no extra lookup; got %d", q.calls)
	}
}

func TestClusterDelegation_StaleFailoverEventIsIgnored(t *testing.T) {
	q := &lookupQueue{results: []nop.ClusterAnchorInfo{{ActiveNid: "urn:nps:node:x:anchor-b", ClusterEpoch: 3}}}
	r := newResolver(t, q)
	if _, err := r.ResolveDelegateTarget(delegateFrame(delegationCluster)); err != nil {
		t.Fatal(err)
	}

	// EQUAL is stale, not idempotent-accept.
	if accepted, _ := r.OnAnchorFailover(delegationCluster, "urn:nps:node:x:anchor-c", 3); accepted {
		t.Error("an EQUAL cluster_epoch is STALE and must be rejected")
	}
	if accepted, _ := r.OnAnchorFailover(delegationCluster, "urn:nps:node:x:anchor-c", 2); accepted {
		t.Error("a LOWER cluster_epoch must be rejected")
	}

	got, _ := r.ResolveDelegateTarget(delegateFrame(delegationCluster))
	if got != "urn:nps:node:x:anchor-b" {
		t.Errorf("the active Anchor must be unchanged, got %s", got)
	}
}

func TestClusterDelegation_InvalidateForcesAFreshLookup(t *testing.T) {
	q := &lookupQueue{results: []nop.ClusterAnchorInfo{
		{ActiveNid: "urn:nps:node:x:anchor-a", ClusterEpoch: 1},
		{ActiveNid: "urn:nps:node:x:anchor-b", ClusterEpoch: 2},
	}}
	r := newResolver(t, q)

	if got, _ := r.ResolveDelegateTarget(delegateFrame(delegationCluster)); got != "urn:nps:node:x:anchor-a" {
		t.Fatalf("first resolution = %s", got)
	}

	// The documented recovery path after an NWP-ANCHOR-NOT-LEADER rejection.
	r.Invalidate(delegationCluster)

	if got, _ := r.ResolveDelegateTarget(delegateFrame(delegationCluster)); got != "urn:nps:node:x:anchor-b" {
		t.Fatalf("after Invalidate the next resolution must be fresh, got %s", got)
	}
	if q.calls != 2 {
		t.Errorf("expected exactly 2 lookups, got %d", q.calls)
	}
}

// ── Additional contract details ──────────────────────────────────────────────

func TestClusterDelegation_FirstObservationIsAcceptedUnconditionally(t *testing.T) {
	q := &lookupQueue{fail: true}
	r := newResolver(t, q)

	if accepted, _ := r.OnAnchorFailover(delegationCluster, "urn:nps:node:x:anchor-a", 1); !accepted {
		t.Fatal("the first observation of a cluster is accepted unconditionally")
	}
	got, err := r.ResolveDelegateTarget(delegateFrame(delegationCluster))
	if err != nil {
		t.Fatal(err)
	}
	if got != "urn:nps:node:x:anchor-a" {
		t.Errorf("target = %s", got)
	}
	if q.calls != 0 {
		t.Error("the failover-populated entry must serve without an NDP lookup")
	}
}

func TestClusterDelegation_NegativeResultsAreNotCached(t *testing.T) {
	calls := 0
	r, err := nop.NewClusterDelegationResolver(func(string) (nop.ClusterAnchorInfo, bool, error) {
		calls++
		if calls < 3 {
			return nop.ClusterAnchorInfo{}, false, nil // no live owner
		}
		return nop.ClusterAnchorInfo{ActiveNid: "urn:nps:node:x:anchor-a", ClusterEpoch: 1}, true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		got, err := r.ResolveDelegateTarget(delegateFrame(delegationCluster))
		if err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Errorf("an unresolvable cluster returns empty, got %s", got)
		}
	}
	if got, _ := r.ResolveDelegateTarget(delegateFrame(delegationCluster)); got != "urn:nps:node:x:anchor-a" {
		t.Errorf("a negative result must not be cached, got %s", got)
	}
	if calls != 3 {
		t.Errorf("expected 3 lookups (negatives uncached), got %d", calls)
	}
}

func TestClusterDelegation_SsrfGuardRejectsARawUrl(t *testing.T) {
	q := &lookupQueue{fail: true}
	r := newResolver(t, q)

	f := delegateFrame("http://169.254.169.254/latest/meta-data/")
	if _, err := r.ResolveDelegateTarget(f); err == nil {
		t.Fatal("target_cluster_anchor MUST be a urn:nps: NID, never a raw URL")
	}
	if q.calls != 0 {
		t.Error("a rejected target must never be dereferenced")
	}
}

func TestClusterDelegation_ArgumentValidation(t *testing.T) {
	if _, err := nop.NewClusterDelegationResolver(nil); err == nil {
		t.Error("a nil resolveCluster must be rejected")
	}
	r := newResolver(t, &lookupQueue{fail: true})

	if _, err := r.ResolveDelegateTarget(nil); err == nil {
		t.Error("a nil frame must be rejected")
	}
	if _, _, err := r.ResolveActive(""); err == nil {
		t.Error("an empty clusterAnchor must be rejected")
	}
	if _, err := r.OnAnchorFailover("", "n", 1); err == nil {
		t.Error("an empty clusterAnchor must be rejected")
	}
	if _, err := r.OnAnchorFailover("c", "", 1); err == nil {
		t.Error("an empty successorNid must be rejected")
	}
}

func TestClusterDelegation_ConcurrentUseIsRaceFree(t *testing.T) {
	var mu sync.Mutex
	epoch := uint64(0)
	r, err := nop.NewClusterDelegationResolver(func(string) (nop.ClusterAnchorInfo, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		epoch++
		return nop.ClusterAnchorInfo{ActiveNid: "urn:nps:node:x:anchor-a", ClusterEpoch: epoch}, true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = r.ResolveDelegateTarget(delegateFrame(delegationCluster))
				_, _ = r.OnAnchorFailover(delegationCluster, "urn:nps:node:x:anchor-b", uint64(j))
				if j%50 == 0 {
					r.Invalidate(delegationCluster)
				}
			}
		}(i)
	}
	wg.Wait()
}

// The composition-root adaptation: AnnounceFrame -> ClusterAnchorInfo with
// (frame.NID, frame.ClusterEpoch ?? 1). Modelled here without importing NDP, so
// NOP keeps carrying no NDP dependency.
func TestClusterDelegation_ResolverCarriesNoNdpDependency(t *testing.T) {
	adapt := func(nid string, clusterEpoch *uint64) nop.ClusterAnchorInfo {
		e := uint64(1)
		if clusterEpoch != nil {
			e = *clusterEpoch
		}
		return nop.ClusterAnchorInfo{ActiveNid: nid, ClusterEpoch: e}
	}
	r, err := nop.NewClusterDelegationResolver(func(string) (nop.ClusterAnchorInfo, bool, error) {
		return adapt("urn:nps:node:x:anchor-a", nil), true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	info, ok, err := r.ResolveActive(delegationCluster)
	if err != nil || !ok {
		t.Fatalf("%v / %v", ok, err)
	}
	if info.ClusterEpoch != 1 {
		t.Errorf("an absent cluster_epoch adapts to 1, got %d", info.ClusterEpoch)
	}
}
