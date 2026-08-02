// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nop

import (
	"errors"
	"sync"
)

// NPS-CR-0009 §3.4 — delegation re-resolution.
//
// There is no orchestrator type in this SDK, so the resolver is standalone. It
// carries NO NDP dependency: the cluster lookup is an injected function, and the
// composition root adapts an NDP AnnounceFrame to a ClusterAnchorInfo with
// (frame.NID, frame.ClusterEpoch ?? 1).

// ClusterAnchorInfo is the currently-believed active owner of a cluster.
type ClusterAnchorInfo struct {
	ActiveNid    string
	ClusterEpoch uint64
}

// ResolveClusterFunc looks a cluster up, e.g. via NDP highest-epoch resolution.
// A (zero, false) return means "no live owner"; an error means the lookup failed.
type ResolveClusterFunc func(clusterAnchor string) (ClusterAnchorInfo, bool, error)

// ClusterDelegationResolver maps a DelegateFrame onto the NID that should
// receive it, caching each cluster's active Anchor.
//
// Thread-safe by design: concurrent readers and writers are safe and the
// compare-then-set in OnAnchorFailover is atomic with respect to them.
type ClusterDelegationResolver struct {
	resolveCluster ResolveClusterFunc

	mu     sync.Mutex
	active map[string]ClusterAnchorInfo
}

// NewClusterDelegationResolver builds a resolver over an injected cluster lookup.
func NewClusterDelegationResolver(resolveCluster ResolveClusterFunc) (*ClusterDelegationResolver, error) {
	if resolveCluster == nil {
		return nil, errors.New("nop: resolveCluster is required")
	}
	return &ClusterDelegationResolver{
		resolveCluster: resolveCluster,
		active:         make(map[string]ClusterAnchorInfo),
	}, nil
}

// ResolveDelegateTarget returns the NID a DelegateFrame should be dispatched to.
//
// With no target_cluster_anchor the frame's target_agent_nid is returned and NO
// cluster lookup happens at all. Otherwise the cluster's current active Anchor
// is resolved.
//
// An empty return means "cannot resolve": the CALLER decides retry vs fail, and
// the resolver never raises for this.
//
// SSRF guard (§1.5): target_cluster_anchor MUST be a `urn:nps:...` NID, never a
// raw URL — a non-NID value is refused rather than dereferenced.
func (r *ClusterDelegationResolver) ResolveDelegateTarget(frame *DelegateFrame) (string, error) {
	if frame == nil {
		return "", errors.New("nop: frame is required")
	}
	if frame.TargetClusterAnchor == nil || *frame.TargetClusterAnchor == "" {
		return frame.TargetNID, nil
	}
	cluster := *frame.TargetClusterAnchor
	if !isNpsNid(cluster) {
		return "", errors.New("nop: target_cluster_anchor must be a urn:nps: NID, not a URL: " + cluster)
	}

	info, ok, err := r.ResolveActive(cluster)
	if err != nil || !ok {
		return "", err
	}
	return info.ActiveNid, nil
}

// ResolveActive returns the cached active Anchor for a cluster, performing the
// injected lookup only on a cache MISS. A negative result is NOT cached, so a
// cluster that has no live owner yet is re-checked on the next call.
func (r *ClusterDelegationResolver) ResolveActive(clusterAnchor string) (ClusterAnchorInfo, bool, error) {
	if clusterAnchor == "" {
		return ClusterAnchorInfo{}, false, errors.New("nop: clusterAnchor is required")
	}

	r.mu.Lock()
	if cached, ok := r.active[clusterAnchor]; ok {
		r.mu.Unlock()
		return cached, true, nil
	}
	r.mu.Unlock()

	// The lookup runs OUTSIDE the lock so a slow NDP round-trip cannot block
	// concurrent readers of other clusters.
	fresh, ok, err := r.resolveCluster(clusterAnchor)
	if err != nil || !ok {
		return ClusterAnchorInfo{}, false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// A concurrent OnAnchorFailover may have populated a NEWER entry while we
	// were looking up; never let a stale lookup result overwrite it.
	if cur, exists := r.active[clusterAnchor]; exists {
		if fresh.ClusterEpoch <= cur.ClusterEpoch {
			return cur, true, nil
		}
	}
	r.active[clusterAnchor] = fresh
	return fresh, true, nil
}

// OnAnchorFailover applies a received anchor_failover event, returning true iff
// it was accepted.
//
// MONOTONIC PER CLUSTER: an event whose cluster_epoch is <= the cached epoch is
// STALE and ignored. Equal is stale, not idempotent-accept — an equal epoch from
// a different claimant is exactly the split-brain case, and accepting it would
// let a replayed event flip the cluster back.
//
// The first observation of a cluster is accepted unconditionally.
func (r *ClusterDelegationResolver) OnAnchorFailover(clusterAnchor, successorNid string, clusterEpoch uint64) (bool, error) {
	if clusterAnchor == "" {
		return false, errors.New("nop: clusterAnchor is required")
	}
	if successorNid == "" {
		return false, errors.New("nop: successorNid is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.active[clusterAnchor]; ok {
		if clusterEpoch <= cur.ClusterEpoch {
			return false, nil // STALE
		}
	}
	r.active[clusterAnchor] = ClusterAnchorInfo{ActiveNid: successorNid, ClusterEpoch: clusterEpoch}
	return true, nil
}

// Invalidate drops a cluster's cache entry.
//
// This is the documented recovery path after a dispatch is rejected with
// NWP-ANCHOR-NOT-LEADER: drop the entry, take a fresh NDP lookup, retry. The
// cache is otherwise invalidated ONLY by a strictly-newer anchor_failover — no
// TTL is modelled.
func (r *ClusterDelegationResolver) Invalidate(clusterAnchor string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.active, clusterAnchor)
}

// isNpsNid is the §1.5 SSRF guard: a cluster target must be a NID, never a URL.
func isNpsNid(s string) bool {
	return len(s) > len("urn:nps:") && s[:len("urn:nps:")] == "urn:nps:"
}
