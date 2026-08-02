// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ndp

import "fmt"

// NPS-CR-0009 §3 — highest-epoch cluster resolution.
//
// .NET expresses this as a *default interface method* on INdpRegistry so every
// registry implementation inherits the identical rule. Go has no default
// interface methods, so the rule lives here as a free function over the
// narrowest possible interface (AnnounceLister). Any registry that can list its
// live AnnounceFrames gets the rule for free by passing itself to
// ResolveCluster — there is exactly one implementation of the election and no
// way for a registry to accidentally reimplement it.

// DefaultClusterEpoch is the value an absent `cluster_epoch` denotes (NDP §9).
// A single-Anchor cluster stays at 1 forever.
const DefaultClusterEpoch uint64 = 1

// ClusterEpochOrDefault coerces an absent cluster_epoch to 1. The coercion
// happens at COMPARISON time only — the stored frame keeps its nil.
func (f *AnnounceFrame) ClusterEpochOrDefault() uint64 {
	if f == nil || f.ClusterEpoch == nil {
		return DefaultClusterEpoch
	}
	return *f.ClusterEpoch
}

// ClusterSplitError is raised when a cluster has more than one live member at
// the top epoch. The registry MUST NOT resolve arbitrarily (NDP-CLUSTER-SPLIT).
type ClusterSplitError struct {
	ClusterAnchor string
	Epoch         uint64
}

// ErrorCode returns the NDP wire error code for this fault.
func (e *ClusterSplitError) ErrorCode() string { return ErrClusterSplit }

// NpsStatus returns the NPS status code this fault maps to.
func (e *ClusterSplitError) NpsStatus() string { return NdpErrorToNpsStatus[ErrClusterSplit] }

func (e *ClusterSplitError) Error() string {
	return fmt.Sprintf(
		"%s: cluster '%s' has multiple live active Anchors at epoch %d.",
		ErrClusterSplit, e.ClusterAnchor, e.Epoch)
}

// AnnounceLister is the registry surface the cluster election needs: the set of
// LIVE AnnounceFrames. Liveness (TTL purging, ttl==0 eviction) is the lister's
// job, exactly as it is for INdpRegistry.GetAll in the reference impl.
type AnnounceLister interface {
	GetAll() []*AnnounceFrame
}

// ResolveCluster returns the single live Anchor that currently owns clusterAnchor,
// i.e. the member with the strictly highest `cluster_epoch` (NPS-CR-0009 §3.1).
//
//   - an empty clusterAnchor, or a nil registry, resolves to (nil, nil);
//   - a cluster with no live members resolves to (nil, nil) — NOT an error;
//   - two or more live members tied at the top epoch return a *ClusterSplitError.
//     Two members that both OMIT cluster_epoch tie at 1 and therefore split — this
//     is deliberate, not an edge case to special-case away;
//   - membership is ORDINAL (exact byte) equality on cluster_anchor, and is NOT
//     filtered by node role: any live entry whose cluster_anchor matches
//     participates in the election.
func ResolveCluster(registry AnnounceLister, clusterAnchor string) (*AnnounceFrame, error) {
	if registry == nil || clusterAnchor == "" {
		return nil, nil
	}

	var members []*AnnounceFrame
	for _, f := range registry.GetAll() {
		if f != nil && f.ClusterAnchor == clusterAnchor {
			members = append(members, f)
		}
	}
	if len(members) == 0 {
		return nil, nil
	}

	top := members[0].ClusterEpochOrDefault()
	for _, f := range members[1:] {
		if e := f.ClusterEpochOrDefault(); e > top {
			top = e
		}
	}

	var leaders []*AnnounceFrame
	for _, f := range members {
		if f.ClusterEpochOrDefault() == top {
			leaders = append(leaders, f)
		}
	}
	if len(leaders) > 1 {
		return nil, &ClusterSplitError{ClusterAnchor: clusterAnchor, Epoch: top}
	}
	return leaders[0], nil
}

// ResolveCluster is the ergonomic method form of the free function above; it
// carries no rule of its own so the in-memory registry and any third-party
// registry provably agree.
func (r *InMemoryNdpRegistry) ResolveCluster(clusterAnchor string) (*AnnounceFrame, error) {
	return ResolveCluster(r, clusterAnchor)
}
