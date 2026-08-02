// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"fmt"
	"sync"

	"github.com/labacacia/NPS-sdk-go/core"
)

// AnchorEpochGuard implements the CR-0009 §3.2 epoch fence and leader check.
//
// There is NO .NET implementation of this — the reference only declares the two
// error constants. This is built from the spec (NPS-CR-0009 §4, NWP v0.18 §12.2).
//
// Intra-cluster consensus (Raft/Paxos/a lease store) is explicitly out of scope:
// only the observable wire contract below is normative. The guard models the
// observable half — own epoch, ACTIVE/STANDBY role, read-only-degraded flag —
// and leaves *how* ownership is decided to the deployment, which drives it via
// TakeOwnership / OnQuorumLost.
//
// The zero value is not usable; construct with NewAnchorEpochGuard.
type AnchorEpochGuard struct {
	mu        sync.Mutex
	anchorNid string
	ownEpoch  uint64
	standby   bool
	degraded  bool

	// EmitEvent, when set, receives every TopologyEvent the guard generates
	// (the terminal anchor_failover on self-fencing, anchor_quorum_lost, and the
	// anchor_failover published on taking ownership). Set it before first use.
	EmitEvent func(TopologyEvent)
	// CloseStreams, when set, is invoked once when the guard self-fences, so the
	// host can close all topology streams as §3.2 requires. Set it before first use.
	CloseStreams func()
}

// NewAnchorEpochGuard creates a guard for anchorNid that starts ACTIVE at epoch 1
// — the single-Anchor steady state, which never changes without an explicit
// TakeOwnership.
func NewAnchorEpochGuard(anchorNid string) *AnchorEpochGuard {
	return &AnchorEpochGuard{anchorNid: anchorNid, ownEpoch: 1}
}

// AnchorNid returns the NID this guard fences for.
func (g *AnchorEpochGuard) AnchorNid() string { return g.anchorNid }

// OwnEpoch returns the epoch this Anchor currently claims.
func (g *AnchorEpochGuard) OwnEpoch() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ownEpoch
}

// IsActive reports whether this Anchor is the cluster's active owner.
func (g *AnchorEpochGuard) IsActive() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.standby
}

// IsDegraded reports whether this Anchor is in read-only-degraded (quorum-lost) state.
func (g *AnchorEpochGuard) IsDegraded() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.degraded
}

// OnInboundFrame applies, in order:
//
//	(a) the EPOCH FENCE — for ANY inbound frame, read or write. An inbound
//	    cluster_epoch STRICTLY GREATER than our own means we are a superseded
//	    leader: we drop to STANDBY, emit a terminal anchor_failover naming the
//	    sender as successor with reason "active_lost", close all topology
//	    streams, and fail with NWP-ANCHOR-EPOCH-FENCED.
//	    An inbound epoch <= our own is NOT an error.
//	(b) the LEADER CHECK — writes only. A topology write that arrives at a
//	    standby, or at the active owner while read-only-degraded, fails with
//	    NWP-ANCHOR-NOT-LEADER.
//	(c) reads are always allowed; a standby MAY serve stale reads stamped with
//	    its last-known epoch (see StampSnapshot).
//
// inboundEpoch is nil when the frame omits cluster_epoch, which reads as 1.
// A nil returned error means "proceed".
func (g *AnchorEpochGuard) OnInboundFrame(inboundEpoch *uint64, senderAnchorNid string, isTopologyWrite bool) *TopologyProtocolError {
	inbound := uint64(1)
	if inboundEpoch != nil {
		inbound = *inboundEpoch
	}

	g.mu.Lock()
	// (a) epoch fence.
	if inbound > g.ownEpoch {
		own := g.ownEpoch
		fencedNow := !g.standby
		g.standby = true
		emit, closeStreams := g.EmitEvent, g.CloseStreams
		g.mu.Unlock()

		if fencedNow {
			if emit != nil {
				emit(NewAnchorFailoverEvent(senderAnchorNid, inbound, AnchorFailoverReasonActiveLost, 0))
			}
			if closeStreams != nil {
				closeStreams()
			}
		}
		return &TopologyProtocolError{
			NwpErrorCode: ErrAnchorEpochFenced,
			NpsStatus:    core.NpsClientConflict,
			Message: fmt.Sprintf(
				"%s: inbound cluster_epoch %d supersedes this Anchor's epoch %d; it is no longer the cluster owner.",
				ErrAnchorEpochFenced, inbound, own),
		}
	}

	// (b) leader check — writes only.
	if isTopologyWrite && (g.standby || g.degraded) {
		reason := "this Anchor is a standby"
		if !g.standby {
			reason = "this Anchor has lost quorum and is read-only-degraded"
		}
		g.mu.Unlock()
		return &TopologyProtocolError{
			NwpErrorCode: ErrAnchorNotLeader,
			NpsStatus:    core.NpsClientConflict,
			Message: fmt.Sprintf("%s: topology writes are accepted only by the active cluster owner — %s.",
				ErrAnchorNotLeader, reason),
		}
	}

	// (c) proceed.
	g.mu.Unlock()
	return nil
}

// StampSnapshot stamps the guard's current epoch onto a topology response, as
// NWP §12.2 requires of every topology.snapshot / topology.stream response. A
// standby stamps its last-known epoch, which is what makes its reads visibly stale.
// A nil guard is a no-op, so a single-Anchor deployment that configures none
// keeps omitting cluster_epoch exactly as it did pre-CR-0009.
func (g *AnchorEpochGuard) StampSnapshot(snap *TopologySnapshot) {
	if g == nil || snap == nil {
		return
	}
	e := g.OwnEpoch()
	snap.ClusterEpoch = &e
}

// OnQuorumLost puts the Anchor into read-only-degraded state and emits
// anchor_quorum_lost. The host is separately responsible for setting its NDP
// self-announcement `health` to "degraded".
func (g *AnchorEpochGuard) OnQuorumLost(quorumSize, available uint32) TopologyEvent {
	g.mu.Lock()
	g.degraded = true
	emit := g.EmitEvent
	g.mu.Unlock()

	ev := NewAnchorQuorumLostEventDefaults(quorumSize, available)
	if emit != nil {
		emit(ev)
	}
	return ev
}

// OnQuorumRestored clears read-only-degraded state.
func (g *AnchorEpochGuard) OnQuorumRestored() {
	g.mu.Lock()
	g.degraded = false
	g.mu.Unlock()
}

// TakeOwnership promotes this Anchor to ACTIVE at newEpoch and emits
// anchor_failover naming itself as successor.
//
// newEpoch MUST be strictly greater than every epoch this guard has observed —
// a non-increasing epoch is rejected rather than silently accepted, because the
// epoch is a fencing token and a replayed value would defeat it.
//
// The caller MUST then re-sign and re-publish its AnnounceFrame with
// cluster_epoch = newEpoch: cluster_epoch is inside the signed canonical form
// (NPS-CR-0009 §1.1), so an ownership claim is only authenticated once re-signed.
func (g *AnchorEpochGuard) TakeOwnership(newEpoch uint64, reason string) (TopologyEvent, error) {
	if reason == "" {
		reason = AnchorFailoverReasonPlanned
	}

	g.mu.Lock()
	if newEpoch <= g.ownEpoch {
		own := g.ownEpoch
		g.mu.Unlock()
		return TopologyEvent{}, fmt.Errorf(
			"cluster_epoch must strictly increase on every ownership transfer: %d is not greater than the observed %d",
			newEpoch, own)
	}
	g.ownEpoch = newEpoch
	g.standby = false
	g.degraded = false
	emit := g.EmitEvent
	g.mu.Unlock()

	ev := NewAnchorFailoverEvent(g.anchorNid, newEpoch, reason, 0)
	if emit != nil {
		emit(ev)
	}
	return ev, nil
}

// ObserveEpoch records a peer's epoch without fencing, so a guard that only
// listens can keep its "highest epoch ever observed" floor current. It never
// lowers the guard's own epoch.
func (g *AnchorEpochGuard) ObserveEpoch(epoch uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if epoch > g.ownEpoch {
		g.standby = true
	}
}
