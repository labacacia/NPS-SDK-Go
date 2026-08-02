// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import "encoding/json"

// AnchorState sub-type tags (NPS-2 §12.2, NPS-CR-0009).
//
// These deliberately live next to AnchorStateEvent rather than in the shared
// topology wire-constant block: they are the sub-type tag of ONE event type, not
// part of the general topology vocabulary. Subscribers already MUST ignore
// unknown anchor_state sub-types, so the two CR-0009 additions are safe for
// pre-CR-0009 subscribers.
const (
	// AnchorStateFieldVersionRebased predates CR-0009.
	AnchorStateFieldVersionRebased = "version_rebased"
	// AnchorStateFieldAnchorFailover announces an Anchor ownership transfer.
	AnchorStateFieldAnchorFailover = "anchor_failover"
	// AnchorStateFieldAnchorQuorumLost announces entry into read-only-degraded state.
	AnchorStateFieldAnchorQuorumLost = "anchor_quorum_lost"
)

// anchor_failover `reason` enum values.
const (
	// AnchorFailoverReasonPlanned is the factory default.
	AnchorFailoverReasonPlanned = "planned"
	// AnchorFailoverReasonActiveLost is emitted when the previous active was lost
	// (including by a superseded leader self-fencing).
	AnchorFailoverReasonActiveLost = "active_lost"
)

// NewAnchorFailoverEvent builds the `anchor_failover` AnchorState event
// (NPS-CR-0009 §1.2). Not signed.
//
// details wire keys, all required:
//
//	successor_nid  string NID  the Anchor that took ownership
//	cluster_epoch  uint64      the new, strictly-greater epoch
//	reason         string      "planned" | "active_lost"
//
// Go has no default arguments, so this is the full-arity form; use
// NewAnchorFailoverEventDefaults for the reason="planned", version=0 defaults.
func NewAnchorFailoverEvent(successorNid string, clusterEpoch uint64, reason string, version uint64) TopologyEvent {
	details, _ := json.Marshal(map[string]any{
		"successor_nid": successorNid,
		"cluster_epoch": clusterEpoch,
		"reason":        reason,
	})
	return TopologyEvent{
		Kind:    eventAnchorState,
		Version: version,
		AnchorState: &AnchorStateEvent{
			Field:   AnchorStateFieldAnchorFailover,
			Details: details,
		},
	}
}

// NewAnchorFailoverEventDefaults is the convenience form of NewAnchorFailoverEvent
// supplying the reference impl's defaulted trailing parameters: reason="planned",
// version=0.
func NewAnchorFailoverEventDefaults(successorNid string, clusterEpoch uint64) TopologyEvent {
	return NewAnchorFailoverEvent(successorNid, clusterEpoch, AnchorFailoverReasonPlanned, 0)
}

// NewAnchorQuorumLostEvent builds the `anchor_quorum_lost` AnchorState event
// (NPS-CR-0009 §1.3). Not signed.
//
// details wire keys, both required: `quorum_size` uint32, `available` uint32.
func NewAnchorQuorumLostEvent(quorumSize, available uint32, version uint64) TopologyEvent {
	details, _ := json.Marshal(map[string]any{
		"quorum_size": quorumSize,
		"available":   available,
	})
	return TopologyEvent{
		Kind:    eventAnchorState,
		Version: version,
		AnchorState: &AnchorStateEvent{
			Field:   AnchorStateFieldAnchorQuorumLost,
			Details: details,
		},
	}
}

// NewAnchorQuorumLostEventDefaults is the convenience form supplying version=0.
func NewAnchorQuorumLostEventDefaults(quorumSize, available uint32) TopologyEvent {
	return NewAnchorQuorumLostEvent(quorumSize, available, 0)
}

// AnchorFailoverDetails is the decoded `details` payload of an anchor_failover event.
type AnchorFailoverDetails struct {
	SuccessorNid string `json:"successor_nid"`
	ClusterEpoch uint64 `json:"cluster_epoch"`
	Reason       string `json:"reason"`
}

// AnchorQuorumLostDetails is the decoded `details` payload of an anchor_quorum_lost event.
type AnchorQuorumLostDetails struct {
	QuorumSize uint32 `json:"quorum_size"`
	Available  uint32 `json:"available"`
}

// DecodeAnchorFailover decodes an AnchorStateEvent as an anchor_failover payload.
// The second return is false when the event is a different sub-type or is malformed.
func DecodeAnchorFailover(ev *AnchorStateEvent) (AnchorFailoverDetails, bool) {
	var out AnchorFailoverDetails
	if ev == nil || ev.Field != AnchorStateFieldAnchorFailover || len(ev.Details) == 0 {
		return out, false
	}
	if err := json.Unmarshal(ev.Details, &out); err != nil {
		return out, false
	}
	return out, true
}

// DecodeAnchorQuorumLost decodes an AnchorStateEvent as an anchor_quorum_lost payload.
func DecodeAnchorQuorumLost(ev *AnchorStateEvent) (AnchorQuorumLostDetails, bool) {
	var out AnchorQuorumLostDetails
	if ev == nil || ev.Field != AnchorStateFieldAnchorQuorumLost || len(ev.Details) == 0 {
		return out, false
	}
	if err := json.Unmarshal(ev.Details, &out); err != nil {
		return out, false
	}
	return out, true
}
