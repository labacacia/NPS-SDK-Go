// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ndp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/labacacia/NPS-sdk-go/core"
)

const (
	maxGraphNodes = 256
	maxGraphEdges = 1024
)

func str(d core.FrameDict, k string) string {
	if v, ok := d[k].(string); ok {
		return v
	}
	return ""
}
func optStr(d core.FrameDict, k string) *string {
	if v, ok := d[k].(string); ok {
		return &v
	}
	return nil
}
func toUint64(v any) uint64 {
	switch x := v.(type) {
	case int64:
		return uint64(x)
	case uint64:
		return x
	case float64:
		return uint64(x)
	case int:
		return uint64(x)
	case json.Number:
		n, err := strconv.ParseUint(x.String(), 10, 64)
		if err == nil {
			return n
		}
	}
	return 0
}
func toSliceStr(v any) []string {
	if ss, ok := v.([]string); ok {
		return ss
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, a := range arr {
		if s, ok := a.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
func toSliceMap(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, a := range arr {
		if m, ok := a.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
func toMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// ── AnnounceFrame ─────────────────────────────────────────────────────────────

type AnnounceFrame struct {
	NID             string
	Addresses       []map[string]any
	Caps            []string
	TTL             uint64
	Timestamp       string
	Signature       string
	NodeType        *string
	NodeRoles       []string
	ClusterAnchor   string
	SpawnSpecRef    string // NDP v0.9: opaque ref resolving to a SpawnSpec
	BridgeProtocols []string
	// BridgeInboundProtocols declares the external protocols this Bridge Node accepts
	// INBOUND (external -> NPS), wire key `bridge_inbound_protocols` (NPS-CR-0010,
	// NDP v0.11). Independent of BridgeProtocols, which is the outbound set.
	// Receivers MUST treat an absent value as [] (a pre-alpha.16 outbound-only Bridge).
	// It IS part of the signed canonical form and is omitted entirely when unset.
	BridgeInboundProtocols []string
	ActivationMode         string
	ActivationEndpoint     map[string]any
	HeartbeatIntervalMs    uint64 // NDP v0.9; default 60000
	// ClusterEpoch is the epoch under which this Anchor owns its `cluster_anchor`
	// cluster (NPS-CR-0009, NDP v0.10). Starts at 1 and strictly increases on every
	// ownership transfer — a fencing token.
	//
	// Absence is NOT an error: an absent value means 1 (single-Anchor). nil is
	// serialized by OMITTING the key entirely, never as `null` or `0`, so the
	// canonical bytes of a single-Anchor frame stay bit-identical to pre-CR-0009
	// frames. It IS inside the signed canonical form, so changing it requires
	// re-signing the AnnounceFrame.
	ClusterEpoch *uint64
	// NDP v0.9 liveness — wire-only, NOT part of the signed canonical form
	// (last_seen updates every heartbeat → must not require re-signing; §3.2.1).
	Health   string // "healthy" / "degraded" / "draining"
	LastSeen string // ISO 8601 UTC liveness beat
	// GraphSeq is the NDP v0.12 per-NID monotonic registry sequence. It is signed
	// when present and omitted entirely when absent.
	GraphSeq *uint64
}

func (f *AnnounceFrame) FrameType() core.FrameType { return core.FrameTypeAnnounce }

// UnsignedDict returns the canonical dict without signature (for signing).
func (f *AnnounceFrame) UnsignedDict() core.FrameDict {
	d := core.FrameDict{
		"nid":                   f.NID,
		"addresses":             f.Addresses,
		"capabilities":          f.Caps,
		"ttl":                   f.TTL,
		"timestamp":             f.Timestamp,
		"heartbeat_interval_ms": f.HeartbeatIntervalMs,
	}
	if f.NodeType != nil {
		d["node_type"] = *f.NodeType
	}
	if len(f.NodeRoles) > 0 {
		d["node_roles"] = f.NodeRoles
	}
	if f.ClusterAnchor != "" {
		d["cluster_anchor"] = f.ClusterAnchor
	}
	if f.SpawnSpecRef != "" {
		d["spawn_spec_ref"] = f.SpawnSpecRef
	}
	if len(f.BridgeProtocols) > 0 {
		d["bridge_protocols"] = f.BridgeProtocols
	}
	if len(f.BridgeInboundProtocols) > 0 {
		d["bridge_inbound_protocols"] = f.BridgeInboundProtocols
	}
	if f.ActivationMode != "" {
		d["activation_mode"] = f.ActivationMode
	}
	if f.ActivationEndpoint != nil {
		d["activation_endpoint"] = f.ActivationEndpoint
	}
	if f.ClusterEpoch != nil {
		d["cluster_epoch"] = *f.ClusterEpoch
	}
	if f.GraphSeq != nil {
		d["graph_seq"] = *f.GraphSeq
	}
	// Sort keys for canonical representation
	return sortedDict(d)
}

func (f *AnnounceFrame) ToDict() core.FrameDict {
	d := f.UnsignedDict()
	d["signature"] = f.Signature
	if f.NodeType != nil {
		d["node_type"] = *f.NodeType
	}
	if len(f.NodeRoles) > 0 {
		d["node_roles"] = f.NodeRoles
	}
	if f.ClusterAnchor != "" {
		d["cluster_anchor"] = f.ClusterAnchor
	}
	if f.SpawnSpecRef != "" {
		d["spawn_spec_ref"] = f.SpawnSpecRef
	}
	if len(f.BridgeProtocols) > 0 {
		d["bridge_protocols"] = f.BridgeProtocols
	}
	if len(f.BridgeInboundProtocols) > 0 {
		d["bridge_inbound_protocols"] = f.BridgeInboundProtocols
	}
	if f.ActivationMode != "" {
		d["activation_mode"] = f.ActivationMode
	}
	if f.ActivationEndpoint != nil {
		d["activation_endpoint"] = f.ActivationEndpoint
	}
	if f.ClusterEpoch != nil {
		d["cluster_epoch"] = *f.ClusterEpoch
	}
	if f.GraphSeq != nil {
		d["graph_seq"] = *f.GraphSeq
	}
	d["heartbeat_interval_ms"] = f.HeartbeatIntervalMs
	if f.Health != "" {
		d["health"] = f.Health
	}
	if f.LastSeen != "" {
		d["last_seen"] = f.LastSeen
	}
	return d
}

func AnnounceFrameFromDict(d core.FrameDict) *AnnounceFrame {
	// NDP spec: parsers MUST accept node_kind as a parse-time alias for node_roles.
	nodeRoles := d["node_roles"]
	if nodeRoles == nil {
		nodeRoles = d["node_kind"] // legacy alias
	}
	caps := d["capabilities"]
	if caps == nil {
		caps = d["caps"] // legacy pre-polish alias
	}
	hbMs := uint64(60_000)
	if _, ok := d["heartbeat_interval_ms"]; ok {
		hbMs = toUint64(d["heartbeat_interval_ms"])
	}
	// cluster_epoch: absent stays nil (coerced to 1 only at comparison time, never
	// at storage time — see ClusterEpochOrDefault / ResolveCluster).
	var clusterEpoch *uint64
	if raw, ok := d["cluster_epoch"]; ok && raw != nil {
		v := toUint64(raw)
		clusterEpoch = &v
	}
	var graphSeq *uint64
	if raw, ok := d["graph_seq"]; ok && raw != nil {
		v := toUint64(raw)
		graphSeq = &v
	}
	f := &AnnounceFrame{
		NID:                    str(d, "nid"),
		Addresses:              toSliceMap(d["addresses"]),
		Caps:                   toSliceStr(caps),
		TTL:                    toUint64(d["ttl"]),
		Timestamp:              str(d, "timestamp"),
		Signature:              str(d, "signature"),
		NodeType:               optStr(d, "node_type"),
		NodeRoles:              toSliceStr(nodeRoles),
		ClusterAnchor:          str(d, "cluster_anchor"),
		SpawnSpecRef:           str(d, "spawn_spec_ref"),
		BridgeProtocols:        toSliceStr(d["bridge_protocols"]),
		BridgeInboundProtocols: toSliceStr(d["bridge_inbound_protocols"]),
		ActivationMode:         str(d, "activation_mode"),
		ActivationEndpoint:     toMap(d["activation_endpoint"]),
		HeartbeatIntervalMs:    hbMs,
		ClusterEpoch:           clusterEpoch,
		Health:                 str(d, "health"),
		LastSeen:               str(d, "last_seen"),
		GraphSeq:               graphSeq,
	}
	if f.TTL == 0 {
		f.TTL = 300
	}
	return f
}

func sortedDict(d core.FrameDict) core.FrameDict {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(core.FrameDict, len(d))
	for _, k := range keys {
		out[k] = d[k]
	}
	return out
}

// ── ResolveFrame ──────────────────────────────────────────────────────────────

type ResolveFrame struct {
	Target       string
	RequesterNID *string
	Resolved     map[string]any
}

func (f *ResolveFrame) FrameType() core.FrameType { return core.FrameTypeResolve }

func (f *ResolveFrame) ToDict() core.FrameDict {
	d := core.FrameDict{"target": f.Target}
	if f.RequesterNID != nil {
		d["requester_nid"] = *f.RequesterNID
	}
	if f.Resolved != nil {
		d["resolved"] = f.Resolved
	}
	return d
}

func ResolveFrameFromDict(d core.FrameDict) *ResolveFrame {
	var resolved map[string]any
	if v, ok := d["resolved"].(map[string]any); ok {
		resolved = v
	}
	return &ResolveFrame{
		Target:       str(d, "target"),
		RequesterNID: optStr(d, "requester_nid"),
		Resolved:     resolved,
	}
}

// ── GraphFrame ────────────────────────────────────────────────────────────────

// GraphNode is a single node entry in a topology snapshot (NPS-4 §3.3).
type GraphNode struct {
	NID           string   `json:"nid"`
	ClusterAnchor string   `json:"cluster_anchor,omitempty"`
	NodeRoles     []string `json:"node_roles,omitempty"`
}

// NdpGraphEdge describes a directional link between two nodes (NPS-4 §3.3).
type NdpGraphEdge struct {
	FromNID   string `json:"from_nid"`
	ToNID     string `json:"to_nid"`
	LatencyMs *int   `json:"latency_ms,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
}

// GraphFrame is a topology snapshot frame (NPS-4 §3.3, alpha.11 redesign).
type GraphFrame struct {
	GraphID  string         `json:"graph_id"`
	Nodes    []GraphNode    `json:"nodes"`
	Edges    []NdpGraphEdge `json:"edges"`
	TTL      int            `json:"ttl"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

func (f *GraphFrame) FrameType() core.FrameType { return core.FrameTypeGraph }

func (f *GraphFrame) Validate() error {
	if len(f.Nodes) > maxGraphNodes {
		return fmt.Errorf("%s: nodes length exceeds %d", ErrGraphTooLarge, maxGraphNodes)
	}
	if len(f.Edges) > maxGraphEdges {
		return fmt.Errorf("%s: edges length exceeds %d", ErrGraphTooLarge, maxGraphEdges)
	}

	nodeIDs := make(map[string]struct{}, len(f.Nodes))
	for _, node := range f.Nodes {
		if node.NID == "" {
			return fmt.Errorf("%s: graph nodes require nid", ErrGraphInvalid)
		}
		nodeIDs[node.NID] = struct{}{}
	}
	for _, edge := range f.Edges {
		if edge.FromNID == "" || edge.ToNID == "" {
			return fmt.Errorf("%s: graph edges require from_nid and to_nid", ErrGraphInvalid)
		}
		if edge.FromNID == edge.ToNID {
			return fmt.Errorf("%s: graph self-edges are forbidden", ErrGraphInvalid)
		}
		if _, ok := nodeIDs[edge.FromNID]; !ok {
			return fmt.Errorf("%s: graph edge endpoints must appear in nodes", ErrGraphInvalid)
		}
		if _, ok := nodeIDs[edge.ToNID]; !ok {
			return fmt.Errorf("%s: graph edge endpoints must appear in nodes", ErrGraphInvalid)
		}
	}
	return nil
}

func (f *GraphFrame) ToDict() core.FrameDict {
	d := core.FrameDict{
		"graph_id": f.GraphID,
		"nodes":    f.Nodes,
		"edges":    f.Edges,
		"ttl":      f.TTL,
	}
	if f.Metadata != nil {
		d["metadata"] = f.Metadata
	}
	return d
}

func graphNodeFromMap(m map[string]any) GraphNode {
	n := GraphNode{NID: "", ClusterAnchor: "", NodeRoles: nil}
	if v, ok := m["nid"].(string); ok {
		n.NID = v
	}
	if v, ok := m["cluster_anchor"].(string); ok {
		n.ClusterAnchor = v
	}
	n.NodeRoles = toSliceStr(m["node_roles"])
	return n
}

func ndpGraphEdgeFromMap(m map[string]any) NdpGraphEdge {
	e := NdpGraphEdge{}
	if v, ok := m["from_nid"].(string); ok {
		e.FromNID = v
	}
	if v, ok := m["to_nid"].(string); ok {
		e.ToNID = v
	}
	if v, ok := m["protocol"].(string); ok {
		e.Protocol = v
	}
	if v, ok := m["latency_ms"]; ok {
		switch x := v.(type) {
		case float64:
			i := int(x)
			e.LatencyMs = &i
		case int:
			e.LatencyMs = &x
		case int64:
			i := int(x)
			e.LatencyMs = &i
		}
	}
	return e
}

func GraphFrameFromDict(d core.FrameDict) *GraphFrame {
	var nodes []GraphNode
	if arr, ok := d["nodes"].([]any); ok {
		for _, item := range arr {
			if m, ok := item.(map[string]any); ok {
				nodes = append(nodes, graphNodeFromMap(m))
			}
		}
	}
	var edges []NdpGraphEdge
	if arr, ok := d["edges"].([]any); ok {
		for _, item := range arr {
			if m, ok := item.(map[string]any); ok {
				edges = append(edges, ndpGraphEdgeFromMap(m))
			}
		}
	}
	var metadata map[string]any
	if v, ok := d["metadata"].(map[string]any); ok {
		metadata = v
	}
	ttl := 0
	switch x := d["ttl"].(type) {
	case float64:
		ttl = int(x)
	case int:
		ttl = x
	case int64:
		ttl = int(x)
	}
	return &GraphFrame{
		GraphID:  str(d, "graph_id"),
		Nodes:    nodes,
		Edges:    edges,
		TTL:      ttl,
		Metadata: metadata,
	}
}
