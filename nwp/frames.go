// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"github.com/labacacia/NPS-sdk-go/core"
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
func optUint64(d core.FrameDict, k string) *uint64 {
	switch x := d[k].(type) {
	case int64:
		v := uint64(x)
		return &v
	case uint64:
		return &x
	case float64:
		v := uint64(x)
		return &v
	}
	return nil
}
func optUint32(d core.FrameDict, k string) *uint32 {
	if v, ok := d[k]; ok {
		switch n := v.(type) {
		case float64:
			u := uint32(n)
			return &u
		case uint32:
			return &n
		}
	}
	return nil
}
func optBool(d core.FrameDict, k string) bool {
	v, _ := d[k].(bool)
	return v
}

const (
	TopologySnapshotKind = "topology.snapshot"
	TopologyStreamKind   = "topology.stream"
)

type TopologySnapshotRequest struct {
	Kind                string
	AnchorRef           *string
	IncludeBridges      bool
	IncludeCapabilities bool
	MaxDepth            *uint64
	Since               *string
}

type TopologyStreamRequest struct {
	Kind                   string
	AnchorRef              *string
	IncludeInitialSnapshot bool
	EventTypes             []string
	Since                  *string
}

type TopologyMember struct {
	NodeID       string
	NodeType     *string
	AnchorRef    *string
	Capabilities []string
	Metadata     map[string]any
}

type BridgeNodeSpec struct {
	BridgeID       string
	SourceProtocol string
	TargetProtocol string
	SourceRef      *string
	TargetRef      *string
	Capabilities   []string
	Metadata       map[string]any
}

// ── SubscribeFrame ────────────────────────────────────────────────────────────

type SubscribeFrame struct {
	SubscriptionID      string
	Filter              any
	HeartbeatIntervalMs *uint32
	MaxEvents           *uint32
	Cursor              *string
}

func (f *SubscribeFrame) FrameType() core.FrameType { return core.FrameTypeSubscribe }

func (f *SubscribeFrame) ToDict() core.FrameDict {
	d := core.FrameDict{"subscription_id": f.SubscriptionID}
	if f.Filter != nil {
		d["filter"] = f.Filter
	}
	if f.HeartbeatIntervalMs != nil {
		d["heartbeat_interval_ms"] = *f.HeartbeatIntervalMs
	}
	if f.MaxEvents != nil {
		d["max_events"] = *f.MaxEvents
	}
	if f.Cursor != nil {
		d["cursor"] = *f.Cursor
	}
	return d
}

func SubscribeFrameFromDict(d core.FrameDict) *SubscribeFrame {
	return &SubscribeFrame{
		SubscriptionID:      str(d, "subscription_id"),
		Filter:              d["filter"],
		HeartbeatIntervalMs: optUint32(d, "heartbeat_interval_ms"),
		MaxEvents:           optUint32(d, "max_events"),
		Cursor:              optStr(d, "cursor"),
	}
}

// ── QueryFrame ────────────────────────────────────────────────────────────────

type QueryFrame struct {
	AnchorRef    string
	Filter       any
	Order        any
	Fields       []string
	VectorSearch any
	Cursor       *string
	TokenBudget  *uint64
	Tokenizer    *string
	RequestID    *string
	AutoAnchor   *bool
	Stream       *bool
	Aggregate    any
	Limit        *uint64
	Offset       *uint64
	Depth        *uint64
}

func (f *QueryFrame) FrameType() core.FrameType { return core.FrameTypeQuery }

func (f *QueryFrame) ToDict() core.FrameDict {
	d := core.FrameDict{"anchor_ref": f.AnchorRef}
	if f.Filter != nil {
		d["filter"] = f.Filter
	}
	if f.Order != nil {
		d["order"] = f.Order
	}
	if f.Fields != nil {
		d["fields"] = f.Fields
	}
	if f.VectorSearch != nil {
		d["vector_search"] = f.VectorSearch
	}
	if f.Cursor != nil {
		d["cursor"] = *f.Cursor
	}
	if f.TokenBudget != nil {
		d["token_budget"] = *f.TokenBudget
	}
	if f.Tokenizer != nil {
		d["tokenizer"] = *f.Tokenizer
	}
	if f.RequestID != nil {
		d["request_id"] = *f.RequestID
	}
	if f.AutoAnchor != nil {
		d["auto_anchor"] = *f.AutoAnchor
	}
	if f.Stream != nil {
		d["stream"] = *f.Stream
	}
	if f.Aggregate != nil {
		d["aggregate"] = f.Aggregate
	}
	if f.Limit != nil {
		d["limit"] = *f.Limit
	}
	if f.Offset != nil {
		d["offset"] = *f.Offset
	}
	if f.Depth != nil {
		d["depth"] = *f.Depth
	}
	return d
}

func QueryFrameFromDict(d core.FrameDict) *QueryFrame {
	return &QueryFrame{
		AnchorRef:    str(d, "anchor_ref"),
		Filter:       d["filter"],
		Order:        orderValue(d),
		Fields:       stringSlice(d["fields"]),
		VectorSearch: d["vector_search"],
		Cursor:       optStr(d, "cursor"),
		TokenBudget:  optUint64(d, "token_budget"),
		Tokenizer:    optStr(d, "tokenizer"),
		RequestID:    optStr(d, "request_id"),
		AutoAnchor:   optBoolPtr(d, "auto_anchor"),
		Stream:       optBoolPtr(d, "stream"),
		Aggregate:    d["aggregate"],
		Limit:        optUint64(d, "limit"),
		Offset:       optUint64(d, "offset"),
		Depth:        optUint64(d, "depth"),
	}
}

func orderValue(d core.FrameDict) any {
	if v := d["order"]; v != nil {
		return v
	}
	return d["order_by"]
}

func optBoolPtr(d core.FrameDict, k string) *bool {
	if v, ok := d[k].(bool); ok {
		return &v
	}
	return nil
}

func stringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		if s, ok := v.([]string); ok {
			return s
		}
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ── ActionFrame ───────────────────────────────────────────────────────────────

type ActionFrame struct {
	Action         string
	Params         any
	AnchorRef      *string
	Async          bool
	IdempotencyKey *string
	TimeoutMs      *uint32
	RequestID      *string
}

func (f *ActionFrame) FrameType() core.FrameType { return core.FrameTypeAction }

func (f *ActionFrame) ToDict() core.FrameDict {
	d := core.FrameDict{"action_id": f.Action, "action": f.Action, "async": f.Async}
	if f.Params != nil {
		d["params"] = f.Params
	}
	if f.AnchorRef != nil {
		d["anchor_ref"] = *f.AnchorRef
	}
	if f.RequestID != nil {
		d["request_id"] = *f.RequestID
	}
	if f.IdempotencyKey != nil {
		d["idempotency_key"] = *f.IdempotencyKey
	}
	if f.TimeoutMs != nil {
		d["timeout_ms"] = *f.TimeoutMs
	}
	return d
}

func ActionFrameFromDict(d core.FrameDict) *ActionFrame {
	action := str(d, "action_id")
	if action == "" {
		action = str(d, "action")
	}
	return &ActionFrame{
		Action:         action,
		Params:         d["params"],
		AnchorRef:      optStr(d, "anchor_ref"),
		Async:          optBool(d, "async"),
		IdempotencyKey: optStr(d, "idempotency_key"),
		TimeoutMs:      optUint32(d, "timeout_ms"),
		RequestID:      optStr(d, "request_id"),
	}
}

// ── AsyncActionResponse ───────────────────────────────────────────────────────

type AsyncActionResponse struct {
	TaskID      string
	StatusURL   *string
	CallbackURL *string
}

func AsyncActionResponseFromDict(d core.FrameDict) *AsyncActionResponse {
	return &AsyncActionResponse{
		TaskID:      str(d, "task_id"),
		StatusURL:   optStr(d, "status_url"),
		CallbackURL: optStr(d, "callback_url"),
	}
}

// ── NWP v0.14 manifest versioning ─────────────────────────────────────────────

// XNwmVersion is the HTTP response header name carrying the manifest version (NWP v0.14).
const XNwmVersion = "X-NWM-Version"
