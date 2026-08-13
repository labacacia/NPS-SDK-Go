// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ncp

import (
	"github.com/labacacia/NPS-sdk-go/core"
)

// ── helpers ───────────────────────────────────────────────────────────────────

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
	}
	return 0
}

// ── AnchorFrame ───────────────────────────────────────────────────────────────

type AnchorFrame struct {
	AnchorID    string
	Schema      core.FrameDict
	Namespace   *string
	Description *string
	NodeType    *string
	TTL         uint64
}

func (f *AnchorFrame) FrameType() core.FrameType { return core.FrameTypeAnchor }

func (f *AnchorFrame) ToDict() core.FrameDict {
	d := core.FrameDict{
		"anchor_id": f.AnchorID,
		"schema":    f.Schema,
		"ttl":       f.TTL,
	}
	if f.Namespace != nil {
		d["namespace"] = *f.Namespace
	}
	if f.Description != nil {
		d["description"] = *f.Description
	}
	if f.NodeType != nil {
		d["node_type"] = *f.NodeType
	}
	return d
}

func AnchorFrameFromDict(d core.FrameDict) *AnchorFrame {
	schema, _ := d["schema"].(map[string]any)
	f := &AnchorFrame{
		AnchorID: str(d, "anchor_id"),
		Schema:   schema,
		TTL:      toUint64(d["ttl"]),
	}
	if f.TTL == 0 {
		f.TTL = 3600
	}
	f.Namespace = optStr(d, "namespace")
	f.Description = optStr(d, "description")
	f.NodeType = optStr(d, "node_type")
	return f
}

// ── DiffFrame ─────────────────────────────────────────────────────────────────

type DiffFrame struct {
	AnchorID    string
	NewAnchorID string
	Patch       []any
}

func (f *DiffFrame) FrameType() core.FrameType { return core.FrameTypeDiff }

func (f *DiffFrame) ToDict() core.FrameDict {
	return core.FrameDict{
		"anchor_id":     f.AnchorID,
		"new_anchor_id": f.NewAnchorID,
		"patch":         f.Patch,
	}
}

func DiffFrameFromDict(d core.FrameDict) *DiffFrame {
	var patch []any
	if v, ok := d["patch"].([]any); ok {
		patch = v
	}
	return &DiffFrame{
		AnchorID:    str(d, "anchor_id"),
		NewAnchorID: str(d, "new_anchor_id"),
		Patch:       patch,
	}
}

// ── StreamFrame ───────────────────────────────────────────────────────────────

type StreamFrame struct {
	AnchorID string
	Seq      uint64
	Payload  any
	IsLast   bool
}

func (f *StreamFrame) FrameType() core.FrameType { return core.FrameTypeStream }

func (f *StreamFrame) ToDict() core.FrameDict {
	return core.FrameDict{
		"anchor_id": f.AnchorID,
		"seq":       f.Seq,
		"payload":   f.Payload,
		"is_last":   f.IsLast,
	}
}

func StreamFrameFromDict(d core.FrameDict) *StreamFrame {
	isLast, _ := d["is_last"].(bool)
	return &StreamFrame{
		AnchorID: str(d, "anchor_id"),
		Seq:      toUint64(d["seq"]),
		Payload:  d["payload"],
		IsLast:   isLast,
	}
}

// ── CapsFrame ─────────────────────────────────────────────────────────────────

type CapsFrame struct {
	NodeID        string
	Caps          []string
	AnchorRef     *string
	Count         uint64
	Data          []any
	NextCursor    *string
	TokenEst      *uint64
	Cached        *bool
	TokenizerUsed *string
	RequestID     *string
	Payload       any
}

func (f *CapsFrame) FrameType() core.FrameType { return core.FrameTypeCaps }

func (f *CapsFrame) ToDict() core.FrameDict {
	d := core.FrameDict{}
	if f.NodeID != "" {
		d["node_id"] = f.NodeID
	}
	if len(f.Caps) > 0 {
		d["caps"] = f.Caps
	}
	if f.AnchorRef != nil {
		d["anchor_ref"] = *f.AnchorRef
	}
	if f.Data != nil || f.Count != 0 {
		d["count"] = f.Count
		if f.Count == 0 {
			d["count"] = uint64(len(f.Data))
		}
		d["data"] = f.Data
	}
	if f.NextCursor != nil {
		d["next_cursor"] = *f.NextCursor
	}
	if f.TokenEst != nil {
		d["token_est"] = *f.TokenEst
	}
	if f.Cached != nil {
		d["cached"] = *f.Cached
	}
	if f.TokenizerUsed != nil {
		d["tokenizer_used"] = *f.TokenizerUsed
	}
	if f.RequestID != nil {
		d["request_id"] = *f.RequestID
	}
	if f.Payload != nil {
		d["payload"] = f.Payload
	}
	return d
}

func CapsFrameFromDict(d core.FrameDict) *CapsFrame {
	var caps []string
	switch v := d["caps"].(type) {
	case []string:
		caps = v
	case []any:
		for _, c := range v {
			if s, ok := c.(string); ok {
				caps = append(caps, s)
			}
		}
	}
	return &CapsFrame{
		NodeID:        str(d, "node_id"),
		Caps:          caps,
		AnchorRef:     optStr(d, "anchor_ref"),
		Count:         toUint64(d["count"]),
		Data:          anySlice(d["data"]),
		NextCursor:    optStr(d, "next_cursor"),
		TokenEst:      optUint64Ptr(d, "token_est"),
		Cached:        optBoolPtr(d, "cached"),
		TokenizerUsed: optStr(d, "tokenizer_used"),
		RequestID:     optStr(d, "request_id"),
		Payload:       d["payload"],
	}
}

func NewCapsFrame(anchorRef string, data []any) *CapsFrame {
	return &CapsFrame{
		AnchorRef: &anchorRef,
		Count:     uint64(len(data)),
		Data:      data,
	}
}

func anySlice(v any) []any {
	switch items := v.(type) {
	case []any:
		return items
	case nil:
		return nil
	default:
		return []any{items}
	}
}

func optBoolPtr(d core.FrameDict, k string) *bool {
	if v, ok := d[k].(bool); ok {
		return &v
	}
	return nil
}

func optUint64Ptr(d core.FrameDict, k string) *uint64 {
	if v, ok := d[k]; ok {
		u := toUint64(v)
		return &u
	}
	return nil
}

// ── HelloFrame ────────────────────────────────────────────────────────────────

// HelloFrame is the native-mode client handshake frame (NPS-1 §4.6).
//
// The Agent MUST send this as the very first frame after opening a TCP/QUIC
// connection; the Node replies with a CapsFrame. Not used in HTTP mode.
//
// Preferred encoding is Tier-1 JSON because the encoding has not yet been
// negotiated at handshake time.
type HelloFrame struct {
	NpsVersion           string
	SupportedEncodings   []string
	SupportedProtocols   []string
	MinVersion           *string
	AgentID              *string
	MaxFramePayload      uint64
	ExtSupport           bool
	MaxConcurrentStreams uint64
	E2eEncAlgorithms     []string // nil when absent
	PingIntervalMs       uint64   // NCP v0.8; 0 = disabled
}

const (
	HelloDefaultMaxFramePayload      uint64 = 0xFFFF
	HelloDefaultMaxConcurrentStreams uint64 = 32
)

func (f *HelloFrame) FrameType() core.FrameType { return core.FrameTypeHello }

func (f *HelloFrame) ToDict() core.FrameDict {
	maxPayload := f.MaxFramePayload
	if maxPayload == 0 {
		maxPayload = HelloDefaultMaxFramePayload
	}
	maxStreams := f.MaxConcurrentStreams
	if maxStreams == 0 {
		maxStreams = HelloDefaultMaxConcurrentStreams
	}
	d := core.FrameDict{
		"nps_version":            f.NpsVersion,
		"supported_encodings":    f.SupportedEncodings,
		"supported_protocols":    f.SupportedProtocols,
		"max_frame_payload":      maxPayload,
		"ext_support":            f.ExtSupport,
		"max_concurrent_streams": maxStreams,
	}
	if f.MinVersion != nil {
		d["min_version"] = *f.MinVersion
	}
	if f.AgentID != nil {
		d["agent_id"] = *f.AgentID
	}
	if f.E2eEncAlgorithms != nil {
		d["e2e_enc_algorithms"] = f.E2eEncAlgorithms
	}
	if f.PingIntervalMs > 0 {
		d["ping_interval_ms"] = f.PingIntervalMs
	}
	return d
}

func HelloFrameFromDict(d core.FrameDict) *HelloFrame {
	asStringSlice := func(v any) []string {
		switch x := v.(type) {
		case []string:
			return x
		case []any:
			out := make([]string, 0, len(x))
			for _, e := range x {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
		return nil
	}

	f := &HelloFrame{
		NpsVersion:         str(d, "nps_version"),
		SupportedEncodings: asStringSlice(d["supported_encodings"]),
		SupportedProtocols: asStringSlice(d["supported_protocols"]),
		MinVersion:         optStr(d, "min_version"),
		AgentID:            optStr(d, "agent_id"),
	}
	if v, ok := d["ext_support"].(bool); ok {
		f.ExtSupport = v
	}
	f.MaxFramePayload = toUint64(d["max_frame_payload"])
	if f.MaxFramePayload == 0 {
		f.MaxFramePayload = HelloDefaultMaxFramePayload
	}
	f.MaxConcurrentStreams = toUint64(d["max_concurrent_streams"])
	if f.MaxConcurrentStreams == 0 {
		f.MaxConcurrentStreams = HelloDefaultMaxConcurrentStreams
	}
	if _, present := d["e2e_enc_algorithms"]; present {
		f.E2eEncAlgorithms = asStringSlice(d["e2e_enc_algorithms"])
	}
	f.PingIntervalMs = toUint64(d["ping_interval_ms"])
	return f
}

// ── NopFrame (0x07) ───────────────────────────────────────────────────────────

// NopFrame is a keepalive/heartbeat frame with no payload (NCP v0.8).
type NopFrame struct{}

func (f *NopFrame) FrameType() core.FrameType { return core.FrameTypeNop }

func (f *NopFrame) ToDict() core.FrameDict { return core.FrameDict{} }

func NopFrameFromDict(_ core.FrameDict) *NopFrame { return &NopFrame{} }

// ── ErrorFrame ────────────────────────────────────────────────────────────────

type ErrorFrame struct {
	ErrorCode string
	Message   string
	Detail    any
}

func (f *ErrorFrame) FrameType() core.FrameType { return core.FrameTypeError }

func (f *ErrorFrame) ToDict() core.FrameDict {
	d := core.FrameDict{"error_code": f.ErrorCode, "message": f.Message}
	if f.Detail != nil {
		d["detail"] = f.Detail
	}
	return d
}

func ErrorFrameFromDict(d core.FrameDict) *ErrorFrame {
	return &ErrorFrame{
		ErrorCode: str(d, "error_code"),
		Message:   str(d, "message"),
		Detail:    d["detail"],
	}
}
