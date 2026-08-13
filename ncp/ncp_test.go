// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ncp_test

import (
	"testing"

	"github.com/labacacia/NPS-sdk-go/core"
	"github.com/labacacia/NPS-sdk-go/ncp"
)

// ── AnchorFrame ───────────────────────────────────────────────────────────────

func TestAnchorFrame_Roundtrip(t *testing.T) {
	ns := "com.example"
	desc := "User schema"
	nt := "complex"
	f := &ncp.AnchorFrame{
		AnchorID:    "sha256:abc",
		Schema:      core.FrameDict{"type": "object", "version": "1"},
		Namespace:   &ns,
		Description: &desc,
		NodeType:    &nt,
		TTL:         7200,
	}
	d := f.ToDict()
	f2 := ncp.AnchorFrameFromDict(d)
	if f2.AnchorID != "sha256:abc" {
		t.Errorf("AnchorID mismatch")
	}
	if f2.TTL != 7200 {
		t.Errorf("TTL mismatch: got %d", f2.TTL)
	}
	if f2.Namespace == nil || *f2.Namespace != ns {
		t.Errorf("Namespace mismatch")
	}
	if f2.Description == nil || *f2.Description != desc {
		t.Errorf("Description mismatch")
	}
	if f2.NodeType == nil || *f2.NodeType != nt {
		t.Errorf("NodeType mismatch")
	}
}

func TestAnchorFrame_DefaultTTL(t *testing.T) {
	d := core.FrameDict{"anchor_id": "sha256:x", "schema": map[string]any{}}
	f := ncp.AnchorFrameFromDict(d)
	if f.TTL != 3600 {
		t.Errorf("expected default TTL=3600, got %d", f.TTL)
	}
}

func TestAnchorFrame_FrameType(t *testing.T) {
	f := &ncp.AnchorFrame{}
	if f.FrameType() != core.FrameTypeAnchor {
		t.Errorf("wrong frame type: 0x%02X", f.FrameType())
	}
}

// ── DiffFrame ─────────────────────────────────────────────────────────────────

func TestDiffFrame_Roundtrip(t *testing.T) {
	patch := []any{map[string]any{"op": "replace", "path": "/version", "value": "2"}}
	f := &ncp.DiffFrame{
		AnchorID:    "sha256:old",
		NewAnchorID: "sha256:new",
		Patch:       patch,
	}
	d := f.ToDict()
	f2 := ncp.DiffFrameFromDict(d)
	if f2.AnchorID != "sha256:old" {
		t.Errorf("AnchorID mismatch")
	}
	if f2.NewAnchorID != "sha256:new" {
		t.Errorf("NewAnchorID mismatch")
	}
	if len(f2.Patch) != 1 {
		t.Errorf("Patch length mismatch")
	}
}

// ── StreamFrame ───────────────────────────────────────────────────────────────

func TestStreamFrame_Roundtrip(t *testing.T) {
	f := &ncp.StreamFrame{
		AnchorID: "sha256:abc",
		Seq:      5,
		Payload:  map[string]any{"chunk": "data"},
		IsLast:   true,
	}
	d := f.ToDict()
	f2 := ncp.StreamFrameFromDict(d)
	if f2.Seq != 5 {
		t.Errorf("Seq mismatch")
	}
	if !f2.IsLast {
		t.Error("IsLast should be true")
	}
}

// ── CapsFrame ─────────────────────────────────────────────────────────────────

func TestCapsFrame_Roundtrip(t *testing.T) {
	ref := "sha256:abc"
	requestID := "req-caps-1"
	f := &ncp.CapsFrame{
		NodeID:    "urn:nps:node:example.com:n1",
		Caps:      []string{"nwp", "nop", "nip"},
		AnchorRef: &ref,
		Payload:   map[string]any{"meta": "data"},
		RequestID: &requestID,
	}
	d := f.ToDict()
	f2 := ncp.CapsFrameFromDict(d)
	if f2.NodeID != f.NodeID {
		t.Errorf("NodeID mismatch")
	}
	if len(f2.Caps) != 3 {
		t.Errorf("Caps length mismatch: %v", f2.Caps)
	}
	if f2.AnchorRef == nil || *f2.AnchorRef != ref {
		t.Errorf("AnchorRef mismatch")
	}
	if f2.RequestID == nil || *f2.RequestID != requestID {
		t.Errorf("RequestID mismatch")
	}
}

// ── ErrorFrame ────────────────────────────────────────────────────────────────

func TestErrorFrame_Roundtrip(t *testing.T) {
	f := &ncp.ErrorFrame{
		ErrorCode: "NCP-FRAME-TOO-LARGE",
		Message:   "payload exceeds limit",
		Detail:    map[string]any{"max": 65535},
	}
	d := f.ToDict()
	f2 := ncp.ErrorFrameFromDict(d)
	if f2.ErrorCode != "NCP-FRAME-TOO-LARGE" {
		t.Errorf("ErrorCode mismatch")
	}
	if f2.Message != "payload exceeds limit" {
		t.Errorf("Message mismatch")
	}
	if f2.Detail == nil {
		t.Error("Detail should not be nil")
	}
}

// ── HelloFrame ────────────────────────────────────────────────────────────────

func TestHelloFrame_FrameType(t *testing.T) {
	f := &ncp.HelloFrame{}
	if f.FrameType() != core.FrameTypeHello {
		t.Errorf("wrong frame type: 0x%02X", f.FrameType())
	}
	if byte(core.FrameTypeHello) != 0x06 {
		t.Errorf("HELLO frame code must be 0x06, got 0x%02X", byte(core.FrameTypeHello))
	}
}

func TestHelloFrame_DefaultRegistry_ContainsHello(t *testing.T) {
	reg := core.CreateDefaultRegistry()
	if !reg.IsRegistered(core.FrameTypeHello) {
		t.Error("HELLO must be registered in default registry")
	}
}

func TestHelloFrame_FullRoundtrip_JSON(t *testing.T) {
	minVer := "0.1"
	agent := "urn:nps:agent:example.com:hello-1"
	f := &ncp.HelloFrame{
		NpsVersion:           "0.2",
		SupportedEncodings:   []string{"tier-1", "tier-2"},
		SupportedProtocols:   []string{"ncp", "nwp", "nip"},
		MinVersion:           &minVer,
		AgentID:              &agent,
		MaxFramePayload:      0xFFFF,
		ExtSupport:           true,
		MaxConcurrentStreams: 64,
		E2eEncAlgorithms:     []string{"aes-256-gcm"},
	}

	reg := core.CreateDefaultRegistry()
	codec := core.NewNpsFrameCodec(reg)
	// Handshake: always JSON since encoding not yet negotiated.
	wire, err := codec.Encode(f.FrameType(), f.ToDict(), core.EncodingTierJSON, true)
	if err != nil {
		t.Fatal(err)
	}
	ft, dict, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if ft != core.FrameTypeHello {
		t.Errorf("frame type mismatch: 0x%02X", ft)
	}
	f2 := ncp.HelloFrameFromDict(dict)
	if f2.NpsVersion != "0.2" {
		t.Errorf("nps_version mismatch: %s", f2.NpsVersion)
	}
	if len(f2.SupportedEncodings) != 2 || f2.SupportedEncodings[0] != "tier-1" {
		t.Errorf("supported_encodings mismatch: %v", f2.SupportedEncodings)
	}
	if f2.MinVersion == nil || *f2.MinVersion != "0.1" {
		t.Errorf("min_version mismatch")
	}
	if f2.AgentID == nil || *f2.AgentID != agent {
		t.Errorf("agent_id mismatch")
	}
	if !f2.ExtSupport {
		t.Error("ext_support should be true")
	}
	if f2.MaxConcurrentStreams != 64 {
		t.Errorf("max_concurrent_streams mismatch: %d", f2.MaxConcurrentStreams)
	}
	if len(f2.E2eEncAlgorithms) != 1 || f2.E2eEncAlgorithms[0] != "aes-256-gcm" {
		t.Errorf("e2e_enc_algorithms mismatch: %v", f2.E2eEncAlgorithms)
	}
}

func TestHelloFrame_MinimalRoundtrip_MsgPack(t *testing.T) {
	f := &ncp.HelloFrame{
		NpsVersion:         "0.2",
		SupportedEncodings: []string{"tier-1"},
		SupportedProtocols: []string{"ncp"},
	}

	reg := core.CreateDefaultRegistry()
	codec := core.NewNpsFrameCodec(reg)
	wire, err := codec.Encode(f.FrameType(), f.ToDict(), core.EncodingTierMsgPack, true)
	if err != nil {
		t.Fatal(err)
	}
	_, dict, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	f2 := ncp.HelloFrameFromDict(dict)
	if f2.MinVersion != nil {
		t.Error("min_version should be nil")
	}
	if f2.AgentID != nil {
		t.Error("agent_id should be nil")
	}
	if f2.E2eEncAlgorithms != nil {
		t.Error("e2e_enc_algorithms should be nil")
	}
	if f2.ExtSupport {
		t.Error("ext_support should default to false")
	}
	if f2.MaxFramePayload != ncp.HelloDefaultMaxFramePayload {
		t.Errorf("max_frame_payload should default to 0xFFFF, got %d", f2.MaxFramePayload)
	}
	if f2.MaxConcurrentStreams != ncp.HelloDefaultMaxConcurrentStreams {
		t.Errorf("max_concurrent_streams should default to 32, got %d", f2.MaxConcurrentStreams)
	}
}

// ── Codec integration with NCP frames ─────────────────────────────────────────

func TestCodec_AnchorFrame_MsgPack(t *testing.T) {
	reg := core.CreateFullRegistry()
	codec := core.NewNpsFrameCodec(reg)

	f := &ncp.AnchorFrame{
		AnchorID: "sha256:test",
		Schema:   core.FrameDict{"type": "object"},
		TTL:      3600,
	}
	wire, err := codec.Encode(f.FrameType(), f.ToDict(), core.EncodingTierMsgPack, true)
	if err != nil {
		t.Fatal(err)
	}
	ft, dict, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if ft != core.FrameTypeAnchor {
		t.Errorf("frame type mismatch")
	}
	f2 := ncp.AnchorFrameFromDict(dict)
	if f2.AnchorID != "sha256:test" {
		t.Errorf("AnchorID mismatch after codec roundtrip")
	}
}
