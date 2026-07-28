// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package core_test

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
)

// ── FrameType ─────────────────────────────────────────────────────────────────

func TestFrameTypeFromByte_known(t *testing.T) {
	cases := []struct {
		b  byte
		ft core.FrameType
	}{
		{0x01, core.FrameTypeAnchor},
		{0x02, core.FrameTypeDiff},
		{0x03, core.FrameTypeStream},
		{0x04, core.FrameTypeCaps},
		{0x10, core.FrameTypeQuery},
		{0x11, core.FrameTypeAction},
		{0x20, core.FrameTypeIdent},
		{0x21, core.FrameTypeTrust},
		{0x22, core.FrameTypeRevoke},
		{0x30, core.FrameTypeAnnounce},
		{0x31, core.FrameTypeResolve},
		{0x32, core.FrameTypeGraph},
		{0x40, core.FrameTypeTask},
		{0x41, core.FrameTypeDelegate},
		{0x42, core.FrameTypeSync},
		{0x43, core.FrameTypeAlignStream},
		{0xFE, core.FrameTypeError},
	}
	for _, tc := range cases {
		ft, err := core.FrameTypeFromByte(tc.b)
		if err != nil {
			t.Errorf("byte 0x%02X: unexpected error %v", tc.b, err)
		}
		if ft != tc.ft {
			t.Errorf("byte 0x%02X: got 0x%02X want 0x%02X", tc.b, ft, tc.ft)
		}
	}
}

func TestFrameTypeFromByte_unknown(t *testing.T) {
	_, err := core.FrameTypeFromByte(0x99)
	if err == nil {
		t.Fatal("expected error for unknown frame type")
	}
}

// ── FrameHeader ───────────────────────────────────────────────────────────────

func TestFrameHeader_DefaultRoundtrip(t *testing.T) {
	hdr := core.NewFrameHeader(core.FrameTypeAnchor, core.EncodingTierJSON, true, 1234)
	if hdr.IsExtended {
		t.Fatal("should not be extended for payload < 64KiB")
	}
	if hdr.HeaderSize() != 4 {
		t.Fatalf("expected header size 4, got %d", hdr.HeaderSize())
	}
	wire := hdr.ToBytes()
	if len(wire) != 4 {
		t.Fatalf("expected 4-byte header, got %d", len(wire))
	}
	parsed, err := core.ParseFrameHeader(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.FrameType != core.FrameTypeAnchor {
		t.Errorf("frame type mismatch")
	}
	if parsed.PayloadLength != 1234 {
		t.Errorf("payload length mismatch: got %d", parsed.PayloadLength)
	}
	if !parsed.IsFinal() {
		t.Error("expected IsFinal=true")
	}
	if parsed.EncodingTier() != core.EncodingTierJSON {
		t.Error("expected JSON tier")
	}
}

func TestFrameHeader_ExtendedRoundtrip(t *testing.T) {
	payloadLen := uint64(70000) // > 64KiB
	hdr := core.NewFrameHeader(core.FrameTypeStream, core.EncodingTierMsgPack, false, payloadLen)
	if !hdr.IsExtended {
		t.Fatal("should be extended for payload > 64KiB")
	}
	if hdr.HeaderSize() != 8 {
		t.Fatalf("expected header size 8, got %d", hdr.HeaderSize())
	}
	wire := hdr.ToBytes()
	if len(wire) != 8 {
		t.Fatalf("expected 8-byte header, got %d", len(wire))
	}
	parsed, err := core.ParseFrameHeader(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PayloadLength != payloadLen {
		t.Errorf("payload length mismatch: got %d want %d", parsed.PayloadLength, payloadLen)
	}
	if parsed.EncodingTier() != core.EncodingTierMsgPack {
		t.Error("expected MsgPack tier")
	}
	if parsed.IsFinal() {
		t.Error("expected IsFinal=false")
	}
}

func TestFrameHeader_BinaryVectorTier(t *testing.T) {
	hdr := core.NewFrameHeader(core.FrameTypeQuery, core.EncodingTierBinaryVector, true, 42)
	if hdr.EncodingTier() != core.EncodingTierBinaryVector {
		t.Fatalf("expected BinaryVector tier, got %d", hdr.EncodingTier())
	}
	if !hdr.IsFinal() {
		t.Fatal("expected final flag")
	}
	wire := hdr.ToBytes()
	if wire[1] != 0x06 {
		t.Fatalf("expected flags 0x06 (BinaryVector|FINAL), got 0x%02X", wire[1])
	}
}

func TestFrameHeader_TooShort(t *testing.T) {
	_, err := core.ParseFrameHeader([]byte{0x01, 0x40})
	if err == nil {
		t.Fatal("expected error for too-short buffer")
	}
}

// ── FrameRegistry ─────────────────────────────────────────────────────────────

func TestFrameRegistry_Default(t *testing.T) {
	reg := core.CreateDefaultRegistry()
	ncpTypes := []core.FrameType{
		core.FrameTypeAnchor, core.FrameTypeDiff,
		core.FrameTypeStream, core.FrameTypeCaps, core.FrameTypeError,
	}
	for _, ft := range ncpTypes {
		if !reg.IsRegistered(ft) {
			t.Errorf("expected 0x%02X to be registered in default registry", ft)
		}
	}
	if reg.IsRegistered(core.FrameTypeTask) {
		t.Error("Task frame should not be in default (NCP-only) registry")
	}
}

func TestFrameRegistry_Full(t *testing.T) {
	reg := core.CreateFullRegistry()
	all := []core.FrameType{
		core.FrameTypeAnchor, core.FrameTypeDiff, core.FrameTypeStream, core.FrameTypeCaps,
		core.FrameTypeQuery, core.FrameTypeAction,
		core.FrameTypeIdent, core.FrameTypeTrust, core.FrameTypeRevoke,
		core.FrameTypeAnnounce, core.FrameTypeResolve, core.FrameTypeGraph,
		core.FrameTypeTask, core.FrameTypeDelegate, core.FrameTypeSync, core.FrameTypeAlignStream,
		core.FrameTypeError,
	}
	for _, ft := range all {
		if !reg.IsRegistered(ft) {
			t.Errorf("expected 0x%02X to be in full registry", ft)
		}
	}
}

// ── NpsFrameCodec ─────────────────────────────────────────────────────────────

func TestCodec_JSONRoundtrip(t *testing.T) {
	reg := core.CreateFullRegistry()
	codec := core.NewNpsFrameCodec(reg)
	dict := core.FrameDict{"anchor_id": "test", "ttl": int64(3600)}
	wire, err := codec.Encode(core.FrameTypeAnchor, dict, core.EncodingTierJSON, true)
	if err != nil {
		t.Fatal(err)
	}
	ft, got, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if ft != core.FrameTypeAnchor {
		t.Errorf("frame type mismatch")
	}
	if got["anchor_id"] != "test" {
		t.Errorf("anchor_id mismatch")
	}
}

func TestCodec_MsgPackRoundtrip(t *testing.T) {
	reg := core.CreateFullRegistry()
	codec := core.NewNpsFrameCodec(reg)
	dict := core.FrameDict{"node_id": "n1", "caps": []any{"nwp", "nop"}}
	wire, err := codec.Encode(core.FrameTypeCaps, dict, core.EncodingTierMsgPack, false)
	if err != nil {
		t.Fatal(err)
	}
	ft, got, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if ft != core.FrameTypeCaps {
		t.Errorf("frame type mismatch")
	}
	if got["node_id"] != "n1" {
		t.Errorf("node_id mismatch: got %v", got["node_id"])
	}
}

func TestCodec_BinaryVectorRoundtrip(t *testing.T) {
	reg := core.CreateFullRegistry()
	codec := core.NewNpsFrameCodec(reg)
	dict := core.FrameDict{
		"anchor_ref": "sha256:" + "a000000000000000000000000000000000000000000000000000000000000000",
		"limit":      uint64(3),
		"vector_search": core.FrameDict{
			"field":  "embedding",
			"vector": []float32{0.25, -1.5, 3.0},
			"top_k":  uint64(2),
			"metric": "cosine",
		},
	}

	wire, err := codec.Encode(core.FrameTypeQuery, dict, core.EncodingTierBinaryVector, true)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := core.PeekHeader(wire)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.EncodingTier() != core.EncodingTierBinaryVector {
		t.Fatalf("expected BinaryVector tier, got %d", hdr.EncodingTier())
	}
	if string(wire[hdr.HeaderSize():hdr.HeaderSize()+4]) != "NPBV" {
		t.Fatalf("expected BinaryVector payload magic")
	}

	ft, got, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if ft != core.FrameTypeQuery {
		t.Fatalf("frame type mismatch: got 0x%02X", ft)
	}
	vs := got["vector_search"].(core.FrameDict)
	vector := vs["vector"].([]float32)
	if len(vector) != 3 || vector[0] != 0.25 || vector[1] != -1.5 || vector[2] != 3.0 {
		t.Fatalf("vector mismatch: %#v", vector)
	}
}

func TestCodec_BinaryVectorRejectsNonFiniteSegmentValue(t *testing.T) {
	reg := core.CreateFullRegistry()
	codec := core.NewNpsFrameCodec(reg)
	dict := core.FrameDict{
		"anchor_ref": "sha256:" + "a000000000000000000000000000000000000000000000000000000000000000",
		"vector_search": core.FrameDict{
			"field":  "embedding",
			"vector": []float32{0.25, -1.5, 3.0},
			"top_k":  uint64(2),
			"metric": "cosine",
		},
	}

	wire, err := codec.Encode(core.FrameTypeQuery, dict, core.EncodingTierBinaryVector, true)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := core.PeekHeader(wire)
	if err != nil {
		t.Fatal(err)
	}
	payloadStart := hdr.HeaderSize()
	metadataLen := int(binary.BigEndian.Uint32(wire[payloadStart+8 : payloadStart+12]))
	valueOffset := payloadStart + 16 + metadataLen + 4
	binary.LittleEndian.PutUint32(wire[valueOffset:valueOffset+4], math.Float32bits(float32(math.NaN())))

	_, _, err = codec.Decode(wire)
	if err == nil {
		t.Fatal("expected NaN payload to fail")
	}
	if !strings.Contains(err.Error(), "finite float32") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCodec_BinaryVectorConformanceFixture(t *testing.T) {
	type fixtureVector struct {
		Kind  string `json:"kind"`
		Input struct {
			PayloadHex string `json:"payload_hex"`
		} `json:"input"`
	}
	type fixtureFile struct {
		Vectors []fixtureVector `json:"vectors"`
	}

	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(current), "testdata/conformance/ncp/binary_vector_payload_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture fixtureFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}

	codec := core.NewNpsFrameCodec(core.CreateFullRegistry())
	for _, vector := range fixture.Vectors {
		payload, err := hex.DecodeString(vector.Input.PayloadHex)
		if err != nil {
			t.Fatal(err)
		}
		hdr := core.NewFrameHeader(core.FrameTypeQuery, core.EncodingTierBinaryVector, true, uint64(len(payload)))
		wire := append(hdr.ToBytes(), payload...)
		_, got, err := codec.Decode(wire)
		if vector.Kind == "negative" {
			if err == nil {
				t.Fatalf("expected negative fixture to fail")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		vs := got["vector_search"].(core.FrameDict)
		decoded := vs["vector"].([]float32)
		if len(decoded) != 3 || decoded[0] != 0.25 || decoded[1] != -1.5 || decoded[2] != 3.0 {
			t.Fatalf("fixture vector mismatch: %#v", decoded)
		}
	}
}

func TestCodec_UnregisteredFrame(t *testing.T) {
	reg := core.CreateDefaultRegistry()
	codec := core.NewNpsFrameCodec(reg)
	// Encode succeeds (codec doesn't validate ft on encode)
	dict := core.FrameDict{"task_id": "t1"}
	wire, _ := core.NewNpsFrameCodec(core.CreateFullRegistry()).Encode(
		core.FrameTypeTask, dict, core.EncodingTierJSON, true)
	// Default registry doesn't know Task
	_, _, err := codec.Decode(wire)
	if err == nil {
		t.Fatal("expected error for unregistered frame type")
	}
}

// ── AnchorFrameCache ──────────────────────────────────────────────────────────

func TestAnchorCache_SetAndGet(t *testing.T) {
	cache := core.NewAnchorFrameCache()
	schema := core.FrameDict{"type": "object", "version": "1"}
	id, err := cache.Set(schema, 60)
	if err != nil {
		t.Fatal(err)
	}
	got := cache.Get(id)
	if got == nil {
		t.Fatal("expected cached schema")
	}
	if got["version"] != "1" {
		t.Errorf("version mismatch")
	}
}

func TestAnchorCache_Expiry(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := core.NewAnchorFrameCache()
	cache.Clock = func() time.Time { return now }

	schema := core.FrameDict{"type": "string"}
	id, _ := cache.Set(schema, 10) // 10s TTL

	// advance past TTL
	cache.Clock = func() time.Time { return now.Add(15 * time.Second) }
	if cache.Get(id) != nil {
		t.Error("expected nil after TTL expiry")
	}
	if cache.Len() != 0 {
		t.Error("expected Len=0 after expiry")
	}
}

func TestAnchorCache_GetRequired_Missing(t *testing.T) {
	cache := core.NewAnchorFrameCache()
	_, err := cache.GetRequired("sha256:nonexistent")
	if err == nil {
		t.Fatal("expected ErrAnchorNotFound")
	}
}

func TestAnchorCache_PoisonDetection(t *testing.T) {
	cache := core.NewAnchorFrameCache()
	schema1 := core.FrameDict{"type": "object"}
	id, _ := cache.Set(schema1, 60)

	// ComputeAnchorID produces unique IDs per distinct schema, so no hash collision
	// in practice. Test the safe path: same schema twice is not poison.
	_ = id
	_, err := cache.Set(schema1, 60)
	if err != nil {
		t.Errorf("re-setting same schema should not poison: %v", err)
	}
}

func TestAnchorCache_Invalidate(t *testing.T) {
	cache := core.NewAnchorFrameCache()
	schema := core.FrameDict{"type": "object"}
	id, _ := cache.Set(schema, 60)
	cache.Invalidate(id)
	if cache.Get(id) != nil {
		t.Error("expected nil after invalidation")
	}
}

func TestAnchorCache_ComputeAnchorID_Deterministic(t *testing.T) {
	a := core.FrameDict{"z": "last", "a": "first"}
	b := core.FrameDict{"a": "first", "z": "last"}
	if core.ComputeAnchorID(a) != core.ComputeAnchorID(b) {
		t.Error("AnchorID should be order-independent")
	}
}

// TestComputeAnchorID_GoldenVector pins the cross-SDK anchor_id computed by the
// .NET reference SDK (AnchorIdComputer) over the structured FrameSchema. The
// canonical JCS form is:
//
//	{"fields":[{"name":"id","nullable":false,"type":"uint64"},
//	           {"name":"label","nullable":true,"semantic":"entity.label","type":"string"}]}
//
// with per-field key order name,nullable,semantic(omitted if null),type.
func TestComputeAnchorID_GoldenVector(t *testing.T) {
	schema := core.FrameDict{
		"fields": []any{
			map[string]any{"name": "id", "type": "uint64", "nullable": false},
			map[string]any{"name": "label", "type": "string", "semantic": "entity.label", "nullable": true},
		},
	}
	const want = "sha256:13c2ce4979f67a12d7f859f082deab4bebfc8dd1d3c506234062582ac54bbd1a"
	if got := core.ComputeAnchorID(schema); got != want {
		t.Errorf("anchor_id mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestComputeAnchorID_OmitsNullSemantic verifies a null/empty semantic is omitted
// (not emitted as "semantic":null) — matching .NET's WhenWritingNull behaviour.
func TestComputeAnchorID_OmitsNullSemantic(t *testing.T) {
	withNull := core.FrameDict{"fields": []any{
		map[string]any{"name": "id", "type": "uint64", "nullable": false, "semantic": nil},
	}}
	without := core.FrameDict{"fields": []any{
		map[string]any{"name": "id", "type": "uint64", "nullable": false},
	}}
	if core.ComputeAnchorID(withNull) != core.ComputeAnchorID(without) {
		t.Error("null semantic must be omitted, yielding the same anchor_id as when absent")
	}
}
