// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/labacacia/NPS-sdk-go/core"
	"github.com/labacacia/NPS-sdk-go/ncp"
	"github.com/labacacia/NPS-sdk-go/nwp"
)

type scriptedReadWriter struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func newScriptedReadWriter(input []byte) *scriptedReadWriter {
	return &scriptedReadWriter{input: bytes.NewReader(input)}
}

func (rw *scriptedReadWriter) Read(p []byte) (int, error) {
	return rw.input.Read(p)
}

func (rw *scriptedReadWriter) Write(p []byte) (int, error) {
	return rw.output.Write(p)
}

func TestNativeServerDispatchWireQuery(t *testing.T) {
	codec := core.NewNpsFrameCodec(core.CreateFullRegistry())
	server := nwp.NewNwpNativeNodeServer()
	server.QueryHandler = func(_ context.Context, _ *nwp.QueryFrame) (*ncp.CapsFrame, error) {
		return ncp.NewCapsFrame("native:test", []any{map[string]any{"id": 42}}), nil
	}
	requestID := "req-query-1"
	wire, err := codec.Encode(core.FrameTypeQuery, (&nwp.QueryFrame{AnchorRef: "sha256:a", RequestID: &requestID}).ToDict(), core.EncodingTierMsgPack, true)
	if err != nil {
		t.Fatal(err)
	}
	out, err := server.DispatchWire(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	ft, dict, err := codec.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if ft != core.FrameTypeCaps {
		t.Fatalf("expected CapsFrame, got 0x%02X", ft)
	}
	caps := ncp.CapsFrameFromDict(dict)
	if caps.Count != 1 {
		t.Fatalf("count = %d", caps.Count)
	}
	if caps.RequestID == nil || *caps.RequestID != requestID {
		t.Fatalf("request_id = %v", caps.RequestID)
	}
}

func TestNativeServerServeReadsMsgPackFrame(t *testing.T) {
	codec := core.NewNpsFrameCodec(core.CreateFullRegistry())
	server := nwp.NewNwpNativeNodeServer()
	server.QueryHandler = func(_ context.Context, _ *nwp.QueryFrame) (*ncp.CapsFrame, error) {
		return ncp.NewCapsFrame("native:test", []any{map[string]any{"id": 42}}), nil
	}
	wire, err := codec.Encode(core.FrameTypeQuery, (&nwp.QueryFrame{AnchorRef: "sha256:a"}).ToDict(), core.EncodingTierMsgPack, true)
	if err != nil {
		t.Fatal(err)
	}

	rw := newScriptedReadWriter(wire)
	if err := server.Serve(context.Background(), rw); err != nil {
		t.Fatal(err)
	}
	ft, dict, err := codec.Decode(rw.output.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if ft != core.FrameTypeCaps {
		t.Fatalf("expected CapsFrame, got 0x%02X", ft)
	}
	if ncp.CapsFrameFromDict(dict).Count != 1 {
		t.Fatalf("unexpected caps: %+v", dict)
	}
}

func TestNativeServerDispatchWireAcceptsActionID(t *testing.T) {
	codec := core.NewNpsFrameCodec(core.CreateFullRegistry())
	server := nwp.NewNwpNativeNodeServer()
	server.ActionHandler = func(_ context.Context, frame *nwp.ActionFrame) (any, error) {
		return map[string]any{"action": frame.Action}, nil
	}
	requestID := "req-action-1"
	wire, err := codec.Encode(core.FrameTypeAction, core.FrameDict{"action_id": "ping", "request_id": requestID}, core.EncodingTierMsgPack, true)
	if err != nil {
		t.Fatal(err)
	}
	out, err := server.DispatchWire(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	_, dict, err := codec.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	caps := ncp.CapsFrameFromDict(dict)
	if caps.Data[0].(map[string]any)["action"] != "ping" {
		t.Fatalf("unexpected caps data: %+v", caps.Data)
	}
	if caps.RequestID == nil || *caps.RequestID != requestID {
		t.Fatalf("request_id = %v", caps.RequestID)
	}
}

func TestNativeServerRejectsUnnegotiatedBinaryVector(t *testing.T) {
	codec := core.NewNpsFrameCodec(core.CreateFullRegistry())
	server := nwp.NewNwpNativeNodeServer()
	server.QueryHandler = func(_ context.Context, _ *nwp.QueryFrame) (*ncp.CapsFrame, error) {
		return ncp.NewCapsFrame("native:test", []any{map[string]any{"id": 42}}), nil
	}
	wire, err := codec.Encode(core.FrameTypeQuery, vectorQueryDict(), core.EncodingTierBinaryVector, true)
	if err != nil {
		t.Fatal(err)
	}
	out, err := server.DispatchWire(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	ft, dict, err := codec.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if ft != core.FrameTypeError {
		t.Fatalf("expected ErrorFrame, got 0x%02X", ft)
	}
	if dict["error"] != ncp.ErrEncodingUnsupported {
		t.Fatalf("unexpected error: %+v", dict)
	}
}

func TestNativeServerAllowsNegotiatedBinaryVectorQuery(t *testing.T) {
	codec := core.NewNpsFrameCodec(core.CreateFullRegistry())
	server := nwp.NewNwpNativeNodeServer()
	server.EnabledEncodings = []string{"msgpack", "binary_vector.v1"}
	server.QueryHandler = func(_ context.Context, _ *nwp.QueryFrame) (*ncp.CapsFrame, error) {
		return ncp.NewCapsFrame("native:test", []any{map[string]any{"id": 42}}), nil
	}
	wire, err := codec.Encode(core.FrameTypeQuery, vectorQueryDict(), core.EncodingTierBinaryVector, true)
	if err != nil {
		t.Fatal(err)
	}
	out, err := server.DispatchWire(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	ft, dict, err := codec.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if ft != core.FrameTypeCaps {
		t.Fatalf("expected CapsFrame, got 0x%02X", ft)
	}
	if ncp.CapsFrameFromDict(dict).Count != 1 {
		t.Fatalf("unexpected caps: %+v", dict)
	}
}

func vectorQueryDict() core.FrameDict {
	return core.FrameDict{
		"limit": uint64(1),
		"vector_search": map[string]any{
			"field":  "embedding",
			"vector": []float32{0.25, -1.5, 3.0},
			"top_k":  uint64(1),
		},
	}
}
