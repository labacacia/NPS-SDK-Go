// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ncp_test

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
	"github.com/labacacia/NPS-sdk-go/ncp"
)

func newCodec() *core.NpsFrameCodec {
	return core.NewNpsFrameCodec(core.CreateFullRegistry())
}

func hostPort(t *testing.T, addr net.Addr) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return h, port
}

// startServer boots a loopback NcpServer and runs handler against the first
// accepted connection on a goroutine. errCh reports the handler's result.
func startServer(t *testing.T, handler func(*ncp.NcpServerConnection) error) (*ncp.NcpServer, <-chan error) {
	t.Helper()
	srv, err := ncp.NewNcpServer("127.0.0.1:0", newCodec(), nil)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		sc, err := srv.AcceptConnection()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- handler(sc)
	}()
	return srv, errCh
}

func clientHello() *ncp.HelloFrame {
	return &ncp.HelloFrame{
		NpsVersion:         "0.2",
		SupportedEncodings: []string{"json", "msgpack"},
		SupportedProtocols: []string{"ncp", "nwp"},
	}
}

func serverCaps() *ncp.NcpHandshakeCapsFrame {
	return &ncp.NcpHandshakeCapsFrame{
		NodeID: "urn:nps:node:example.com:n1",
		Caps:   []string{"ncp", "nwp", "nip"},
	}
}

// ── Handshake happy path ──────────────────────────────────────────────────────

func TestHandshake_HappyPath(t *testing.T) {
	srv, errCh := startServer(t, func(sc *ncp.NcpServerConnection) error {
		if sc.ClientHello.NpsVersion != "0.2" {
			t.Errorf("server saw wrong nps_version: %s", sc.ClientHello.NpsVersion)
		}
		sess, err := sc.Accept(serverCaps())
		if err != nil {
			return err
		}
		defer sess.Close()
		return nil
	})
	defer srv.Close()

	host, port := hostPort(t, srv.Addr())
	client := ncp.NewNcpNativeClient(newCodec())
	sess, err := client.Connect(host, port, clientHello())
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer sess.Close()

	if sess.ServerCaps.NodeID != "urn:nps:node:example.com:n1" {
		t.Errorf("wrong server node id: %s", sess.ServerCaps.NodeID)
	}
	if len(sess.ServerCaps.Caps) != 3 {
		t.Errorf("wrong caps: %v", sess.ServerCaps.Caps)
	}
	if sess.ServerCaps.SessionVersion == nil || *sess.ServerCaps.SessionVersion != "0.2" {
		t.Errorf("wrong session version: %v", sess.ServerCaps.SessionVersion)
	}
	if sess.ServerCaps.MaxFramePayload == nil ||
		*sess.ServerCaps.MaxFramePayload != ncp.HelloDefaultMaxFramePayload {
		t.Errorf("wrong max frame payload: %v", sess.ServerCaps.MaxFramePayload)
	}
	if !sess.IsConnected() {
		t.Error("session should report connected")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handler: %v", err)
	}
}

// ── Encoding negotiation: msgpack preferred → default tier MsgPack ────────────

func TestHandshake_EncodingNegotiation_MsgPack(t *testing.T) {
	srv, errCh := startServer(t, func(sc *ncp.NcpServerConnection) error {
		sess, err := sc.Accept(serverCaps())
		if err != nil {
			return err
		}
		defer sess.Close()
		return nil
	})
	defer srv.Close()

	host, port := hostPort(t, srv.Addr())
	client := ncp.NewNcpNativeClient(newCodec())
	hello := clientHello()
	// Order msgpack first so the server picks MsgPack as the stable default.
	hello.SupportedEncodings = []string{"msgpack", "json"}
	sess, err := client.Connect(host, port, hello)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer sess.Close()

	if sess.NegotiatedTier() != core.EncodingTierMsgPack {
		t.Errorf("expected negotiated MsgPack, got %d", sess.NegotiatedTier())
	}
	if sess.ServerCaps.NegotiatedEncoding == nil || *sess.ServerCaps.NegotiatedEncoding != "msgpack" {
		t.Errorf("expected negotiated_encoding=msgpack, got %v", sess.ServerCaps.NegotiatedEncoding)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handler: %v", err)
	}
}

func TestHandshake_EncodingNegotiation_BinaryVectorExtension(t *testing.T) {
	srv, errCh := startServer(t, func(sc *ncp.NcpServerConnection) error {
		sess, err := sc.Accept(serverCaps())
		if err != nil {
			return err
		}
		defer sess.Close()
		return nil
	})
	defer srv.Close()

	host, port := hostPort(t, srv.Addr())
	client := ncp.NewNcpNativeClient(newCodec())
	hello := clientHello()
	hello.SupportedEncodings = []string{"json", "binary_vector.v1"}
	sess, err := client.Connect(host, port, hello)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer sess.Close()

	if sess.NegotiatedTier() != core.EncodingTierJSON {
		t.Errorf("expected default JSON, got %d", sess.NegotiatedTier())
	}
	if !sess.EncodingPolicy.BinaryVectorEnabled {
		t.Error("binary vector extension should be enabled")
	}
	enabled := sess.ServerCaps.EnabledEncodings
	if len(enabled) != 2 || enabled[0] != "json" || enabled[1] != "binary_vector.v1" {
		t.Errorf("enabled encodings mismatch: %v", enabled)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handler: %v", err)
	}
}

// ── Server rejection → NcpHandshakeError ─────────────────────────────────────

func TestHandshake_ServerRejection(t *testing.T) {
	srv, errCh := startServer(t, func(sc *ncp.NcpServerConnection) error {
		return sc.Reject(&ncp.ErrorFrame{
			ErrorCode: ncp.ErrVersionIncompatible,
			Message:   "nps 0.2 not supported",
		})
	})
	defer srv.Close()

	host, port := hostPort(t, srv.Addr())
	client := ncp.NewNcpNativeClient(newCodec())
	_, err := client.Connect(host, port, clientHello())
	if err == nil {
		t.Fatal("expected handshake error, got nil")
	}
	he, ok := err.(*ncp.NcpHandshakeError)
	if !ok {
		t.Fatalf("expected *NcpHandshakeError, got %T: %v", err, err)
	}
	if he.ErrorCode != ncp.ErrVersionIncompatible {
		t.Errorf("wrong error code: %s", he.ErrorCode)
	}
	if he.Message != "nps 0.2 not supported" {
		t.Errorf("wrong message: %s", he.Message)
	}
	<-errCh
}

// ── EXT header round-trip via ReadFrameHeader over a real socket ─────────────

func TestExtHeader_RoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A payload > 0xFFFF forces the extended (8-byte) header.
	bigPayload := make([]byte, 0x10000)
	hdr := core.NewFrameHeader(core.FrameTypeStream, core.EncodingTierJSON, false, uint64(len(bigPayload)))
	if !hdr.IsExtended {
		t.Fatal("expected extended header for >64KiB payload")
	}

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write(hdr.ToBytes())
		_, _ = c.Write(bigPayload)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got, err := ncp.ReadFrameHeader(conn)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if !got.IsExtended {
		t.Error("parsed header should be extended")
	}
	if got.FrameType != core.FrameTypeStream {
		t.Errorf("frame type mismatch: 0x%02X", got.FrameType)
	}
	if got.PayloadLength != uint64(len(bigPayload)) {
		t.Errorf("payload length mismatch: %d", got.PayloadLength)
	}
}

// ── Live-session frame exchange ──────────────────────────────────────────────

func TestSession_FrameExchange(t *testing.T) {
	srv, errCh := startServer(t, func(sc *ncp.NcpServerConnection) error {
		sess, err := sc.Accept(serverCaps())
		if err != nil {
			return err
		}
		defer sess.Close()
		// Echo one frame: read an AnchorFrame, reply with a CapsFrame.
		ft, dict, err := sess.Receive()
		if err != nil {
			return err
		}
		if ft != core.FrameTypeAnchor {
			t.Errorf("server expected Anchor, got 0x%02X", ft)
		}
		anchor := ncp.AnchorFrameFromDict(dict)
		ref := anchor.AnchorID
		return sess.SendDefault(&ncp.CapsFrame{AnchorRef: &ref, Data: []any{"ok"}}, true)
	})
	defer srv.Close()

	host, port := hostPort(t, srv.Addr())
	codec := newCodec()
	client := ncp.NewNcpNativeClient(codec)
	sess, err := client.Connect(host, port, clientHello())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()
	sess.SetCodec(codec) // client sessions need a codec for Send/Receive

	if err := sess.SendDefault(&ncp.AnchorFrame{AnchorID: "sha256:abc", Schema: core.FrameDict{"t": "o"}, TTL: 60}, true); err != nil {
		t.Fatalf("send anchor: %v", err)
	}
	ft, dict, err := sess.Receive()
	if err != nil {
		t.Fatalf("receive caps: %v", err)
	}
	if ft != core.FrameTypeCaps {
		t.Fatalf("expected Caps reply, got 0x%02X", ft)
	}
	caps := ncp.CapsFrameFromDict(dict)
	if caps.AnchorRef == nil || *caps.AnchorRef != "sha256:abc" {
		t.Errorf("caps anchor_ref mismatch: %v", caps.AnchorRef)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handler: %v", err)
	}
}

// ── Invalid preamble rejected by the server ──────────────────────────────────

func TestServer_InvalidPreamble(t *testing.T) {
	srv, errCh := startServer(t, func(sc *ncp.NcpServerConnection) error {
		return nil
	})
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GARBAGE!"))

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected preamble error from server")
		}
		if _, ok := err.(*ncp.ErrPreambleInvalid); !ok {
			t.Fatalf("expected *ErrPreambleInvalid, got %T: %v", err, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not reject invalid preamble in time")
	}
}

// ── NcpEncodingPolicy allow/deny ─────────────────────────────────────────────

func TestEncodingPolicy_AllowDeny(t *testing.T) {
	// Default MsgPack, binary vector extension enabled.
	p := ncp.NewNcpEncodingPolicy(core.EncodingTierMsgPack, true)

	if !p.Allows(core.EncodingTierMsgPack, core.FrameTypeAnchor) {
		t.Error("default tier must be allowed for any frame")
	}
	// BinaryVector is only allowed for the Query frame class.
	if !p.Allows(core.EncodingTierBinaryVector, core.FrameTypeQuery) {
		t.Error("binary vector must be allowed for Query when enabled")
	}
	if p.Allows(core.EncodingTierBinaryVector, core.FrameTypeAnchor) {
		t.Error("binary vector must be denied for non-Query frames")
	}
	// A non-default tier that isn't the binary-vector extension is denied.
	if p.Allows(core.EncodingTierJSON, core.FrameTypeAnchor) {
		t.Error("JSON must be denied when default is MsgPack")
	}

	// EnsureAllows: violation returns an error.
	badHdr := core.NewFrameHeader(core.FrameTypeAnchor, core.EncodingTierJSON, false, 0)
	if err := p.EnsureAllows(badHdr); err == nil {
		t.Error("EnsureAllows should reject JSON anchor under MsgPack policy")
	}
	okHdr := core.NewFrameHeader(core.FrameTypeAnchor, core.EncodingTierMsgPack, false, 0)
	if err := p.EnsureAllows(okHdr); err != nil {
		t.Errorf("EnsureAllows should permit MsgPack anchor: %v", err)
	}

	// FromEnabledEncodings mirrors the wire tokens.
	fp := ncp.NcpEncodingPolicyFromEnabledEncodings(core.EncodingTierJSON, []string{"json", "binary_vector.v1"})
	if !fp.BinaryVectorEnabled {
		t.Error("FromEnabledEncodings should detect binary_vector.v1")
	}
	got := fp.EnabledEncodings()
	if len(got) != 2 || got[0] != "json" || got[1] != "binary_vector.v1" {
		t.Errorf("EnabledEncodings mismatch: %v", got)
	}
}

func TestEncodingToken(t *testing.T) {
	cases := map[core.EncodingTier]string{
		core.EncodingTierJSON:         "json",
		core.EncodingTierMsgPack:      "msgpack",
		core.EncodingTierBinaryVector: "binary_vector.v1",
	}
	for tier, want := range cases {
		if got := ncp.EncodingToken(tier); got != want {
			t.Errorf("EncodingToken(%d) = %s, want %s", tier, got, want)
		}
	}
}

// ── NcpPatchFormat ───────────────────────────────────────────────────────────

func TestPatchFormat_Validate(t *testing.T) {
	if ncp.PatchFormatJSONPatch != "json_patch" {
		t.Errorf("json_patch constant mismatch: %s", ncp.PatchFormatJSONPatch)
	}
	if ncp.PatchFormatBinaryBitset != "binary_bitset" {
		t.Errorf("binary_bitset constant mismatch: %s", ncp.PatchFormatBinaryBitset)
	}

	// json_patch is valid on any tier.
	if err := ncp.ValidatePatchFormat(ncp.PatchFormatJSONPatch, core.EncodingTierJSON); err != nil {
		t.Errorf("json_patch on JSON should be valid: %v", err)
	}
	if err := ncp.ValidatePatchFormat(ncp.PatchFormatJSONPatch, core.EncodingTierMsgPack); err != nil {
		t.Errorf("json_patch on MsgPack should be valid: %v", err)
	}

	// binary_bitset requires Tier-2 MsgPack.
	if err := ncp.ValidatePatchFormat(ncp.PatchFormatBinaryBitset, core.EncodingTierMsgPack); err != nil {
		t.Errorf("binary_bitset on MsgPack should be valid: %v", err)
	}
	if err := ncp.ValidatePatchFormat(ncp.PatchFormatBinaryBitset, core.EncodingTierJSON); err == nil {
		t.Error("binary_bitset on JSON must be rejected")
	}

	// Unknown format rejected.
	if err := ncp.ValidatePatchFormat("bogus", core.EncodingTierMsgPack); err == nil {
		t.Error("unknown patch format must be rejected")
	}
}

// ── NcpHandshakeCapsFrame round-trip ─────────────────────────────────────────

func TestNcpHandshakeCapsFrame_Roundtrip(t *testing.T) {
	neg := "msgpack"
	ref := "sha256:root"
	f := &ncp.NcpHandshakeCapsFrame{
		NodeID:             "urn:nps:node:example.com:n1",
		Caps:               []string{"ncp", "nwp"},
		NegotiatedEncoding: &neg,
		EnabledEncodings:   []string{"msgpack", "binary_vector.v1"},
		AnchorRef:          &ref,
		Payload:            map[string]any{"k": "v"},
	}
	f2 := ncp.NcpHandshakeCapsFrameFromDict(f.ToDict())
	if f2.NodeID != f.NodeID {
		t.Errorf("node id mismatch")
	}
	if len(f2.Caps) != 2 {
		t.Errorf("caps mismatch: %v", f2.Caps)
	}
	if f2.NegotiatedEncoding == nil || *f2.NegotiatedEncoding != "msgpack" {
		t.Errorf("negotiated encoding mismatch")
	}
	if len(f2.EnabledEncodings) != 2 {
		t.Errorf("enabled encodings mismatch: %v", f2.EnabledEncodings)
	}
	if f2.AnchorRef == nil || *f2.AnchorRef != ref {
		t.Errorf("anchor ref mismatch")
	}
}
