// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ncp

import (
	"io"
	"net"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
)

// ErrUnexpectedFirstFrame is raised when the first frame after the preamble is
// not a HelloFrame.
const ErrUnexpectedFirstFrame = "NCP-HANDSHAKE-UNEXPECTED-FRAME"

// NcpServerOptions configures a native-mode NCP server.
type NcpServerOptions struct {
	// AuthenticateConn optionally wraps or authenticates the accepted connection
	// before the NCP preamble is read (e.g. to install TLS/mTLS). If nil, the raw
	// connection is used.
	AuthenticateConn func(net.Conn) (net.Conn, error)

	// RequireAuthenticatedConn, when true, requires AuthenticateConn to return a
	// different connection instance, making accidental plaintext native mode fail
	// fast.
	RequireAuthenticatedConn bool

	// MaxHelloPayload is the maximum payload accepted for the initial HelloFrame.
	// Defaults to the non-extended frame payload ceiling (0xFFFF).
	MaxHelloPayload uint64

	// HandshakeReadTimeout is the wall-clock budget for the preamble, frame
	// read. The name is retained for source compatibility. Zero disables it.
	HandshakeReadTimeout time.Duration

	// HelloReadTimeout is the separate budget for the Hello header and payload.
	// Zero disables it.
	HelloReadTimeout time.Duration

	// HandshakeProfile controls deterministic version, encoding, protocol, and
	// resource-limit negotiation. Nil uses the portable v0.11 defaults.
	HandshakeProfile *NcpHandshakeProfile
}

func (o *NcpServerOptions) withDefaults() NcpServerOptions {
	out := NcpServerOptions{}
	if o != nil {
		out = *o
	}
	if out.MaxHelloPayload == 0 {
		out.MaxHelloPayload = HelloDefaultMaxFramePayload // 0xFFFF
	}
	if out.HandshakeReadTimeout == 0 && (o == nil) {
		out.HandshakeReadTimeout = PreambleReadTimeoutSecs * time.Second
	}
	if out.HelloReadTimeout == 0 && (o == nil) {
		out.HelloReadTimeout = 5 * time.Second
	}
	if out.HandshakeProfile == nil {
		profile := DefaultNcpHandshakeProfile()
		out.HandshakeProfile = &profile
	}
	return out
}

// NcpServer is a native-mode NCP TCP server. It listens on a configured
// endpoint, validates the connection preamble, reads the client's HelloFrame,
// and returns an NcpServerConnection for the application to accept or reject
// (NPS-1 §4.6).
type NcpServer struct {
	listener net.Listener
	codec    *core.NpsFrameCodec
	options  NcpServerOptions
}

// NewNcpServer starts listening on addr (e.g. "127.0.0.1:0") and returns a
// server. codec is shared with accepted connections.
func NewNcpServer(addr string, codec *core.NpsFrameCodec, options *NcpServerOptions) (*NcpServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &NcpServer{listener: ln, codec: codec, options: options.withDefaults()}, nil
}

// Addr returns the address the server is listening on.
func (s *NcpServer) Addr() net.Addr { return s.listener.Addr() }

// Close stops the listener and releases the port binding.
func (s *NcpServer) Close() error { return s.listener.Close() }

// AcceptConnection accepts the next inbound connection, validates the NPS
// preamble, reads the client's HelloFrame, and returns an NcpServerConnection.
func (s *NcpServer) AcceptConnection() (*NcpServerConnection, error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}

	sc, err := s.handshake(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return sc, nil
}

func (s *NcpServer) handshake(rawConn net.Conn) (*NcpServerConnection, error) {
	conn, err := s.authenticate(rawConn)
	if err != nil {
		return nil, err
	}

	if s.options.HandshakeReadTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(s.options.HandshakeReadTimeout))
	}

	// 1 — read & validate preamble.
	preambleBuf := make([]byte, PreambleLength)
	if _, err := io.ReadFull(conn, preambleBuf); err != nil {
		return nil, err
	}
	if err := ValidatePreamble(preambleBuf); err != nil {
		return nil, err
	}

	if s.options.HelloReadTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(s.options.HelloReadTimeout))
	} else {
		_ = conn.SetReadDeadline(time.Time{})
	}

	// 2 — read and validate the frame header before allocating payload.
	header, err := ReadFrameHeader(conn)
	if err != nil {
		return nil, err
	}
	if decision := EvaluateHelloHeader(header, 0, s.options.HelloReadTimeout, s.options.MaxHelloPayload); decision.Action != NcpHandshakeContinue {
		return nil, &core.ErrFrame{Msg: "Invalid native NCP Hello header."}
	}

	// 3 — read payload and deserialise HelloFrame.
	payload := make([]byte, header.PayloadLength)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	// Clear the handshake deadline now that the Hello has been read.
	_ = conn.SetReadDeadline(time.Time{})

	wire := append(header.ToBytes(), payload...)
	_, dict, err := s.codec.Decode(wire)
	if err != nil {
		return nil, err
	}
	hello := HelloFrameFromDict(dict)

	return &NcpServerConnection{
		conn:        conn,
		codec:       s.codec,
		ClientHello: hello,
		profile:     *s.options.HandshakeProfile,
	}, nil
}

func (s *NcpServer) authenticate(conn net.Conn) (net.Conn, error) {
	if s.options.AuthenticateConn == nil {
		if s.options.RequireAuthenticatedConn {
			return nil, &core.ErrFrame{Msg: "NcpServerOptions.RequireAuthenticatedConn is true, but no AuthenticateConn hook is configured."}
		}
		return conn, nil
	}
	authed, err := s.options.AuthenticateConn(conn)
	if err != nil {
		return nil, err
	}
	if authed == nil {
		return nil, &core.ErrFrame{Msg: "NCP connection authentication hook returned nil."}
	}
	if s.options.RequireAuthenticatedConn && authed == conn {
		return nil, &core.ErrFrame{Msg: "NCP connection authentication hook returned the original connection while RequireAuthenticatedConn is true."}
	}
	return authed, nil
}

// NcpServerConnection is the server-side representation of an inbound NCP
// connection that has passed the preamble check and sent its HelloFrame. Call
// Accept to complete the handshake, or Reject to send an error and close.
type NcpServerConnection struct {
	conn  net.Conn
	codec *core.NpsFrameCodec

	// ClientHello is the HelloFrame sent by the connecting client.
	ClientHello *HelloFrame
	profile     NcpHandshakeProfile
}

// Accept sends serverCaps to the client and returns a live NcpSession. The
// encoding policy is negotiated from the client's SupportedEncodings list; the
// serverCaps NegotiatedEncoding and EnabledEncodings fields are overwritten with
// the negotiated values.
func (c *NcpServerConnection) Accept(serverCaps *NcpHandshakeCapsFrame) (*NcpSession, error) {
	decision := NegotiateHandshake(c.profile, c.ClientHello)
	if decision.Action != NcpHandshakeAccept {
		errCode := decision.Error
		if errCode == "" {
			errCode = ErrVersionIncompatible
		}
		status := decision.Status
		if status == "" {
			status = core.NpsProtoVersionIncompatible
		}
		_ = c.Reject(&ErrorFrame{
			ErrorCode: errCode,
			Message:   "Native NCP handshake negotiation failed.",
			Detail:    map[string]any{"status": status},
		})
		return nil, &core.ErrFrame{Msg: "[" + errCode + "] Native NCP handshake negotiation failed."}
	}

	tier := core.EncodingTierJSON
	if decision.NegotiatedEncoding == "msgpack" {
		tier = core.EncodingTierMsgPack
	}
	policy := NewNcpEncodingPolicy(tier, containsToken(decision.EnabledEncodings, "binary_vector.v1"))
	caps := *serverCaps
	caps.NegotiatedEncoding = &decision.NegotiatedEncoding
	caps.EnabledEncodings = decision.EnabledEncodings
	caps.SessionVersion = &decision.SessionVersion
	caps.SupportedProtocols = decision.SupportedProtocols
	caps.MaxFramePayload = decision.MaxFramePayload
	caps.ExtSupport = decision.ExtSupport
	caps.MaxConcurrentStreams = decision.MaxConcurrentStreams

	wire, err := c.codec.Encode(caps.FrameType(), caps.ToDict(), policy.DefaultTier, true)
	if err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(wire); err != nil {
		return nil, err
	}
	sess := newNcpSession(c.conn, &caps, policy)
	sess.SetCodec(c.codec)
	return sess, nil
}

// Reject sends an ErrorFrame to the client and closes the connection.
func (c *NcpServerConnection) Reject(errFrame *ErrorFrame) error {
	wire, err := c.codec.Encode(errFrame.FrameType(), errFrame.ToDict(), core.EncodingTierJSON, true)
	if err == nil {
		_, _ = c.conn.Write(wire)
	}
	return c.conn.Close()
}

// Close closes the underlying connection.
func (c *NcpServerConnection) Close() error { return c.conn.Close() }

// negotiateEncodingPolicy selects a stable default encoding from the client's
// SupportedEncodings list. Optional encodings such as BinaryVector are recorded
// as extensions, not defaults. Mirrors .NET NcpServerConnection.NegotiateEncodingPolicy.
func negotiateEncodingPolicy(hello *HelloFrame) (NcpEncodingPolicy, error) {
	binaryVectorEnabled := containsToken(hello.SupportedEncodings, "binary_vector.v1")
	for _, enc := range hello.SupportedEncodings {
		switch enc {
		case "msgpack":
			return NewNcpEncodingPolicy(core.EncodingTierMsgPack, binaryVectorEnabled), nil
		case "json":
			return NewNcpEncodingPolicy(core.EncodingTierJSON, binaryVectorEnabled), nil
		}
	}
	return NcpEncodingPolicy{}, &core.ErrCodec{Msg: "Client did not offer a supported stable default encoding (expected msgpack or json)."}
}
