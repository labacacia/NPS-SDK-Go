// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ncp_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
	"github.com/labacacia/NPS-sdk-go/ncp"
)

type handshakeFixture struct {
	Vectors []struct {
		ID    string `json:"id"`
		Input struct {
			Server struct {
				MinVersion           string   `json:"min_version"`
				NpsVersion           string   `json:"nps_version"`
				SupportedEncodings   []string `json:"supported_encodings"`
				SupportedProtocols   []string `json:"supported_protocols"`
				MaxFramePayload      uint64   `json:"max_frame_payload"`
				ExtSupport           bool     `json:"ext_support"`
				MaxConcurrentStreams uint64   `json:"max_concurrent_streams"`
				MaxHelloPayload      uint64   `json:"max_hello_payload"`
				PreambleTimeoutMs    uint64   `json:"preamble_timeout_ms"`
				HelloTimeoutMs       uint64   `json:"hello_timeout_ms"`
			} `json:"server"`
			Transport struct {
				PreambleHex         string `json:"preamble_hex"`
				PreambleElapsedMs   uint64 `json:"preamble_elapsed_ms"`
				FirstFrameType      string `json:"first_frame_type"`
				FirstFrameTier      string `json:"first_frame_tier"`
				FirstFrameEncrypted bool   `json:"first_frame_encrypted"`
				FirstFrameExtended  bool   `json:"first_frame_extended"`
				HelloPayloadLength  uint64 `json:"hello_payload_length"`
				HelloElapsedMs      uint64 `json:"hello_elapsed_ms"`
			} `json:"transport"`
			Hello struct {
				MinVersion           string   `json:"min_version"`
				NpsVersion           string   `json:"nps_version"`
				SupportedEncodings   []string `json:"supported_encodings"`
				SupportedProtocols   []string `json:"supported_protocols"`
				MaxFramePayload      uint64   `json:"max_frame_payload"`
				ExtSupport           bool     `json:"ext_support"`
				MaxConcurrentStreams uint64   `json:"max_concurrent_streams"`
			} `json:"hello"`
		} `json:"input"`
		Expected struct {
			Action               ncp.NcpHandshakeAction `json:"action"`
			Status               string                 `json:"status"`
			Error                string                 `json:"error"`
			DiagnosticError      string                 `json:"diagnostic_error"`
			SessionVersion       string                 `json:"session_version"`
			NegotiatedEncoding   string                 `json:"negotiated_encoding"`
			EnabledEncodings     []string               `json:"enabled_encodings"`
			SupportedProtocols   []string               `json:"supported_protocols"`
			MaxFramePayload      uint64                 `json:"max_frame_payload"`
			ExtSupport           bool                   `json:"ext_support"`
			MaxConcurrentStreams uint64                 `json:"max_concurrent_streams"`
		} `json:"expected"`
	} `json:"vectors"`
}

func TestAlpha17PortableHandshakeVectors(t *testing.T) {
	var fixture handshakeFixture
	readFixture(t, "native_server_handshake_vectors.json", &fixture)
	for _, vector := range fixture.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			server := vector.Input.Server
			transport := vector.Input.Transport
			preamble, err := hex.DecodeString(transport.PreambleHex)
			if err != nil {
				t.Fatal(err)
			}
			decision := ncp.EvaluatePreamble(
				preamble,
				time.Duration(transport.PreambleElapsedMs)*time.Millisecond,
				time.Duration(server.PreambleTimeoutMs)*time.Millisecond,
			)
			if decision.Action == ncp.NcpHandshakeSilentClose {
				assertHandshakeDecision(t, decision, vector.Expected)
				return
			}

			frameByte, err := strconv.ParseUint(strings.TrimPrefix(transport.FirstFrameType, "0x"), 16, 8)
			if err != nil {
				t.Fatal(err)
			}
			tier := core.EncodingTierJSON
			if transport.FirstFrameTier == "msgpack" {
				tier = core.EncodingTierMsgPack
			}
			header := core.NewFrameHeader(
				core.FrameType(frameByte), tier, true, transport.HelloPayloadLength)
			if transport.FirstFrameEncrypted {
				header.Flags |= 0x08
			}
			if transport.FirstFrameExtended {
				header.Flags |= 0x80
				header.IsExtended = true
			}
			decision = ncp.EvaluateHelloHeader(
				header,
				time.Duration(transport.HelloElapsedMs)*time.Millisecond,
				time.Duration(server.HelloTimeoutMs)*time.Millisecond,
				server.MaxHelloPayload,
			)
			if decision.Action == ncp.NcpHandshakeSilentClose {
				assertHandshakeDecision(t, decision, vector.Expected)
				return
			}

			helloFixture := vector.Input.Hello
			var minVersion *string
			if helloFixture.MinVersion != "" {
				minVersion = &helloFixture.MinVersion
			}
			decision = ncp.NegotiateHandshake(ncp.NcpHandshakeProfile{
				MinVersion:           server.MinVersion,
				NpsVersion:           server.NpsVersion,
				SupportedEncodings:   server.SupportedEncodings,
				SupportedProtocols:   server.SupportedProtocols,
				MaxFramePayload:      server.MaxFramePayload,
				ExtSupport:           server.ExtSupport,
				MaxConcurrentStreams: server.MaxConcurrentStreams,
			}, &ncp.HelloFrame{
				MinVersion:           minVersion,
				NpsVersion:           helloFixture.NpsVersion,
				SupportedEncodings:   helloFixture.SupportedEncodings,
				SupportedProtocols:   helloFixture.SupportedProtocols,
				MaxFramePayload:      helloFixture.MaxFramePayload,
				ExtSupport:           helloFixture.ExtSupport,
				MaxConcurrentStreams: helloFixture.MaxConcurrentStreams,
			})
			assertHandshakeDecision(t, decision, vector.Expected)
		})
	}
}

func assertHandshakeDecision(t *testing.T, actual ncp.NcpHandshakeDecision, expected struct {
	Action               ncp.NcpHandshakeAction `json:"action"`
	Status               string                 `json:"status"`
	Error                string                 `json:"error"`
	DiagnosticError      string                 `json:"diagnostic_error"`
	SessionVersion       string                 `json:"session_version"`
	NegotiatedEncoding   string                 `json:"negotiated_encoding"`
	EnabledEncodings     []string               `json:"enabled_encodings"`
	SupportedProtocols   []string               `json:"supported_protocols"`
	MaxFramePayload      uint64                 `json:"max_frame_payload"`
	ExtSupport           bool                   `json:"ext_support"`
	MaxConcurrentStreams uint64                 `json:"max_concurrent_streams"`
}) {
	t.Helper()
	if actual.Action != expected.Action || actual.Status != expected.Status ||
		actual.Error != expected.Error || actual.DiagnosticError != expected.DiagnosticError {
		t.Fatalf("decision mismatch: got %#v want %#v", actual, expected)
	}
	if actual.Action != ncp.NcpHandshakeAccept {
		return
	}
	if actual.SessionVersion != expected.SessionVersion ||
		actual.NegotiatedEncoding != expected.NegotiatedEncoding ||
		!reflect.DeepEqual(actual.EnabledEncodings, expected.EnabledEncodings) ||
		!reflect.DeepEqual(actual.SupportedProtocols, expected.SupportedProtocols) ||
		actual.MaxFramePayload == nil || *actual.MaxFramePayload != expected.MaxFramePayload ||
		actual.ExtSupport == nil || *actual.ExtSupport != expected.ExtSupport ||
		actual.MaxConcurrentStreams == nil || *actual.MaxConcurrentStreams != expected.MaxConcurrentStreams {
		t.Fatalf("negotiation mismatch: got %#v want %#v", actual, expected)
	}
}

func readFixture(t *testing.T, name string, out any) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path, err := testfixture.ConformanceFile(file, "ncp", name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
}
