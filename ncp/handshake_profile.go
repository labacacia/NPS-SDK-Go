// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ncp

import (
	"strconv"
	"strings"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
)

// NcpHandshakeProfile describes server capabilities used for deterministic
// native NCP negotiation.
type NcpHandshakeProfile struct {
	MinVersion           string
	NpsVersion           string
	SupportedEncodings   []string
	SupportedProtocols   []string
	MaxFramePayload      uint64
	ExtSupport           bool
	MaxConcurrentStreams uint64
}

// DefaultNcpHandshakeProfile returns the NCP v0.11 portable server defaults.
func DefaultNcpHandshakeProfile() NcpHandshakeProfile {
	return NcpHandshakeProfile{
		MinVersion:           "0.1",
		NpsVersion:           "0.11",
		SupportedEncodings:   []string{"msgpack", "json", "binary_vector.v1"},
		SupportedProtocols:   []string{"ncp", "nwp", "nip", "ndp", "nop"},
		MaxFramePayload:      HelloDefaultMaxFramePayload,
		ExtSupport:           false,
		MaxConcurrentStreams: HelloDefaultMaxConcurrentStreams,
	}
}

type NcpHandshakeAction string

const (
	NcpHandshakeContinue    NcpHandshakeAction = "continue"
	NcpHandshakeAccept      NcpHandshakeAction = "accept"
	NcpHandshakeSilentClose NcpHandshakeAction = "silent_close"
	NcpHandshakeErrorClose  NcpHandshakeAction = "error_close"
)

type NcpHandshakeDecision struct {
	Action               NcpHandshakeAction
	Status               string
	Error                string
	DiagnosticError      string
	SessionVersion       string
	NegotiatedEncoding   string
	EnabledEncodings     []string
	SupportedProtocols   []string
	MaxFramePayload      *uint64
	ExtSupport           *bool
	MaxConcurrentStreams *uint64
}

// EvaluatePreamble applies the portable preamble admission policy without I/O.
func EvaluatePreamble(received []byte, elapsed, timeout time.Duration) NcpHandshakeDecision {
	if timeout > 0 && elapsed >= timeout {
		return NcpHandshakeDecision{Action: NcpHandshakeSilentClose}
	}
	if len(received) < PreambleLength {
		return NcpHandshakeDecision{Action: NcpHandshakeContinue}
	}
	if !PreambleMatches(received) {
		return NcpHandshakeDecision{
			Action:          NcpHandshakeSilentClose,
			DiagnosticError: ErrPreambleInvalidCode,
		}
	}
	return NcpHandshakeDecision{Action: NcpHandshakeContinue}
}

// EvaluateHelloHeader validates the first frame before allocating its payload.
func EvaluateHelloHeader(header core.FrameHeader, elapsed, timeout time.Duration, maxHelloPayload uint64) NcpHandshakeDecision {
	if timeout > 0 && elapsed >= timeout {
		return NcpHandshakeDecision{Action: NcpHandshakeSilentClose}
	}
	if header.FrameType != core.FrameTypeHello ||
		header.EncodingTier() != core.EncodingTierJSON ||
		header.Flags&0x08 != 0 ||
		header.IsExtended ||
		header.PayloadLength > maxHelloPayload {
		return NcpHandshakeDecision{Action: NcpHandshakeSilentClose}
	}
	return NcpHandshakeDecision{Action: NcpHandshakeContinue}
}

// NegotiateHandshake selects deterministic session parameters for a decoded Hello.
func NegotiateHandshake(server NcpHandshakeProfile, client *HelloFrame) NcpHandshakeDecision {
	serverMin, ok1 := parseProtocolVersion(server.MinVersion)
	serverMax, ok2 := parseProtocolVersion(server.NpsVersion)
	clientMinToken := client.NpsVersion
	if client.MinVersion != nil {
		clientMinToken = *client.MinVersion
	}
	clientMin, ok3 := parseProtocolVersion(clientMinToken)
	clientMax, ok4 := parseProtocolVersion(client.NpsVersion)
	if !ok1 || !ok2 || !ok3 || !ok4 ||
		compareProtocolVersion(serverMin, serverMax) > 0 ||
		compareProtocolVersion(clientMin, clientMax) > 0 {
		return ncpVersionError()
	}
	overlapMin := maxProtocolVersion(serverMin, clientMin)
	overlapMax := minProtocolVersion(serverMax, clientMax)
	if compareProtocolVersion(overlapMin, overlapMax) > 0 {
		return ncpVersionError()
	}

	serverEncodings := stringSet(server.SupportedEncodings)
	stable := ""
	for _, token := range client.SupportedEncodings {
		if (token == "msgpack" || token == "json") && serverEncodings[token] {
			stable = token
			break
		}
	}
	if stable == "" {
		return NcpHandshakeDecision{
			Action: NcpHandshakeErrorClose,
			Status: core.NpsServerEncodingUnsupported,
			Error:  ErrEncodingUnsupported,
		}
	}

	serverProtocols := stringSet(server.SupportedProtocols)
	seen := map[string]bool{}
	protocols := make([]string, 0, len(client.SupportedProtocols))
	for _, token := range client.SupportedProtocols {
		if serverProtocols[token] && !seen[token] {
			seen[token] = true
			protocols = append(protocols, token)
		}
	}
	if !seen["ncp"] || client.MaxFramePayload == 0 ||
		server.MaxFramePayload == 0 || client.MaxConcurrentStreams == 0 ||
		server.MaxConcurrentStreams == 0 {
		return ncpVersionError()
	}

	enabled := []string{stable}
	if serverEncodings["binary_vector.v1"] && containsToken(client.SupportedEncodings, "binary_vector.v1") {
		enabled = append(enabled, "binary_vector.v1")
	}
	maxPayload := min(client.MaxFramePayload, server.MaxFramePayload)
	extSupport := client.ExtSupport && server.ExtSupport
	maxStreams := min(client.MaxConcurrentStreams, server.MaxConcurrentStreams)
	return NcpHandshakeDecision{
		Action:               NcpHandshakeAccept,
		SessionVersion:       overlapMax.String(),
		NegotiatedEncoding:   stable,
		EnabledEncodings:     enabled,
		SupportedProtocols:   protocols,
		MaxFramePayload:      &maxPayload,
		ExtSupport:           &extSupport,
		MaxConcurrentStreams: &maxStreams,
	}
}

type protocolVersion struct {
	major uint64
	minor uint64
}

func (v protocolVersion) String() string {
	return strconv.FormatUint(v.major, 10) + "." + strconv.FormatUint(v.minor, 10)
}

func parseProtocolVersion(value string) (protocolVersion, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return protocolVersion{}, false
	}
	major, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return protocolVersion{}, false
	}
	minor, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return protocolVersion{}, false
	}
	return protocolVersion{major: major, minor: minor}, true
}

func compareProtocolVersion(left, right protocolVersion) int {
	if left.major < right.major || (left.major == right.major && left.minor < right.minor) {
		return -1
	}
	if left == right {
		return 0
	}
	return 1
}

func minProtocolVersion(left, right protocolVersion) protocolVersion {
	if compareProtocolVersion(left, right) <= 0 {
		return left
	}
	return right
}

func maxProtocolVersion(left, right protocolVersion) protocolVersion {
	if compareProtocolVersion(left, right) >= 0 {
		return left
	}
	return right
}

func ncpVersionError() NcpHandshakeDecision {
	return NcpHandshakeDecision{
		Action: NcpHandshakeErrorClose,
		Status: core.NpsProtoVersionIncompatible,
		Error:  ErrVersionIncompatible,
	}
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
