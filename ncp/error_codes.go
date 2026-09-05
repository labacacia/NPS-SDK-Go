// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ncp

import "github.com/labacacia/NPS-sdk-go/core"

// NCP error code wire constants — mirror of spec/error-codes.md NCP section.
const (
	ErrAnchorNotFound        = "NCP-ANCHOR-NOT-FOUND"
	ErrAnchorSchemaInvalid   = "NCP-ANCHOR-SCHEMA-INVALID"
	ErrAnchorIdMismatch      = "NCP-ANCHOR-ID-MISMATCH"
	ErrFrameUnknownType      = "NCP-FRAME-UNKNOWN-TYPE"
	ErrFramePayloadTooLarge  = "NCP-FRAME-PAYLOAD-TOO-LARGE"
	ErrFrameFlagsInvalid     = "NCP-FRAME-FLAGS-INVALID"
	ErrStreamSeqGap          = "NCP-STREAM-SEQ-GAP"
	ErrStreamNotFound        = "NCP-STREAM-NOT-FOUND"
	ErrStreamLimitExceeded   = "NCP-STREAM-LIMIT-EXCEEDED"
	ErrEncodingUnsupported   = "NCP-ENCODING-UNSUPPORTED"
	ErrAnchorStale           = "NCP-ANCHOR-STALE"
	ErrDiffFormatUnsupported = "NCP-DIFF-FORMAT-UNSUPPORTED"
	ErrVersionIncompatible   = "NCP-VERSION-INCOMPATIBLE"
	ErrStreamWindowOverflow  = "NCP-STREAM-WINDOW-OVERFLOW"
	ErrEncNotNegotiated      = "NCP-ENC-NOT-NEGOTIATED"
	ErrEncAuthFailed         = "NCP-ENC-AUTH-FAILED"
	ErrPreambleInvalidCode   = "NCP-PREAMBLE-INVALID"
	// RFC-0006 §6.3–§6.4 native-mode TLS binding. The failover trigger on the
	// native path (NPS-CR-0009 §3.3): the mTLS client-certificate NID does not
	// match the session IdentFrame NID, or a resumed TLS session's certificate
	// NID differs from the ticket-bound NID.
	ErrNidMismatch = "NCP-NID-MISMATCH"
	// v0.8 keepalive
	ErrKeepaliveTimeout  = "NCP-KEEPALIVE-TIMEOUT"
	ErrRekeyRequired     = "NCP-REKEY-REQUIRED"
	ErrEarlyDataRejected = "NCP-EARLY-DATA-REJECTED"
)

// NcpErrorToNpsStatus maps each NCP error code to its NPS status code.
var NcpErrorToNpsStatus = map[string]string{
	ErrAnchorNotFound:        core.NpsClientNotFound,
	ErrAnchorSchemaInvalid:   core.NpsClientBadFrame,
	ErrAnchorIdMismatch:      core.NpsClientConflict,
	ErrFrameUnknownType:      core.NpsClientBadFrame,
	ErrFramePayloadTooLarge:  core.NpsLimitPayload,
	ErrFrameFlagsInvalid:     core.NpsClientBadFrame,
	ErrStreamSeqGap:          core.NpsStreamSeqGap,
	ErrStreamNotFound:        core.NpsStreamNotFound,
	ErrStreamLimitExceeded:   core.NpsStreamLimit,
	ErrEncodingUnsupported:   core.NpsServerEncodingUnsupported,
	ErrAnchorStale:           core.NpsClientConflict,
	ErrDiffFormatUnsupported: core.NpsClientBadFrame,
	ErrVersionIncompatible:   core.NpsProtoVersionIncompatible,
	ErrStreamWindowOverflow:  core.NpsStreamLimit,
	ErrEncNotNegotiated:      core.NpsClientBadFrame,
	ErrEncAuthFailed:         core.NpsClientBadFrame,
	ErrPreambleInvalidCode:   core.NpsProtoPreambleInvalid,
	ErrKeepaliveTimeout:      core.NpsServerTimeout,
	ErrRekeyRequired:         core.NpsClientBadFrame,
	ErrNidMismatch:           core.NpsAuthUnauthenticated,
	ErrEarlyDataRejected:     core.NpsProtoVersionIncompatible,
}
