// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"strings"

	"github.com/labacacia/NPS-sdk-go/core"
)

// NPS-2 §16.3 — Bridge error mapping.
//
// This is the SINGLE implementation serving BOTH directions and ALL THREE
// foreign protocols. No inbound or outbound path may hand-roll its own mapping:
// the whole point of §16.3 is that a distinct NPS status class always reaches
// the foreign peer as a distinct foreign code, and per-path tables drift.

// JSON-RPC 2.0 error codes used by the MCP and A2A surfaces.
const (
	JsonRpcParseError     = -32700
	JsonRpcInvalidRequest = -32600
	JsonRpcMethodNotFound = -32601
	JsonRpcInvalidParams  = -32602
	JsonRpcInternalError  = -32603

	// Implementation-defined server range.
	JsonRpcUpstreamError    = -32000 // hosting-layer dispatch timeout
	JsonRpcUnauthenticated  = -32001
	JsonRpcForbidden        = -32003
	JsonRpcConflict         = -32004
	JsonRpcLimitExceeded    = -32005
	jsonRpcRetiredResources = -32002 // RETIRED by CR-0010; MUST NOT be emitted.
)

// GrpcStatusCode is a canonical gRPC status code. The numeric values match the
// gRPC wire codes (and google.golang.org/grpc/codes.Code), so a transport
// binding can convert with a plain numeric cast without this package taking a
// dependency on grpc-go.
type GrpcStatusCode int

const (
	GrpcOK                 GrpcStatusCode = 0
	GrpcCancelled          GrpcStatusCode = 1
	GrpcUnknown            GrpcStatusCode = 2
	GrpcInvalidArgument    GrpcStatusCode = 3
	GrpcDeadlineExceeded   GrpcStatusCode = 4
	GrpcNotFound           GrpcStatusCode = 5
	GrpcAlreadyExists      GrpcStatusCode = 6
	GrpcPermissionDenied   GrpcStatusCode = 7
	GrpcResourceExhausted  GrpcStatusCode = 8
	GrpcFailedPrecondition GrpcStatusCode = 9
	GrpcAborted            GrpcStatusCode = 10
	GrpcOutOfRange         GrpcStatusCode = 11
	GrpcUnimplemented      GrpcStatusCode = 12
	GrpcInternal           GrpcStatusCode = 13
	GrpcUnavailable        GrpcStatusCode = 14
	GrpcDataLoss           GrpcStatusCode = 15
	GrpcUnauthenticated    GrpcStatusCode = 16
)

// ── §16.3.1 NPS status -> JSON-RPC (MCP, A2A) ────────────────────────────────

// BridgeToJsonRpc maps an NPS status onto a JSON-RPC error code.
//
// resourceRead selects the one param-sensitive row: NPS-CLIENT-NOT-FOUND is
// -32601 (Method not found) for an unknown TOOL in tools/call, but -32602
// (Invalid params) for an unknown URI in resources/read — the URI is a
// parameter, the tool name names the callable.
func BridgeToJsonRpc(npsStatus string, resourceRead bool) int {
	switch npsStatus {
	case core.NpsClientBadFrame:
		return JsonRpcInvalidRequest
	case core.NpsClientBadParam, core.NpsClientUnprocessable:
		return JsonRpcInvalidParams
	case core.NpsClientNotFound:
		if resourceRead {
			return JsonRpcInvalidParams
		}
		return JsonRpcMethodNotFound
	case core.NpsClientGone:
		return JsonRpcInvalidParams
	case core.NpsClientConflict:
		return JsonRpcConflict
	case core.NpsAuthUnauthenticated:
		// MUST be a JSON-RPC error, never a successful result carrying an error payload.
		return JsonRpcUnauthenticated
	case core.NpsAuthForbidden:
		// MUST NOT be collapsed onto -32001.
		return JsonRpcForbidden
	case core.NpsLimitRate, core.NpsLimitBudget, core.NpsLimitPayload:
		return JsonRpcLimitExceeded
	case core.NpsServerUnsupported:
		// Includes NWP-BRIDGE-DIRECTION-UNSUPPORTED.
		return JsonRpcMethodNotFound
	case core.NpsServerInternal, core.NpsServerUnavailable, core.NpsServerTimeout, core.NpsDownstreamUnavailable:
		return JsonRpcInternalError
	default:
		return JsonRpcInternalError
	}
}

// ── §16.3.2 NPS status -> gRPC ───────────────────────────────────────────────

// BridgeToGrpcStatus maps an NPS status onto a gRPC status code.
//
// Explicitly fixed vs the pre-CR-0010 ingress, which collapsed 401 and 403 both
// onto PERMISSION_DENIED and every 5xx onto UNAVAILABLE: §16.3 forbids
// collapsing distinct NPS status classes.
func BridgeToGrpcStatus(npsStatus string) GrpcStatusCode {
	switch npsStatus {
	case core.NpsClientBadFrame, core.NpsClientBadParam, core.NpsClientUnprocessable:
		return GrpcInvalidArgument
	case core.NpsClientNotFound, core.NpsClientGone:
		return GrpcNotFound
	case core.NpsClientConflict:
		return GrpcAborted
	case core.NpsAuthUnauthenticated:
		return GrpcUnauthenticated
	case core.NpsAuthForbidden:
		return GrpcPermissionDenied
	case core.NpsLimitRate, core.NpsLimitBudget, core.NpsLimitPayload:
		return GrpcResourceExhausted
	case core.NpsServerUnsupported:
		return GrpcUnimplemented
	case core.NpsServerInternal:
		return GrpcInternal
	case core.NpsServerUnavailable, core.NpsDownstreamUnavailable:
		return GrpcUnavailable
	case core.NpsServerTimeout:
		return GrpcDeadlineExceeded
	default:
		return GrpcInternal
	}
}

// ── §16.3.4 reverse direction: foreign error -> NPS status ───────────────────
//
// Choose the MOST SPECIFIC NPS status wherever the inverse is not injective;
// never a blanket NPS-SERVER-INTERNAL.

// BridgeFromHttpStatus maps an HTTP status onto an NPS status.
func BridgeFromHttpStatus(status int) string {
	switch status {
	case 400:
		return core.NpsClientBadParam
	case 401:
		return core.NpsAuthUnauthenticated
	case 403:
		return core.NpsAuthForbidden
	case 404:
		return core.NpsClientNotFound
	case 408:
		return core.NpsServerTimeout
	case 409:
		return core.NpsClientConflict
	case 410:
		return core.NpsClientGone
	case 413:
		return core.NpsLimitPayload
	case 415:
		return core.NpsServerEncodingUnsupported
	case 422:
		return core.NpsClientUnprocessable
	case 429:
		return core.NpsLimitRate
	case 501:
		return core.NpsServerUnsupported
	case 502, 504:
		return core.NpsDownstreamUnavailable
	case 503:
		return core.NpsServerUnavailable
	}
	switch {
	case status >= 500:
		return core.NpsServerInternal
	case status >= 400:
		return core.NpsClientBadParam
	default:
		return core.NpsOk
	}
}

// BridgeFromJsonRpc maps a JSON-RPC error code onto an NPS status.
func BridgeFromJsonRpc(code int) string {
	switch code {
	case JsonRpcParseError, JsonRpcInvalidRequest:
		return core.NpsClientBadFrame
	case JsonRpcMethodNotFound:
		return core.NpsClientNotFound
	case JsonRpcInvalidParams:
		return core.NpsClientBadParam
	case JsonRpcInternalError:
		return core.NpsServerInternal
	case JsonRpcUnauthenticated:
		return core.NpsAuthUnauthenticated
	case JsonRpcForbidden:
		return core.NpsAuthForbidden
	case JsonRpcConflict:
		return core.NpsClientConflict
	case JsonRpcLimitExceeded:
		return core.NpsLimitRate
	case JsonRpcUpstreamError:
		return core.NpsDownstreamUnavailable
	default:
		return core.NpsServerInternal
	}
}

// BridgeFromGrpcStatus maps a gRPC status code onto an NPS status.
func BridgeFromGrpcStatus(code GrpcStatusCode) string {
	switch code {
	case GrpcOK:
		return core.NpsOk
	case GrpcInvalidArgument:
		return core.NpsClientBadParam
	case GrpcFailedPrecondition:
		return core.NpsClientUnprocessable
	case GrpcNotFound:
		return core.NpsClientNotFound
	case GrpcAlreadyExists, GrpcAborted:
		return core.NpsClientConflict
	case GrpcUnauthenticated:
		return core.NpsAuthUnauthenticated
	case GrpcPermissionDenied:
		return core.NpsAuthForbidden
	case GrpcResourceExhausted:
		return core.NpsLimitRate
	case GrpcUnimplemented:
		return core.NpsServerUnsupported
	case GrpcUnavailable:
		return core.NpsServerUnavailable
	case GrpcDeadlineExceeded:
		return core.NpsServerTimeout
	case GrpcInternal, GrpcUnknown, GrpcDataLoss:
		return core.NpsServerInternal
	default:
		return core.NpsServerInternal
	}
}

// ── §16.3.5 the protocol-error vs isError split ──────────────────────────────

// BridgeMustBeProtocolError reports whether an NPS status MUST surface as a
// foreign-protocol ERROR rather than as a successful result flagged isError.
//
// True for the infrastructure classes: the tool DID NOT RUN. Both pre-CR-0010
// implementations returned these as a successful result with isError: true,
// which lets an MCP client mistake a 403 for a tool that merely returned unhappy
// text. Genuine tool-DOMAIN failures (the NPS-CLIENT-* classes) stay as
// isError: true content — that is what MCP's flag is for.
func BridgeMustBeProtocolError(npsStatus string) bool {
	switch npsStatus {
	case core.NpsAuthUnauthenticated,
		core.NpsAuthForbidden,
		core.NpsLimitRate,
		core.NpsLimitBudget,
		core.NpsLimitPayload,
		core.NpsServerUnsupported,
		core.NpsServerInternal,
		core.NpsServerUnavailable,
		core.NpsServerTimeout,
		core.NpsDownstreamUnavailable:
		return true
	default:
		return false
	}
}

// bridgeDetail renders the "{npsStatus} {nwpError}: {message}" detail string a
// gRPC caller needs to recover the exact NPS fault, not just the coarse gRPC class.
func bridgeDetail(npsStatus, nwpError, message string) string {
	var b strings.Builder
	b.WriteString(npsStatus)
	if nwpError != "" {
		b.WriteString(" ")
		b.WriteString(nwpError)
	}
	if message != "" {
		b.WriteString(": ")
		b.WriteString(message)
	}
	return b.String()
}
