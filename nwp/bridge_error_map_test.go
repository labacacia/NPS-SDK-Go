// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp_test

import (
	"testing"

	"github.com/labacacia/NPS-sdk-go/core"
	"github.com/labacacia/NPS-sdk-go/nwp"
)

// NPS-2 §16.3 — the normative mapping tables.

func TestBridgeToJsonRpc_TableRows(t *testing.T) {
	rows := []struct {
		status string
		want   int
	}{
		{core.NpsClientBadFrame, -32600},
		{core.NpsClientBadParam, -32602},
		{core.NpsClientUnprocessable, -32602},
		{core.NpsClientNotFound, -32601},
		{core.NpsClientGone, -32602},
		{core.NpsClientConflict, -32004},
		{core.NpsAuthUnauthenticated, -32001},
		{core.NpsAuthForbidden, -32003},
		{core.NpsLimitRate, -32005},
		{core.NpsLimitBudget, -32005},
		{core.NpsLimitPayload, -32005},
		{core.NpsServerUnsupported, -32601},
		{core.NpsServerInternal, -32603},
		{core.NpsServerUnavailable, -32603},
		{core.NpsServerTimeout, -32603},
		{core.NpsDownstreamUnavailable, -32603},
		{"NPS-SOMETHING-ELSE", -32603},
	}
	for _, r := range rows {
		if got := nwp.BridgeToJsonRpc(r.status, false); got != r.want {
			t.Errorf("ToJsonRpc(%s) = %d, want %d", r.status, got, r.want)
		}
	}
}

func TestBridgeToJsonRpc_ToolVsResourceIsTheOnlyParamSensitiveRow(t *testing.T) {
	// The unknown-TOOL case in tools/call.
	if got := nwp.BridgeToJsonRpc(core.NpsClientNotFound, false); got != -32601 {
		t.Errorf("unknown tool = %d, want -32601", got)
	}
	// The unknown-URI case in resources/read.
	if got := nwp.BridgeToJsonRpc(core.NpsClientNotFound, true); got != -32602 {
		t.Errorf("unknown resource URI = %d, want -32602", got)
	}
	// No other row is param-sensitive.
	for _, s := range []string{
		core.NpsClientBadFrame, core.NpsClientBadParam, core.NpsClientConflict,
		core.NpsAuthForbidden, core.NpsServerUnsupported, core.NpsServerInternal,
	} {
		if nwp.BridgeToJsonRpc(s, false) != nwp.BridgeToJsonRpc(s, true) {
			t.Errorf("%s must not be param-sensitive", s)
		}
	}
}

func TestBridgeToJsonRpc_AuthClassesAreNotCollapsed(t *testing.T) {
	un := nwp.BridgeToJsonRpc(core.NpsAuthUnauthenticated, false)
	fb := nwp.BridgeToJsonRpc(core.NpsAuthForbidden, false)
	if un == fb {
		t.Fatalf("NPS-AUTH-FORBIDDEN must NOT be collapsed onto NPS-AUTH-UNAUTHENTICATED (%d)", un)
	}
	if un != -32001 || fb != -32003 {
		t.Errorf("got %d / %d, want -32001 / -32003", un, fb)
	}
}

func TestBridgeToJsonRpc_NeverEmitsTheRetired32002(t *testing.T) {
	for _, s := range []string{
		core.NpsOk, core.NpsClientBadFrame, core.NpsClientBadParam, core.NpsClientNotFound,
		core.NpsClientConflict, core.NpsClientGone, core.NpsClientUnprocessable,
		core.NpsAuthUnauthenticated, core.NpsAuthForbidden,
		core.NpsLimitRate, core.NpsLimitBudget, core.NpsLimitPayload,
		core.NpsServerUnsupported, core.NpsServerInternal, core.NpsServerUnavailable,
		core.NpsServerTimeout, core.NpsDownstreamUnavailable, "NPS-UNKNOWN",
	} {
		for _, rr := range []bool{false, true} {
			if nwp.BridgeToJsonRpc(s, rr) == -32002 {
				t.Errorf("-32002 is retired by CR-0010 and MUST NOT be emitted (from %s)", s)
			}
		}
	}
}

func TestBridgeToGrpcStatus_TableRows(t *testing.T) {
	rows := []struct {
		status string
		want   nwp.GrpcStatusCode
	}{
		{core.NpsClientBadFrame, nwp.GrpcInvalidArgument},
		{core.NpsClientBadParam, nwp.GrpcInvalidArgument},
		{core.NpsClientUnprocessable, nwp.GrpcInvalidArgument},
		{core.NpsClientNotFound, nwp.GrpcNotFound},
		{core.NpsClientGone, nwp.GrpcNotFound},
		{core.NpsClientConflict, nwp.GrpcAborted},
		{core.NpsAuthUnauthenticated, nwp.GrpcUnauthenticated},
		{core.NpsAuthForbidden, nwp.GrpcPermissionDenied},
		{core.NpsLimitRate, nwp.GrpcResourceExhausted},
		{core.NpsLimitBudget, nwp.GrpcResourceExhausted},
		{core.NpsLimitPayload, nwp.GrpcResourceExhausted},
		{core.NpsServerUnsupported, nwp.GrpcUnimplemented},
		{core.NpsServerInternal, nwp.GrpcInternal},
		{core.NpsServerUnavailable, nwp.GrpcUnavailable},
		{core.NpsDownstreamUnavailable, nwp.GrpcUnavailable},
		{core.NpsServerTimeout, nwp.GrpcDeadlineExceeded},
		{"NPS-SOMETHING-ELSE", nwp.GrpcInternal},
	}
	for _, r := range rows {
		if got := nwp.BridgeToGrpcStatus(r.status); got != r.want {
			t.Errorf("ToGrpcStatus(%s) = %d, want %d", r.status, got, r.want)
		}
	}
}

func TestBridgeToGrpcStatus_ServerClassesAreNotAllCollapsedOntoUnavailable(t *testing.T) {
	got := map[nwp.GrpcStatusCode]bool{}
	for _, s := range []string{
		core.NpsServerInternal, core.NpsServerUnavailable,
		core.NpsServerTimeout, core.NpsServerUnsupported,
	} {
		got[nwp.BridgeToGrpcStatus(s)] = true
	}
	if len(got) != 4 {
		t.Fatalf("the four server classes must map to four distinct gRPC codes, got %v", got)
	}
	// ...and the two auth classes are likewise distinct (the old ingress collapsed them).
	if nwp.BridgeToGrpcStatus(core.NpsAuthUnauthenticated) == nwp.BridgeToGrpcStatus(core.NpsAuthForbidden) {
		t.Error("401 and 403 must not both become PERMISSION_DENIED")
	}
}

func TestBridgeFromHttpStatus_TableRows(t *testing.T) {
	rows := []struct {
		status int
		want   string
	}{
		{400, core.NpsClientBadParam},
		{401, core.NpsAuthUnauthenticated},
		{403, core.NpsAuthForbidden},
		{404, core.NpsClientNotFound},
		{408, core.NpsServerTimeout},
		{409, core.NpsClientConflict},
		{410, core.NpsClientGone},
		{413, core.NpsLimitPayload},
		{415, core.NpsServerEncodingUnsupported},
		{422, core.NpsClientUnprocessable},
		{429, core.NpsLimitRate},
		{501, core.NpsServerUnsupported},
		{502, core.NpsDownstreamUnavailable},
		{503, core.NpsServerUnavailable},
		{504, core.NpsDownstreamUnavailable},
		{500, core.NpsServerInternal},
		{599, core.NpsServerInternal},
		{451, core.NpsClientBadParam},
		{200, core.NpsOk},
		{204, core.NpsOk},
	}
	for _, r := range rows {
		if got := nwp.BridgeFromHttpStatus(r.status); got != r.want {
			t.Errorf("FromHttpStatus(%d) = %s, want %s", r.status, got, r.want)
		}
	}
}

func TestBridgeFromJsonRpc_TableRows(t *testing.T) {
	rows := []struct {
		code int
		want string
	}{
		{-32700, core.NpsClientBadFrame},
		{-32600, core.NpsClientBadFrame},
		{-32601, core.NpsClientNotFound},
		{-32602, core.NpsClientBadParam},
		{-32603, core.NpsServerInternal},
		{-32001, core.NpsAuthUnauthenticated},
		{-32003, core.NpsAuthForbidden},
		{-32004, core.NpsClientConflict},
		{-32005, core.NpsLimitRate},
		{-32000, core.NpsDownstreamUnavailable},
		{-31999, core.NpsServerInternal},
	}
	for _, r := range rows {
		if got := nwp.BridgeFromJsonRpc(r.code); got != r.want {
			t.Errorf("FromJsonRpc(%d) = %s, want %s", r.code, got, r.want)
		}
	}
}

func TestBridgeFromGrpcStatus_TableRows(t *testing.T) {
	rows := []struct {
		code nwp.GrpcStatusCode
		want string
	}{
		{nwp.GrpcOK, core.NpsOk},
		{nwp.GrpcInvalidArgument, core.NpsClientBadParam},
		{nwp.GrpcFailedPrecondition, core.NpsClientUnprocessable},
		{nwp.GrpcNotFound, core.NpsClientNotFound},
		{nwp.GrpcAlreadyExists, core.NpsClientConflict},
		{nwp.GrpcAborted, core.NpsClientConflict},
		{nwp.GrpcUnauthenticated, core.NpsAuthUnauthenticated},
		{nwp.GrpcPermissionDenied, core.NpsAuthForbidden},
		{nwp.GrpcResourceExhausted, core.NpsLimitRate},
		{nwp.GrpcUnimplemented, core.NpsServerUnsupported},
		{nwp.GrpcUnavailable, core.NpsServerUnavailable},
		{nwp.GrpcDeadlineExceeded, core.NpsServerTimeout},
		{nwp.GrpcInternal, core.NpsServerInternal},
		{nwp.GrpcUnknown, core.NpsServerInternal},
		{nwp.GrpcDataLoss, core.NpsServerInternal},
		{nwp.GrpcOutOfRange, core.NpsServerInternal},
	}
	for _, r := range rows {
		if got := nwp.BridgeFromGrpcStatus(r.code); got != r.want {
			t.Errorf("FromGrpcStatus(%d) = %s, want %s", r.code, got, r.want)
		}
	}
}

func TestBridgeMustBeProtocolError_TheExactSet(t *testing.T) {
	must := []string{
		core.NpsAuthUnauthenticated, core.NpsAuthForbidden,
		core.NpsLimitRate, core.NpsLimitBudget, core.NpsLimitPayload,
		core.NpsServerUnsupported, core.NpsServerInternal,
		core.NpsServerUnavailable, core.NpsServerTimeout, core.NpsDownstreamUnavailable,
	}
	mustNot := []string{
		core.NpsOk, core.NpsClientBadFrame, core.NpsClientBadParam, core.NpsClientNotFound,
		core.NpsClientConflict, core.NpsClientGone, core.NpsClientUnprocessable, "NPS-UNKNOWN",
	}
	for _, s := range must {
		if !nwp.BridgeMustBeProtocolError(s) {
			t.Errorf("%s is an infrastructure class — the tool did not run — and MUST be a protocol error", s)
		}
	}
	for _, s := range mustNot {
		if nwp.BridgeMustBeProtocolError(s) {
			t.Errorf("%s is a tool-domain class and must stay an isError result", s)
		}
	}
}

func TestBridgeErrorCodes_StatusMappings(t *testing.T) {
	rows := map[string]string{
		nwp.ErrBridgeDirectionUnsupported:    core.NpsServerUnsupported,
		nwp.ErrBridgeTargetInvalid:           core.NpsClientUnprocessable,
		nwp.ErrBridgeProtocolUnsupported:     core.NpsServerUnsupported,
		nwp.ErrBridgeEndpointInvalid:         core.NpsClientUnprocessable,
		nwp.ErrBridgeUpstreamFailed:          core.NpsDownstreamUnavailable,
		nwp.ErrBridgeServerToolNotFound:      core.NpsClientNotFound,
		nwp.ErrBridgeServerDispatcherMissing: core.NpsServerInternal,
		nwp.ErrBridgeServerDispatchFailed:    core.NpsServerInternal,
	}
	for code, want := range rows {
		if got := nwp.NwpErrorToNpsStatus[code]; got != want {
			t.Errorf("%s maps to %s, want %s", code, got, want)
		}
	}

	// The statuses CR-0010 removed must not be reintroduced anywhere in the map.
	invented := map[string]bool{
		"NPS-SERVER-NOT-IMPLEMENTED": true, "NPS-SERVER-ERROR": true,
		"NPS-CLIENT-UNAUTHORIZED": true, "NPS-CLIENT-BAD-REQUEST": true,
		"NPS-SERVER-UPSTREAM-FAILED": true,
	}
	for code, status := range nwp.NwpErrorToNpsStatus {
		if invented[status] {
			t.Errorf("%s maps to the invented status %s, removed by CR-0010", code, status)
		}
	}
}

func TestAnchorErrorCodes_StatusMappings(t *testing.T) {
	if got := nwp.NwpErrorToNpsStatus[nwp.ErrAnchorNotLeader]; got != core.NpsClientConflict {
		t.Errorf("NWP-ANCHOR-NOT-LEADER maps to %s, want NPS-CLIENT-CONFLICT", got)
	}
	if got := nwp.NwpErrorToNpsStatus[nwp.ErrAnchorEpochFenced]; got != core.NpsClientConflict {
		t.Errorf("NWP-ANCHOR-EPOCH-FENCED maps to %s, want NPS-CLIENT-CONFLICT", got)
	}
	// NPS-CLIENT-CONFLICT is 409.
	if got := core.ToHttpStatus(core.NpsClientConflict); got != 409 {
		t.Errorf("NPS-CLIENT-CONFLICT is HTTP 409, got %d", got)
	}
}
