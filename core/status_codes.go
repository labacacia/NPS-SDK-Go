// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package core

// NPS native status codes — mirror of spec/status-codes.md.
const (
	// Success
	NpsOk          = "NPS-OK"
	NpsOkAccepted  = "NPS-OK-ACCEPTED"
	NpsOkNoContent = "NPS-OK-NO-CONTENT"

	// Client errors
	NpsClientBadFrame      = "NPS-CLIENT-BAD-FRAME"
	NpsClientBadParam      = "NPS-CLIENT-BAD-PARAM"
	NpsClientNotFound      = "NPS-CLIENT-NOT-FOUND"
	NpsClientConflict      = "NPS-CLIENT-CONFLICT"
	NpsClientGone          = "NPS-CLIENT-GONE"
	NpsClientUnprocessable = "NPS-CLIENT-UNPROCESSABLE"

	// Auth errors
	NpsAuthUnauthenticated = "NPS-AUTH-UNAUTHENTICATED"
	NpsAuthForbidden       = "NPS-AUTH-FORBIDDEN"

	// Limit errors
	NpsLimitRate     = "NPS-LIMIT-RATE"
	NpsLimitBudget   = "NPS-LIMIT-BUDGET"
	NpsLimitPayload  = "NPS-LIMIT-PAYLOAD"
	NpsLimitResource = "NPS-LIMIT-RESOURCE"

	// Server errors
	NpsServerInternal            = "NPS-SERVER-INTERNAL"
	NpsServerUnsupported         = "NPS-SERVER-UNSUPPORTED"
	NpsServerUnavailable         = "NPS-SERVER-UNAVAILABLE"
	NpsServerTimeout             = "NPS-SERVER-TIMEOUT"
	NpsServerEncodingUnsupported = "NPS-SERVER-ENCODING-UNSUPPORTED"
	NpsDownstreamUnavailable     = "NPS-DOWNSTREAM-UNAVAILABLE"

	// Stream errors
	NpsStreamSeqGap   = "NPS-STREAM-SEQ-GAP"
	NpsStreamNotFound = "NPS-STREAM-NOT-FOUND"
	NpsStreamLimit    = "NPS-STREAM-LIMIT"

	// Protocol-level errors
	NpsProtoVersionIncompatible = "NPS-PROTO-VERSION-INCOMPATIBLE"
	NpsProtoPreambleInvalid     = "NPS-PROTO-PREAMBLE-INVALID"

	// Extra codes referenced in error-codes.md but not listed in the status table.
	NpsClientRateLimited     = "NPS-CLIENT-RATE-LIMITED"
	NpsLimitExceeded         = "NPS-LIMIT-EXCEEDED"
	NpsClientRequestTooLarge = "NPS-CLIENT-REQUEST-TOO-LARGE"
)

// HttpStatusMap maps each NPS status code to an HTTP status code.
// For codes with dual HTTP values (e.g. NPS-SERVER-TIMEOUT maps to both 408
// and 504) the more specific server-side value is used.
var HttpStatusMap = map[string]int{
	NpsOk:          200,
	NpsOkAccepted:  202,
	NpsOkNoContent: 204,

	NpsClientBadFrame:      400,
	NpsClientBadParam:      400,
	NpsClientNotFound:      404,
	NpsClientConflict:      409,
	NpsClientGone:          410,
	NpsClientUnprocessable: 422,

	NpsAuthUnauthenticated: 401,
	NpsAuthForbidden:       403,

	NpsLimitRate:     429,
	NpsLimitBudget:   429,
	NpsLimitPayload:  413,
	NpsLimitResource: 429,

	NpsServerInternal:            500,
	NpsServerUnsupported:         501,
	NpsServerUnavailable:         503,
	NpsServerTimeout:             504,
	NpsServerEncodingUnsupported: 415,
	NpsDownstreamUnavailable:     502,

	NpsStreamSeqGap:   422,
	NpsStreamNotFound: 404,
	NpsStreamLimit:    429,

	NpsProtoVersionIncompatible: 426,
	NpsProtoPreambleInvalid:     400,

	NpsClientRateLimited:     429,
	NpsLimitExceeded:         429,
	NpsClientRequestTooLarge: 413,
}

// ToHttpStatus returns the HTTP status code for the given NPS status code,
// defaulting to 500 for unknown codes.
func ToHttpStatus(code string) int {
	if h, ok := HttpStatusMap[code]; ok {
		return h
	}
	return 500
}
