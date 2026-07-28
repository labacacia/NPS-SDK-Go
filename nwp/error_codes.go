// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import "github.com/labacacia/NPS-sdk-go/core"

// NWP error code wire constants — mirror of spec/error-codes.md NWP section.
const (
	// Auth / NID errors
	ErrAuthNidScopeViolation    = "NWP-AUTH-NID-SCOPE-VIOLATION"
	ErrAuthNidExpired           = "NWP-AUTH-NID-EXPIRED"
	ErrAuthNidRevoked           = "NWP-AUTH-NID-REVOKED"
	ErrAuthNidUntrustedIssuer   = "NWP-AUTH-NID-UNTRUSTED-ISSUER"
	ErrAuthNidCapabilityMissing = "NWP-AUTH-NID-CAPABILITY-MISSING"
	ErrAuthAssuranceTooLow      = "NWP-AUTH-ASSURANCE-TOO-LOW"
	ErrAuthReputationBlocked    = "NWP-AUTH-REPUTATION-BLOCKED" // Deprecated alias

	// Reputation (RFC-0005)
	ErrReputationThrottled = "NWP-REPUTATION-THROTTLED"
	ErrReputationRejected  = "NWP-REPUTATION-REJECTED"
	ErrReputationBanned    = "NWP-REPUTATION-BANNED"

	// Query errors
	ErrQueryFilterInvalid        = "NWP-QUERY-FILTER-INVALID"
	ErrQueryFieldUnknown         = "NWP-QUERY-FIELD-UNKNOWN"
	ErrQueryCursorInvalid        = "NWP-QUERY-CURSOR-INVALID"
	ErrQueryRegexUnsafe          = "NWP-QUERY-REGEX-UNSAFE"
	ErrQueryVectorUnsupported    = "NWP-QUERY-VECTOR-UNSUPPORTED"
	ErrQueryAggregateUnsupported = "NWP-QUERY-AGGREGATE-UNSUPPORTED"
	ErrQueryAggregateInvalid     = "NWP-QUERY-AGGREGATE-INVALID"
	ErrQueryStreamUnsupported    = "NWP-QUERY-STREAM-UNSUPPORTED"

	// Action errors
	ErrActionNotFound            = "NWP-ACTION-NOT-FOUND"
	ErrActionParamsInvalid       = "NWP-ACTION-PARAMS-INVALID"
	ErrActionIdempotencyConflict = "NWP-ACTION-IDEMPOTENCY-CONFLICT"

	// Task errors
	ErrTaskNotFound         = "NWP-TASK-NOT-FOUND"
	ErrTaskAlreadyCancelled = "NWP-TASK-ALREADY-CANCELLED"
	ErrTaskAlreadyCompleted = "NWP-TASK-ALREADY-COMPLETED"
	ErrTaskAlreadyFailed    = "NWP-TASK-ALREADY-FAILED"

	// Subscribe errors
	ErrSubscribeStreamNotFound    = "NWP-SUBSCRIBE-STREAM-NOT-FOUND"
	ErrSubscribeLimitExceeded     = "NWP-SUBSCRIBE-LIMIT-EXCEEDED"
	ErrSubscribeFilterUnsupported = "NWP-SUBSCRIBE-FILTER-UNSUPPORTED"
	ErrSubscribeInterrupted       = "NWP-SUBSCRIBE-INTERRUPTED"
	ErrSubscribeSeqTooOld         = "NWP-SUBSCRIBE-SEQ-TOO-OLD"

	// Budget / rate errors
	ErrBudgetExceeded    = "NWP-BUDGET-EXCEEDED"
	ErrCgnLimitExceeded  = "NWP-CGN-LIMIT-EXCEEDED"
	ErrDepthExceeded     = "NWP-DEPTH-EXCEEDED"
	ErrGraphCycle        = "NWP-GRAPH-CYCLE"
	ErrNodeUnavailable   = "NWP-NODE-UNAVAILABLE"
	ErrRateLimitExceeded = "NWP-RATE-LIMIT-EXCEEDED"

	// Manifest errors
	ErrManifestVersionUnsupported = "NWP-MANIFEST-VERSION-UNSUPPORTED"
	ErrManifestNodeTypeRemoved    = "NWP-MANIFEST-NODE-TYPE-REMOVED"
	ErrManifestNodeTypeUnknown    = "NWP-MANIFEST-NODE-TYPE-UNKNOWN"

	// Reserved type
	ErrReservedTypeUnsupported = "NWP-RESERVED-TYPE-UNSUPPORTED"

	// HTTP binding / advertised capability
	ErrHttpOriginForbidden               = "NWP-HTTP-ORIGIN-FORBIDDEN"
	ErrHttpContentTypeUnsupported        = "NWP-HTTP-CONTENT-TYPE-UNSUPPORTED"
	ErrHttpAcceptUnsatisfiable           = "NWP-HTTP-ACCEPT-UNSATISFIABLE"
	ErrHttpRequestIdMismatch             = "NWP-HTTP-REQUEST-ID-MISMATCH"
	ErrHttpFrameBodyMalformed            = "NWP-HTTP-FRAME-BODY-MALFORMED"
	ErrCapabilityAdvertisedUnimplemented = "NWP-CAPABILITY-ADVERTISED-UNIMPLEMENTED"

	// Topology (NPS-CR-0002)
	ErrTopologyUnauthorized      = "NWP-TOPOLOGY-UNAUTHORIZED"
	ErrTopologyUnsupportedScope  = "NWP-TOPOLOGY-UNSUPPORTED-SCOPE"
	ErrTopologyDepthUnsupported  = "NWP-TOPOLOGY-DEPTH-UNSUPPORTED"
	ErrTopologyFilterUnsupported = "NWP-TOPOLOGY-FILTER-UNSUPPORTED"
)

// NwpErrorToNpsStatus maps each NWP error code to its NPS status code.
var NwpErrorToNpsStatus = map[string]string{
	ErrAuthNidScopeViolation:             core.NpsAuthForbidden,
	ErrAuthNidExpired:                    core.NpsAuthUnauthenticated,
	ErrAuthNidRevoked:                    core.NpsAuthUnauthenticated,
	ErrAuthNidUntrustedIssuer:            core.NpsAuthUnauthenticated,
	ErrAuthNidCapabilityMissing:          core.NpsAuthForbidden,
	ErrAuthAssuranceTooLow:               core.NpsAuthForbidden,
	ErrAuthReputationBlocked:             core.NpsAuthForbidden,
	ErrReputationThrottled:               core.NpsClientRateLimited,
	ErrReputationRejected:                core.NpsAuthForbidden,
	ErrReputationBanned:                  core.NpsAuthForbidden,
	ErrQueryFilterInvalid:                core.NpsClientBadParam,
	ErrQueryFieldUnknown:                 core.NpsClientBadParam,
	ErrQueryCursorInvalid:                core.NpsClientBadParam,
	ErrQueryRegexUnsafe:                  core.NpsClientBadParam,
	ErrQueryVectorUnsupported:            core.NpsServerUnsupported,
	ErrQueryAggregateUnsupported:         core.NpsServerUnsupported,
	ErrQueryAggregateInvalid:             core.NpsClientBadParam,
	ErrQueryStreamUnsupported:            core.NpsServerUnsupported,
	ErrActionNotFound:                    core.NpsClientNotFound,
	ErrActionParamsInvalid:               core.NpsClientUnprocessable,
	ErrActionIdempotencyConflict:         core.NpsClientConflict,
	ErrTaskNotFound:                      core.NpsClientNotFound,
	ErrTaskAlreadyCancelled:              core.NpsClientConflict,
	ErrTaskAlreadyCompleted:              core.NpsClientConflict,
	ErrTaskAlreadyFailed:                 core.NpsClientConflict,
	ErrSubscribeStreamNotFound:           core.NpsClientNotFound,
	ErrSubscribeLimitExceeded:            core.NpsLimitExceeded,
	ErrSubscribeFilterUnsupported:        core.NpsServerUnsupported,
	ErrSubscribeInterrupted:              core.NpsServerUnavailable,
	ErrSubscribeSeqTooOld:                core.NpsClientConflict,
	ErrBudgetExceeded:                    core.NpsLimitBudget,
	ErrCgnLimitExceeded:                  core.NpsClientRequestTooLarge,
	ErrDepthExceeded:                     core.NpsClientBadParam,
	ErrGraphCycle:                        core.NpsClientUnprocessable,
	ErrNodeUnavailable:                   core.NpsServerUnavailable,
	ErrRateLimitExceeded:                 core.NpsLimitRate,
	ErrManifestVersionUnsupported:        core.NpsClientBadParam,
	ErrManifestNodeTypeRemoved:           core.NpsClientBadFrame,
	ErrManifestNodeTypeUnknown:           core.NpsClientBadFrame,
	ErrReservedTypeUnsupported:           core.NpsServerUnsupported,
	ErrHttpOriginForbidden:               core.NpsAuthForbidden,
	ErrHttpContentTypeUnsupported:        core.NpsClientBadFrame,
	ErrHttpAcceptUnsatisfiable:           core.NpsClientBadParam,
	ErrHttpRequestIdMismatch:             core.NpsClientBadParam,
	ErrHttpFrameBodyMalformed:            core.NpsClientBadFrame,
	ErrCapabilityAdvertisedUnimplemented: core.NpsServerUnsupported,
	ErrTopologyUnauthorized:              core.NpsAuthForbidden,
	ErrTopologyUnsupportedScope:          core.NpsClientBadParam,
	ErrTopologyDepthUnsupported:          core.NpsClientBadParam,
	ErrTopologyFilterUnsupported:         core.NpsClientBadParam,
}
