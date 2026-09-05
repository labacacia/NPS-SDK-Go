// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ndp

import "github.com/labacacia/NPS-sdk-go/core"

// NDP error code wire constants — mirror of spec/error-codes.md NDP section.
const (
	ErrResolveNotFound          = "NDP-RESOLVE-NOT-FOUND"
	ErrResolveAmbiguous         = "NDP-RESOLVE-AMBIGUOUS"
	ErrResolveTimeout           = "NDP-RESOLVE-TIMEOUT"
	ErrResolveStale             = "NDP-RESOLVE-STALE"
	ErrAnnounceSignatureInvalid = "NDP-ANNOUNCE-SIGNATURE-INVALID"
	ErrAnnounceNidMismatch      = "NDP-ANNOUNCE-NID-MISMATCH"
	ErrAnnounceRoleRemoved      = "NDP-ANNOUNCE-ROLE-REMOVED"
	ErrAnnounceRoleUnknown      = "NDP-ANNOUNCE-ROLE-UNKNOWN"
	ErrAnnounceConflict         = "NDP-ANNOUNCE-CONFLICT"
	ErrAnnounceProfileViolation = "NDP-ANNOUNCE-PROFILE-VIOLATION"
	ErrGraphSeqRollback         = "NDP-GRAPH-SEQ-ROLLBACK"
	ErrGraphSeqGap              = "NDP-GRAPH-SEQ-GAP"
	ErrIssuerNotAllowed         = "NDP-ISSUER-NOT-ALLOWED"
	ErrCaAttestRequired         = "NDP-CA-ATTEST-REQUIRED"
	ErrRegistryUnavailable      = "NDP-REGISTRY-UNAVAILABLE"

	// Additional codes referenced in task description.
	ErrGraphInvalid   = "NDP-GRAPH-INVALID"
	ErrGraphTooLarge  = "NDP-GRAPH-TOO-LARGE"
	ErrFederationLoop = "NDP-FEDERATION-LOOP"
	ErrClusterSplit   = "NDP-CLUSTER-SPLIT"
	// v0.9 heartbeat
	ErrAnnounceStale    = "NDP-ANNOUNCE-STALE"
	ErrStateUnavailable = "NDP-STATE-UNAVAILABLE"
	ErrStateCorrupt     = "NDP-STATE-CORRUPT"
)

// NdpErrorToNpsStatus maps each NDP error code to its NPS status code.
var NdpErrorToNpsStatus = map[string]string{
	ErrResolveNotFound:          core.NpsClientNotFound,
	ErrResolveAmbiguous:         core.NpsClientConflict,
	ErrResolveTimeout:           core.NpsServerTimeout,
	ErrResolveStale:             core.NpsClientNotFound,
	ErrAnnounceSignatureInvalid: core.NpsAuthUnauthenticated,
	ErrAnnounceNidMismatch:      core.NpsClientBadFrame,
	ErrAnnounceRoleRemoved:      core.NpsClientBadFrame,
	ErrAnnounceRoleUnknown:      core.NpsClientBadFrame,
	ErrAnnounceConflict:         core.NpsClientConflict,
	ErrAnnounceProfileViolation: core.NpsAuthForbidden,
	ErrGraphSeqRollback:         core.NpsClientBadFrame,
	ErrGraphSeqGap:              core.NpsStreamSeqGap,
	ErrIssuerNotAllowed:         core.NpsAuthForbidden,
	ErrCaAttestRequired:         core.NpsAuthUnauthenticated,
	ErrRegistryUnavailable:      core.NpsServerUnavailable,
	ErrGraphInvalid:             core.NpsClientBadFrame,
	ErrGraphTooLarge:            core.NpsLimitPayload,
	ErrFederationLoop:           core.NpsClientConflict,
	ErrClusterSplit:             core.NpsClientConflict,
	ErrAnnounceStale:            core.NpsClientNotFound,
	ErrStateUnavailable:         core.NpsServerUnavailable,
	ErrStateCorrupt:             core.NpsServerInternal,
}
