// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import "github.com/labacacia/NPS-sdk-go/core"

// NIP error code wire constants — mirror of spec/error-codes.md NIP section.
const (
	// Cert verification (v1 + v2).
	ErrCertExpired           = "NIP-CERT-EXPIRED"
	ErrCertRevoked           = "NIP-CERT-REVOKED"
	ErrCertSignatureInvalid  = "NIP-CERT-SIGNATURE-INVALID"
	ErrCertUntrustedIssuer   = "NIP-CERT-UNTRUSTED-ISSUER"
	ErrCertCapabilityMissing = "NIP-CERT-CAPABILITY-MISSING"
	ErrCertScopeViolation    = "NIP-CERT-SCOPE-VIOLATION"

	// CA service.
	ErrCaNidNotFound          = "NIP-CA-NID-NOT-FOUND"
	ErrCaNidAlreadyExists     = "NIP-CA-NID-ALREADY-EXISTS"
	ErrCaSerialDuplicate      = "NIP-CA-SERIAL-DUPLICATE"
	ErrCaRenewalTooEarly      = "NIP-CA-RENEWAL-TOO-EARLY"
	ErrCaScopeExpansionDenied = "NIP-CA-SCOPE-EXPANSION-DENIED"

	ErrOcspUnavailable   = "NIP-OCSP-UNAVAILABLE"
	ErrTrustFrameInvalid = "NIP-TRUST-FRAME-INVALID"

	// RFC-0003 (assurance level).
	ErrAssuranceMismatch = "NIP-ASSURANCE-MISMATCH"
	ErrAssuranceUnknown  = "NIP-ASSURANCE-UNKNOWN"

	// RFC-0004 (reputation log).
	ErrReputationEntryInvalid   = "NIP-REPUTATION-ENTRY-INVALID"
	ErrReputationLogUnreachable = "NIP-REPUTATION-LOG-UNREACHABLE"

	// RFC-0002 (X.509 + ACME).
	ErrCertFormatInvalid      = "NIP-CERT-FORMAT-INVALID"
	ErrCertEkuMissing         = "NIP-CERT-EKU-MISSING"
	ErrCertSubjectNidMismatch = "NIP-CERT-SUBJECT-NID-MISMATCH"
	ErrAcmeChallengeFailed    = "NIP-ACME-CHALLENGE-FAILED"

	// TrustFrame errors (NPS-3 §5.2).
	ErrTrustFrameExpired             = "NIP-TRUST-FRAME-EXPIRED"
	ErrTrustFrameGrantorRevoked      = "NIP-TRUST-FRAME-GRANTOR-REVOKED"
	ErrTrustFrameScopeExceedsGrantor = "NIP-TRUST-FRAME-SCOPE-EXCEEDS-GRANTOR"
	ErrTrustFrameNodesPatternInvalid = "NIP-TRUST-FRAME-NODES-PATTERN-INVALID"

	// RevokeFrame errors (NPS-3 §5.3).
	ErrRevokeFrameInvalid            = "NIP-REVOKE-FRAME-INVALID"
	ErrRevokeFrameUnauthorizedIssuer = "NIP-REVOKE-FRAME-UNAUTHORIZED-ISSUER"
	ErrRevokeFrameSerialMismatch     = "NIP-REVOKE-FRAME-SERIAL-MISMATCH"
	ErrRevokeFrameReasonUnknown      = "NIP-REVOKE-FRAME-REASON-UNKNOWN"

	// Reputation gossip (RFC-0004 §4.5).
	ErrReputationGossipFork       = "NIP-REPUTATION-GOSSIP-FORK"
	ErrReputationGossipSigInvalid = "NIP-REPUTATION-GOSSIP-SIG-INVALID"

	// CA group/parent/session/JWS (NPS-CR-0003).
	ErrCaGroupRevoked           = "NIP-CA-GROUP-REVOKED"
	ErrCaParentNotFound         = "NIP-CA-PARENT-NOT-FOUND"
	ErrCaParentNotGroup         = "NIP-CA-PARENT-NOT-GROUP"
	ErrCaSessionValidityInvalid = "NIP-CA-SESSION-VALIDITY-INVALID"
	ErrCaJwsInvalid             = "NIP-CA-JWS-INVALID"
	ErrCaJwsExpired             = "NIP-CA-JWS-EXPIRED"

	// Chain check (NPS-3 §7, NPS-CR-0003).
	ErrCertParentRevoked = "NIP-CERT-PARENT-REVOKED"

	// NPS-CR-0005 RA enrollment tiers.
	ErrRaTokenInvalid    = "NIP-RA-TOKEN-INVALID"
	ErrRaTokenExpired    = "NIP-RA-TOKEN-EXPIRED"
	ErrRaNidNotAllowed   = "NIP-RA-NID-NOT-ALLOWED"
	ErrRaPendingRejected = "NIP-RA-PENDING-REJECTED"

	// OCSP staple.
	ErrOcspStapleExpired = "NIP-OCSP-STAPLE-EXPIRED"

	// NIP v0.10 — node_roles.
	ErrCertNodeRolesMismatch = "NIP-CERT-NODE-ROLES-MISMATCH"

	// NIP v0.12 §7.5 — Phase-3 enforcement. The only new code in v0.12.
	// Note the deliberate asymmetry with its sibling ErrCertNodeRolesMismatch:
	// this one maps to NPS-AUTH-FORBIDDEN, that one to NPS-CLIENT-BAD-FRAME.
	ErrCertCapabilitiesExceeded = "NIP-CERT-CAPABILITIES-EXCEEDED"
)

// NipErrorToNpsStatus maps each NIP error code to its NPS status code.
var NipErrorToNpsStatus = map[string]string{
	ErrCertExpired:           core.NpsAuthUnauthenticated,
	ErrCertRevoked:           core.NpsAuthUnauthenticated,
	ErrCertSignatureInvalid:  core.NpsAuthUnauthenticated,
	ErrCertUntrustedIssuer:   core.NpsAuthUnauthenticated,
	ErrCertCapabilityMissing: core.NpsAuthForbidden,
	ErrCertScopeViolation:    core.NpsAuthForbidden,

	ErrCaNidNotFound:          core.NpsClientNotFound,
	ErrCaNidAlreadyExists:     core.NpsClientConflict,
	ErrCaSerialDuplicate:      core.NpsClientConflict,
	ErrCaRenewalTooEarly:      core.NpsClientBadParam,
	ErrCaScopeExpansionDenied: core.NpsAuthForbidden,

	ErrOcspUnavailable:   core.NpsServerUnavailable,
	ErrTrustFrameInvalid: core.NpsClientBadFrame,

	ErrAssuranceMismatch: core.NpsClientBadFrame,
	ErrAssuranceUnknown:  core.NpsClientBadFrame,

	ErrReputationEntryInvalid:   core.NpsClientBadFrame,
	ErrReputationLogUnreachable: core.NpsDownstreamUnavailable,

	ErrCertFormatInvalid:      core.NpsClientBadFrame,
	ErrCertEkuMissing:         core.NpsClientBadFrame,
	ErrCertSubjectNidMismatch: core.NpsClientBadFrame,
	ErrAcmeChallengeFailed:    core.NpsClientBadFrame,

	ErrTrustFrameExpired:             core.NpsAuthUnauthenticated,
	ErrTrustFrameGrantorRevoked:      core.NpsAuthUnauthenticated,
	ErrTrustFrameScopeExceedsGrantor: core.NpsAuthForbidden,
	ErrTrustFrameNodesPatternInvalid: core.NpsClientBadFrame,

	ErrRevokeFrameInvalid:            core.NpsClientBadFrame,
	ErrRevokeFrameUnauthorizedIssuer: core.NpsAuthForbidden,
	ErrRevokeFrameSerialMismatch:     core.NpsClientBadParam,
	ErrRevokeFrameReasonUnknown:      core.NpsClientBadFrame,

	ErrReputationGossipFork:       core.NpsServerInternal,
	ErrReputationGossipSigInvalid: core.NpsClientBadFrame,

	ErrCaGroupRevoked:           core.NpsAuthForbidden,
	ErrCaParentNotFound:         core.NpsClientNotFound,
	ErrCaParentNotGroup:         core.NpsClientBadParam,
	ErrCaSessionValidityInvalid: core.NpsClientBadParam,
	ErrCaJwsInvalid:             core.NpsAuthUnauthenticated,
	ErrCaJwsExpired:             core.NpsAuthUnauthenticated,

	ErrCertParentRevoked: core.NpsAuthUnauthenticated,
	ErrRaTokenInvalid:    core.NpsAuthUnauthenticated,
	ErrRaTokenExpired:    core.NpsAuthUnauthenticated,
	ErrRaNidNotAllowed:   core.NpsAuthForbidden,
	ErrRaPendingRejected: core.NpsAuthForbidden,
	ErrOcspStapleExpired: core.NpsAuthUnauthenticated,
	// spec/error-codes.md:119 — NIP-CERT-NODE-ROLES-MISMATCH is NPS-CLIENT-BAD-FRAME.
	ErrCertNodeRolesMismatch: core.NpsClientBadFrame,
	// spec/error-codes.md:120 — ...while its Phase-3 sibling is NPS-AUTH-FORBIDDEN.
	ErrCertCapabilitiesExceeded: core.NpsAuthForbidden,
}
