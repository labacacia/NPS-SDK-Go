// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

// Package acme — ACME `agent-01` client + in-process server per NPS-RFC-0002 §4.4.
package acme

const (
	ContentTypeJoseJSON = "application/jose+json"
	ContentTypeProblem  = "application/problem+json"
	ContentTypePemCert  = "application/pem-certificate-chain"

	ChallengeAgent01  = "agent-01"
	IdentifierTypeNID = "nid"
)

// ACME status enumeration values (RFC 8555 §7.1.6).
const (
	StatusPending     = "pending"
	StatusReady       = "ready"
	StatusProcessing  = "processing"
	StatusValid       = "valid"
	StatusInvalid     = "invalid"
	StatusExpired     = "expired"
	StatusDeactivated = "deactivated"
	StatusRevoked     = "revoked"
)
