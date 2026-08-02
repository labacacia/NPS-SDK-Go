// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

// Package x509 — NPS X.509 NID certificate primitives per NPS-RFC-0002 §4.
package x509

import (
	"encoding/asn1"

	npsnip "github.com/labacacia/NPS-sdk-go/nip"
)

// The 1.3.6.1.4.1.65715 arc is the LabAcacia IANA-assigned PEN
// (NPS-CR-0004, assigned 2026-05-08; see NPS-RFC-0002 §10 OQ-2).
var (
	// EKU OIDs (NPS-RFC-0002 §4.1).
	OidEkuAgentIdentity       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 1, 1}
	OidEkuNodeIdentity        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 1, 2}
	OidEkuCaIntermediateAgent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 1, 3}

	// Custom extensions.
	OidNidAssuranceLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 2, 1}

	// Re-exported from package nip so both import paths name the same value.
	// Consumed by the NIP v0.12 §7.5 Phase-3 enforcer.
	OidIdNpsNodeRoles    = npsnip.OidIdNpsNodeRoles
	OidIdNpsCapabilities = npsnip.OidIdNpsCapabilities
)
