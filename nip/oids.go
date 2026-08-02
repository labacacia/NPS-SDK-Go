// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import "encoding/asn1"

// NPS X.509 custom-extension OIDs under the LabAcacia IANA-assigned PEN arc
// 1.3.6.1.4.1.65715 (NPS-CR-0004, assigned 2026-05-08).
//
// These live in package nip rather than nip/x509 because nip/x509 imports nip
// (so nip cannot import it back), and the Phase-3 enforcer — which runs as step
// 3c of NipIdentVerifier — needs them. nip/x509 re-exports them, so both import
// paths keep working against a single source of truth.
var (
	// OidIdNpsNodeRoles is id-nps-node-roles: SEQUENCE OF UTF8String, the set of
	// node roles the CA attests for this subject.
	OidIdNpsNodeRoles = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 2, 2}
	// OidIdNpsCapabilities is id-nps-capabilities: SEQUENCE OF UTF8String, the set
	// of capabilities the CA attests for this subject (NIP v0.12 Phase-3).
	OidIdNpsCapabilities = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 2, 3}
)
