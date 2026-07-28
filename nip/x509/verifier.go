// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package x509

import (
	"bytes"
	cryptox509 "crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	npsnip "github.com/labacacia/NPS-sdk-go/nip"
)

// VerifyResult — outcome of NipX509Verifier.Verify.
type VerifyResult struct {
	Valid     bool
	ErrorCode string
	Message   string
	Leaf      *cryptox509.Certificate
}

func ok(leaf *cryptox509.Certificate) VerifyResult {
	return VerifyResult{Valid: true, Leaf: leaf}
}

func fail(errorCode, message string) VerifyResult {
	return VerifyResult{Valid: false, ErrorCode: errorCode, Message: message}
}

// VerifyOptions — inputs for Verify.
type VerifyOptions struct {
	CertChainBase64UrlDer  []string
	AssertedNID            string
	AssertedAssuranceLevel *npsnip.AssuranceLevel // nil = skip step
	TrustedRootCerts       []*cryptox509.Certificate
}

// Verify validates an NPS X.509 NID certificate chain per NPS-RFC-0002 §4.6.
//
// Stages:
//  1. Decode chain (base64url DER → x509.Certificate).
//  2. Leaf EKU check — critical, contains agent-identity OR node-identity OID.
//  3. Subject CN / SAN URI match against asserted NID.
//  4. Assurance-level extension match against asserted level (if both present).
//  5. Chain signature verification — leaf → intermediates → trusted root.
func Verify(opts VerifyOptions) VerifyResult {
	if len(opts.CertChainBase64UrlDer) == 0 {
		return fail(npsnip.ErrCertFormatInvalid, "cert_chain is empty")
	}
	chain := make([]*cryptox509.Certificate, 0, len(opts.CertChainBase64UrlDer))
	for i, s := range opts.CertChainBase64UrlDer {
		der, err := base64UrlDecode(s)
		if err != nil {
			return fail(npsnip.ErrCertFormatInvalid,
				fmt.Sprintf("chain[%d] base64url decode: %v", i, err))
		}
		c, err := cryptox509.ParseCertificate(der)
		if err != nil {
			return fail(npsnip.ErrCertFormatInvalid,
				fmt.Sprintf("chain[%d] DER parse: %v", i, err))
		}
		chain = append(chain, c)
	}
	leaf := chain[0]

	if r := checkLeafEku(leaf); !r.Valid {
		return r
	}
	if r := checkSubjectNid(leaf, opts.AssertedNID); !r.Valid {
		return r
	}
	if r := checkAssuranceLevel(leaf, opts.AssertedAssuranceLevel); !r.Valid {
		return r
	}
	if r := checkChainSignature(chain, opts.TrustedRootCerts); !r.Valid {
		return r
	}
	return ok(leaf)
}

func checkLeafEku(leaf *cryptox509.Certificate) VerifyResult {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidExtensionExtendedKeyUsage) {
			if !ext.Critical {
				return fail(npsnip.ErrCertEkuMissing,
					"ExtendedKeyUsage extension is not marked critical")
			}
			// Walk leaf.UnknownExtKeyUsage (where stdlib parks unrecognized OIDs).
			for _, oid := range leaf.UnknownExtKeyUsage {
				if oid.Equal(OidEkuAgentIdentity) || oid.Equal(OidEkuNodeIdentity) {
					return ok(leaf)
				}
			}
			return fail(npsnip.ErrCertEkuMissing,
				"ExtendedKeyUsage does not contain agent-identity or node-identity OID")
		}
	}
	return fail(npsnip.ErrCertEkuMissing, "leaf has no ExtendedKeyUsage extension")
}

func checkSubjectNid(leaf *cryptox509.Certificate, assertedNid string) VerifyResult {
	if leaf.Subject.CommonName != assertedNid {
		return fail(npsnip.ErrCertSubjectNidMismatch,
			fmt.Sprintf("leaf subject CN (%q) does not match asserted NID (%q)",
				leaf.Subject.CommonName, assertedNid))
	}
	for _, u := range leaf.URIs {
		if u != nil && u.String() == assertedNid {
			return ok(leaf)
		}
	}
	return fail(npsnip.ErrCertSubjectNidMismatch, "no SAN URI matches asserted NID")
}

func checkAssuranceLevel(leaf *cryptox509.Certificate, asserted *npsnip.AssuranceLevel) VerifyResult {
	if asserted == nil {
		return ok(leaf)
	}
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(OidNidAssuranceLevel) {
			continue
		}
		// ASN.1 ENUMERATED: tag=0x0A, len=0x01, content=<rank>.
		if len(ext.Value) != 3 || ext.Value[0] != 0x0A || ext.Value[1] != 0x01 {
			return fail(npsnip.ErrCertFormatInvalid,
				fmt.Sprintf("malformed assurance-level extension: %s", hex.EncodeToString(ext.Value)))
		}
		certLevel, err := npsnip.AssuranceFromRank(int(ext.Value[2]))
		if err != nil {
			return fail(npsnip.ErrAssuranceUnknown,
				fmt.Sprintf("assurance-level extension contains unknown value: %d", ext.Value[2]))
		}
		if certLevel != *asserted {
			return fail(npsnip.ErrAssuranceMismatch,
				fmt.Sprintf("cert assurance-level (%s) does not match asserted (%s)",
					certLevel.Wire, asserted.Wire))
		}
		return ok(leaf)
	}
	// Extension absent — optional in v0.1, pass silently.
	return ok(leaf)
}

func checkChainSignature(chain []*cryptox509.Certificate, trustedRoots []*cryptox509.Certificate) VerifyResult {
	if len(trustedRoots) == 0 {
		return fail(npsnip.ErrCertFormatInvalid, "no trusted X.509 roots configured")
	}
	// Walk leaf → intermediates: each MUST be signed by its successor.
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return fail(npsnip.ErrCertFormatInvalid,
				fmt.Sprintf("chain link %d signature did not verify: %v", i, err))
		}
	}
	last := chain[len(chain)-1]
	for _, root := range trustedRoots {
		if bytes.Equal(last.Raw, root.Raw) {
			return ok(chain[0])
		}
		// Verify last is issued under this root.
		if err := last.CheckSignatureFrom(root); err == nil {
			return ok(chain[0])
		}
	}
	return fail(npsnip.ErrCertFormatInvalid, "chain does not anchor to any trusted root")
}

func base64UrlDecode(s string) ([]byte, error) {
	// Pad if needed.
	if pad := len(s) % 4; pad != 0 {
		s += "===="[:4-pad]
	}
	return base64.URLEncoding.DecodeString(s)
}
