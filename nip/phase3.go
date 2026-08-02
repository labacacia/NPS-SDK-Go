// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import (
	cryptox509 "crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// NIP v0.12 §7.5 — Phase-3 enforcement.
//
// Phase 1–2 (VerifierOptions.Phase3Enforcement == false, the current default):
// receivers SHOULD perform these checks but a failure is ADVISORY — logged or
// metered, never on its own a reason to reject the IdentFrame.
// With the flag on, all four normative rows are hard failures.
//
// The flag day (v1.0.0-beta.1) flips the DEFAULT to true; it is a default
// change, not a code change. `public-federated` deployments (NDP §7) MUST NOT
// then set it false; `local-dev` / `org-private` MAY.
//
// The four normative rows are:
//
//	assurance     IdentFrame.assurance_level == id-nid-assurance-level  NIP-ASSURANCE-MISMATCH
//	node roles    node_roles   ⊆ id-nps-node-roles                      NIP-CERT-NODE-ROLES-MISMATCH
//	capabilities  capabilities ⊆ id-nps-capabilities                    NIP-CERT-CAPABILITIES-EXCEEDED
//	OCSP staple   ocsp_staple present and nextUpdate in the future      NIP-OCSP-STAPLE-EXPIRED
//
// Phase3Enforce implements rows 2, 3, 4 in that fixed order. The ASSURANCE row
// deliberately lives elsewhere — nip/x509.checkAssuranceLevel — and runs
// UNCONDITIONALLY as step 3 of chain validation regardless of the flag, exactly
// as in the reference impl. With the flag on, all four are hard failures.

// Phase3Step is the verifier step Phase-3 failures are attributed to.
const Phase3Step = 3

// Phase3Enforce runs the Phase-3 attribute and staple checks for a v2-x509
// IdentFrame against its leaf certificate.
//
// Pass the zero time.Time for `now` to use the current UTC time; tests inject a
// fixed clock. The function is stateless and pure — no I/O, no network.
func Phase3Enforce(frame *IdentFrame, leaf *cryptox509.Certificate, now time.Time) IdentVerifyResult {
	if frame == nil {
		return fail(Phase3Step, ErrCertFormatInvalid, "Phase-3 enforcement requires an IdentFrame.")
	}
	if leaf == nil {
		return fail(Phase3Step, ErrCertFormatInvalid, "Phase-3 enforcement requires a leaf certificate.")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Row 2 — node_roles ⊆ id-nps-node-roles.
	if attested, present := ReadUtf8SequenceExtension(leaf, OidIdNpsNodeRoles); present {
		if excess := subsetExcess(frame.NodeRoles, attested); len(excess) > 0 {
			return fail(Phase3Step, ErrCertNodeRolesMismatch, fmt.Sprintf(
				"IdentFrame.node_roles claims role(s) not attested by id-nps-node-roles: %s.",
				strings.Join(excess, ", ")))
		}
	}

	// Row 3 — capabilities ⊆ id-nps-capabilities.
	if attested, present := ReadUtf8SequenceExtension(leaf, OidIdNpsCapabilities); present {
		if excess := subsetExcess(frame.Capabilities, attested); len(excess) > 0 {
			return fail(Phase3Step, ErrCertCapabilitiesExceeded, fmt.Sprintf(
				"IdentFrame.capabilities claims capabilit(ies) not attested by id-nps-capabilities: %s.",
				strings.Join(excess, ", ")))
		}
	}

	// Row 4 — the OCSP staple. Unlike the two attribute rows there is no
	// "only if present" escape: under enforcement every v2-x509 frame must
	// carry a fresh staple. All four failure modes below collapse onto
	// NIP-OCSP-STAPLE-EXPIRED — fail closed.
	if strings.TrimSpace(frame.OCSPStaple) == "" {
		return fail(Phase3Step, ErrOcspStapleExpired,
			"Phase-3 enforcement requires ocsp_staple on v2-x509 IdentFrames; none was supplied.")
	}
	der, err := decodeBase64UrlLoose(frame.OCSPStaple)
	if err != nil {
		return fail(Phase3Step, ErrOcspStapleExpired, "ocsp_staple is not valid base64url.")
	}
	nextUpdate, ok := TryGetOcspNextUpdate(der)
	if !ok {
		return fail(Phase3Step, ErrOcspStapleExpired,
			"ocsp_staple could not be parsed as a DER OCSPResponse with a nextUpdate.")
	}
	// Note `<=`, not `<`: nextUpdate exactly equal to now has elapsed.
	if !nextUpdate.After(now) {
		return fail(Phase3Step, ErrOcspStapleExpired, fmt.Sprintf(
			"ocsp_staple nextUpdate %s has elapsed.", nextUpdate.UTC().Format(time.RFC3339Nano)))
	}

	return IdentVerifyResult{Valid: true}
}

// subsetExcess returns the claimed entries absent from attested — the
// set difference `claimed \ attested`. Comparison is ORDINAL (exact byte)
// string equality: no case folding, no normalization, no trimming.
// A nil `claimed` is the empty set and is therefore always a subset.
func subsetExcess(claimed, attested []string) []string {
	if len(claimed) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(attested))
	for _, a := range attested {
		allowed[a] = struct{}{}
	}
	var excess []string
	seen := make(map[string]struct{}, len(claimed))
	for _, c := range claimed {
		if _, ok := allowed[c]; ok {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		excess = append(excess, c)
	}
	return excess
}

// ReadUtf8SequenceExtension reads a `SEQUENCE OF UTF8String` X.509 extension.
//
// The tri-state return IS the rule for "applies only when the corresponding
// extension is present":
//
//	extension absent from the cert        -> (nil, false)  check is SKIPPED entirely
//	present, valid SEQUENCE OF UTF8String -> (list, true)  subset check runs (list may be empty)
//	present but malformed ASN.1           -> ([], true)    strictest reading: any claim exceeds it
//
// Collapsing "absent" into "present but empty" would turn a fail-closed case
// into a skip, so callers MUST branch on the boolean, not on len(list).
func ReadUtf8SequenceExtension(cert *cryptox509.Certificate, oid asn1.ObjectIdentifier) ([]string, bool) {
	if cert == nil {
		return nil, false
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		// First extension whose OID matches wins.
		values, err := parseUtf8Sequence(ext.Value)
		if err != nil {
			// Present but malformed: the strictest reading is an empty attested
			// set, so any claim at all exceeds it.
			return []string{}, true
		}
		return values, true
	}
	return nil, false
}

func parseUtf8Sequence(der []byte) ([]string, error) {
	seq, _, err := readTLV(der)
	if err != nil {
		return nil, err
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, fmt.Errorf("expected a DER SEQUENCE")
	}
	out := []string{}
	rest := seq.Bytes
	for len(rest) > 0 {
		var item asn1.RawValue
		item, rest, err = readTLV(rest)
		if err != nil {
			return nil, err
		}
		if item.Class != asn1.ClassUniversal || item.Tag != asn1.TagUTF8String {
			return nil, fmt.Errorf("expected UTF8String, got class %d tag %d", item.Class, item.Tag)
		}
		out = append(out, string(item.Bytes))
	}
	return out, nil
}

// TryGetOcspNextUpdate is a minimal RFC 6960 DER walk that recovers the first
// SingleResponse's nextUpdate. It deliberately does NOT verify the OCSP
// signature — Phase-3's concern is freshness, not authenticity, and the
// authenticity of the responder is a chain-validation concern.
//
//	OCSPResponse      ::= SEQUENCE { responseStatus ENUMERATED,
//	                                 responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
//	ResponseBytes     ::= SEQUENCE { responseType OID (id-pkix-ocsp-basic 1.3.6.1.5.5.7.48.1.1),
//	                                 response OCTET STRING }   -- wraps BasicOCSPResponse
//	BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData, ... }
//	ResponseData      ::= SEQUENCE { version [0] EXPLICIT OPTIONAL,
//	                                 responderID CHOICE [1]/[2],
//	                                 producedAt GeneralizedTime,
//	                                 responses SEQUENCE OF SingleResponse }
//	SingleResponse    ::= SEQUENCE { certID SEQUENCE, certStatus CHOICE (context-specific),
//	                                 thisUpdate GeneralizedTime,
//	                                 nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL, ... }
//
// Returns ok == false when responseBytes is absent, `responses` is empty,
// nextUpdate is absent, or any ASN.1 content is malformed. Only the FIRST
// SingleResponse is inspected.
func TryGetOcspNextUpdate(der []byte) (time.Time, bool) {
	var zero time.Time

	outer, _, err := readTLV(der)
	if err != nil || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return zero, false
	}
	rest := outer.Bytes

	// responseStatus ENUMERATED — skipped.
	if _, rest, err = readTLV(rest); err != nil {
		return zero, false
	}

	// responseBytes [0] EXPLICIT — OPTIONAL; absent means there is nothing to read.
	respBytes, _, err := readTLV(rest)
	if err != nil || respBytes.Class != asn1.ClassContextSpecific || respBytes.Tag != 0 {
		return zero, false
	}
	inner, _, err := readTLV(respBytes.Bytes)
	if err != nil || inner.Tag != asn1.TagSequence {
		return zero, false
	}
	r := inner.Bytes

	// responseType OID — skipped (we only ever consume id-pkix-ocsp-basic).
	if _, r, err = readTLV(r); err != nil {
		return zero, false
	}
	octet, _, err := readTLV(r)
	if err != nil || octet.Tag != asn1.TagOctetString {
		return zero, false
	}

	basic, _, err := readTLV(octet.Bytes)
	if err != nil || basic.Tag != asn1.TagSequence {
		return zero, false
	}
	tbs, _, err := readTLV(basic.Bytes)
	if err != nil || tbs.Tag != asn1.TagSequence {
		return zero, false
	}
	c := tbs.Bytes

	// version [0] EXPLICIT OPTIONAL — skip when the constructed [0] tag is present.
	v, after, err := readTLV(c)
	if err != nil {
		return zero, false
	}
	if v.Class == asn1.ClassContextSpecific && v.Tag == 0 && v.IsCompound {
		c = after
	}
	// responderID CHOICE [1] byName / [2] byKey — skip any context-specific value.
	v, after, err = readTLV(c)
	if err != nil {
		return zero, false
	}
	if v.Class == asn1.ClassContextSpecific {
		c = after
	}
	// producedAt GeneralizedTime — skipped.
	if _, c, err = readTLV(c); err != nil {
		return zero, false
	}

	// responses SEQUENCE OF SingleResponse.
	responses, _, err := readTLV(c)
	if err != nil || responses.Tag != asn1.TagSequence {
		return zero, false
	}
	if len(responses.Bytes) == 0 {
		return zero, false // empty responses
	}
	single, _, err := readTLV(responses.Bytes)
	if err != nil || single.Tag != asn1.TagSequence {
		return zero, false
	}
	s := single.Bytes

	// certID SEQUENCE, certStatus CHOICE, thisUpdate GeneralizedTime — all skipped.
	for i := 0; i < 3; i++ {
		if _, s, err = readTLV(s); err != nil {
			return zero, false
		}
	}

	// nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL.
	nu, _, err := readTLV(s)
	if err != nil || nu.Class != asn1.ClassContextSpecific || nu.Tag != 0 {
		return zero, false
	}
	gt, _, err := readTLV(nu.Bytes)
	if err != nil || gt.Tag != asn1.TagGeneralizedTime {
		return zero, false
	}
	return parseGeneralizedTime(string(gt.Bytes))
}

func parseGeneralizedTime(s string) (time.Time, bool) {
	for _, layout := range []string{
		"20060102150405Z0700",
		"20060102150405.999999999Z0700",
		"20060102150405",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// readTLV consumes one DER TLV off the front of b and returns it plus the remainder.
func readTLV(b []byte) (asn1.RawValue, []byte, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(b, &v)
	if err != nil {
		return v, nil, err
	}
	return v, rest, nil
}

// decodeBase64Url decodes base64url with or without padding, accepting the
// standard alphabet's '+'/'/' too so a mis-encoded staple still round-trips.
func decodeBase64UrlLoose(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	return base64.RawStdEncoding.DecodeString(s)
}

// DecodeCertChainLeaf decodes cert_chain[0] — base64url(DER) — into a certificate.
func DecodeCertChainLeaf(chain []string) (*cryptox509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("cert_chain is empty")
	}
	der, err := decodeBase64UrlLoose(chain[0])
	if err != nil {
		return nil, err
	}
	return cryptox509.ParseCertificate(der)
}
