// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/nip"
)

// Brief B Part 1 §6 — fixed clock.
var phase3Now = time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

// ── Cert fixture ──────────────────────────────────────────────────────────────

// utf8SequenceDER encodes a `SEQUENCE OF UTF8String` extension value.
func utf8SequenceDER(t *testing.T, values []string) []byte {
	t.Helper()
	var body []byte
	for _, v := range values {
		item, err := asn1.MarshalWithParams(v, "utf8")
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, item...)
	}
	seq, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

// phase3Cert builds a self-signed ECDSA P-256 cert, CN=phase3-test, valid
// Now-1d .. Now+30d, optionally carrying the id-nps-* extensions.
// Pass nil to OMIT an extension; pass a (possibly empty) slice to include it.
func phase3Cert(t *testing.T, roles, caps []string) *cryptox509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &cryptox509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "phase3-test"},
		NotBefore:    phase3Now.Add(-24 * time.Hour),
		NotAfter:     phase3Now.Add(30 * 24 * time.Hour),
	}
	if roles != nil {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: nip.OidIdNpsNodeRoles, Critical: false, Value: utf8SequenceDER(t, roles),
		})
	}
	if caps != nil {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: nip.OidIdNpsCapabilities, Critical: false, Value: utf8SequenceDER(t, caps),
		})
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := cryptox509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// certWithRawExtension builds a cert carrying a deliberately malformed extension value.
func certWithRawExtension(t *testing.T, oid asn1.ObjectIdentifier, value []byte) *cryptox509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &cryptox509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "phase3-test"},
		NotBefore:       phase3Now.Add(-24 * time.Hour),
		NotAfter:        phase3Now.Add(30 * 24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oid, Value: value}},
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := cryptox509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// ── OCSP staple fixture (hand-built minimal RFC 6960 OCSPResponse) ────────────

func tlv(class, tag int, compound bool, body []byte) []byte {
	out, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: body})
	if err != nil {
		panic(err)
	}
	return out
}

func genTime(t time.Time) []byte {
	return tlv(asn1.ClassUniversal, asn1.TagGeneralizedTime, false,
		[]byte(t.UTC().Format("20060102150405Z")))
}

// ocspStaple builds a minimal DER OCSPResponse whose single SingleResponse
// carries the given nextUpdate, base64url-encoded without padding.
// Pass withNextUpdate=false to omit the optional nextUpdate entirely.
func ocspStaple(nextUpdate time.Time, withNextUpdate bool) string {
	// SingleResponse ::= SEQUENCE { certID SEQUENCE, certStatus [0] good,
	//                               thisUpdate GeneralizedTime, nextUpdate [0] EXPLICIT ... }
	var single []byte
	single = append(single, tlv(asn1.ClassUniversal, asn1.TagSequence, true, nil)...) // certID
	single = append(single, tlv(asn1.ClassContextSpecific, 0, false, nil)...)         // certStatus good
	single = append(single, genTime(nextUpdate.Add(-time.Hour))...)                   // thisUpdate
	if withNextUpdate {
		single = append(single, tlv(asn1.ClassContextSpecific, 0, true, genTime(nextUpdate))...)
	}
	singleSeq := tlv(asn1.ClassUniversal, asn1.TagSequence, true, single)
	responses := tlv(asn1.ClassUniversal, asn1.TagSequence, true, singleSeq)

	// ResponseData ::= SEQUENCE { responderID [1], producedAt, responses }
	var rd []byte
	rd = append(rd, tlv(asn1.ClassContextSpecific, 1, true, nil)...) // responderID byName
	rd = append(rd, genTime(nextUpdate.Add(-2*time.Hour))...)        // producedAt
	rd = append(rd, responses...)
	responseData := tlv(asn1.ClassUniversal, asn1.TagSequence, true, rd)

	// BasicOCSPResponse ::= SEQUENCE { tbsResponseData, ... }
	basic := tlv(asn1.ClassUniversal, asn1.TagSequence, true, responseData)
	octet := tlv(asn1.ClassUniversal, asn1.TagOctetString, false, basic)

	oid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1})
	respBytes := tlv(asn1.ClassUniversal, asn1.TagSequence, true, append(oid, octet...))

	status, _ := asn1.Marshal(asn1.Enumerated(0))
	outer := tlv(asn1.ClassUniversal, asn1.TagSequence, true,
		append(status, tlv(asn1.ClassContextSpecific, 0, true, respBytes)...))

	return base64.RawURLEncoding.EncodeToString(outer)
}

// ── IdentFrame fixture ────────────────────────────────────────────────────────

func phase3Frame(roles, caps []string, staple string) *nip.IdentFrame {
	sig := "ed25519:test"
	format := nip.CertFormatV2X509
	return &nip.IdentFrame{
		NID:          "urn:nps:agent:ca.example.com:p3-001",
		PubKey:       "ed25519:AAAA",
		Signature:    &sig,
		CertFormat:   &format,
		NodeRoles:    roles,
		Capabilities: caps,
		OCSPStaple:   staple,
	}
}

// ── §6 — the eight enforcer scenarios ─────────────────────────────────────────

func TestPhase3_SubsetClaimsWithFreshStaplePass(t *testing.T) {
	cert := phase3Cert(t, []string{"memory", "anchor"}, []string{"nwp:query", "nwp:action"})
	frame := phase3Frame([]string{"memory"}, []string{"nwp:query"},
		ocspStaple(phase3Now.Add(6*time.Hour), true))

	if r := nip.Phase3Enforce(frame, cert, phase3Now); !r.Valid {
		t.Fatalf("expected valid, got %s: %s", r.ErrorCode, r.Message)
	}
}

func TestPhase3_UnattestedRoleFailsWithNodeRolesMismatch(t *testing.T) {
	cert := phase3Cert(t, []string{"memory"}, nil)
	frame := phase3Frame([]string{"memory", "orchestrator"}, nil,
		ocspStaple(phase3Now.Add(6*time.Hour), true))

	r := nip.Phase3Enforce(frame, cert, phase3Now)
	if r.Valid || r.ErrorCode != "NIP-CERT-NODE-ROLES-MISMATCH" {
		t.Fatalf("got valid=%v code=%s", r.Valid, r.ErrorCode)
	}
	if r.StepFailed != 3 {
		t.Errorf("Phase-3 failures use step 3, got %d", r.StepFailed)
	}
	if !strings.Contains(r.Message, "orchestrator") {
		t.Errorf("the message must enumerate the excess: %s", r.Message)
	}
}

func TestPhase3_UnattestedCapabilityFailsWithCapabilitiesExceeded(t *testing.T) {
	cert := phase3Cert(t, nil, []string{"nwp:query"})
	frame := phase3Frame(nil, []string{"nwp:query", "nop:orchestrate"},
		ocspStaple(phase3Now.Add(6*time.Hour), true))

	r := nip.Phase3Enforce(frame, cert, phase3Now)
	if r.Valid || r.ErrorCode != "NIP-CERT-CAPABILITIES-EXCEEDED" {
		t.Fatalf("got valid=%v code=%s", r.Valid, r.ErrorCode)
	}
	if !strings.Contains(r.Message, "nop:orchestrate") {
		t.Errorf("the message must enumerate the excess: %s", r.Message)
	}
	// The new code's status mapping, and the asymmetry with its sibling.
	if got := nip.NipErrorToNpsStatus["NIP-CERT-CAPABILITIES-EXCEEDED"]; got != "NPS-AUTH-FORBIDDEN" {
		t.Errorf("NIP-CERT-CAPABILITIES-EXCEEDED must map to NPS-AUTH-FORBIDDEN, got %s", got)
	}
	if got := nip.NipErrorToNpsStatus["NIP-CERT-NODE-ROLES-MISMATCH"]; got != "NPS-CLIENT-BAD-FRAME" {
		t.Errorf("NIP-CERT-NODE-ROLES-MISMATCH must map to NPS-CLIENT-BAD-FRAME, got %s", got)
	}
}

func TestPhase3_NoExtensionsMeansAttributeChecksDoNotApply(t *testing.T) {
	cert := phase3Cert(t, nil, nil) // no id-nps-* extensions at all
	frame := phase3Frame([]string{"anything", "at", "all"}, []string{"nop:orchestrate"},
		ocspStaple(phase3Now.Add(6*time.Hour), true))

	if r := nip.Phase3Enforce(frame, cert, phase3Now); !r.Valid {
		t.Fatalf("an absent extension SKIPS its check; got %s: %s", r.ErrorCode, r.Message)
	}
}

func TestPhase3_MissingStapleFails(t *testing.T) {
	cert := phase3Cert(t, nil, nil)
	frame := phase3Frame(nil, nil, "")

	r := nip.Phase3Enforce(frame, cert, phase3Now)
	if r.Valid || r.ErrorCode != "NIP-OCSP-STAPLE-EXPIRED" {
		t.Fatalf("got valid=%v code=%s", r.Valid, r.ErrorCode)
	}
	if !strings.Contains(r.Message, "none was supplied") {
		t.Errorf("message: %s", r.Message)
	}
}

func TestPhase3_ExpiredStapleFails(t *testing.T) {
	cert := phase3Cert(t, nil, nil)
	frame := phase3Frame(nil, nil, ocspStaple(phase3Now.Add(-time.Minute), true))

	r := nip.Phase3Enforce(frame, cert, phase3Now)
	if r.Valid || r.ErrorCode != "NIP-OCSP-STAPLE-EXPIRED" {
		t.Fatalf("got valid=%v code=%s", r.Valid, r.ErrorCode)
	}
	if !strings.Contains(r.Message, "elapsed") {
		t.Errorf("message must contain \"elapsed\": %s", r.Message)
	}
}

func TestPhase3_MalformedStapleFailsClosed(t *testing.T) {
	cert := phase3Cert(t, nil, nil)
	frame := phase3Frame(nil, nil, "bm90LWFuLW9jc3A")

	r := nip.Phase3Enforce(frame, cert, phase3Now)
	if r.Valid || r.ErrorCode != "NIP-OCSP-STAPLE-EXPIRED" {
		t.Fatalf("a malformed staple must fail closed; got valid=%v code=%s", r.Valid, r.ErrorCode)
	}
}

func TestPhase3_Utf8SequenceExtensionParses(t *testing.T) {
	cert := phase3Cert(t, []string{"memory", "anchor"}, nil)

	roles, present := nip.ReadUtf8SequenceExtension(cert, nip.OidIdNpsNodeRoles)
	if !present {
		t.Fatal("id-nps-node-roles must be reported present")
	}
	if len(roles) != 2 || roles[0] != "memory" || roles[1] != "anchor" {
		t.Errorf("roles: %v", roles)
	}

	caps, present := nip.ReadUtf8SequenceExtension(cert, nip.OidIdNpsCapabilities)
	if present {
		t.Error("an absent id-nps-capabilities must report present == false (the null case)")
	}
	if caps != nil {
		t.Errorf("an absent extension returns nil, not []: %v", caps)
	}
}

// ── Ports SHOULD additionally add (brief B §6 tail) ──────────────────────────

func TestPhase3_MalformedExtensionIsTreatedAsEmptyAndAnyClaimFails(t *testing.T) {
	cert := certWithRawExtension(t, nip.OidIdNpsCapabilities, []byte{0x01, 0x02, 0x03})

	values, present := nip.ReadUtf8SequenceExtension(cert, nip.OidIdNpsCapabilities)
	if !present {
		t.Fatal("a malformed extension is still PRESENT — the strictest reading")
	}
	if values == nil || len(values) != 0 {
		t.Fatalf("a malformed extension reads as the empty list, got %v", values)
	}

	frame := phase3Frame(nil, []string{"nwp:query"}, ocspStaple(phase3Now.Add(time.Hour), true))
	r := nip.Phase3Enforce(frame, cert, phase3Now)
	if r.Valid || r.ErrorCode != "NIP-CERT-CAPABILITIES-EXCEEDED" {
		t.Fatalf("any claim against a malformed extension must fail; got valid=%v code=%s", r.Valid, r.ErrorCode)
	}
}

func TestPhase3_PresentButEmptyExtensionRejectsAnyClaimAndAllowsNone(t *testing.T) {
	cert := phase3Cert(t, []string{}, nil) // present, valid, empty

	values, present := nip.ReadUtf8SequenceExtension(cert, nip.OidIdNpsNodeRoles)
	if !present || len(values) != 0 {
		t.Fatalf("present-but-empty must be distinguishable from absent: present=%v values=%v", present, values)
	}

	staple := ocspStaple(phase3Now.Add(time.Hour), true)
	if r := nip.Phase3Enforce(phase3Frame(nil, nil, staple), cert, phase3Now); !r.Valid {
		t.Errorf("claiming nothing is a subset of the empty set: %s", r.Message)
	}
	if r := nip.Phase3Enforce(phase3Frame([]string{"memory"}, nil, staple), cert, phase3Now); r.Valid {
		t.Error("claiming anything exceeds the empty attested set")
	}
}

func TestPhase3_NextUpdateExactlyNowFails(t *testing.T) {
	cert := phase3Cert(t, nil, nil)
	frame := phase3Frame(nil, nil, ocspStaple(phase3Now, true))

	r := nip.Phase3Enforce(frame, cert, phase3Now)
	if r.Valid {
		t.Fatal("the comparison is `nextUpdate <= now`, so exactly-now has elapsed")
	}
	if r.ErrorCode != "NIP-OCSP-STAPLE-EXPIRED" {
		t.Errorf("code: %s", r.ErrorCode)
	}
}

func TestPhase3_StapleWithoutNextUpdateFails(t *testing.T) {
	cert := phase3Cert(t, nil, nil)
	frame := phase3Frame(nil, nil, ocspStaple(phase3Now.Add(time.Hour), false))

	r := nip.Phase3Enforce(frame, cert, phase3Now)
	if r.Valid || r.ErrorCode != "NIP-OCSP-STAPLE-EXPIRED" {
		t.Fatalf("a staple with no nextUpdate must fail closed; got valid=%v code=%s", r.Valid, r.ErrorCode)
	}
	if !strings.Contains(r.Message, "nextUpdate") {
		t.Errorf("message: %s", r.Message)
	}
}

func TestPhase3_SubsetComparisonIsOrdinal(t *testing.T) {
	cert := phase3Cert(t, nil, []string{"NWP:Query"})
	frame := phase3Frame(nil, []string{"nwp:query"}, ocspStaple(phase3Now.Add(time.Hour), true))

	if r := nip.Phase3Enforce(frame, cert, phase3Now); r.Valid {
		t.Error("comparison is ordinal / exact-byte — case must NOT be folded")
	}
}

func TestPhase3_EvaluationOrderIsRolesThenCapsThenStaple(t *testing.T) {
	// A frame that violates all three: the roles row must be the one reported.
	cert := phase3Cert(t, []string{}, []string{})
	frame := phase3Frame([]string{"memory"}, []string{"nwp:query"}, "")

	if r := nip.Phase3Enforce(frame, cert, phase3Now); r.ErrorCode != "NIP-CERT-NODE-ROLES-MISMATCH" {
		t.Fatalf("node_roles must be evaluated first, got %s", r.ErrorCode)
	}

	// With roles clean, capabilities is next — ahead of the missing staple.
	frame = phase3Frame(nil, []string{"nwp:query"}, "")
	if r := nip.Phase3Enforce(frame, cert, phase3Now); r.ErrorCode != "NIP-CERT-CAPABILITIES-EXCEEDED" {
		t.Fatalf("capabilities must be evaluated before the staple, got %s", r.ErrorCode)
	}
}

func TestTryGetOcspNextUpdate_IsExportedAndReadsTheStaple(t *testing.T) {
	want := phase3Now.Add(6 * time.Hour)
	der, err := base64.RawURLEncoding.DecodeString(ocspStaple(want, true))
	if err != nil {
		t.Fatal(err)
	}

	got, ok := nip.TryGetOcspNextUpdate(der)
	if !ok {
		t.Fatal("expected a nextUpdate")
	}
	if !got.Equal(want) {
		t.Errorf("nextUpdate = %s, want %s", got, want)
	}

	if _, ok := nip.TryGetOcspNextUpdate([]byte("not-an-ocsp")); ok {
		t.Error("garbage must not parse")
	}
	if _, ok := nip.TryGetOcspNextUpdate(nil); ok {
		t.Error("nil must not parse")
	}
}

// ── Verifier integration (step 3c) ────────────────────────────────────────────

func phase3VerifierFixture(t *testing.T, enforce bool, chainOK bool) (*nip.NipIdentVerifier, *cryptox509.Certificate) {
	t.Helper()
	cert := phase3Cert(t, []string{"memory"}, []string{"nwp:query"})
	v := nip.NewNipIdentVerifier(
		nip.VerifierOptions{
			TrustedX509Roots:  []*cryptox509.Certificate{cert},
			Phase3Enforcement: enforce,
			Now:               phase3Now,
		},
		func([]string, string, *nip.AssuranceLevel, []*cryptox509.Certificate) (bool, string, string) {
			if chainOK {
				return true, "", ""
			}
			return false, "NIP-CERT-UNTRUSTED-ISSUER", "chain rejected"
		},
	)
	return v, cert
}

// signedFrame produces a frame whose step-1 signature verifies, so the verifier
// reaches step 3.
func signedFrame(t *testing.T, cert *cryptox509.Certificate, roles, caps []string, staple string) (*nip.IdentFrame, *nip.NipIdentity, string) {
	t.Helper()
	id, err := nip.Generate()
	if err != nil {
		t.Fatal(err)
	}
	f := phase3Frame(roles, caps, staple)
	f.CertChain = []string{base64.RawURLEncoding.EncodeToString(cert.Raw)}
	sig := id.Sign(f.UnsignedDict())
	f.Signature = &sig
	return f, id, "urn:nps:org:example.com"
}

func TestVerifier_Phase3FlagOffLeavesAFailingFrameValid(t *testing.T) {
	v, cert := phase3VerifierFixture(t, false, true)
	f, id, issuer := signedFrame(t, cert, []string{"memory", "orchestrator"}, nil, "")
	v.Options.TrustedCaPublicKeys = map[string]string{issuer: id.PubKeyString()}

	if r := v.Verify(f, issuer); !r.Valid {
		t.Fatalf("with phase3_enforcement=false the checks are ADVISORY; got %s: %s", r.ErrorCode, r.Message)
	}
}

func TestVerifier_Phase3FlagOnRejectsTheSameFrame(t *testing.T) {
	v, cert := phase3VerifierFixture(t, true, true)
	f, id, issuer := signedFrame(t, cert, []string{"memory", "orchestrator"}, nil, "")
	v.Options.TrustedCaPublicKeys = map[string]string{issuer: id.PubKeyString()}

	r := v.Verify(f, issuer)
	if r.Valid || r.ErrorCode != "NIP-CERT-NODE-ROLES-MISMATCH" || r.StepFailed != 3 {
		t.Fatalf("expected a step-3 NIP-CERT-NODE-ROLES-MISMATCH, got valid=%v code=%s step=%d",
			r.Valid, r.ErrorCode, r.StepFailed)
	}
}

func TestVerifier_Phase3IsNotInvokedForNonV2Frames(t *testing.T) {
	v, cert := phase3VerifierFixture(t, true, true)
	f, id, issuer := signedFrame(t, cert, []string{"memory", "orchestrator"}, nil, "")
	f.CertFormat = nil // a self-declared / v1 NID
	sig := id.Sign(f.UnsignedDict())
	f.Signature = &sig
	v.Options.TrustedCaPublicKeys = map[string]string{issuer: id.PubKeyString()}

	if r := v.Verify(f, issuer); !r.Valid {
		t.Fatalf("self-declared / v1 NIDs are entirely unaffected by Phase-3; got %s", r.ErrorCode)
	}
}

func TestVerifier_Phase3RunsOnlyAfterTheChainCheckPasses(t *testing.T) {
	v, cert := phase3VerifierFixture(t, true, false) // chain check FAILS
	f, id, issuer := signedFrame(t, cert, []string{"memory", "orchestrator"}, nil, "")
	v.Options.TrustedCaPublicKeys = map[string]string{issuer: id.PubKeyString()}

	r := v.Verify(f, issuer)
	if r.ErrorCode != "NIP-CERT-UNTRUSTED-ISSUER" {
		t.Fatalf("the chain failure must short-circuit before Phase-3, got %s", r.ErrorCode)
	}
}

func TestVerifier_Phase3PassesAConformantV2Frame(t *testing.T) {
	v, cert := phase3VerifierFixture(t, true, true)
	f, id, issuer := signedFrame(t, cert, []string{"memory"}, []string{"nwp:query"},
		ocspStaple(phase3Now.Add(6*time.Hour), true))
	v.Options.TrustedCaPublicKeys = map[string]string{issuer: id.PubKeyString()}

	if r := v.Verify(f, issuer); !r.Valid {
		t.Fatalf("a conformant frame must verify: %s / %s", r.ErrorCode, r.Message)
	}
}

// ── IdentFrame.capabilities canonical-form regression ────────────────────────

func TestIdentFrame_CapabilitiesIsSignedButOmittedWhenUnset(t *testing.T) {
	f := phase3Frame(nil, nil, "")
	if _, ok := f.UnsignedDict()["capabilities"]; ok {
		t.Fatal("an unset capabilities must be omitted from the signed body")
	}

	f.Capabilities = []string{"nwp:query"}
	if _, ok := f.UnsignedDict()["capabilities"]; !ok {
		t.Fatal("capabilities MUST be inside the signed body when present")
	}
	// node_roles stays excluded from the signed body, as in the reference impl.
	f.NodeRoles = []string{"memory"}
	if _, ok := f.UnsignedDict()["node_roles"]; ok {
		t.Error("node_roles must stay OUT of the signed body")
	}
	if _, ok := f.ToDict()["node_roles"]; !ok {
		t.Error("node_roles must still be on the wire")
	}
}
