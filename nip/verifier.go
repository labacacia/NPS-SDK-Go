// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import (
	"context"
	"crypto/ed25519"
	cryptox509 "crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// VerifierOptions — configuration for NipIdentVerifier per NPS-3 §7 / NPS-RFC-0002 §8.1.
type VerifierOptions struct {
	// TrustedCaPublicKeys maps issuer NID → CA public key string ("ed25519:<base64url>").
	// Used by both the legacy dual-trust Verify and the full VerifyFull (steps 2–3).
	TrustedCaPublicKeys map[string]string
	// TrustedX509Roots — empty/nil makes the X.509 chain step skip even for v2 frames.
	TrustedX509Roots []*cryptox509.Certificate
	// MinAssuranceLevel — when non-nil, frames below this rank are rejected.
	MinAssuranceLevel *AssuranceLevel

	// ── Full NPS-3 §7 verifier (VerifyFull) extras ──────────────────────────

	// LocalRevokedSerials — offline CRL checked first (Step 4). Nil means skip.
	LocalRevokedSerials map[string]struct{}
	// RevocationCheck — live callback run after the local CRL and before the
	// store / OCSP checks (Step 4). Nil means skip.
	RevocationCheck NipRevocationCheck
	// RevocationStore — live revocation source consulted by serial (Step 4).
	// Nil means skip.
	RevocationStore RevocationStore
	// OcspURL — optional CA OCSP endpoint. When set (and no earlier source
	// rejected), the verifier GETs {OcspURL}/{nid} expecting JSON
	// {"valid":bool,"error_code":string} (Step 4).
	OcspURL string
	// OcspFailOpen — when true, OCSP transport failures pass through; the
	// secure default is fail-closed (NIP-OCSP-UNAVAILABLE).
	OcspFailOpen bool
	// HTTPClient — used for OCSP; defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// NipRevocationCheck is a live revocation callback (NPS-3 §7 Step 4). Return a
// failing (Valid=false) result to reject the identity, or a nil pointer / a
// Valid result to continue to the next configured revocation source.
type NipRevocationCheck func(ctx context.Context, frame *IdentFrame) *IdentVerifyResult

// The NIP CA certificate record consulted during revocation (NipCertRecord)
// is defined in ca_store.go: a populated RevokedAt marks the serial as revoked.

// RevocationStore is a live revocation source keyed by serial (mirror of the
// .NET INipCaStore.GetBySerialAsync surface used by the verifier).
type RevocationStore interface {
	GetBySerial(ctx context.Context, serial string) (*NipCertRecord, error)
}

// VerifyContext carries per-request inputs for NPS-3 §7 steps 1, 5 and 6.
// All fields are optional — omit to skip the corresponding check.
type VerifyContext struct {
	// RequiredCapabilities the Node requires the Agent to hold (Step 5).
	RequiredCapabilities []string
	// TargetNodePath the Agent is trying to access (Step 6), e.g.
	// "nwp://api.myapp.com/products".
	TargetNodePath string
	// AsOf overrides the clock for the expiry check (Step 1). Zero = time.Now().
	AsOf time.Time
}

// IdentVerifyResult — outcome of NipIdentVerifier.Verify / VerifyFull.
//
// For the legacy dual-trust Verify, StepFailed is: 0 none, 1 sig, 2 assurance,
// 3 X.509. For the full VerifyFull (NPS-3 §7), StepFailed follows the six-step
// numbering: 1 expiry, 2 trusted issuer, 3 signature + X.509 chain,
// 4 revocation, 5 capabilities, 6 scope.
type IdentVerifyResult struct {
	Valid      bool
	StepFailed int
	ErrorCode  string
	Message    string
}

// X509ChainVerifier — pluggable hook so this package doesn't import nip/x509
// (which itself imports nip — would cycle). Tests / callers wire up a verifier
// that delegates to nip/x509.Verify.
type X509ChainVerifier func(
	chainBase64UrlDer []string,
	assertedNid string,
	assertedAssuranceLevel *AssuranceLevel,
	trustedRoots []*cryptox509.Certificate,
) (valid bool, errorCode, message string)

// NipIdentVerifier — Phase 1 dual-trust IdentFrame verifier.
type NipIdentVerifier struct {
	Options      VerifierOptions
	X509Verifier X509ChainVerifier // optional — required only for Step 3b
}

func NewNipIdentVerifier(opts VerifierOptions, x509Verifier X509ChainVerifier) *NipIdentVerifier {
	return &NipIdentVerifier{Options: opts, X509Verifier: x509Verifier}
}

// Verify runs the three-step Phase 1 dual-trust check.
func (v *NipIdentVerifier) Verify(frame *IdentFrame, issuerNid string) IdentVerifyResult {
	// Step 1: v1 Ed25519 signature check ─────────────────────────────────────
	caPubKeyStr, ok := v.Options.TrustedCaPublicKeys[issuerNid]
	if !ok {
		return fail(1, ErrCertUntrustedIssuer,
			fmt.Sprintf("no trusted CA public key for issuer: %s", issuerNid))
	}
	if frame.Signature == nil || !strings.HasPrefix(*frame.Signature, "ed25519:") {
		return fail(1, ErrCertSignatureInvalid, "missing or malformed signature")
	}
	caPubBytes, err := parsePubKeyString(caPubKeyStr)
	if err != nil {
		return fail(1, ErrCertSignatureInvalid, err.Error())
	}
	sigB64 := (*frame.Signature)[len("ed25519:"):]
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fail(1, ErrCertSignatureInvalid, fmt.Sprintf("base64url decode: %v", err))
	}
	canonical := canonicalSorted(frame.UnsignedDict())
	if !ed25519.Verify(caPubBytes, []byte(canonical), sigBytes) {
		return fail(1, ErrCertSignatureInvalid,
			"v1 Ed25519 signature did not verify against issuer CA key")
	}

	// Step 2: minimum assurance level ────────────────────────────────────────
	if v.Options.MinAssuranceLevel != nil {
		got := AssuranceAnonymous
		if frame.AssuranceLevel != nil {
			got = *frame.AssuranceLevel
		}
		if !got.MeetsOrExceeds(*v.Options.MinAssuranceLevel) {
			return fail(2, ErrAssuranceMismatch,
				fmt.Sprintf("assurance_level (%s) below required minimum (%s)",
					got.Wire, v.Options.MinAssuranceLevel.Wire))
		}
	}

	// Step 3b: X.509 chain check (only if both opt-ins present) ──────────────
	hasV2Trust := len(v.Options.TrustedX509Roots) > 0 && v.X509Verifier != nil
	isV2Frame := frame.CertFormat != nil && *frame.CertFormat == CertFormatV2X509
	if hasV2Trust && isV2Frame {
		ok, code, msg := v.X509Verifier(
			frame.CertChain, frame.NID, frame.AssuranceLevel, v.Options.TrustedX509Roots)
		if !ok {
			if code == "" {
				code = ErrCertFormatInvalid
			}
			return fail(3, code, msg)
		}
	}

	return IdentVerifyResult{Valid: true}
}

func fail(step int, code, msg string) IdentVerifyResult {
	return IdentVerifyResult{Valid: false, StepFailed: step, ErrorCode: code, Message: msg}
}

// VerifyFull runs the complete NPS-3 §7 six-step IdentFrame verification flow.
// All applicable steps MUST pass. The issuer is read from frame.IssuedBy
// (matching the .NET reference). A nil vctx behaves like an empty context.
//
//	Step 1  Expiry:        expires_at > now (vctx.AsOf or time.Now()).
//	Step 2  Trusted issuer: issued_by ∈ Options.TrustedCaPublicKeys.
//	Step 3  Signature:      Ed25519 over UnsignedDict + X.509 chain when
//	                        cert_format=v2-x509 and TrustedX509Roots is set.
//	Step 4  Revocation:     local CRL → RevocationCheck → RevocationStore → OCSP.
//	Step 5  Capabilities:   frame capabilities ⊇ vctx.RequiredCapabilities.
//	Step 6  Scope:          scope.nodes patterns cover vctx.TargetNodePath.
func (v *NipIdentVerifier) VerifyFull(ctx context.Context, frame *IdentFrame, vctx *VerifyContext) IdentVerifyResult {
	if vctx == nil {
		vctx = &VerifyContext{}
	}
	now := vctx.AsOf
	if now.IsZero() {
		now = time.Now()
	}

	// ── Step 1: Expiry ───────────────────────────────────────────────────────
	expiresAt, err := time.Parse(time.RFC3339, frame.ExpiresAt)
	if err != nil || !expiresAt.After(now) {
		return fail(1, ErrCertExpired, fmt.Sprintf("certificate expired at %s", frame.ExpiresAt))
	}

	// ── Step 2: Trusted issuer ───────────────────────────────────────────────
	issuerPubKeyStr, ok := v.Options.TrustedCaPublicKeys[frame.IssuedBy]
	if !ok {
		return fail(2, ErrCertUntrustedIssuer,
			fmt.Sprintf("issuer '%s' is not in the trusted issuers list", frame.IssuedBy))
	}

	// ── Step 3: Signature (v1 Ed25519) ───────────────────────────────────────
	issuerPubKey, err := parsePubKeyString(issuerPubKeyStr)
	if err != nil {
		return fail(3, ErrCertSignatureInvalid,
			fmt.Sprintf("failed to decode public key for issuer '%s': %v", frame.IssuedBy, err))
	}
	if frame.Signature == nil || !strings.HasPrefix(*frame.Signature, "ed25519:") {
		return fail(3, ErrCertSignatureInvalid, "missing or malformed signature")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString((*frame.Signature)[len("ed25519:"):])
	if err != nil {
		return fail(3, ErrCertSignatureInvalid, fmt.Sprintf("base64url decode: %v", err))
	}
	canonical := canonicalSorted(frame.UnsignedDict())
	if !ed25519.Verify(issuerPubKey, []byte(canonical), sigBytes) {
		return fail(3, ErrCertSignatureInvalid, "certificate signature verification failed")
	}

	// ── Step 3b: X.509 chain (NPS-RFC-0002, only when cert_format=v2-x509) ────
	// A v1-only verifier (no TrustedX509Roots / no X509Verifier wired) treats a
	// v2 frame as v1 — the X.509 chain is ignored (RFC §8.1 Phase 1).
	hasV2Trust := len(v.Options.TrustedX509Roots) > 0 && v.X509Verifier != nil
	isV2Frame := frame.CertFormat != nil && *frame.CertFormat == CertFormatV2X509
	if hasV2Trust && isV2Frame {
		ok, code, msg := v.X509Verifier(
			frame.CertChain, frame.NID, frame.AssuranceLevel, v.Options.TrustedX509Roots)
		if !ok {
			if code == "" {
				code = ErrCertFormatInvalid
			}
			return fail(3, code, msg)
		}
	}

	// ── Step 4: Revocation ───────────────────────────────────────────────────
	if r := v.checkRevocation(ctx, frame); !r.Valid {
		return r
	}

	// ── Step 5: Capabilities ─────────────────────────────────────────────────
	if len(vctx.RequiredCapabilities) > 0 {
		have := make(map[string]struct{}, len(frame.Capabilities))
		for _, c := range frame.Capabilities {
			have[c] = struct{}{}
		}
		var missing []string
		for _, c := range vctx.RequiredCapabilities {
			if _, ok := have[c]; !ok {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			return fail(5, ErrCertCapabilityMissing,
				fmt.Sprintf("certificate is missing required capabilities: %s", strings.Join(missing, ", ")))
		}
	}

	// ── Step 6: Scope ────────────────────────────────────────────────────────
	if vctx.TargetNodePath != "" {
		if r := checkScope(frame, vctx.TargetNodePath); !r.Valid {
			return r
		}
	}

	return IdentVerifyResult{Valid: true}
}

// checkRevocation runs the Step 4 revocation sources in .NET order:
// local CRL → RevocationCheck callback → RevocationStore → OCSP. When none is
// configured, revocation is a pass-through.
func (v *NipIdentVerifier) checkRevocation(ctx context.Context, frame *IdentFrame) IdentVerifyResult {
	// Local CRL first (fast, no network).
	if v.Options.LocalRevokedSerials != nil {
		if _, revoked := v.Options.LocalRevokedSerials[frame.Serial]; revoked {
			return fail(4, ErrCertRevoked,
				fmt.Sprintf("certificate serial %s is in the local revocation list", frame.Serial))
		}
	}

	if v.Options.RevocationCheck != nil {
		if r := v.Options.RevocationCheck(ctx, frame); r != nil && !r.Valid {
			return *r
		}
	}

	if v.Options.RevocationStore != nil {
		record, err := v.Options.RevocationStore.GetBySerial(ctx, frame.Serial)
		if err != nil {
			return fail(4, ErrOcspUnavailable,
				fmt.Sprintf("revocation store lookup failed for serial %s: %v", frame.Serial, err))
		}
		if record != nil && record.RevokedAt != nil {
			return fail(4, ErrCertRevoked,
				fmt.Sprintf("certificate serial %s was revoked at %s: %s",
					frame.Serial, record.RevokedAt.Format(time.RFC3339), ptrStr(record.RevokeReason)))
		}
	}

	if v.Options.OcspURL != "" {
		return v.ocspCheck(ctx, frame.NID)
	}

	return IdentVerifyResult{Valid: true} // pass-through when unconfigured
}

// ocspCheck GETs {OcspURL}/{nid} and expects JSON {"valid":bool,"error_code":string}.
// Transport failures honour OcspFailOpen (open = pass, closed = NIP-OCSP-UNAVAILABLE).
func (v *NipIdentVerifier) ocspCheck(ctx context.Context, nid string) IdentVerifyResult {
	client := v.Options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(v.Options.OcspURL, "/") + "/" + url.PathEscape(nid)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return v.ocspTransportFailure(nid, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return v.ocspTransportFailure(nid, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fail(4, ErrOcspUnavailable, fmt.Sprintf("OCSP endpoint returned %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return v.ocspTransportFailure(nid, err)
	}
	var payload struct {
		Valid     bool   `json:"valid"`
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fail(4, ErrOcspUnavailable, fmt.Sprintf("OCSP response parse failed for NID %s: %v", nid, err))
	}
	if !payload.Valid {
		code := payload.ErrorCode
		if code == "" {
			code = ErrCertRevoked
		}
		return fail(4, code, fmt.Sprintf("OCSP check failed for NID %s", nid))
	}
	return IdentVerifyResult{Valid: true}
}

func (v *NipIdentVerifier) ocspTransportFailure(nid string, err error) IdentVerifyResult {
	if v.Options.OcspFailOpen {
		return IdentVerifyResult{Valid: true}
	}
	return fail(4, ErrOcspUnavailable, fmt.Sprintf("OCSP call failed for NID %s: %v", nid, err))
}

// checkScope verifies that targetPath is covered by frame.Scope["nodes"] (Step 6).
func checkScope(frame *IdentFrame, targetPath string) IdentVerifyResult {
	nodes := stringSlice(frame.Scope["nodes"])
	if frame.Scope == nil || nodes == nil {
		return fail(6, ErrCertScopeViolation, "IdentFrame scope is missing 'nodes' field")
	}
	for _, pattern := range nodes {
		if NwpPathMatches(pattern, targetPath) {
			return IdentVerifyResult{Valid: true}
		}
	}
	return fail(6, ErrCertScopeViolation,
		fmt.Sprintf("target path '%s' is not covered by the certificate scope", targetPath))
}

// NwpPathMatches matches a NWP path against a scope pattern:
//   - a bare "*" matches any path;
//   - a trailing "/*" (e.g. "nwp://api.myapp.com/*") matches the prefix and any
//     path under it at a '/' boundary;
//   - all other patterns are exact case-insensitive matches.
func NwpPathMatches(pattern, path string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-2]
		if !strings.HasPrefix(strings.ToLower(path), strings.ToLower(prefix)) {
			return false
		}
		return len(path) == len(prefix) || path[len(prefix)] == '/'
	}
	return strings.EqualFold(pattern, path)
}

func parsePubKeyString(s string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(s, "ed25519:") {
		return nil, fmt.Errorf("unsupported public key format: %s", s)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[len("ed25519:"):])
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key wrong size: %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// canonicalSorted matches NipIdentity.canonicalJSON — sorted top-level keys.
func canonicalSorted(d map[string]any) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]any, len(d))
	for _, k := range keys {
		ordered[k] = d[k]
	}
	b, _ := json.Marshal(ordered)
	return string(b)
}
