// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	npsnip "github.com/labacacia/NPS-sdk-go/nip"
)

// Go parallel of the .NET NipIdentVerifier six-step flow (NPS-3 §7).

const caNidFull = "urn:nps:org:ca.example.com"

// buildSignedFrame builds a fully-populated v1 IdentFrame signed by caPriv over
// its UnsignedDict(), then sets the NPS-3 §5.1 cert fields (which are not signed
// in this SDK's canonical form).
func buildSignedFrame(t *testing.T, caPriv ed25519.PrivateKey, mutate func(*npsnip.IdentFrame)) *npsnip.IdentFrame {
	t.Helper()
	agentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	frame := &npsnip.IdentFrame{
		NID:          "urn:nps:agent:ca.example.com:agent-1",
		PubKey:       pubKeyHex(agentPub),
		IssuedBy:     caNidFull,
		IssuedAt:     time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Serial:       "0x0A3F9C",
		Capabilities: []string{"nwp:query", "nwp:stream"},
		Scope:        map[string]any{"nodes": []any{"nwp://api.myapp.com/*"}},
	}
	if mutate != nil {
		mutate(frame)
	}
	canonical := canonicalSorted(frame.UnsignedDict())
	sig := ed25519.Sign(caPriv, []byte(canonical))
	sigWire := "ed25519:" + base64.RawURLEncoding.EncodeToString(sig)
	frame.Signature = &sigWire
	return frame
}

func fullVerifier(caPub ed25519.PublicKey, mutate func(*npsnip.VerifierOptions)) *npsnip.NipIdentVerifier {
	opts := npsnip.VerifierOptions{
		TrustedCaPublicKeys: map[string]string{caNidFull: pubKeyHex(caPub)},
	}
	if mutate != nil {
		mutate(&opts)
	}
	return npsnip.NewNipIdentVerifier(opts, nil)
}

func TestVerifyFull_HappyPath(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	v := fullVerifier(caPub, nil)
	r := v.VerifyFull(context.Background(), frame, &npsnip.VerifyContext{
		RequiredCapabilities: []string{"nwp:query"},
		TargetNodePath:       "nwp://api.myapp.com/products",
	})
	if !r.Valid {
		t.Fatalf("expected valid; step=%d code=%s msg=%s", r.StepFailed, r.ErrorCode, r.Message)
	}
}

func TestVerifyFull_Step1_Expired(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, func(f *npsnip.IdentFrame) {
		f.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	})
	v := fullVerifier(caPub, nil)
	r := v.VerifyFull(context.Background(), frame, nil)
	assertFail(t, r, 1, npsnip.ErrCertExpired)
}

func TestVerifyFull_Step1_AsOfOverride(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	v := fullVerifier(caPub, nil)
	// AsOf far in the future → expired.
	r := v.VerifyFull(context.Background(), frame, &npsnip.VerifyContext{AsOf: time.Now().Add(48 * time.Hour)})
	assertFail(t, r, 1, npsnip.ErrCertExpired)
}

func TestVerifyFull_Step2_UntrustedIssuer(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, func(f *npsnip.IdentFrame) {
		f.IssuedBy = "urn:nps:org:evil"
	})
	v := fullVerifier(otherPub, nil)
	r := v.VerifyFull(context.Background(), frame, nil)
	assertFail(t, r, 2, npsnip.ErrCertUntrustedIssuer)
}

func TestVerifyFull_Step3_BadSignature(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	// Tamper the signature so it no longer verifies against the CA key.
	bad := "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	frame.Signature = &bad
	v := fullVerifier(caPub, nil)
	r := v.VerifyFull(context.Background(), frame, nil)
	assertFail(t, r, 3, npsnip.ErrCertSignatureInvalid)
}

func TestVerifyFull_Step4_LocalCRL(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	v := fullVerifier(caPub, func(o *npsnip.VerifierOptions) {
		o.LocalRevokedSerials = map[string]struct{}{"0x0A3F9C": {}}
	})
	r := v.VerifyFull(context.Background(), frame, nil)
	assertFail(t, r, 4, npsnip.ErrCertRevoked)
}

func TestVerifyFull_Step4_RequiredWithoutSourceFailsClosed(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	v := fullVerifier(caPub, func(o *npsnip.VerifierOptions) {
		o.RevocationMode = npsnip.NipRevocationRequired
	})
	r := v.VerifyFull(context.Background(), frame, nil)
	assertFail(t, r, 4, npsnip.ErrOcspUnavailable)
}

func TestVerifyFull_Step4_RequiredAcceptsConfiguredEmptyLocalCRL(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	v := fullVerifier(caPub, func(o *npsnip.VerifierOptions) {
		o.LocalRevokedSerials = map[string]struct{}{}
		o.RevocationMode = npsnip.NipRevocationRequired
	})
	r := v.VerifyFull(context.Background(), frame, nil)
	if !r.Valid {
		t.Fatalf("expected valid; step=%d code=%s msg=%s", r.StepFailed, r.ErrorCode, r.Message)
	}
}

func TestVerifyFull_Step4_RevocationCallback(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	v := fullVerifier(caPub, func(o *npsnip.VerifierOptions) {
		o.RevocationCheck = func(_ context.Context, _ *npsnip.IdentFrame) *npsnip.IdentVerifyResult {
			r := npsnip.IdentVerifyResult{Valid: false, StepFailed: 4, ErrorCode: npsnip.ErrCertRevoked, Message: "callback"}
			return &r
		}
	})
	r := v.VerifyFull(context.Background(), frame, nil)
	assertFail(t, r, 4, npsnip.ErrCertRevoked)
}

func TestVerifyFull_Step4_RevocationStore(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	now := time.Now()
	reason := "key_compromise"
	v := fullVerifier(caPub, func(o *npsnip.VerifierOptions) {
		o.RevocationStore = stubStore{rec: &npsnip.NipCertRecord{Serial: "0x0A3F9C", RevokedAt: &now, RevokeReason: &reason}}
	})
	r := v.VerifyFull(context.Background(), frame, nil)
	assertFail(t, r, 4, npsnip.ErrCertRevoked)
}

func TestVerifyFull_Step4_OCSP_ValidPasses(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
	}))
	defer srv.Close()
	v := fullVerifier(caPub, func(o *npsnip.VerifierOptions) { o.OcspURL = srv.URL })
	r := v.VerifyFull(context.Background(), frame, nil)
	if !r.Valid {
		t.Fatalf("expected valid; step=%d code=%s", r.StepFailed, r.ErrorCode)
	}
}

func TestVerifyFull_Step4_OCSP_RevokedFails(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "error_code": npsnip.ErrCertRevoked})
	}))
	defer srv.Close()
	v := fullVerifier(caPub, func(o *npsnip.VerifierOptions) { o.OcspURL = srv.URL })
	r := v.VerifyFull(context.Background(), frame, nil)
	assertFail(t, r, 4, npsnip.ErrCertRevoked)
}

func TestVerifyFull_Step4_OCSP_FailClosed(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	// Unreachable endpoint (server started then immediately closed).
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	v := fullVerifier(caPub, func(o *npsnip.VerifierOptions) {
		o.OcspURL = url
		o.OcspFailOpen = false
	})
	r := v.VerifyFull(context.Background(), frame, nil)
	assertFail(t, r, 4, npsnip.ErrOcspUnavailable)
}

func TestVerifyFull_Step4_OCSP_FailOpen(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	v := fullVerifier(caPub, func(o *npsnip.VerifierOptions) {
		o.OcspURL = url
		o.OcspFailOpen = true
	})
	r := v.VerifyFull(context.Background(), frame, nil)
	if !r.Valid {
		t.Fatalf("fail-open OCSP should pass; step=%d code=%s", r.StepFailed, r.ErrorCode)
	}
}

func TestVerifyFull_Step5_CapabilityMissing(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	v := fullVerifier(caPub, nil)
	r := v.VerifyFull(context.Background(), frame, &npsnip.VerifyContext{
		RequiredCapabilities: []string{"nwp:admin"},
	})
	assertFail(t, r, 5, npsnip.ErrCertCapabilityMissing)
}

func TestVerifyFull_Step6_ScopeViolation(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	frame := buildSignedFrame(t, caPriv, nil)
	v := fullVerifier(caPub, nil)
	r := v.VerifyFull(context.Background(), frame, &npsnip.VerifyContext{
		TargetNodePath: "nwp://other.example.com/x",
	})
	assertFail(t, r, 6, npsnip.ErrCertScopeViolation)
}

func TestNwpPathMatches(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"*", "nwp://anything/at/all", true},
		{"nwp://api.myapp.com/*", "nwp://api.myapp.com", true},
		{"nwp://api.myapp.com/*", "nwp://api.myapp.com/products", true},
		{"nwp://api.myapp.com/*", "nwp://api.myapp.com-evil/x", false},
		{"nwp://api.myapp.com/products", "nwp://API.myapp.com/products", true},
		{"nwp://api.myapp.com/products", "nwp://api.myapp.com/orders", false},
	}
	for _, c := range cases {
		if got := npsnip.NwpPathMatches(c.pattern, c.path); got != c.want {
			t.Errorf("NwpPathMatches(%q,%q)=%v want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestValidateTrustFrame(t *testing.T) {
	base := func() *npsnip.TrustFrame {
		return &npsnip.TrustFrame{
			GrantorNID: "urn:nps:root:anchor",
			GranteeCA:  caNidFull,
			TrustScope: []string{"nwp:query"},
			Nodes:      []string{"nwp://api.myapp.com/*"},
			IssuedAt:   time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			ExpiresAt:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			Serial:     "0x01",
			SignerNID:  "urn:nps:root:anchor",
			Signature:  "ed25519:AAAA",
		}
	}
	ctx := npsnip.TrustFrameValidationContext{
		TrustedGrantors:      map[string]struct{}{"urn:nps:root:anchor": {}},
		ExpectedGranteeCA:    caNidFull,
		RequiredCapabilities: []string{"nwp:query"},
		TargetNodePath:       "nwp://api.myapp.com/products",
	}

	if r := npsnip.ValidateTrustFrame(base(), ctx); !r.Valid {
		t.Fatalf("expected valid; step=%d code=%s msg=%s", r.StepFailed, r.ErrorCode, r.Message)
	}

	// Missing field.
	f := base()
	f.Serial = ""
	if r := npsnip.ValidateTrustFrame(f, ctx); r.Valid || r.ErrorCode != npsnip.ErrTrustFrameInvalid {
		t.Fatalf("missing serial: want %s got %+v", npsnip.ErrTrustFrameInvalid, r)
	}

	// Expired.
	f = base()
	f.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if r := npsnip.ValidateTrustFrame(f, ctx); r.Valid || r.ErrorCode != npsnip.ErrTrustFrameExpired {
		t.Fatalf("expired: want %s got %+v", npsnip.ErrTrustFrameExpired, r)
	}

	// Untrusted grantor.
	f = base()
	f.GrantorNID = "urn:nps:root:evil"
	f.SignerNID = "urn:nps:root:evil"
	if r := npsnip.ValidateTrustFrame(f, ctx); r.Valid || r.ErrorCode != npsnip.ErrCertUntrustedIssuer {
		t.Fatalf("untrusted grantor: want %s got %+v", npsnip.ErrCertUntrustedIssuer, r)
	}

	// Capability exceeds trust scope.
	over := ctx
	over.RequiredCapabilities = []string{"nwp:admin"}
	if r := npsnip.ValidateTrustFrame(base(), over); r.Valid || r.ErrorCode != npsnip.ErrTrustFrameScopeExceedsGrantor {
		t.Fatalf("cap exceeds: want %s got %+v", npsnip.ErrTrustFrameScopeExceedsGrantor, r)
	}

	// Node scope not covered.
	outofscope := ctx
	outofscope.TargetNodePath = "nwp://other.example.com/x"
	if r := npsnip.ValidateTrustFrame(base(), outofscope); r.Valid || r.ErrorCode != npsnip.ErrCertScopeViolation {
		t.Fatalf("node scope: want %s got %+v", npsnip.ErrCertScopeViolation, r)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

type stubStore struct{ rec *npsnip.NipCertRecord }

func (s stubStore) GetBySerial(_ context.Context, _ string) (*npsnip.NipCertRecord, error) {
	return s.rec, nil
}

func assertFail(t *testing.T, r npsnip.IdentVerifyResult, step int, code string) {
	t.Helper()
	if r.Valid {
		t.Fatalf("expected failure at step %d (%s), got valid", step, code)
	}
	if r.StepFailed != step {
		t.Fatalf("want step %d, got %d (code=%s msg=%s)", step, r.StepFailed, r.ErrorCode, r.Message)
	}
	if r.ErrorCode != code {
		t.Fatalf("want code %s, got %s (msg=%s)", code, r.ErrorCode, r.Message)
	}
}
