// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	npsnip "github.com/labacacia/NPS-sdk-go/nip"
)

func newRouterServer(t *testing.T, tune func(*npsnip.NipCaOptions)) (*httptest.Server, *npsnip.NipCaService) {
	t.Helper()
	keys, _ := npsnip.Generate()
	store := npsnip.NewInMemoryNipCaStore()
	opts := npsnip.DefaultNipCaOptions("urn:nps:org:ca.example.com", "https://ca.example.com")
	if tune != nil {
		tune(&opts)
	}
	ca := npsnip.NewNipCaService(opts, store, keys)
	boot := npsnip.NewInMemoryBootstrapTokenStore()
	pend := npsnip.NewInMemoryPendingStore(opts.PendingQueueMaxAge)
	rt, err := npsnip.NewNipCaRouter(opts, ca, boot, pend)
	if err != nil {
		t.Fatalf("NewNipCaRouter: %v", err)
	}
	return httptest.NewServer(rt), ca
}

func doJSON(t *testing.T, method, url string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func TestRouterWellKnown(t *testing.T) {
	srv, _ := newRouterServer(t, nil)
	defer srv.Close()
	status, body := doJSON(t, "GET", srv.URL+"/.well-known/nps-ca", nil)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if body["issuer"] != "urn:nps:org:ca.example.com" {
		t.Fatalf("issuer: %v", body["issuer"])
	}
	if _, ok := body["public_key"].(string); !ok {
		t.Fatal("missing public_key")
	}
}

func TestRouterRegisterVerifyRevokeFlow(t *testing.T) {
	srv, _ := newRouterServer(t, nil)
	defer srv.Close()

	status, body := doJSON(t, "POST", srv.URL+"/v1/agents/register", map[string]any{
		"identifier": "web-1", "pub_key": freshPubKey(t), "capabilities": []string{"chat"},
	})
	if status != 201 {
		t.Fatalf("register status %d: %v", status, body)
	}
	nid, _ := body["nid"].(string)
	if nid == "" {
		t.Fatal("no nid in register response")
	}

	// Verify (OCSP) → valid.
	status, body = doJSON(t, "GET", srv.URL+"/v1/agents/"+url.PathEscape(nid)+"/verify", nil)
	if status != 200 || body["valid"] != true {
		t.Fatalf("verify: status=%d body=%v", status, body)
	}

	// Revoke.
	status, _ = doJSON(t, "POST", srv.URL+"/v1/agents/"+url.PathEscape(nid)+"/revoke",
		map[string]any{"reason": "key_compromise"})
	if status != 200 {
		t.Fatalf("revoke status %d", status)
	}

	// Verify → revoked (200, valid=false).
	status, body = doJSON(t, "GET", srv.URL+"/v1/agents/"+url.PathEscape(nid)+"/verify", nil)
	if status != 200 || body["valid"] != false || body["error_code"] != npsnip.ErrCertRevoked {
		t.Fatalf("verify after revoke: status=%d body=%v", status, body)
	}
}

func TestRouterVerifyNotFound(t *testing.T) {
	srv, _ := newRouterServer(t, nil)
	defer srv.Close()
	status, body := doJSON(t, "GET", srv.URL+"/v1/agents/"+url.PathEscape("urn:nps:agent:ca.example.com:ghost")+"/verify", nil)
	if status != 404 || body["error_code"] != npsnip.ErrCaNidNotFound {
		t.Fatalf("expected 404 NID-NOT-FOUND, got %d %v", status, body)
	}
}

func TestRouterDuplicateNidConflict(t *testing.T) {
	srv, _ := newRouterServer(t, nil)
	defer srv.Close()
	pk := freshPubKey(t)
	doJSON(t, "POST", srv.URL+"/v1/agents/register", map[string]any{"identifier": "dupe", "pub_key": pk})
	status, body := doJSON(t, "POST", srv.URL+"/v1/agents/register", map[string]any{"identifier": "dupe", "pub_key": pk})
	if status != 409 || body["error_code"] != npsnip.ErrCaNidAlreadyExists {
		t.Fatalf("expected 409 conflict, got %d %v", status, body)
	}
}

func TestRouterBadPubKey(t *testing.T) {
	srv, _ := newRouterServer(t, nil)
	defer srv.Close()
	status, _ := doJSON(t, "POST", srv.URL+"/v1/agents/register", map[string]any{"identifier": "x", "pub_key": "nope"})
	if status != 400 {
		t.Fatalf("expected 400, got %d", status)
	}
}

func TestRouterOperatorAuth(t *testing.T) {
	srv, _ := newRouterServer(t, func(o *npsnip.NipCaOptions) { o.OperatorApiKey = "secret-key" })
	defer srv.Close()

	// No auth → 401.
	status, _ := doJSON(t, "POST", srv.URL+"/v1/agents/register", map[string]any{"identifier": "a", "pub_key": freshPubKey(t)})
	if status != 401 {
		t.Fatalf("expected 401 without token, got %d", status)
	}
	status, _ = doJSON(t, "GET", srv.URL+"/v1/certificates", nil)
	if status != 401 {
		t.Fatalf("expected certificate inventory 401 without token, got %d", status)
	}

	// With bearer → 201.
	b, _ := json.Marshal(map[string]any{"identifier": "a", "pub_key": freshPubKey(t)})
	req, _ := http.NewRequest("POST", srv.URL+"/v1/agents/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201 with token, got %d", resp.StatusCode)
	}

	listReq, _ := http.NewRequest("GET", srv.URL+"/v1/certificates", nil)
	listReq.Header.Set("Authorization", "Bearer secret-key")
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != 200 {
		t.Fatalf("expected certificate inventory 200, got %d", listResp.StatusCode)
	}
	var list npsnip.NipCaCertificateList
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Entries) != 1 {
		t.Fatalf("expected one certificate, got %d", len(list.Entries))
	}
}

func TestRouterGroupRegisterAndOperatorIssueSession(t *testing.T) {
	srv, _ := newRouterServer(t, nil)
	defer srv.Close()

	status, body := doJSON(t, "POST", srv.URL+"/v1/orchestrators/groups/register", map[string]any{
		"identifier": "group-r1", "pub_key": freshPubKey(t), "capabilities": []string{"chat", "search"},
	})
	if status != 201 {
		t.Fatalf("group register status %d: %v", status, body)
	}
	groupNid, _ := body["nid"].(string)
	if _, ok := body["lineage"].(map[string]any); !ok {
		t.Fatalf("group frame missing lineage: %v", body)
	}

	// Issue session via operator JSON path.
	status, body = doJSON(t, "POST", srv.URL+"/v1/orchestrators/groups/"+url.PathEscape(groupNid)+"/sessions/issue",
		map[string]any{"session_pub_key": freshPubKey(t), "validity_seconds": 3600, "capabilities": []string{"chat"}})
	if status != 201 {
		t.Fatalf("issue session status %d: %v", status, body)
	}
	if lin, ok := body["lineage"].(map[string]any); !ok || lin["role"] != "session" {
		t.Fatalf("session frame lineage wrong: %v", body["lineage"])
	}

	// List sessions.
	status, body = doJSON(t, "GET", srv.URL+"/v1/orchestrators/groups/"+url.PathEscape(groupNid)+"/sessions", nil)
	if status != 200 || body["count"].(float64) != 1 {
		t.Fatalf("list sessions: %d %v", status, body)
	}
}

func TestRouterIssueSessionViaGroupJws(t *testing.T) {
	srv, _ := newRouterServer(t, nil)
	defer srv.Close()

	// Register a group with a known keypair so we can sign the JWS.
	groupSeed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(groupSeed)
	groupPriv := ed25519.NewKeyFromSeed(groupSeed)
	groupPub := groupPriv.Public().(ed25519.PublicKey)
	groupPubStr := "ed25519:" + base64.RawURLEncoding.EncodeToString(groupPub)

	status, body := doJSON(t, "POST", srv.URL+"/v1/orchestrators/groups/register", map[string]any{
		"identifier": "group-jws", "pub_key": groupPubStr, "capabilities": []string{"chat"},
	})
	if status != 201 {
		t.Fatalf("group register: %d %v", status, body)
	}
	groupNid, _ := body["nid"].(string)

	// Build a signed group-JWS.
	header := map[string]any{"alg": "EdDSA", "kid": groupNid, "nps-purpose": "session-issue"}
	payload := map[string]any{"session_pub_key": freshPubKey(t), "iat": time.Now().Unix(), "purpose": "jws-path"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	prot := base64.RawURLEncoding.EncodeToString(hb)
	pl := base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(groupPriv, []byte(prot+"."+pl))
	jws := map[string]any{
		"protected": prot, "payload": pl,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	}

	b, _ := json.Marshal(jws)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/orchestrators/groups/"+url.PathEscape(groupNid)+"/sessions/issue", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("jws issue status %d: %s", resp.StatusCode, raw)
	}
}

func TestRouterBootstrapTokenEnrollment(t *testing.T) {
	srv, _ := newRouterServer(t, func(o *npsnip.NipCaOptions) {
		o.EnrollmentTier = npsnip.EnrollmentTierBootstrapToken
	})
	defer srv.Close()

	// Create a token.
	status, body := doJSON(t, "POST", srv.URL+"/v1/enrollment/tokens", map[string]any{"label": "ci", "ttl_seconds": 600})
	if status != 201 {
		t.Fatalf("create token status %d: %v", status, body)
	}
	tok, _ := body["token"].(string)
	if tok == "" {
		t.Fatal("no token returned")
	}

	// Register without token → 401.
	status, _ = doJSON(t, "POST", srv.URL+"/v1/agents/register", map[string]any{"identifier": "boot1", "pub_key": freshPubKey(t)})
	if status != 401 {
		t.Fatalf("expected 401 without token, got %d", status)
	}

	// Register with token header → 201.
	b, _ := json.Marshal(map[string]any{"identifier": "boot1", "pub_key": freshPubKey(t)})
	req, _ := http.NewRequest("POST", srv.URL+"/v1/agents/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NPS-Enrollment-Token", tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201 with token, got %d", resp.StatusCode)
	}
}

func TestRouterPendingQueueEnrollment(t *testing.T) {
	srv, _ := newRouterServer(t, func(o *npsnip.NipCaOptions) {
		o.EnrollmentTier = npsnip.EnrollmentTierPendingQueue
	})
	defer srv.Close()

	// Register → 202 queued.
	status, body := doJSON(t, "POST", srv.URL+"/v1/agents/register", map[string]any{"identifier": "pq1", "pub_key": freshPubKey(t)})
	if status != 202 {
		t.Fatalf("expected 202, got %d %v", status, body)
	}
	pendingID, _ := body["pending_id"].(string)
	if pendingID == "" {
		t.Fatal("no pending_id")
	}

	// List pending.
	status, body = doJSON(t, "GET", srv.URL+"/v1/enrollment/pending", nil)
	if status != 200 || body["count"].(float64) != 1 {
		t.Fatalf("list pending: %d %v", status, body)
	}

	// Approve → 201 issues the cert.
	status, _ = doJSON(t, "POST", srv.URL+"/v1/enrollment/pending/"+url.PathEscape(pendingID)+"/approve", nil)
	if status != 201 {
		t.Fatalf("approve status %d", status)
	}

	// Approve again → 409.
	status, _ = doJSON(t, "POST", srv.URL+"/v1/enrollment/pending/"+url.PathEscape(pendingID)+"/approve", nil)
	if status != 409 {
		t.Fatalf("re-approve should be 409, got %d", status)
	}
}

func TestRouterCrl(t *testing.T) {
	srv, ca := newRouterServer(t, nil)
	defer srv.Close()
	frame, _ := ca.Register("agent", "crl-1", freshPubKey(t), nil, "{}", "")
	_, _ = ca.Revoke(frame.NID, "superseded")

	status, body := doJSON(t, "GET", srv.URL+"/v1/crl", nil)
	if status != 200 {
		t.Fatalf("crl status %d", status)
	}
	if body["signature"] == nil || body["signature"] == "" {
		t.Fatal("CRL not signed")
	}
	entries, _ := body["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected 1 CRL entry, got %d", len(entries))
	}
	raw, _ := json.Marshal(body)
	var crl npsnip.NipCaCrl
	if err := json.Unmarshal(raw, &crl); err != nil {
		t.Fatal(err)
	}
	if !npsnip.VerifyCrlSignature(&crl, ca.GetCaPublicKey()) {
		t.Fatal("generated CRL signature did not verify")
	}
}
