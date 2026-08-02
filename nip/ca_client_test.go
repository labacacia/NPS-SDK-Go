// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNipCaClientRegisterAgentSendsBearer(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nip/v1/agents/register" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"frame":"0x20","nid":"urn:nps:agent:example.test:a","pub_key":"ed25519:a","capabilities":["nwp:query"],"scope":{},"issued_by":"urn:nps:org:example.test","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z","serial":"0x1","signature":"ed25519:sig"}`))
	}))
	defer srv.Close()

	client := NewNipCaClientFull(srv.URL, "/nip", srv.Client())
	frame, err := client.RegisterAgent(context.Background(), NipCaRegisterRequest{
		Identifier:   "a",
		PubKey:       "ed25519:a",
		Capabilities: []string{"nwp:query"},
		ScopeJSON:    "{}",
	}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if frame.NID != "urn:nps:agent:example.test:a" {
		t.Fatalf("unexpected nid %s", frame.NID)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("unexpected auth %q", gotAuth)
	}
	if gotBody["identifier"] != "a" {
		t.Fatalf("unexpected body %#v", gotBody)
	}
}

func TestNipCaClientTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error_code":"NIP-CA-UNAUTHORIZED","message":"nope"}`))
	}))
	defer srv.Close()

	client := NewNipCaClientFull(srv.URL, "", srv.Client())
	_, err := client.RenewAgent(context.Background(), "urn:nps:agent:example.test:a", "")
	var caErr *NipCaClientError
	if !errors.As(err, &caErr) {
		t.Fatalf("expected NipCaClientError, got %T", err)
	}
	if caErr.ErrorCode != "NIP-CA-UNAUTHORIZED" || caErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected error %#v", caErr)
	}
}

func TestNipCaClientGetCertificatesSendsBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/nip/v1/certificates" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"entries":[{"nid":"urn:nps:agent:example.test:a","entity_type":"agent","serial":"0x1","pub_key":"ed25519:a","capabilities":[],"scope":{},"issued_by":"urn:nps:org:example.test","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z"}]}`))
	}))
	defer srv.Close()

	client := NewNipCaClientFull(srv.URL, "/nip", srv.Client())
	list, err := client.GetCertificates(context.Background(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("unexpected auth %q", gotAuth)
	}
	if len(list.Entries) != 1 || list.Entries[0].Serial != "0x1" {
		t.Fatalf("unexpected certificate list %#v", list)
	}
}
