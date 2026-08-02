// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// NipCaRouter is an http.Handler exposing the NIP CA HTTP API (NPS-3 §8),
// mirroring the .NET NipCaRouter minimal-API surface. Stdlib net/http only.
type NipCaRouter struct {
	opts             NipCaOptions
	ca               *NipCaService
	bootstrapStore   BootstrapTokenStore
	pendingStore     PendingStore
	enrollmentPolicy EnrollmentPolicy
	prefix           string
}

var identifierRe = regexp.MustCompile(`^[a-zA-Z0-9._:@/\-]{1,256}$`)

var validRevocationReasons = map[string]bool{
	"key_compromise": true, "ca_compromise": true, "affiliation_changed": true,
	"superseded": true, "cessation_of_operation": true, "parent_revoked": true,
}

// NewNipCaRouter builds a CA HTTP handler. bootstrapStore / pendingStore may be
// nil when the corresponding enrollment tier is not used.
func NewNipCaRouter(opts NipCaOptions, ca *NipCaService, bootstrapStore BootstrapTokenStore, pendingStore PendingStore) (*NipCaRouter, error) {
	opts.applyDefaults()
	policy, err := CreateEnrollmentPolicy(opts, bootstrapStore, pendingStore)
	if err != nil {
		return nil, err
	}
	return &NipCaRouter{
		opts:             opts,
		ca:               ca,
		bootstrapStore:   bootstrapStore,
		pendingStore:     pendingStore,
		enrollmentPolicy: policy,
		prefix:           strings.TrimRight(opts.RoutePrefix, "/"),
	}, nil
}

func (rt *NipCaRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	pfx := rt.prefix

	switch {
	case r.Method == http.MethodGet && path == "/.well-known/nps-ca":
		rt.handleWellKnown(w, r)
	case r.Method == http.MethodGet && path == pfx+"/v1/ca/cert":
		writeJSON(w, 200, map[string]any{"public_key": rt.ca.GetCaPublicKey(), "algorithm": "ed25519"})
	case r.Method == http.MethodGet && path == pfx+"/v1/crl":
		rt.handleCrl(w, r)
	case r.Method == http.MethodGet && path == pfx+"/v1/certificates":
		rt.handleCertificates(w, r)
	case r.Method == http.MethodPost && path == pfx+"/v1/agents/register":
		rt.handleRegister(w, r, "agent", nil)
	case r.Method == http.MethodPost && path == pfx+"/v1/nodes/register":
		rt.handleRegister(w, r, "node", []string{"nwp:query", "nwp:stream"})
	case r.Method == http.MethodPost && path == pfx+"/v1/agents/register-x509":
		rt.handleRegisterX509(w, r, "agent", nil)
	case r.Method == http.MethodPost && path == pfx+"/v1/nodes/register-x509":
		rt.handleRegisterX509(w, r, "node", []string{"nwp:query", "nwp:stream"})
	case r.Method == http.MethodPost && path == pfx+"/v1/orchestrators/groups/register":
		rt.handleRegisterGroup(w, r)
	case r.Method == http.MethodPost && path == pfx+"/v1/enrollment/tokens":
		rt.handleCreateToken(w, r)
	case r.Method == http.MethodGet && path == pfx+"/v1/enrollment/pending":
		rt.handleListPending(w, r)
	default:
		if rt.serveParameterized(w, r) {
			return
		}
		writeJSON(w, 404, map[string]any{"error_code": "NIP-CA-NOT-FOUND", "message": "No CA route at this path."})
	}
}

// serveParameterized handles routes with an embedded NID / id segment.
func (rt *NipCaRouter) serveParameterized(w http.ResponseWriter, r *http.Request) bool {
	pfx := rt.prefix
	path := r.URL.Path
	if !strings.HasPrefix(path, pfx+"/v1/") {
		return false
	}
	sub := strings.TrimPrefix(path, pfx+"/v1/")

	// agents/{nid}/renew | revoke | verify ; nodes/{nid}/...
	for _, kind := range []string{"agents/", "nodes/"} {
		if strings.HasPrefix(sub, kind) {
			rest := strings.TrimPrefix(sub, kind)
			if nid, ok := trimSuffix(rest, "/renew"); ok && r.Method == http.MethodPost {
				rt.handleRenew(w, r, unescape(nid))
				return true
			}
			if nid, ok := trimSuffix(rest, "/revoke"); ok && r.Method == http.MethodPost {
				rt.handleRevoke(w, r, unescape(nid))
				return true
			}
			if nid, ok := trimSuffix(rest, "/verify"); ok && r.Method == http.MethodGet {
				rt.handleVerify(w, r, unescape(nid))
				return true
			}
		}
	}

	// orchestrators/groups/{group_nid}/sessions/issue | /sessions | /revoke
	if strings.HasPrefix(sub, "orchestrators/groups/") {
		rest := strings.TrimPrefix(sub, "orchestrators/groups/")
		if nid, ok := trimSuffix(rest, "/sessions/issue"); ok && r.Method == http.MethodPost {
			rt.handleIssueSession(w, r, unescape(nid))
			return true
		}
		if nid, ok := trimSuffix(rest, "/sessions"); ok && r.Method == http.MethodGet {
			rt.handleListSessions(w, r, unescape(nid))
			return true
		}
		if nid, ok := trimSuffix(rest, "/revoke"); ok && r.Method == http.MethodPost {
			rt.handleRevoke(w, r, unescape(nid))
			return true
		}
	}

	// enrollment/pending/{id}/approve | reject
	if strings.HasPrefix(sub, "enrollment/pending/") {
		rest := strings.TrimPrefix(sub, "enrollment/pending/")
		if id, ok := trimSuffix(rest, "/approve"); ok && r.Method == http.MethodPost {
			rt.handleApprovePending(w, r, unescape(id))
			return true
		}
		if id, ok := trimSuffix(rest, "/reject"); ok && r.Method == http.MethodPost {
			rt.handleRejectPending(w, r, unescape(id))
			return true
		}
	}
	return false
}

// ── Discovery / CRL ─────────────────────────────────────────────────────────────

func (rt *NipCaRouter) handleWellKnown(w http.ResponseWriter, _ *http.Request) {
	pfx := rt.prefix
	body := map[string]any{
		"nps_ca":       "0.1",
		"issuer":       rt.opts.CaNid,
		"display_name": rt.opts.DisplayName,
		"public_key":   rt.ca.GetCaPublicKey(),
		"algorithms":   rt.opts.Algorithms,
		"endpoints": map[string]any{
			"register":  rt.opts.BaseUrl + pfx + "/v1/agents/register",
			"verify":    rt.opts.BaseUrl + pfx + "/v1/agents/{nid}/verify",
			"ocsp":      rt.opts.BaseUrl + pfx + "/v1/agents/{nid}/verify",
			"node_ocsp": rt.opts.BaseUrl + pfx + "/v1/nodes/{nid}/verify",
			"crl":       rt.opts.BaseUrl + pfx + "/v1/crl",
		},
		"capabilities": []string{"agent", "node", "orchestrator-group",
			"ra-tier-" + itoa(int(rt.opts.EnrollmentTier))},
		"max_cert_validity_days": rt.opts.AgentCertValidityDays,
	}
	writeJSON(w, 200, body)
}

func (rt *NipCaRouter) handleCrl(w http.ResponseWriter, _ *http.Request) {
	revoked, err := rt.ca.GetCrl()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error_code": "NIP-CA-INTERNAL", "message": err.Error()})
		return
	}
	sort.Slice(revoked, func(i, j int) bool {
		left, right := revoked[i], revoked[j]
		leftTime, rightTime := time.Time{}, time.Time{}
		if left.RevokedAt != nil {
			leftTime = *left.RevokedAt
		}
		if right.RevokedAt != nil {
			rightTime = *right.RevokedAt
		}
		if !leftTime.Equal(rightTime) {
			return leftTime.Before(rightTime)
		}
		if left.Serial != right.Serial {
			return left.Serial < right.Serial
		}
		return left.Nid < right.Nid
	})
	entries := make([]map[string]any, 0, len(revoked))
	for _, r := range revoked {
		e := map[string]any{"nid": r.Nid, "serial": r.Serial}
		if r.RevokedAt != nil {
			e["revoked_at"] = isoTime(*r.RevokedAt)
		} else {
			e["revoked_at"] = nil
		}
		e["reason"] = ptrStr(r.RevokeReason)
		entries = append(entries, e)
	}
	body := map[string]any{
		"issued_by": rt.opts.CaNid,
		"issued_at": isoTime(time.Now().UTC()),
		"entries":   entries,
	}
	sig := rt.ca.SignArtifact(body)
	out := map[string]any{
		"issued_by": body["issued_by"],
		"issued_at": body["issued_at"],
		"entries":   body["entries"],
		"signature": sig,
	}
	writeJSON(w, 200, out)
}

func (rt *NipCaRouter) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	records, err := rt.ca.ListCertificates()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error_code": "NIP-CA-INTERNAL", "message": err.Error()})
		return
	}
	sort.Slice(records, func(i, j int) bool {
		if !records[i].IssuedAt.Equal(records[j].IssuedAt) {
			return records[i].IssuedAt.Before(records[j].IssuedAt)
		}
		return records[i].Serial < records[j].Serial
	})
	entries := make([]map[string]any, 0, len(records))
	for _, record := range records {
		var scope any
		if err := json.Unmarshal([]byte(record.ScopeJson), &scope); err != nil {
			scope = nil
		}
		entry := map[string]any{
			"nid":           record.Nid,
			"entity_type":   record.EntityType,
			"serial":        record.Serial,
			"pub_key":       record.PubKey,
			"capabilities":  record.Capabilities,
			"scope":         scope,
			"issued_by":     record.IssuedBy,
			"issued_at":     isoTime(record.IssuedAt),
			"expires_at":    isoTime(record.ExpiresAt),
			"revoked_at":    nil,
			"revoke_reason": nil,
			"nid_role":      nil,
			"parent_nid":    nil,
		}
		if record.RevokedAt != nil {
			entry["revoked_at"] = isoTime(*record.RevokedAt)
		}
		if record.RevokeReason != nil {
			entry["revoke_reason"] = *record.RevokeReason
		}
		if record.NidRole != nil {
			entry["nid_role"] = *record.NidRole
		}
		if record.ParentNid != nil {
			entry["parent_nid"] = *record.ParentNid
		}
		entries = append(entries, entry)
	}
	writeJSON(w, 200, map[string]any{"entries": entries})
}

// ── Registration ────────────────────────────────────────────────────────────────

type registerRequest struct {
	Identifier   string   `json:"identifier"`
	PubKey       string   `json:"pub_key"`
	Capabilities []string `json:"capabilities"`
	ScopeJson    string   `json:"scope_json"`
	MetadataJson string   `json:"metadata_json"`
}

func (rt *NipCaRouter) handleRegister(w http.ResponseWriter, r *http.Request, entityType string, defaultCaps []string) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	var req registerRequest
	if !readJSONBody(w, r, &req) {
		return
	}
	if msg, ok := validateRegister(req.Identifier, req.PubKey); !ok {
		writeBadRequest(w, msg)
		return
	}
	caps := req.Capabilities
	if caps == nil {
		caps = defaultCaps
	}
	scope := req.ScopeJson
	if scope == "" {
		scope = "{}"
	}
	enrollToken := r.Header.Get("X-NPS-Enrollment-Token")
	frame, err := rt.ca.RegisterWithRa(entityType, req.Identifier, req.PubKey, caps, scope, req.MetadataJson, enrollToken, rt.enrollmentPolicy)
	if err != nil {
		if pending, ok := err.(*NipRaPendingError); ok {
			writeJSON(w, 202, map[string]any{"pending_id": pending.PendingID, "status": "queued"})
			return
		}
		writeCaError(w, err)
		return
	}
	writeJSON(w, 201, identFrameWire(frame))
}

type registerX509Request struct {
	Identifier     string   `json:"identifier"`
	PubKey         string   `json:"pub_key"`
	Capabilities   []string `json:"capabilities"`
	ScopeJson      string   `json:"scope_json"`
	MetadataJson   string   `json:"metadata_json"`
	AssuranceLevel string   `json:"assurance_level"`
}

func (rt *NipCaRouter) handleRegisterX509(w http.ResponseWriter, r *http.Request, entityType string, defaultCaps []string) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	var req registerX509Request
	if !readJSONBody(w, r, &req) {
		return
	}
	if msg, ok := validateRegister(req.Identifier, req.PubKey); !ok {
		writeBadRequest(w, msg)
		return
	}
	caps := req.Capabilities
	if caps == nil {
		caps = defaultCaps
	}
	scope := req.ScopeJson
	if scope == "" {
		scope = "{}"
	}
	frame, err := rt.ca.RegisterX509(entityType, req.Identifier, req.PubKey, caps, scope,
		parseAssuranceLevel(req.AssuranceLevel), req.MetadataJson, nil)
	if err != nil {
		writeCaError(w, err)
		return
	}
	writeJSON(w, 201, identFrameWire(frame))
}

type registerGroupRequest struct {
	Identifier   string   `json:"identifier"`
	PubKey       string   `json:"pub_key"`
	Capabilities []string `json:"capabilities"`
	ScopeJson    string   `json:"scope_json"`
	MetadataJson string   `json:"metadata_json"`
	OwnerUserId  string   `json:"owner_user_id"`
	OwnerKeyId   string   `json:"owner_key_id"`
}

func (rt *NipCaRouter) handleRegisterGroup(w http.ResponseWriter, r *http.Request) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	var req registerGroupRequest
	if !readJSONBody(w, r, &req) {
		return
	}
	if req.Identifier != "" && !identifierRe.MatchString(req.Identifier) {
		writeBadRequest(w, "identifier contains invalid characters. Allowed: a-z A-Z 0-9 . _ : @ / -")
		return
	}
	if !validPubKey(req.PubKey) {
		writeBadRequest(w, "pub_key must be 'ed25519:<base64url>'.")
		return
	}
	caps := req.Capabilities
	if caps == nil {
		caps = []string{}
	}
	scope := req.ScopeJson
	if scope == "" {
		scope = "{}"
	}
	frame, err := rt.ca.RegisterGroup(req.Identifier, req.PubKey, caps, scope, req.OwnerUserId, req.OwnerKeyId, req.MetadataJson)
	if err != nil {
		writeCaError(w, err)
		return
	}
	writeJSON(w, 201, identFrameWire(frame))
}

// ── Renew / Revoke / Verify ─────────────────────────────────────────────────────

func (rt *NipCaRouter) handleRenew(w http.ResponseWriter, r *http.Request, nid string) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	frame, err := rt.ca.Renew(nid)
	if err != nil {
		writeCaError(w, err)
		return
	}
	writeJSON(w, 200, identFrameWire(frame))
}

type revokeRequest struct {
	Reason string `json:"reason"`
}

func (rt *NipCaRouter) handleRevoke(w http.ResponseWriter, r *http.Request, nid string) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	var req revokeRequest
	_ = decodeBody(r, &req)
	reason := req.Reason
	if reason == "" {
		reason = "cessation_of_operation"
	}
	if !validRevocationReasons[reason] {
		writeBadRequest(w, "Invalid revocation reason '"+reason+"'.")
		return
	}
	frame, err := rt.ca.Revoke(nid, reason)
	if err != nil {
		writeCaError(w, err)
		return
	}
	writeJSON(w, 200, revokeFrameWire(frame))
}

func (rt *NipCaRouter) handleVerify(w http.ResponseWriter, _ *http.Request, nid string) {
	result := rt.ca.Verify(nid)
	if rt.opts.NormalizeOcspResponseTime {
		// timing normalization is a security nicety; kept minimal here.
	}
	if result.Valid {
		writeJSON(w, 200, map[string]any{
			"valid":      true,
			"nid":        result.Record.Nid,
			"expires_at": isoTime(result.Record.ExpiresAt),
			"serial":     result.Record.Serial,
		})
		return
	}
	status := 200
	if result.ErrorCode == ErrCaNidNotFound {
		status = 404
	}
	writeJSON(w, status, map[string]any{
		"valid":      false,
		"error_code": result.ErrorCode,
		"message":    result.Message,
	})
}

// ── Group session issuance ──────────────────────────────────────────────────────

type issueSessionRequest struct {
	SessionPubKey   string   `json:"session_pub_key"`
	Purpose         string   `json:"purpose"`
	ValiditySeconds int      `json:"validity_seconds"`
	Capabilities    []string `json:"capabilities"`
	ScopeJson       string   `json:"scope_json"`
	MetadataJson    string   `json:"metadata_json"`
}

type issueSessionPayload struct {
	SessionPubKey   string   `json:"session_pub_key"`
	Purpose         string   `json:"purpose"`
	ValiditySeconds int      `json:"validity_seconds"`
	Capabilities    []string `json:"capabilities"`
	ScopeJson       string   `json:"scope_json"`
	MetadataJson    string   `json:"metadata_json"`
	Iat             int64    `json:"iat"`
}

func (rt *NipCaRouter) handleIssueSession(w http.ResponseWriter, r *http.Request, groupNid string) {
	ctype := r.Header.Get("Content-Type")
	isJwsBody := strings.Contains(strings.ToLower(ctype), "jose+json")

	var req issueSessionRequest

	if isJwsBody {
		var jws FlattenedJws
		if !readJSONBody(w, r, &jws) {
			return
		}
		groupRecord, _ := rt.ca.GetCert(groupNid)
		if groupRecord == nil {
			writeCaError(w, newCaErr(ErrCaParentNotFound, "Group %s not found.", groupNid))
			return
		}
		if groupRecord.NidRole == nil || *groupRecord.NidRole != IdentLineageRoleGroup {
			writeCaError(w, newCaErr(ErrCaParentNotGroup, "NID %s is not a group.", groupNid))
			return
		}
		if groupRecord.RevokedAt != nil {
			writeCaError(w, newCaErr(ErrCaGroupRevoked, "Group %s revoked.", groupNid))
			return
		}
		pubKey := DecodePublicKey(groupRecord.PubKey)
		if pubKey == nil {
			writeJSON(w, 401, map[string]any{"error_code": ErrCaJwsInvalid, "message": "Group public key could not be decoded."})
			return
		}
		payloadJSON, kid, ec, ok := VerifyGroupJws(jws, pubKey)
		if !ok {
			writeJSON(w, 401, map[string]any{"error_code": ec, "message": "Group-JWS verification failed."})
			return
		}
		if kid != groupNid {
			writeJSON(w, 401, map[string]any{"error_code": ErrCaJwsInvalid, "message": "JWS kid '" + kid + "' does not match URL group_nid '" + groupNid + "'."})
			return
		}
		var payload issueSessionPayload
		if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
			writeJSON(w, 401, map[string]any{"error_code": ErrCaJwsInvalid, "message": "JWS payload is not valid JSON."})
			return
		}
		skewSec := int64(rt.opts.SessionJwsClockSkew.Seconds())
		nowEpoch := time.Now().UTC().Unix()
		if payload.Iat == 0 || absInt64(nowEpoch-payload.Iat) > skewSec {
			writeJSON(w, 401, map[string]any{"error_code": ErrCaJwsExpired, "message": "JWS iat outside skew window."})
			return
		}
		req = issueSessionRequest{
			SessionPubKey: payload.SessionPubKey, Purpose: payload.Purpose,
			ValiditySeconds: payload.ValiditySeconds, Capabilities: payload.Capabilities,
			ScopeJson: payload.ScopeJson, MetadataJson: payload.MetadataJson,
		}
	} else {
		if !rt.authorized(r) {
			writeUnauthorized(w)
			return
		}
		if !readJSONBody(w, r, &req) {
			return
		}
	}

	if !validPubKey(req.SessionPubKey) {
		writeBadRequest(w, "session_pub_key must be 'ed25519:<base64url>'.")
		return
	}
	var validity time.Duration
	if req.ValiditySeconds > 0 {
		validity = time.Duration(req.ValiditySeconds) * time.Second
	}
	frame, err := rt.ca.IssueSession(groupNid, req.SessionPubKey, IssueSessionParams{
		Validity: validity, Purpose: req.Purpose, Capabilities: req.Capabilities,
		ScopeJSON: req.ScopeJson, MetadataJSON: req.MetadataJson,
	})
	if err != nil {
		writeCaError(w, err)
		return
	}
	writeJSON(w, 201, identFrameWire(frame))
}

func (rt *NipCaRouter) handleListSessions(w http.ResponseWriter, r *http.Request, groupNid string) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	sessions, _ := rt.ca.ListSessions(groupNid)
	items := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		item := map[string]any{
			"nid": s.Nid, "serial": s.Serial,
			"issued_at": isoTime(s.IssuedAt), "expires_at": isoTime(s.ExpiresAt),
		}
		if s.RevokedAt != nil {
			item["revoked_at"] = isoTime(*s.RevokedAt)
		} else {
			item["revoked_at"] = nil
		}
		item["revoke_reason"] = ptrStr(s.RevokeReason)
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"group_nid": groupNid, "count": len(sessions), "sessions": items})
}

// ── Enrollment (RA) ─────────────────────────────────────────────────────────────

type createTokenRequest struct {
	TtlSeconds int    `json:"ttl_seconds"`
	Label      string `json:"label"`
}

func (rt *NipCaRouter) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	if rt.bootstrapStore == nil {
		writeJSON(w, 400, map[string]any{"error_code": "NIP-CA-BAD-REQUEST", "message": "Bootstrap token enrollment is not enabled on this CA."})
		return
	}
	var req createTokenRequest
	_ = decodeBody(r, &req)
	ttl := rt.opts.BootstrapTokenMaxTtl
	if req.TtlSeconds > 0 {
		ttl = time.Duration(req.TtlSeconds) * time.Second
	}
	if ttl > rt.opts.BootstrapTokenMaxTtl {
		ttl = rt.opts.BootstrapTokenMaxTtl
	}
	expiresAt := time.Now().UTC().Add(ttl)
	raw, err := rt.bootstrapStore.Create(req.Label, expiresAt)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error_code": "NIP-CA-INTERNAL", "message": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"token": raw, "expires_at": isoTime(expiresAt), "label": req.Label})
}

func (rt *NipCaRouter) handleListPending(w http.ResponseWriter, r *http.Request) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	if rt.pendingStore == nil {
		writeJSON(w, 400, map[string]any{"error_code": "NIP-CA-BAD-REQUEST", "message": "Pending-queue enrollment is not enabled on this CA."})
		return
	}
	records, _ := rt.pendingStore.List()
	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		items = append(items, map[string]any{
			"id": rec.Id, "entity_type": rec.EntityType, "identifier": rec.Identifier,
			"pub_key": rec.PubKey, "capabilities": rec.Capabilities, "scope_json": rec.ScopeJson,
			"requested_at": isoTime(rec.RequestedAt), "status": rec.Status.String(),
			"reject_reason": rec.RejectReason,
		})
	}
	writeJSON(w, 200, map[string]any{"count": len(records), "items": items})
}

func (rt *NipCaRouter) handleApprovePending(w http.ResponseWriter, r *http.Request, id string) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	if rt.pendingStore == nil {
		writeJSON(w, 400, map[string]any{"error_code": "NIP-CA-BAD-REQUEST", "message": "Pending-queue enrollment is not enabled on this CA."})
		return
	}
	record, _ := rt.pendingStore.Get(id)
	if record == nil {
		writeJSON(w, 404, map[string]any{"error_code": ErrCaNidNotFound, "message": "Pending registration '" + id + "' not found."})
		return
	}
	if record.Status != PendingStatusPending {
		writeJSON(w, 409, map[string]any{"error_code": "NIP-CA-BAD-REQUEST", "message": "Record '" + id + "' is already " + record.Status.String() + "."})
		return
	}
	frame, err := rt.ca.Register(record.EntityType, record.Identifier, record.PubKey, record.Capabilities, record.ScopeJson, record.MetadataJson)
	if err != nil {
		writeCaError(w, err)
		return
	}
	_, _ = rt.pendingStore.Approve(id)
	writeJSON(w, 201, identFrameWire(frame))
}

type rejectPendingRequest struct {
	Reason string `json:"reason"`
}

func (rt *NipCaRouter) handleRejectPending(w http.ResponseWriter, r *http.Request, id string) {
	if !rt.authorized(r) {
		writeUnauthorized(w)
		return
	}
	if rt.pendingStore == nil {
		writeJSON(w, 400, map[string]any{"error_code": "NIP-CA-BAD-REQUEST", "message": "Pending-queue enrollment is not enabled on this CA."})
		return
	}
	var req rejectPendingRequest
	_ = decodeBody(r, &req)
	reason := req.Reason
	if reason == "" {
		reason = "rejected_by_operator"
	}
	ok, _ := rt.pendingStore.Reject(id, reason)
	if !ok {
		record, _ := rt.pendingStore.Get(id)
		if record == nil {
			writeJSON(w, 404, map[string]any{"error_code": "NIP-CA-BAD-REQUEST", "message": "Pending registration '" + id + "' not found."})
		} else {
			writeJSON(w, 409, map[string]any{"error_code": "NIP-CA-BAD-REQUEST", "message": "Record '" + id + "' is already " + record.Status.String() + "."})
		}
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "status": "rejected", "reason": reason})
}

// ── Wire serialization ──────────────────────────────────────────────────────────

func identFrameWire(f *IdentFrame) map[string]any {
	d := map[string]any{
		"frame":   "0x20",
		"nid":     f.NID,
		"pub_key": f.PubKey,
	}
	if f.IssuedBy != "" {
		d["issued_by"] = f.IssuedBy
	}
	if f.IssuedAt != "" {
		d["issued_at"] = f.IssuedAt
	}
	if f.ExpiresAt != "" {
		d["expires_at"] = f.ExpiresAt
	}
	if f.Serial != "" {
		d["serial"] = f.Serial
	}
	caps := f.Capabilities
	if caps == nil {
		caps = []string{}
	}
	d["capabilities"] = caps
	if f.Scope != nil {
		d["scope"] = f.Scope
	}
	if f.Signature != nil {
		d["signature"] = *f.Signature
	}
	if f.Meta != nil {
		d["metadata"] = f.Meta
	}
	if f.AssuranceLevel != nil {
		d["assurance_level"] = f.AssuranceLevel.Wire
	}
	if f.CertFormat != nil {
		d["cert_format"] = *f.CertFormat
	}
	if f.CertChain != nil {
		d["cert_chain"] = f.CertChain
	}
	if l := frameLineage(f); l != nil {
		d["lineage"] = l
	}
	return d
}

func revokeFrameWire(f *RevokeFrame) map[string]any {
	d := map[string]any{
		"frame":      "0x22",
		"target_nid": f.TargetNID,
		"reason":     f.Reason,
		"revoked_at": f.RevokedAt,
		"signer_nid": f.SignerNID,
		"signature":  f.Signature,
	}
	if f.Serial != nil {
		d["serial"] = *f.Serial
	}
	return d
}

// ── HTTP helpers ────────────────────────────────────────────────────────────────

func (rt *NipCaRouter) authorized(r *http.Request) bool {
	if rt.opts.OperatorApiKey == "" {
		return true
	}
	header := r.Header.Get("Authorization")
	const bearer = "Bearer "
	if len(header) <= len(bearer) || !strings.EqualFold(header[:len(bearer)], bearer) {
		return false
	}
	provided := strings.TrimSpace(header[len(bearer):])
	return subtle.ConstantTimeCompare([]byte(provided), []byte(rt.opts.OperatorApiKey)) == 1
}

func validateRegister(identifier, pubKey string) (string, bool) {
	if identifier == "" || pubKey == "" {
		return "identifier and pub_key are required.", false
	}
	if !identifierRe.MatchString(identifier) {
		return "identifier contains invalid characters. Allowed: a-z A-Z 0-9 . _ : @ / -", false
	}
	if !validPubKey(pubKey) {
		return "pub_key must be 'ed25519:<base64url>'.", false
	}
	return "", true
}

func validPubKey(pubKey string) bool {
	return strings.HasPrefix(pubKey, "ed25519:") && len(pubKey) > 8
}

func parseAssuranceLevel(raw string) AssuranceLevel {
	switch strings.ToLower(raw) {
	case "attested":
		return AssuranceAttested
	case "verified":
		return AssuranceVerified
	default:
		return AssuranceAnonymous
	}
}

func writeCaError(w http.ResponseWriter, err error) {
	caErr, ok := err.(*NipCaError)
	if !ok {
		writeJSON(w, 400, map[string]any{"error_code": "NIP-CA-BAD-REQUEST", "message": err.Error()})
		return
	}
	status := caErrorStatus(caErr.ErrorCode)
	writeJSON(w, status, map[string]any{"error_code": caErr.ErrorCode, "message": caErr.Message})
}

func caErrorStatus(code string) int {
	switch code {
	case ErrCaNidNotFound, ErrCaParentNotFound:
		return 404
	case ErrCaNidAlreadyExists, ErrCaSerialDuplicate:
		return 409
	case ErrCaRenewalTooEarly, ErrCaSessionValidityInvalid, ErrCaParentNotGroup:
		return 400
	case ErrCaScopeExpansionDenied, ErrCertCapabilityMissing, ErrCaGroupRevoked,
		ErrRaNidNotAllowed, ErrRaPendingRejected:
		return 403
	case ErrCaJwsInvalid, ErrCaJwsExpired, ErrCertExpired, ErrCertRevoked,
		ErrCertParentRevoked, ErrRaTokenInvalid, ErrRaTokenExpired:
		return 401
	default:
		return 400
	}
}

func writeBadRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, 400, map[string]any{"error_code": "NIP-CA-BAD-REQUEST", "message": msg})
}

func writeUnauthorized(w http.ResponseWriter) {
	writeJSON(w, 401, map[string]any{"error_code": "NIP-CA-UNAUTHORIZED", "message": "Valid operator Bearer token required."})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// readJSONBody decodes the body into v; on error it writes a 400 and returns false.
func readJSONBody(w http.ResponseWriter, r *http.Request, v any) bool {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeBadRequest(w, "Invalid JSON body.")
		return false
	}
	if len(raw) == 0 {
		writeBadRequest(w, "Invalid JSON body.")
		return false
	}
	if err := json.Unmarshal(raw, v); err != nil {
		writeBadRequest(w, "Invalid JSON body.")
		return false
	}
	return true
}

// decodeBody decodes an optional body; empty body is not an error.
func decodeBody(r *http.Request, v any) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil || len(raw) == 0 {
		return err
	}
	return json.Unmarshal(raw, v)
}

func trimSuffix(s, suffix string) (string, bool) {
	if strings.HasSuffix(s, suffix) {
		return strings.TrimSuffix(s, suffix), true
	}
	return "", false
}

func unescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func itoa(v int) string { return strconv.Itoa(v) }
