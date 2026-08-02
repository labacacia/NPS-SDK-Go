// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
//
// Framework-agnostic Memory Node HTTP handler for NPS-2 §2.1, §4, §5.
// Implements http.Handler; mount at any path via a mux.

package nwp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strings"
)

// ── Schema types ──────────────────────────────────────────────────────────────

// MemoryNodeField describes a single field in a Memory Node schema (NPS-2 §4.1).
type MemoryNodeField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Nullable    bool   `json:"nullable"`
}

// MemoryNodeSchema is the schema definition for a Memory Node.
type MemoryNodeSchema struct {
	Fields []MemoryNodeField `json:"fields"`
}

// ── Options ───────────────────────────────────────────────────────────────────

// MemoryNodeOptions configures a single Memory Node instance.
type MemoryNodeOptions struct {
	NodeID             string
	DisplayName        string
	Schema             MemoryNodeSchema
	PathPrefix         string
	DefaultLimit       uint64
	MaxLimit           uint64
	RequireAuth        bool
	DefaultTokenBudget uint64
	// CgnLimit is the node-operator server-side CGN cap (token-budget.md §7).
	// effective_budget = min(CgnLimit, X-NWP-Budget); 0 = no operator cap.
	CgnLimit uint64
	// ReputationPolicy enables RFC-0005 reputation gate. Nil = disabled.
	ReputationPolicy *ReputationPolicy
	// TrustAnchors is an optional list of trust-anchor identifiers published in the NWM (alpha.11).
	TrustAnchors []string
}

// ── Provider interface ────────────────────────────────────────────────────────

// MemoryNodeRow is a single data row returned by a provider.
type MemoryNodeRow = map[string]any

// MemoryNodeQueryResult is the result of a provider query.
type MemoryNodeQueryResult struct {
	Rows       []MemoryNodeRow
	NextCursor string
}

// IMemoryNodeProvider is the interface applications implement to back a Memory Node.
type IMemoryNodeProvider interface {
	Query(ctx context.Context, frame *QueryFrame, opts MemoryNodeOptions) (*MemoryNodeQueryResult, error)
}

// StreamingProvider optionally supports NDJSON streaming.
type StreamingProvider interface {
	Stream(ctx context.Context, frame *QueryFrame, opts MemoryNodeOptions) (<-chan []MemoryNodeRow, <-chan error)
}

// ── Server ────────────────────────────────────────────────────────────────────

// MemoryNodeServer is an http.Handler that hosts a Memory Node.
type MemoryNodeServer struct {
	provider   IMemoryNodeProvider
	opts       MemoryNodeOptions
	prefix     string
	anchorID   string
	nwmJSON    []byte
	schemaJSON []byte
}

// NewMemoryNodeServer creates a MemoryNodeServer and pre-computes static payloads.
func NewMemoryNodeServer(provider IMemoryNodeProvider, opts MemoryNodeOptions) *MemoryNodeServer {
	if opts.DefaultLimit == 0 {
		opts.DefaultLimit = 20
	}
	if opts.MaxLimit == 0 {
		opts.MaxLimit = 1000
	}
	prefix := strings.TrimRight(opts.PathPrefix, "/")

	anchorID, schemaJSON, nwmJSON := buildStaticPayloads(opts, prefix)

	return &MemoryNodeServer{
		provider:   provider,
		opts:       opts,
		prefix:     prefix,
		anchorID:   anchorID,
		nwmJSON:    nwmJSON,
		schemaJSON: schemaJSON,
	}
}

// ServeHTTP implements http.Handler.
func (s *MemoryNodeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip prefix
	path := r.URL.Path
	if !strings.HasPrefix(path, s.prefix) {
		http.NotFound(w, r)
		return
	}
	sub := path[len(s.prefix):]
	if sub == "" {
		sub = "/"
	}

	// Auth check
	if s.opts.RequireAuth && r.Header.Get("X-NWP-Agent") == "" {
		writeError(w, 401, "NPS-CLIENT-UNAUTHORIZED", "NWP-AUTH-REQUIRED", "X-NWP-Agent header is required.")
		return
	}

	// Reputation gate (RFC-0005 §4.1.4)
	if s.opts.ReputationPolicy != nil {
		agentNid := r.Header.Get("X-NWP-Agent")
		if agentNid != "" {
			eval := DefaultReputationEvaluator()
			decision, _ := eval.Evaluate(r.Context(), agentNid, "anonymous", *s.opts.ReputationPolicy)
			switch decision.Outcome {
			case RepBan, RepReject:
				writeError(w, 403, "NPS-AUTH-FORBIDDEN", "NWP-AUTH-REPUTATION-BLOCKED",
					"Request rejected by reputation policy.")
				return
			case RepThrottle:
				w.Header().Set("Retry-After", "60")
				writeError(w, 429, "NPS-LIMIT-RATE", "NWP-AUTH-REPUTATION-BLOCKED",
					"Request throttled by reputation policy.")
				return
			}
		}
	}

	norm := strings.TrimRight(sub, "/")
	if norm == "" {
		norm = "/"
	}

	switch {
	case norm == "/.nwm" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-NWP-Node-Type", "memory")
		w.WriteHeader(200)
		w.Write(s.nwmJSON) //nolint:errcheck

	case norm == "/.schema" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-NWP-Schema", s.anchorID)
		w.WriteHeader(200)
		w.Write(s.schemaJSON) //nolint:errcheck

	case norm == "/query":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		s.handleQuery(w, r)

	case norm == "/stream":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		s.handleStream(w, r)

	default:
		http.NotFound(w, r)
	}
}

func (s *MemoryNodeServer) handleQuery(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", "NWP-QUERY-FILTER-INVALID", "Failed to read request body.")
		return
	}
	var dict map[string]any
	if err := json.Unmarshal(body, &dict); err != nil {
		writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", "NWP-QUERY-FILTER-INVALID", "Invalid QueryFrame JSON.")
		return
	}
	frame := queryFrameFromJSON(dict, s.opts)

	result, err := s.provider.Query(r.Context(), frame, s.opts)
	if err != nil {
		writeError(w, 500, "NPS-SERVER-INTERNAL", "NWP-NODE-UNAVAILABLE", err.Error())
		return
	}

	rows := result.Rows
	tokenEst := measureRows(rows)
	budget := effectiveBudget(parseBudget(r), int(s.opts.CgnLimit))
	if budget > 0 && tokenEst > budget {
		rows, tokenEst = trimToBudget(rows, budget)
	}

	caps := map[string]any{
		"frame":       "0x04",
		"anchor_ref":  s.anchorID,
		"count":       len(rows),
		"data":        rows,
		"next_cursor": result.NextCursor,
		"token_est":   tokenEst,
	}
	out, _ := json.Marshal(caps)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-NWP-Schema", s.anchorID)
	w.Header().Set("X-NWP-Tokens", fmt.Sprintf("%d", tokenEst))
	w.Header().Set("X-NWP-Node-Type", "memory")
	w.WriteHeader(200)
	w.Write(out) //nolint:errcheck
}

func (s *MemoryNodeServer) handleStream(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", "NWP-QUERY-FILTER-INVALID", "Failed to read request body.")
		return
	}
	var dict map[string]any
	if err := json.Unmarshal(body, &dict); err != nil {
		writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", "NWP-QUERY-FILTER-INVALID", "Invalid QueryFrame JSON.")
		return
	}
	frame := queryFrameFromJSON(dict, s.opts)
	streamID := randomStreamID()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-NWP-Schema", s.anchorID)
	w.Header().Set("X-NWP-Node-Type", "memory")
	w.WriteHeader(200)

	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	writeChunk := func(seq int, isLast bool, anchorRef string, data []MemoryNodeRow) {
		chunk := map[string]any{
			"frame":     "0x03",
			"stream_id": streamID,
			"seq":       seq,
			"is_last":   isLast,
			"data":      data,
		}
		if anchorRef != "" {
			chunk["anchor_ref"] = anchorRef
		}
		b, _ := json.Marshal(chunk)
		w.Write(append(b, '\n')) //nolint:errcheck
		flush()
	}

	// Try native streaming first
	if sp, ok := s.provider.(StreamingProvider); ok {
		pagesCh, errCh := sp.Stream(r.Context(), frame, s.opts)
		seq := 0
		for page := range pagesCh {
			anchorRef := ""
			if seq == 0 {
				anchorRef = s.anchorID
			}
			writeChunk(seq, false, anchorRef, page)
			seq++
		}
		if e := <-errCh; e != nil {
			errChunk, _ := json.Marshal(map[string]any{
				"frame": "0x03", "stream_id": streamID, "seq": seq,
				"is_last": true, "data": []any{}, "error_code": "NWP-NODE-UNAVAILABLE",
			})
			w.Write(append(errChunk, '\n')) //nolint:errcheck
			return
		}
		writeChunk(seq, true, "", nil)
		return
	}

	// Fall back to single query
	result, err := s.provider.Query(r.Context(), frame, s.opts)
	if err != nil {
		errChunk, _ := json.Marshal(map[string]any{
			"frame": "0x03", "stream_id": streamID, "seq": 0,
			"is_last": true, "data": []any{}, "error_code": "NWP-NODE-UNAVAILABLE",
		})
		w.Write(append(errChunk, '\n')) //nolint:errcheck
		return
	}
	writeChunk(0, false, s.anchorID, result.Rows)
	writeChunk(1, true, "", nil)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func buildStaticPayloads(opts MemoryNodeOptions, prefix string) (anchorID string, schemaJSON, nwmJSON []byte) {
	schemaData := map[string]any{"fields": opts.Schema.Fields}
	schemaJSON, _ = json.Marshal(schemaData)
	h := sha256.Sum256(schemaJSON)
	anchorID = "sha256:" + hex.EncodeToString(h[:])

	nwm := map[string]any{
		"nwp":              "0.4",
		"node_id":          opts.NodeID,
		"node_type":        "memory",
		"display_name":     opts.DisplayName,
		"wire_formats":     []string{"json"},
		"preferred_format": "json",
		"schema_anchors":   map[string]string{"default": anchorID},
		"capabilities":     map[string]bool{"query": true, "stream": true, "token_budget_hint": true},
		"auth":             map[string]any{"required": opts.RequireAuth, "identity_type": "none"},
		"endpoints": map[string]string{
			"query":  prefix + "/query",
			"stream": prefix + "/stream",
			"schema": prefix + "/.schema",
		},
	}
	if opts.RequireAuth {
		nwm["auth"] = map[string]any{"required": true, "identity_type": "nip-cert"}
	}
	if opts.CgnLimit > 0 {
		nwm["token_budget"] = map[string]any{"cgn_limit": opts.CgnLimit, "profile": "cgn.v1"}
	}
	if len(opts.TrustAnchors) > 0 {
		nwm["trust_anchors"] = opts.TrustAnchors
	}
	nwmJSON, _ = json.Marshal(nwm)
	return
}

func writeError(w http.ResponseWriter, status int, npsStatus, code, message string) {
	body, _ := json.Marshal(map[string]string{
		"frame":   "0xFE",
		"status":  npsStatus,
		"error":   code,
		"message": message,
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(body) //nolint:errcheck
}

func queryFrameFromJSON(d map[string]any, opts MemoryNodeOptions) *QueryFrame {
	f := &QueryFrame{}
	if v, ok := d["anchor_ref"].(string); ok {
		f.AnchorRef = v
	}
	if v := d["filter"]; v != nil {
		f.Filter = v
	}
	if v := d["order"]; v != nil {
		f.Order = v
	}
	switch x := d["limit"].(type) {
	case float64:
		v := uint64(math.Min(x, float64(opts.MaxLimit)))
		f.Limit = &v
	}
	if f.Limit == nil {
		v := opts.DefaultLimit
		f.Limit = &v
	}
	if x, ok := d["offset"].(float64); ok {
		v := uint64(x)
		f.Offset = &v
	}
	return f
}

func parseBudget(r *http.Request) int {
	raw := r.Header.Get("X-NWP-Budget")
	if raw == "" {
		return 0
	}
	var n int
	fmt.Sscanf(raw, "%d", &n)
	return n
}

// effectiveBudget returns min(cgnLimit, agentBudget), treating 0 as unlimited.
func effectiveBudget(agentBudget, cgnLimit int) int {
	if cgnLimit == 0 {
		return agentBudget
	}
	if agentBudget == 0 {
		return cgnLimit
	}
	if cgnLimit < agentBudget {
		return cgnLimit
	}
	return agentBudget
}

func measureRows(rows []MemoryNodeRow) int {
	b, _ := json.Marshal(rows)
	return int(math.Ceil(float64(len(b)) / 4))
}

func trimToBudget(rows []MemoryNodeRow, budget int) ([]MemoryNodeRow, int) {
	var trimmed []MemoryNodeRow
	acc := 0
	for _, row := range rows {
		b, _ := json.Marshal(row)
		tok := int(math.Ceil(float64(len(b)) / 4))
		if acc+tok > budget {
			break
		}
		trimmed = append(trimmed, row)
		acc += tok
	}
	return trimmed, acc
}

func randomStreamID() string {
	return fmt.Sprintf("%x%x", rand.Uint64(), rand.Uint64())
}
