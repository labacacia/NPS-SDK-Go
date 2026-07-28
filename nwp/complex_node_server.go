// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
//
// Framework-agnostic Complex Node HTTP handler (NPS-2 §2.1, §11). Faithful port
// of the .NET ComplexNodeMiddleware. Implements http.Handler. Sub-paths:
// /.nwm, /.schema, /actions, /query, /invoke.
//
// On /query, the server asks the provider for local rows, then — if the request
// carries X-NWP-Depth > 0 and at least one child is declared — fetches each
// child's /query concurrently and attaches the embedded CapsFrame bodies under
// the top-level "graph" array. Cycle detection uses X-NWP-Trace; depth is
// clamped to the node's max and the absolute cap (5).

package nwp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AbsoluteMaxDepth is the NPS-2 §11 ceiling on X-NWP-Depth.
const AbsoluteMaxDepth uint = 5

// ── Options ───────────────────────────────────────────────────────────────────

// ComplexGraphRef is a child-node reference declared in the NWM (NPS-2 §11).
type ComplexGraphRef struct {
	// Rel is the semantic relationship label, e.g. "user", "payment".
	Rel string
	// NodeURL is the absolute child URL, e.g. https://api.myapp.com/users.
	NodeURL string
}

// ComplexNodeOptions configures a single Complex Node (NPS-2 §2.1, §11).
type ComplexNodeOptions struct {
	NodeID      string
	DisplayName string
	PathPrefix  string
	// Schema optionally exposes /query + /.schema (Memory-Node-like). Nil = none.
	Schema *MemoryNodeSchema
	// Actions is the action registry (may be empty). Reserved ids MUST NOT appear.
	Actions map[string]ActionSpec
	// Graph declares child node references.
	Graph []ComplexGraphRef
	// GraphMaxDepth is the max traversal depth the node advertises/honours. 0 → 2.
	GraphMaxDepth uint
	// AllowedChildURLPrefixes constrains child URLs (SSRF allowlist).
	AllowedChildURLPrefixes []string
	// RejectPrivateChildURLs rejects loopback/private child hosts. Default true.
	RejectPrivateChildURLs *bool
	// AllowHTTPChildURLs permits http:// child URLs (dev only). Default false.
	AllowHTTPChildURLs bool
	RequireAuth        bool
	DefaultLimit       uint
	MaxLimit           uint
	DefaultTimeoutMs   uint
	MaxTimeoutMs       uint
	// ChildFetchTimeout bounds outbound child fetches. 0 → 10s.
	ChildFetchTimeout time.Duration
}

func (o ComplexNodeOptions) rejectPrivateChildren() bool {
	return o.RejectPrivateChildURLs == nil || *o.RejectPrivateChildURLs
}

func (o ComplexNodeOptions) graphMaxDepth() uint {
	if o.GraphMaxDepth == 0 {
		return 2
	}
	return o.GraphMaxDepth
}

func (o ComplexNodeOptions) childFetchTimeout() time.Duration {
	if o.ChildFetchTimeout > 0 {
		return o.ChildFetchTimeout
	}
	return 10 * time.Second
}

// ── Provider ──────────────────────────────────────────────────────────────────

// IComplexNodeProvider is the local behaviour of a Complex Node. It mirrors the
// Memory + Action Node surfaces so a single provider can serve /query + /invoke.
type IComplexNodeProvider interface {
	Query(ctx context.Context, frame *QueryFrame, opts ComplexNodeOptions) (*MemoryNodeQueryResult, error)
	Execute(ctx context.Context, frame *ActionFrame, actx ActionContext) (*ActionExecutionResult, error)
}

// NullComplexNodeProvider aggregates child nodes only; Query returns empty and
// Execute is never called (unknown action_ids are rejected before the provider).
type NullComplexNodeProvider struct{}

func (NullComplexNodeProvider) Query(context.Context, *QueryFrame, ComplexNodeOptions) (*MemoryNodeQueryResult, error) {
	return &MemoryNodeQueryResult{Rows: []MemoryNodeRow{}}, nil
}

func (NullComplexNodeProvider) Execute(context.Context, *ActionFrame, ActionContext) (*ActionExecutionResult, error) {
	return nil, &complexError{"NullComplexNodeProvider does not handle actions."}
}

type complexError struct{ msg string }

func (e *complexError) Error() string { return e.msg }

// ── Child URL validator ───────────────────────────────────────────────────────

// ValidateComplexChildURL validates a child-node URL before dereferencing it
// (NPS-2 §13.2). Returns "" when acceptable, otherwise a human-readable reason.
func ValidateComplexChildURL(childURL string, allowedPrefixes []string, rejectPrivate, allowHTTP bool) string {
	if strings.TrimSpace(childURL) == "" {
		return "child node URL must not be empty."
	}
	u, err := parseAbsURL(childURL)
	if err != nil {
		return "child node URL '" + childURL + "' is not a valid absolute URI."
	}
	isHTTPS := strings.EqualFold(u.Scheme, "https")
	isHTTP := strings.EqualFold(u.Scheme, "http")
	if !isHTTPS && !(allowHTTP && isHTTP) {
		return "child node URL MUST use the https:// scheme (got '" + u.Scheme + "://')."
	}
	if len(allowedPrefixes) > 0 {
		matched := false
		for _, p := range allowedPrefixes {
			if strings.HasPrefix(strings.ToLower(childURL), strings.ToLower(p)) {
				matched = true
				break
			}
		}
		if !matched {
			return "child node URL '" + childURL + "' is not in the allowed prefix list."
		}
	}
	if rejectPrivate && isPrivateHost(u.Hostname()) {
		return "child node host '" + u.Hostname() + "' resolves to a private or loopback address (SSRF guard)."
	}
	return ""
}

// ── Server ────────────────────────────────────────────────────────────────────

// ComplexNodeServer is an http.Handler hosting a single Complex Node.
type ComplexNodeServer struct {
	provider    IComplexNodeProvider
	opts        ComplexNodeOptions
	prefix      string
	anchorID    string
	http        *http.Client
	nwmJSON     []byte
	schemaJSON  []byte
	actionsJSON []byte
}

// NewComplexNodeServer builds a Complex Node server. httpClient may be nil.
func NewComplexNodeServer(provider IComplexNodeProvider, opts ComplexNodeOptions, httpClient *http.Client) *ComplexNodeServer {
	if _, ok := opts.Actions[SystemTaskStatus]; ok {
		panic("reserved action id '" + SystemTaskStatus + "' MUST NOT be registered on a Complex Node")
	}
	if _, ok := opts.Actions[SystemTaskCancel]; ok {
		panic("reserved action id '" + SystemTaskCancel + "' MUST NOT be registered on a Complex Node")
	}
	if opts.graphMaxDepth() > AbsoluteMaxDepth {
		panic("GraphMaxDepth exceeds NPS-2 §11 absolute cap")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	s := &ComplexNodeServer{
		provider: provider,
		opts:     opts,
		prefix:   strings.TrimRight(opts.PathPrefix, "/"),
		http:     httpClient,
	}
	s.buildStaticPayloads()
	return s
}

// ServeHTTP implements http.Handler.
func (s *ComplexNodeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, s.prefix) {
		http.NotFound(w, r)
		return
	}
	sub := path[len(s.prefix):]

	if s.opts.RequireAuth && r.Header.Get(HeaderAgent) == "" {
		s.writeError(w, 401, "NPS-CLIENT-UNAUTHORIZED", ErrAuthNidScopeViolation,
			"X-NWP-Agent header is required.")
		return
	}

	switch sub {
	case "/.nwm", "/.nwm/":
		w.Header().Set("Content-Type", MimeManifest)
		w.Header().Set(HeaderNodeType, "complex")
		w.WriteHeader(200)
		_, _ = w.Write(s.nwmJSON)
	case "/.schema", "/.schema/":
		w.Header().Set("Content-Type", "application/json")
		if s.anchorID != "" {
			w.Header().Set(HeaderSchema, s.anchorID)
		}
		w.WriteHeader(200)
		_, _ = w.Write(s.schemaJSON)
	case "/actions", "/actions/":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(s.actionsJSON)
	case "/query", "/query/":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		s.handleQuery(w, r)
	case "/invoke", "/invoke/":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		s.handleInvoke(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *ComplexNodeServer) handleQuery(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrQueryFilterInvalid, err.Error())
		return
	}
	var dict map[string]any
	if err := json.Unmarshal(raw, &dict); err != nil {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrQueryFilterInvalid, "invalid QueryFrame JSON.")
		return
	}
	frame := queryFrameFromJSON(dict, MemoryNodeOptions{DefaultLimit: uint64(s.opts.DefaultLimit), MaxLimit: uint64(s.opts.MaxLimit)})

	// Depth parsing (header absent => 0 = local only).
	requestedDepth, derr := s.parseDepth(r)
	if derr != "" {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrDepthExceeded, derr)
		return
	}

	// Cycle detection.
	trace := parseTrace(r)
	for _, t := range trace {
		if t == s.opts.NodeID {
			s.writeError(w, 422, "NPS-CLIENT-UNPROCESSABLE", ErrGraphCycle,
				"graph cycle detected at '"+s.opts.NodeID+"'.")
			return
		}
	}

	local, err := s.provider.Query(r.Context(), frame, s.opts)
	if err != nil {
		s.writeError(w, 500, "NPS-SERVER-INTERNAL", ErrNodeUnavailable, "local query failed.")
		return
	}
	if local == nil {
		local = &MemoryNodeQueryResult{}
	}
	localData := local.Rows
	if localData == nil {
		localData = []MemoryNodeRow{}
	}

	caps := map[string]any{
		"count": len(localData),
		"data":  localData,
	}
	if s.anchorID != "" {
		caps["anchor_ref"] = s.anchorID
	}
	if local.NextCursor != "" {
		caps["next_cursor"] = local.NextCursor
	}

	// Graph expansion.
	if requestedDepth > 0 && len(s.opts.Graph) > 0 {
		nextTrace := append(append([]string{}, trace...), s.opts.NodeID)
		childDepth := requestedDepth - 1
		results := s.fetchChildren(r, raw, childDepth, nextTrace)
		caps["graph"] = results
	}

	w.Header().Set("Content-Type", MimeCapsule)
	w.Header().Set(HeaderNodeType, "complex")
	if s.anchorID != "" {
		w.Header().Set(HeaderSchema, s.anchorID)
	}
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(caps)
}

func (s *ComplexNodeServer) fetchChildren(r *http.Request, frameBody []byte, childDepth uint, nextTrace []string) []map[string]any {
	results := make([]map[string]any, len(s.opts.Graph))
	var wg sync.WaitGroup
	for i, gref := range s.opts.Graph {
		wg.Add(1)
		go func(i int, gref ComplexGraphRef) {
			defer wg.Done()
			results[i] = s.fetchChild(r, gref, frameBody, childDepth, nextTrace)
		}(i, gref)
	}
	wg.Wait()
	return results
}

func (s *ComplexNodeServer) fetchChild(r *http.Request, gref ComplexGraphRef, frameBody []byte, childDepth uint, nextTrace []string) map[string]any {
	base := map[string]any{"rel": gref.Rel, "node": gref.NodeURL}

	if ssrf := ValidateComplexChildURL(gref.NodeURL, s.opts.AllowedChildURLPrefixes,
		s.opts.rejectPrivateChildren(), s.opts.AllowHTTPChildURLs); ssrf != "" {
		base["error"] = map[string]any{"code": ErrAuthNidScopeViolation, "message": ssrf}
		return base
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.opts.childFetchTimeout())
	defer cancel()

	childURL := strings.TrimRight(gref.NodeURL, "/") + "/query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, childURL, bytes.NewReader(frameBody))
	if err != nil {
		base["error"] = map[string]any{"code": ErrNodeUnavailable, "message": err.Error()}
		return base
	}
	req.Header.Set("Content-Type", MimeFrame)
	req.Header.Set(HeaderDepth, strconv.FormatUint(uint64(childDepth), 10))
	req.Header.Set(HeaderTrace, strings.Join(nextTrace, ","))
	if agent := r.Header.Get(HeaderAgent); agent != "" {
		req.Header.Set(HeaderAgent, agent)
	}
	if budget := r.Header.Get(HeaderBudget); budget != "" {
		req.Header.Set(HeaderBudget, budget)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		msg := err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			msg = "child '" + gref.Rel + "' fetch timed out."
		}
		base["error"] = map[string]any{"code": ErrNodeUnavailable, "message": msg}
		return base
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		base["error"] = map[string]any{
			"code":    ErrNodeUnavailable,
			"message": "child '" + gref.Rel + "' returned " + strconv.Itoa(resp.StatusCode) + ": " + truncate(string(body)),
		}
		return base
	}

	var capsule json.RawMessage
	if err := json.Unmarshal(body, &capsule); err != nil {
		base["error"] = map[string]any{
			"code":    ErrNodeUnavailable,
			"message": "child '" + gref.Rel + "' returned non-JSON body: " + err.Error(),
		}
		return base
	}
	base["data"] = capsule
	return base
}

func (s *ComplexNodeServer) handleInvoke(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid, err.Error())
		return
	}
	var frame ActionFrameWire
	if err := json.Unmarshal(raw, &frame); err != nil || frame.ActionID == "" {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid,
			"invalid ActionFrame: missing action_id.")
		return
	}

	spec, ok := s.opts.Actions[frame.ActionID]
	if !ok {
		s.writeError(w, 404, "NPS-CLIENT-NOT-FOUND", ErrActionNotFound,
			"Unknown action_id '"+frame.ActionID+"'.")
		return
	}

	// Complex Node does not own the async task machinery.
	if frame.Async {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid,
			"Complex Node does not support async actions; invoke a downstream Action Node instead.")
		return
	}

	if frame.Priority != "" && frame.Priority != "low" && frame.Priority != "normal" && frame.Priority != "high" {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid,
			"priority '"+frame.Priority+"' is invalid (allowed: low/normal/high).")
		return
	}

	timeoutMs := s.clampTimeout(frame.TimeoutMs, spec)
	priority := frame.Priority
	if priority == "" {
		priority = "normal"
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	result, herr := s.provider.Execute(ctx, frame.toActionFrame(), ActionContext{
		AgentNid:  r.Header.Get(HeaderAgent),
		RequestID: frame.RequestID,
		Spec:      spec,
		TimeoutMs: timeoutMs,
		Priority:  priority,
	})
	if herr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			s.writeError(w, 504, "NPS-SERVER-TIMEOUT", ErrNodeUnavailable, "action execution timed out.")
			return
		}
		s.writeError(w, 500, "NPS-SERVER-INTERNAL", ErrNodeUnavailable, "action execution failed.")
		return
	}
	if result == nil {
		result = &ActionExecutionResult{}
	}

	anchorRef := result.AnchorRef
	if anchorRef == "" {
		anchorRef = spec.ResultAnchor
	}
	var data []json.RawMessage
	if len(result.Result) > 0 {
		data = []json.RawMessage{result.Result}
	} else {
		data = []json.RawMessage{}
	}
	caps := map[string]any{
		"anchor_ref": anchorRef,
		"count":      len(data),
		"data":       data,
		"token_est":  result.TokenEst,
	}
	w.Header().Set("Content-Type", MimeCapsule)
	w.Header().Set(HeaderNodeType, "complex")
	if anchorRef != "" {
		w.Header().Set(HeaderSchema, anchorRef)
	}
	if result.TokenEst > 0 {
		w.Header().Set(HeaderTokens, strconv.FormatUint(uint64(result.TokenEst), 10))
	}
	if frame.RequestID != "" {
		w.Header().Set(HeaderRequestID, frame.RequestID)
	}
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(caps)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func (s *ComplexNodeServer) parseDepth(r *http.Request) (uint, string) {
	raw := r.Header.Get(HeaderDepth)
	if raw == "" {
		return 0, ""
	}
	d, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, "X-NWP-Depth '" + raw + "' is not a non-negative integer."
	}
	depth := uint(d)
	if depth > s.opts.graphMaxDepth() {
		return 0, "X-NWP-Depth " + raw + " exceeds node max_depth " + strconv.FormatUint(uint64(s.opts.graphMaxDepth()), 10) + "."
	}
	if depth > AbsoluteMaxDepth {
		return 0, "X-NWP-Depth " + raw + " exceeds NPS-2 §11 absolute cap " + strconv.FormatUint(uint64(AbsoluteMaxDepth), 10) + "."
	}
	return depth, ""
}

func parseTrace(r *http.Request) []string {
	raw := r.Header.Get(HeaderTrace)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *ComplexNodeServer) clampTimeout(requested uint, spec ActionSpec) uint {
	maxOpt := s.opts.MaxTimeoutMs
	if maxOpt == 0 {
		maxOpt = 300000
	}
	specMax := spec.TimeoutMsMax
	if specMax == 0 {
		specMax = maxOpt
	}
	hardMax := specMax
	if maxOpt < hardMax {
		hardMax = maxOpt
	}
	if requested == 0 {
		if spec.TimeoutMsDefault > 0 {
			return spec.TimeoutMsDefault
		}
		if s.opts.DefaultTimeoutMs > 0 {
			return s.opts.DefaultTimeoutMs
		}
		return 5000
	}
	if requested > hardMax {
		return hardMax
	}
	return requested
}

func truncate(str string) string {
	if len(str) <= 256 {
		return str
	}
	return str[:256] + "…"
}

func (s *ComplexNodeServer) writeError(w http.ResponseWriter, status int, npsStatus, errorCode, message string) {
	env := map[string]any{"status": npsStatus, "error": errorCode, "message": message}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func (s *ComplexNodeServer) buildStaticPayloads() {
	base := s.prefix
	s.schemaJSON = []byte("{}")
	var schemaAnchors map[string]string
	if s.opts.Schema != nil {
		schema := map[string]any{"fields": s.opts.Schema.Fields}
		s.schemaJSON, _ = json.Marshal(schema)
		h := sha256.Sum256(s.schemaJSON)
		s.anchorID = "sha256:" + hex.EncodeToString(h[:])
		schemaAnchors = map[string]string{"default": s.anchorID}
	}

	endpoints := map[string]any{"query": base + "/query", "schema": base + "/.schema"}
	if len(s.opts.Actions) > 0 {
		endpoints["invoke"] = base + "/invoke"
	}

	auth := map[string]any{"required": s.opts.RequireAuth, "identity_type": "none"}
	if s.opts.RequireAuth {
		auth["identity_type"] = "nip-cert"
	}

	nwm := map[string]any{
		"nwp":              "0.4",
		"node_id":          s.opts.NodeID,
		"node_type":        "complex",
		"wire_formats":     []string{"ncp-capsule", "json"},
		"preferred_format": "json",
		"capabilities": map[string]any{
			"query":             s.opts.Schema != nil || len(s.opts.Graph) > 0,
			"stream":            false,
			"token_budget_hint": true,
		},
		"auth":      auth,
		"endpoints": endpoints,
	}
	if s.opts.DisplayName != "" {
		nwm["display_name"] = s.opts.DisplayName
	}
	if schemaAnchors != nil {
		nwm["schema_anchors"] = schemaAnchors
	}
	if len(s.opts.Graph) > 0 {
		refs := make([]map[string]any, 0, len(s.opts.Graph))
		for _, g := range s.opts.Graph {
			refs = append(refs, map[string]any{"rel": g.Rel, "node_url": g.NodeURL})
		}
		nwm["graph"] = map[string]any{"refs": refs, "max_depth": s.opts.graphMaxDepth()}
	}
	s.nwmJSON, _ = json.Marshal(nwm)
	s.actionsJSON, _ = json.Marshal(map[string]any{"actions": s.opts.Actions})
}
