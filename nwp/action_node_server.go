// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
//
// Framework-agnostic Action Node HTTP handler (NPS-2 §2.1, §3.2, §7).
// Faithful port of the .NET ActionNodeMiddleware. Implements http.Handler;
// mount at any path via a mux. Sub-paths: /.nwm, /.schema, /actions, /invoke.
// The reserved actions system.task.status and system.task.cancel are handled
// by the server itself and MUST NOT be registered in ActionNodeOptions.Actions.

package nwp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
)

// Reserved action ids handled by the Action Node server itself (NPS-2 §7.3).
const (
	SystemTaskStatus = "system.task.status"
	SystemTaskCancel = "system.task.cancel"
)

// ── ActionSpec ────────────────────────────────────────────────────────────────

// ActionSpec is an NWM action registry entry (NPS-2 §4.6).
type ActionSpec struct {
	Description        string `json:"description,omitempty"`
	ParamsAnchor       string `json:"params_anchor,omitempty"`
	ResultAnchor       string `json:"result_anchor,omitempty"`
	Async              bool   `json:"async"`
	Idempotent         *bool  `json:"idempotent,omitempty"`
	TimeoutMsDefault   uint   `json:"timeout_ms_default,omitempty"`
	TimeoutMsMax       uint   `json:"timeout_ms_max,omitempty"`
	RequiredCapability string `json:"required_capability,omitempty"`
}

// ── Options ───────────────────────────────────────────────────────────────────

// ActionNodeOptions configures a single Action Node (NPS-2 §2.1, §7).
type ActionNodeOptions struct {
	NodeID      string
	DisplayName string
	// Actions is the action registry keyed by {domain}.{verb}. The reserved
	// system.task.status / system.task.cancel ids MUST NOT appear here.
	Actions    map[string]ActionSpec
	PathPrefix string
	// RequireAuth rejects requests without X-NWP-Agent with 401 when true.
	RequireAuth bool
	// DefaultTimeoutMs applies when neither ActionSpec.TimeoutMsDefault nor the
	// frame's timeout_ms are set. 0 → 5000.
	DefaultTimeoutMs uint
	// MaxTimeoutMs is the hard cap (NPS-2 §7.1). 0 → 300000.
	MaxTimeoutMs uint
	// IdempotencyTTL is the lifetime of idempotency cache entries. 0 → 24h.
	IdempotencyTTL time.Duration
	// TaskRetention is how long terminal tasks stay queryable. 0 → 1h.
	TaskRetention time.Duration
	// RejectPrivateCallbackURLs rejects callback_url resolving to loopback /
	// private ranges (SSRF guard). Defaults to true when unset (see helper).
	RejectPrivateCallbackURLs *bool
	// DefaultTokenBudget applies when X-NWP-Budget is absent. 0 = unlimited.
	DefaultTokenBudget uint
	// Profiles are protocol-specific capability profiles advertised in NWM.
	Profiles map[string]any
}

func (o ActionNodeOptions) rejectPrivateCallbacks() bool {
	return o.RejectPrivateCallbackURLs == nil || *o.RejectPrivateCallbackURLs
}

// ── Provider ──────────────────────────────────────────────────────────────────

// ActionExecutionResult is the result of a single action execution.
type ActionExecutionResult struct {
	// Result is the action output, serialised into CapsFrame.Data (single
	// element). Nil is allowed for side-effecting actions with no payload.
	Result json.RawMessage
	// AnchorRef optionally overrides ActionSpec.ResultAnchor.
	AnchorRef string
	// TokenEst is the approximate token count of the serialised result.
	TokenEst uint
}

// ActionContext is passed to a provider Execute call.
type ActionContext struct {
	AgentNid  string
	RequestID string
	TaskID    string // non-empty for async execution
	Spec      ActionSpec
	TimeoutMs uint
	Priority  string
}

// IActionNodeProvider is implemented by applications to expose actions.
type IActionNodeProvider interface {
	Execute(ctx context.Context, frame *ActionFrame, actx ActionContext) (*ActionExecutionResult, error)
}

// IActionNodeAuthorizer is an optional admission hook. It runs before
// idempotency lookup so cached replay cannot bypass current authorization.
type IActionNodeAuthorizer interface {
	Authorize(ctx context.Context, frame *ActionFrame, actx ActionContext) error
}

// ActionExecutionError lets providers return a canonical NWP error envelope.
type ActionExecutionError struct {
	HTTPStatus int
	NpsStatus  string
	ErrorCode  string
	Message    string
}

func (e *ActionExecutionError) Error() string { return e.Message }

// ── Task store ────────────────────────────────────────────────────────────────

// ActionTaskRecord records the state of one asynchronous action task.
// State machine (NPS-2 §7.2): pending → running → completed / failed / cancelled.
type ActionTaskRecord struct {
	TaskID    string
	ActionID  string
	Status    string // pending | running | completed | failed | cancelled
	Progress  *float64
	CreatedAt time.Time
	UpdatedAt time.Time
	RequestID string
	AgentNid  string
	Result    json.RawMessage
	Error     json.RawMessage
}

// IActionTaskStore stores asynchronous action task state.
type IActionTaskStore interface {
	Create(taskID, actionID, requestID, agentNid string) *ActionTaskRecord
	Get(taskID string) *ActionTaskRecord
	TryTransition(taskID, expectedStatus, newStatus string) bool
	Complete(taskID string, result json.RawMessage) bool
	Fail(taskID string, errPayload json.RawMessage) bool
	Cancel(taskID string) bool
	UpdateProgress(taskID string, progress float64) bool
	PurgeExpired(retention time.Duration, now time.Time) int
}

// InMemoryActionTaskStore is a mutex-guarded in-process task store.
type InMemoryActionTaskStore struct {
	mu    sync.Mutex
	tasks map[string]*ActionTaskRecord
	Clock func() time.Time
}

// NewInMemoryActionTaskStore returns a ready-to-use in-memory task store.
func NewInMemoryActionTaskStore() *InMemoryActionTaskStore {
	return &InMemoryActionTaskStore{tasks: map[string]*ActionTaskRecord{}}
}

func (s *InMemoryActionTaskStore) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now().UTC()
}

func (s *InMemoryActionTaskStore) Create(taskID, actionID, requestID, agentNid string) *ActionTaskRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tasks == nil {
		s.tasks = map[string]*ActionTaskRecord{}
	}
	now := s.now()
	rec := &ActionTaskRecord{
		TaskID: taskID, ActionID: actionID, Status: "pending",
		CreatedAt: now, UpdatedAt: now, RequestID: requestID, AgentNid: agentNid,
	}
	s.tasks[taskID] = rec
	return rec
}

func (s *InMemoryActionTaskStore) Get(taskID string) *ActionTaskRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.tasks[taskID]
	if rec == nil {
		return nil
	}
	cp := *rec
	return &cp
}

func isTerminal(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled"
}

func (s *InMemoryActionTaskStore) TryTransition(taskID, expectedStatus, newStatus string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.tasks[taskID]
	if rec == nil || rec.Status != expectedStatus {
		return false
	}
	rec.Status = newStatus
	rec.UpdatedAt = s.now()
	return true
}

func (s *InMemoryActionTaskStore) Complete(taskID string, result json.RawMessage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.tasks[taskID]
	if rec == nil || isTerminal(rec.Status) {
		return false
	}
	rec.Status = "completed"
	rec.Result = result
	p := 1.0
	rec.Progress = &p
	rec.UpdatedAt = s.now()
	return true
}

func (s *InMemoryActionTaskStore) Fail(taskID string, errPayload json.RawMessage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.tasks[taskID]
	if rec == nil || isTerminal(rec.Status) {
		return false
	}
	rec.Status = "failed"
	rec.Error = errPayload
	rec.UpdatedAt = s.now()
	return true
}

func (s *InMemoryActionTaskStore) Cancel(taskID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.tasks[taskID]
	if rec == nil || isTerminal(rec.Status) {
		return false
	}
	rec.Status = "cancelled"
	rec.UpdatedAt = s.now()
	return true
}

func (s *InMemoryActionTaskStore) UpdateProgress(taskID string, progress float64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.tasks[taskID]
	if rec == nil {
		return false
	}
	if progress < 0 {
		progress = 0
	} else if progress > 1 {
		progress = 1
	}
	rec.Progress = &progress
	rec.UpdatedAt = s.now()
	return true
}

func (s *InMemoryActionTaskStore) PurgeExpired(retention time.Duration, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-retention)
	purged := 0
	for k, rec := range s.tasks {
		if isTerminal(rec.Status) && rec.UpdatedAt.Before(cutoff) {
			delete(s.tasks, k)
			purged++
		}
	}
	return purged
}

// ── Idempotency cache ─────────────────────────────────────────────────────────

// IdempotentEntry is a cached idempotent response (NPS-2 §7.1).
type IdempotentEntry struct {
	ActionID   string
	ParamsHash string
	Result     json.RawMessage
	AnchorRef  string
	TaskID     string
	ExpiresAt  time.Time
}

// IIdempotencyCache caches idempotent action results keyed by
// (action_id, idempotency_key).
type IIdempotencyCache interface {
	Get(actionID, idempotencyKey string) *IdempotentEntry
	// TryStore stores a new entry. If an unexpired entry exists with a
	// different ParamsHash it returns false so the caller can raise conflict.
	TryStore(actionID, idempotencyKey string, entry IdempotentEntry) bool
	PurgeExpired(now time.Time) int
}

// InMemoryIdempotencyCache is a mutex-guarded in-process idempotency cache.
type InMemoryIdempotencyCache struct {
	mu      sync.Mutex
	entries map[string]IdempotentEntry
	Clock   func() time.Time
}

// NewInMemoryIdempotencyCache returns a ready-to-use in-memory idempotency cache.
func NewInMemoryIdempotencyCache() *InMemoryIdempotencyCache {
	return &InMemoryIdempotencyCache{entries: map[string]IdempotentEntry{}}
}

func (c *InMemoryIdempotencyCache) now() time.Time {
	if c.Clock != nil {
		return c.Clock()
	}
	return time.Now().UTC()
}

func idemKey(actionID, idempotencyKey string) string {
	return actionID + "\x1f" + idempotencyKey
}

func (c *InMemoryIdempotencyCache) Get(actionID, idempotencyKey string) *IdempotentEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := idemKey(actionID, idempotencyKey)
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !entry.ExpiresAt.After(c.now()) {
		delete(c.entries, key)
		return nil
	}
	cp := entry
	return &cp
}

func (c *InMemoryIdempotencyCache) TryStore(actionID, idempotencyKey string, entry IdempotentEntry) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]IdempotentEntry{}
	}
	key := idemKey(actionID, idempotencyKey)
	now := c.now()
	if existing, ok := c.entries[key]; ok {
		if existing.ExpiresAt.After(now) {
			return existing.ParamsHash == entry.ParamsHash
		}
	}
	c.entries[key] = entry
	return true
}

func (c *InMemoryIdempotencyCache) PurgeExpired(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	purged := 0
	for k, e := range c.entries {
		if !e.ExpiresAt.After(now) {
			delete(c.entries, k)
			purged++
		}
	}
	return purged
}

// ── Callback URL SSRF validator ─────────────────────────────────────────────

// ValidateCallbackURL validates ActionFrame.callback_url per NPS-2 §7.1.
// Returns "" when valid, otherwise a human-readable error string.
func ValidateCallbackURL(callbackURL string, rejectPrivate bool) string {
	if strings.TrimSpace(callbackURL) == "" {
		return "callback_url must not be empty."
	}
	u, err := parseAbsURL(callbackURL)
	if err != nil {
		return "callback_url '" + callbackURL + "' is not a valid absolute URI."
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "callback_url MUST use the https:// scheme (got '" + u.Scheme + "://')."
	}
	if rejectPrivate && isPrivateHost(u.Hostname()) {
		return "callback_url host '" + u.Hostname() + "' resolves to a private or loopback address (SSRF guard)."
	}
	return ""
}

// parseAbsURL parses an absolute URL with a scheme and host.
func parseAbsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, errNotAbsolute
	}
	return u, nil
}

var errNotAbsolute = &complexError{"not an absolute URL"}

// isPrivateHost detects hostname/IP literals in loopback / link-local / RFC1918
// ranges. DNS resolution is intentionally avoided.
func isPrivateHost(host string) bool {
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	stripped := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip := net.ParseIP(stripped)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		b := v4
		return b[0] == 127 ||
			b[0] == 10 ||
			b[0] == 0 ||
			(b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
			(b[0] == 192 && b[1] == 168) ||
			(b[0] == 169 && b[1] == 254)
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		isIPv6SiteLocal(ip)
}

func isIPv6SiteLocal(ip net.IP) bool {
	// fec0::/10 (deprecated site-local) and fc00::/7 (unique local).
	if len(ip) == net.IPv6len {
		return (ip[0]&0xfe) == 0xfc || (ip[0] == 0xfe && (ip[1]&0xc0) == 0xc0)
	}
	return false
}

// ── Server ────────────────────────────────────────────────────────────────────

// ActionNodeServer is an http.Handler hosting a single Action Node.
type ActionNodeServer struct {
	provider    IActionNodeProvider
	opts        ActionNodeOptions
	taskStore   IActionTaskStore
	idempotency IIdempotencyCache
	prefix      string
	nwmJSON     []byte
	actionsJSON []byte
	cancelMu    sync.Mutex
	taskCancels map[string]context.CancelFunc
	// Clock is a test override; defaults to time.Now().UTC.
	Clock func() time.Time
}

// NewActionNodeServer builds an Action Node server. taskStore and idempotency
// may be nil, in which case in-memory defaults are used.
func NewActionNodeServer(provider IActionNodeProvider, opts ActionNodeOptions, taskStore IActionTaskStore, idempotency IIdempotencyCache) *ActionNodeServer {
	if _, ok := opts.Actions[SystemTaskStatus]; ok {
		panic("reserved action id '" + SystemTaskStatus + "' MUST NOT be registered in ActionNodeOptions.Actions")
	}
	if _, ok := opts.Actions[SystemTaskCancel]; ok {
		panic("reserved action id '" + SystemTaskCancel + "' MUST NOT be registered in ActionNodeOptions.Actions")
	}
	if taskStore == nil {
		taskStore = NewInMemoryActionTaskStore()
	}
	if idempotency == nil {
		idempotency = NewInMemoryIdempotencyCache()
	}
	s := &ActionNodeServer{
		provider:    provider,
		opts:        opts,
		taskStore:   taskStore,
		idempotency: idempotency,
		prefix:      strings.TrimRight(opts.PathPrefix, "/"),
		taskCancels: map[string]context.CancelFunc{},
	}
	s.nwmJSON, s.actionsJSON = s.buildStaticPayloads()
	return s
}

func (s *ActionNodeServer) clock() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now().UTC()
}

func (s *ActionNodeServer) idempotencyTTL() time.Duration {
	if s.opts.IdempotencyTTL > 0 {
		return s.opts.IdempotencyTTL
	}
	return 24 * time.Hour
}

// ServeHTTP implements http.Handler.
func (s *ActionNodeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, s.prefix) {
		http.NotFound(w, r)
		return
	}
	sub := path[len(s.prefix):]

	if s.opts.RequireAuth && r.Header.Get(HeaderAgent) == "" {
		s.writeError(w, 401, "NPS-CLIENT-UNAUTHORIZED", ErrAuthNidScopeViolation,
			"X-NWP-Agent header is required.", nil)
		return
	}

	switch sub {
	case "/.nwm", "/.nwm/":
		w.Header().Set("Content-Type", MimeManifest)
		w.Header().Set(HeaderNodeType, "action")
		w.WriteHeader(200)
		_, _ = w.Write(s.nwmJSON)
	case "/.schema", "/.schema/", "/actions", "/actions/":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(s.actionsJSON)
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

func (s *ActionNodeServer) handleInvoke(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid, err.Error(), nil)
		return
	}
	var frame ActionFrameWire
	if err := json.Unmarshal(raw, &frame); err != nil || frame.ActionID == "" {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid,
			"invalid ActionFrame: missing action_id.", nil)
		return
	}

	// Reserved actions are handled by the server itself.
	if frame.ActionID == SystemTaskStatus {
		s.handleSystemTaskStatus(w, &frame, r.Header.Get(HeaderAgent))
		return
	}
	if frame.ActionID == SystemTaskCancel {
		s.handleSystemTaskCancel(w, &frame, r.Header.Get(HeaderAgent))
		return
	}

	spec, ok := s.opts.Actions[frame.ActionID]
	if !ok {
		s.writeError(w, 404, "NPS-CLIENT-NOT-FOUND", ErrActionNotFound,
			"Unknown action_id '"+frame.ActionID+"'.", nil)
		return
	}

	if frame.Priority != "" && frame.Priority != "low" && frame.Priority != "normal" && frame.Priority != "high" {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid,
			"priority '"+frame.Priority+"' is invalid (allowed: low/normal/high).", nil)
		return
	}

	if frame.Async && !spec.Async {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid,
			"action '"+frame.ActionID+"' does not support async execution.", nil)
		return
	}

	effectiveTimeout := s.clampTimeout(frame.TimeoutMs, spec)

	if frame.CallbackURL != "" {
		if errMsg := ValidateCallbackURL(frame.CallbackURL, s.opts.rejectPrivateCallbacks()); errMsg != "" {
			s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid, errMsg, nil)
			return
		}
	}

	agentNid := r.Header.Get(HeaderAgent)
	priority := frame.Priority
	if priority == "" {
		priority = "normal"
	}
	pf := frame.toActionFrame()
	admissionCtx := ActionContext{
		AgentNid: agentNid, RequestID: frame.RequestID, Spec: spec,
		TimeoutMs: effectiveTimeout, Priority: priority,
	}
	if authorizer, ok := s.provider.(IActionNodeAuthorizer); ok {
		if err := authorizer.Authorize(r.Context(), pf, admissionCtx); err != nil {
			s.writeExecutionError(w, err, "action authorization failed.")
			return
		}
	}

	cacheActionID := s.scopedCacheActionID(frame.ActionID, agentNid)
	paramsHash := hashParams(frame.Params)
	if frame.IdempotencyKey != "" {
		cached := s.idempotency.Get(cacheActionID, frame.IdempotencyKey)
		if cached != nil {
			if cached.ParamsHash != paramsHash {
				s.writeError(w, 409, "NPS-CLIENT-CONFLICT", ErrActionIdempotencyConflict,
					"idempotency_key reuse with different params.", nil)
				return
			}
			if cached.TaskID != "" {
				status := "pending"
				if rec := s.taskStore.Get(cached.TaskID); rec != nil {
					status = rec.Status
				}
				s.writeAsyncResponse(w, cached.TaskID, status, frame.RequestID, nil)
				return
			}
			s.writeCaps(w, cached.Result, cached.AnchorRef, frame.RequestID, 0)
			return
		}
	}

	if frame.Async {
		taskID := randomHex(16)
		s.taskStore.Create(taskID, frame.ActionID, frame.RequestID, agentNid)

		if frame.IdempotencyKey != "" {
			s.idempotency.TryStore(cacheActionID, frame.IdempotencyKey, IdempotentEntry{
				ActionID:   frame.ActionID,
				ParamsHash: paramsHash,
				TaskID:     taskID,
				ExpiresAt:  s.clock().Add(s.idempotencyTTL()),
			})
		}

		runCtx := ActionContext{
			AgentNid:  agentNid,
			RequestID: frame.RequestID,
			TaskID:    taskID,
			Spec:      spec,
			TimeoutMs: effectiveTimeout,
			Priority:  priority,
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(effectiveTimeout)*time.Millisecond)
		s.registerTaskCancel(taskID, cancel)
		go s.runAsyncTask(ctx, cancel, pf, runCtx)

		var est *uint
		if spec.TimeoutMsDefault > 0 {
			est = &spec.TimeoutMsDefault
		}
		s.writeAsyncResponse(w, taskID, "pending", frame.RequestID, est)
		return
	}

	// Synchronous path.
	syncCtx := ActionContext{
		AgentNid:  agentNid,
		RequestID: frame.RequestID,
		Spec:      spec,
		TimeoutMs: effectiveTimeout,
		Priority:  priority,
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(effectiveTimeout)*time.Millisecond)
	defer cancel()

	result, herr := s.executeWithContext(ctx, pf, syncCtx)
	if herr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			s.writeError(w, 504, "NPS-SERVER-TIMEOUT", ErrNodeUnavailable, "action execution timed out.", nil)
			return
		}
		s.writeExecutionError(w, herr, "action execution failed.")
		return
	}
	if result == nil {
		result = &ActionExecutionResult{}
	}

	anchorRef := result.AnchorRef
	if anchorRef == "" {
		anchorRef = spec.ResultAnchor
	}

	if frame.IdempotencyKey != "" {
		s.idempotency.TryStore(cacheActionID, frame.IdempotencyKey, IdempotentEntry{
			ActionID:   frame.ActionID,
			ParamsHash: paramsHash,
			Result:     result.Result,
			AnchorRef:  anchorRef,
			ExpiresAt:  s.clock().Add(s.idempotencyTTL()),
		})
	}

	s.writeCaps(w, result.Result, anchorRef, frame.RequestID, result.TokenEst)
}

func (s *ActionNodeServer) runAsyncTask(
	ctx context.Context,
	cancel context.CancelFunc,
	frame *ActionFrame,
	runCtx ActionContext,
) {
	defer cancel()
	defer s.unregisterTaskCancel(runCtx.TaskID)
	if !s.taskStore.TryTransition(runCtx.TaskID, "pending", "running") {
		return
	}

	res, err := s.executeWithContext(ctx, frame, runCtx)
	if err != nil {
		msg := err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			msg = "task timed out"
		}
		if rec := s.taskStore.Get(runCtx.TaskID); rec != nil && rec.Status == "cancelled" {
			return
		}
		code := ErrNodeUnavailable
		if execErr, ok := err.(*ActionExecutionError); ok {
			code = execErr.ErrorCode
		}
		errPayload, _ := json.Marshal(map[string]any{"code": code, "message": msg})
		s.taskStore.Fail(runCtx.TaskID, errPayload)
		return
	}
	if res == nil {
		res = &ActionExecutionResult{}
	}
	s.taskStore.Complete(runCtx.TaskID, res.Result)
}

type actionExecutionOutcome struct {
	result *ActionExecutionResult
	err    error
}

func (s *ActionNodeServer) executeWithContext(
	ctx context.Context,
	frame *ActionFrame,
	actionContext ActionContext,
) (*ActionExecutionResult, error) {
	outcome := make(chan actionExecutionOutcome, 1)
	go func() {
		result, err := s.provider.Execute(ctx, frame, actionContext)
		outcome <- actionExecutionOutcome{result: result, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case completed := <-outcome:
		return completed.result, completed.err
	}
}

// ── Reserved actions ────────────────────────────────────────────────────────

func (s *ActionNodeServer) handleSystemTaskStatus(w http.ResponseWriter, frame *ActionFrameWire, agentNid string) {
	taskID := readStringParam(frame.Params, "task_id")
	if taskID == "" {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid, "params.task_id is required.", nil)
		return
	}
	rec := s.taskStore.Get(taskID)
	if rec == nil {
		s.writeError(w, 404, "NPS-CLIENT-NOT-FOUND", ErrTaskNotFound, "Unknown task_id '"+taskID+"'.", nil)
		return
	}
	if rec.AgentNid != agentNid {
		s.writeError(w, 403, core.NpsAuthForbidden, ErrAuthNidScopeViolation,
			"The caller does not own this task.", nil)
		return
	}
	status := map[string]any{
		"task_id":    rec.TaskID,
		"status":     rec.Status,
		"created_at": rec.CreatedAt.Format(time.RFC3339Nano),
		"updated_at": rec.UpdatedAt.Format(time.RFC3339Nano),
	}
	if rec.Progress != nil {
		status["progress"] = *rec.Progress
	}
	if rec.RequestID != "" {
		status["request_id"] = rec.RequestID
	}
	if rec.Result != nil {
		status["result"] = json.RawMessage(rec.Result)
	}
	if rec.Error != nil {
		status["error"] = json.RawMessage(rec.Error)
	}
	payload, _ := json.Marshal(status)
	s.writeCaps(w, payload, "", frame.RequestID, 0)
}

func (s *ActionNodeServer) handleSystemTaskCancel(w http.ResponseWriter, frame *ActionFrameWire, agentNid string) {
	taskID := readStringParam(frame.Params, "task_id")
	if taskID == "" {
		s.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid, "params.task_id is required.", nil)
		return
	}
	rec := s.taskStore.Get(taskID)
	if rec == nil {
		s.writeError(w, 404, "NPS-CLIENT-NOT-FOUND", ErrTaskNotFound, "Unknown task_id '"+taskID+"'.", nil)
		return
	}
	if rec.AgentNid != agentNid {
		s.writeError(w, 403, core.NpsAuthForbidden, ErrAuthNidScopeViolation,
			"The caller does not own this task.", nil)
		return
	}
	if isTerminal(rec.Status) {
		s.writeError(w, 409, "NPS-CLIENT-CONFLICT", ErrTaskAlreadyCancelled,
			"Task '"+taskID+"' is already in a terminal state ('"+rec.Status+"').", nil)
		return
	}
	s.taskStore.Cancel(taskID)
	s.cancelTask(taskID)
	payload, _ := json.Marshal(map[string]any{"task_id": taskID, "status": "cancelled"})
	s.writeCaps(w, payload, "", frame.RequestID, 0)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func (s *ActionNodeServer) clampTimeout(requested uint, spec ActionSpec) uint {
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

func (s *ActionNodeServer) scopedCacheActionID(actionID, agentNid string) string {
	return s.opts.NodeID + "\x1f" + actionID + "\x1f" + agentNid
}

func (s *ActionNodeServer) registerTaskCancel(taskID string, cancel context.CancelFunc) {
	s.cancelMu.Lock()
	defer s.cancelMu.Unlock()
	s.taskCancels[taskID] = cancel
}

func (s *ActionNodeServer) unregisterTaskCancel(taskID string) {
	s.cancelMu.Lock()
	defer s.cancelMu.Unlock()
	delete(s.taskCancels, taskID)
}

func (s *ActionNodeServer) cancelTask(taskID string) {
	s.cancelMu.Lock()
	cancel := s.taskCancels[taskID]
	s.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func hashParams(p json.RawMessage) string {
	var data []byte
	if len(p) == 0 {
		data = []byte("null")
	} else {
		// Canonicalize by re-marshalling to remove insignificant whitespace.
		var v any
		if err := json.Unmarshal(p, &v); err == nil {
			if b, err := json.Marshal(v); err == nil {
				data = b
			}
		}
		if data == nil {
			data = p
		}
	}
	sum := sha256.Sum256(data)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func readStringParam(p json.RawMessage, name string) string {
	if len(p) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(p, &m); err != nil {
		return ""
	}
	if v, ok := m[name].(string); ok {
		return v
	}
	return ""
}

func (s *ActionNodeServer) writeAsyncResponse(w http.ResponseWriter, taskID, status, requestID string, estimatedMs *uint) {
	body := map[string]any{
		"task_id":  taskID,
		"status":   status,
		"poll_url": s.prefix + "/invoke",
	}
	if estimatedMs != nil {
		body["estimated_ms"] = *estimatedMs
	}
	if requestID != "" {
		body["request_id"] = requestID
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(HeaderNodeType, "action")
	w.WriteHeader(202)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *ActionNodeServer) writeCaps(w http.ResponseWriter, payload json.RawMessage, anchorRef, requestID string, tokenEst uint) {
	var data []json.RawMessage
	if len(payload) > 0 {
		data = []json.RawMessage{payload}
	} else {
		data = []json.RawMessage{}
	}
	caps := map[string]any{
		"anchor_ref": anchorRef,
		"count":      len(data),
		"data":       data,
		"token_est":  tokenEst,
	}
	w.Header().Set("Content-Type", MimeCapsule)
	w.Header().Set(HeaderNodeType, "action")
	if anchorRef != "" {
		w.Header().Set(HeaderSchema, anchorRef)
	}
	if tokenEst > 0 {
		w.Header().Set(HeaderTokens, strconv.FormatUint(uint64(tokenEst), 10))
	}
	if requestID != "" {
		w.Header().Set(HeaderRequestID, requestID)
	}
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(caps)
}

func (s *ActionNodeServer) writeError(w http.ResponseWriter, status int, npsStatus, errorCode, message string, details any) {
	env := map[string]any{"status": npsStatus, "error": errorCode, "message": message}
	if details != nil {
		env["details"] = details
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func (s *ActionNodeServer) writeExecutionError(w http.ResponseWriter, err error, fallback string) {
	if execErr, ok := err.(*ActionExecutionError); ok {
		s.writeError(w, execErr.HTTPStatus, execErr.NpsStatus, execErr.ErrorCode, execErr.Message, nil)
		return
	}
	s.writeError(w, 500, core.NpsServerInternal, ErrNodeUnavailable, fallback, nil)
}

func (s *ActionNodeServer) buildStaticPayloads() (nwmJSON, actionsJSON []byte) {
	base := s.prefix
	auth := map[string]any{"required": s.opts.RequireAuth, "identity_type": "none"}
	if s.opts.RequireAuth {
		auth["identity_type"] = "nip-cert"
	}
	nwm := map[string]any{
		"nwp":              "0.4",
		"node_id":          s.opts.NodeID,
		"node_type":        "action",
		"wire_formats":     []string{"ncp-capsule", "json"},
		"preferred_format": "json",
		"capabilities":     map[string]any{"query": false, "stream": false, "token_budget_hint": true},
		"auth":             auth,
		"endpoints":        map[string]any{"invoke": base + "/invoke", "schema": base + "/.schema"},
	}
	if s.opts.DisplayName != "" {
		nwm["display_name"] = s.opts.DisplayName
	}
	if s.opts.Profiles != nil {
		nwm["profiles"] = s.opts.Profiles
	}
	nwmJSON, _ = json.Marshal(nwm)
	actionsJSON, _ = json.Marshal(map[string]any{"actions": s.opts.Actions})
	return
}

// ── ActionFrame wire type ─────────────────────────────────────────────────────

// ActionFrameWire is the on-the-wire /invoke request body, matching the .NET
// ActionFrame field set (NPS-2 §6).
type ActionFrameWire struct {
	ActionID       string          `json:"action_id"`
	Params         json.RawMessage `json:"params,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	TimeoutMs      uint            `json:"timeout_ms,omitempty"`
	Async          bool            `json:"async,omitempty"`
	CallbackURL    string          `json:"callback_url,omitempty"`
	Priority       string          `json:"priority,omitempty"`
	RequestID      string          `json:"request_id,omitempty"`
}

func (f *ActionFrameWire) toActionFrame() *ActionFrame {
	af := &ActionFrame{Action: f.ActionID, Async: f.Async}
	if len(f.Params) > 0 {
		var v any
		if err := json.Unmarshal(f.Params, &v); err == nil {
			af.Params = v
		}
	}
	if f.IdempotencyKey != "" {
		af.IdempotencyKey = stringPtr(f.IdempotencyKey)
	}
	if f.TimeoutMs != 0 {
		value := uint32(f.TimeoutMs)
		af.TimeoutMs = &value
	}
	if f.RequestID != "" {
		af.RequestID = stringPtr(f.RequestID)
	}
	return af
}
