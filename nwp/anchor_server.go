// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
	"github.com/labacacia/NPS-sdk-go/nip"
)

// Anchor Node server (net/http, stdlib only). Server-side counterpart of
// AnchorNodeClient, porting the .NET AnchorNodeMiddleware wire contract
// (NPS-AaaS §2, NPS-2 §12) and mirroring the Python/TS reference ports.
//
// The business execution behind /invoke is delegated to an injected
// InvokeHandler (NOP orchestration is host-supplied), mirroring how the .NET
// middleware requires an IAnchorRouter + INopOrchestrator.

const snapshotAnchorRef = "nps:system:topology:snapshot"

// ── Errors ─────────────────────────────────────────────────────────────────────

// TopologyProtocolError is raised while handling a topology request.
type TopologyProtocolError struct {
	NwpErrorCode string
	NpsStatus    string
	Message      string
}

func (e *TopologyProtocolError) Error() string { return e.Message }

// AnchorActionError is returned by an InvokeHandler to produce an NWP error envelope.
type AnchorActionError struct {
	HTTPStatus int
	NpsStatus  string
	ErrorCode  string
	Message    string
	Details    any
}

func (e *AnchorActionError) Error() string { return e.Message }

// ── Topology request types + service ───────────────────────────────────────────

type AnchorSnapshotRequest struct {
	Scope     string
	Include   map[string]bool
	Depth     int
	TargetNid string
}

type AnchorStreamRequest struct {
	Scope        string
	Filter       *TopologyFilter
	SinceVersion *uint64
}

// AnchorTopologyService supplies cluster topology for reserved query types.
type AnchorTopologyService interface {
	AnchorNid() string
	GetSnapshot(ctx context.Context, req AnchorSnapshotRequest) (*TopologySnapshot, error)
	Subscribe(ctx context.Context, req AnchorStreamRequest) (<-chan TopologyEvent, error)
}

// InMemoryAnchorTopologyService is the reference in-memory topology service.
type InMemoryAnchorTopologyService struct {
	Nid     string
	Members []MemberInfo
	Version uint64
	Events  []TopologyEvent
}

func (s *InMemoryAnchorTopologyService) AnchorNid() string { return s.Nid }

func (s *InMemoryAnchorTopologyService) GetSnapshot(_ context.Context, req AnchorSnapshotRequest) (*TopologySnapshot, error) {
	members := s.Members
	if !req.Include["members"] {
		members = nil
	}
	return &TopologySnapshot{
		Version:     s.Version,
		AnchorNid:   s.Nid,
		ClusterSize: uint32(len(s.Members)),
		Members:     members,
	}, nil
}

func (s *InMemoryAnchorTopologyService) Subscribe(_ context.Context, _ AnchorStreamRequest) (<-chan TopologyEvent, error) {
	ch := make(chan TopologyEvent, len(s.Events))
	for _, ev := range s.Events {
		ch <- ev
	}
	close(ch)
	return ch, nil
}

// ── Options / handler / rate limiter ───────────────────────────────────────────

type AnchorActionSpec struct {
	Description        string
	ParamsAnchor       string
	ResultAnchor       string
	EstimatedCgn       int
	TimeoutMsDefault   int
	TimeoutMsMax       int
	RequiredCapability string
	Async              bool
	// TopologyWrite marks an action as a topology-mutating write, so the CR-0009
	// leader check applies to it: a standby, or a quorum-lost owner, refuses it
	// with NWP-ANCHOR-NOT-LEADER. Reads are unaffected.
	TopologyWrite bool
}

type AnchorNodeOptions struct {
	NodeID                    string
	PathPrefix                string
	Actions                   map[string]AnchorActionSpec
	DisplayName               string
	RequireAuth               *bool // nil = true
	RequiredCapabilities      []string
	RequireTopologyCapability bool
	DefaultTimeoutMs          int // 0 = 30000
	MaxTimeoutMs              int // 0 = 300000
	DefaultTokenBudget        int
	CgnLimit                  int
	AssuranceHintURL          string
	ReputationPolicy          *ReputationPolicy
	TrustAnchors              []string
	RateLimits                map[string]any
	AutoInjectTraceContext    *bool // nil = true
}

type InvokeContext struct {
	AgentNid           string
	EffectiveTimeoutMs int
	BudgetCgn          int
	TraceID            string
	SpanID             string
}

// InvokeHandler executes an action and returns the result payload (or an error;
// return *AnchorActionError for a custom NWP error envelope).
type InvokeHandler func(ctx context.Context, actionID string, params json.RawMessage, ic InvokeContext) (any, error)

type RateDecision struct {
	Allowed           bool
	RetryAfterSeconds int
	Reason            string
}

type AnchorRateLimiter interface {
	TryAcquire(consumerKey string, costHint int) RateDecision
	Release(consumerKey string)
}

// AllowAllRateLimiter is the default no-op limiter.
type AllowAllRateLimiter struct{}

func (AllowAllRateLimiter) TryAcquire(string, int) RateDecision { return RateDecision{Allowed: true} }
func (AllowAllRateLimiter) Release(string)                      {}

// ── The app ──────────────────────────────────────────────────────────────────

type AnchorNodeAppDeps struct {
	InvokeHandler       InvokeHandler
	TopologyService     AnchorTopologyService
	ReputationEvaluator IReputationEvaluator
	RateLimiter         AnchorRateLimiter
	// EpochGuard, when set, applies the NPS-CR-0009 epoch fence + leader check to
	// every request and stamps `cluster_epoch` on every topology response. A nil
	// guard leaves the single-Anchor behaviour exactly as it was pre-CR-0009.
	EpochGuard *AnchorEpochGuard
}

type AnchorNodeApp struct {
	opt         AnchorNodeOptions
	prefix      string
	handler     InvokeHandler
	topology    AnchorTopologyService
	evaluator   IReputationEvaluator
	limiter     AnchorRateLimiter
	epoch       *AnchorEpochGuard
	nwmJSON     []byte
	actionsJSON []byte
}

// NewAnchorNodeApp builds an http.Handler Anchor Node server.
func NewAnchorNodeApp(opt AnchorNodeOptions, deps AnchorNodeAppDeps) *AnchorNodeApp {
	a := &AnchorNodeApp{
		opt:       opt,
		prefix:    strings.TrimRight(opt.PathPrefix, "/"),
		handler:   deps.InvokeHandler,
		topology:  deps.TopologyService,
		evaluator: deps.ReputationEvaluator,
		limiter:   deps.RateLimiter,
		epoch:     deps.EpochGuard,
	}
	if a.limiter == nil {
		a.limiter = AllowAllRateLimiter{}
	}
	a.nwmJSON, _ = json.Marshal(a.buildManifest())
	a.actionsJSON, _ = json.Marshal(map[string]any{"actions": a.actionsMap()})
	return a
}

func (a *AnchorNodeApp) requireAuth() bool {
	return a.opt.RequireAuth == nil || *a.opt.RequireAuth
}

// inboundClusterEpoch reads the `cluster_epoch` fencing token off an inbound
// request body. Absence reads as 1 and is never an error, so a pre-CR-0009 peer
// is unaffected.
func inboundClusterEpoch(body map[string]any) (*uint64, string) {
	if body == nil {
		return nil, ""
	}
	sender, _ := body["anchor_nid"].(string)
	if sender == "" {
		sender, _ = body["sender_anchor_nid"].(string)
	}
	raw, ok := body["cluster_epoch"]
	if !ok || raw == nil {
		return nil, sender
	}
	var v uint64
	switch x := raw.(type) {
	case float64:
		v = uint64(x)
	case uint64:
		v = x
	case int64:
		v = uint64(x)
	case int:
		v = uint64(x)
	default:
		return nil, sender
	}
	return &v, sender
}

// guardInbound applies the CR-0009 epoch fence and leader check; it returns
// false when it has already written an error response.
func (a *AnchorNodeApp) guardInbound(w http.ResponseWriter, body map[string]any, isTopologyWrite bool) bool {
	if a.epoch == nil {
		return true
	}
	inbound, sender := inboundClusterEpoch(body)
	if perr := a.epoch.OnInboundFrame(inbound, sender, isTopologyWrite); perr != nil {
		a.writeTopologyError(w, perr)
		return false
	}
	return true
}

func isKnownRoute(sub string) bool {
	switch sub {
	case "/.nwm", "/.nwm/", "/.schema", "/.schema/", "/actions", "/actions/",
		"/invoke", "/invoke/", "/query", "/query/", "/subscribe", "/subscribe/":
		return true
	default:
		return false
	}
}

func (a *AnchorNodeApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, a.prefix) {
		a.writeError(w, 404, "NPS-CLIENT-NOT-FOUND", ErrActionNotFound, "no NWP node at this path.", nil, nil)
		return
	}
	sub := path[len(a.prefix):]

	// Resolve the route BEFORE the auth gate: an unknown sub-path is a 404 regardless of auth, so
	// a missing X-NWP-Agent on a non-existent route does not leak a 401 (auth state) for a path
	// that has no resource. Known routes fall through to the auth check below.
	if !isKnownRoute(sub) {
		a.writeError(w, 404, "NPS-CLIENT-NOT-FOUND", ErrActionNotFound, "unknown anchor sub-path.", nil, nil)
		return
	}

	if a.requireAuth() && r.Header.Get(HeaderAgent) == "" {
		a.writeError(w, 401, "NPS-AUTH-UNAUTHENTICATED", ErrAuthNidScopeViolation,
			"X-NWP-Agent header is required.", nil, nil)
		return
	}

	switch sub {
	case "/.nwm", "/.nwm/":
		w.Header().Set("Content-Type", MimeManifest)
		w.Header().Set(HeaderNodeType, "anchor")
		w.WriteHeader(200)
		_, _ = w.Write(a.nwmJSON)
	case "/.schema", "/.schema/", "/actions", "/actions/":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(a.actionsJSON)
	case "/invoke", "/invoke/":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		a.handleInvoke(w, r)
	case "/query", "/query/":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		a.handleQuery(w, r)
	case "/subscribe", "/subscribe/":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		a.handleSubscribe(w, r)
	default:
		a.writeError(w, 404, "NPS-CLIENT-NOT-FOUND", ErrActionNotFound, "unknown anchor sub-path.", nil, nil)
	}
}

// ── /query ───────────────────────────────────────────────────────────────────

func (a *AnchorNodeApp) handleQuery(w http.ResponseWriter, r *http.Request) {
	if !a.checkTopologyCapability(w, r) {
		return
	}
	body, err := readJSON(r)
	if err != nil {
		a.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrQueryFilterInvalid, err.Error(), nil, nil)
		return
	}
	// CR-0009 §3.2(a): the epoch fence applies to ANY inbound frame, read or write.
	// A snapshot is a read, so only the fence (not the leader check) can reject it.
	if !a.guardInbound(w, body, false) {
		return
	}
	if body["type"] != typeSnapshotWire {
		t, _ := body["type"].(string)
		msg := "Anchor /query requires a reserved type per NPS-2 §12."
		if t != "" {
			msg = "Reserved query type '" + t + "' is not implemented by this Anchor Node."
		}
		a.writeError(w, 501, "NPS-SERVER-UNSUPPORTED", ErrReservedTypeUnsupported, msg, nil, nil)
		return
	}
	if a.topology == nil {
		a.writeError(w, 501, "NPS-SERVER-UNSUPPORTED", ErrNodeUnavailable,
			"topology.snapshot is not available — no topology service registered.", nil, nil)
		return
	}
	req, perr := parseSnapshotRequest(body)
	if perr != nil {
		a.writeTopologyError(w, perr)
		return
	}
	snap, serr := a.topology.GetSnapshot(r.Context(), req)
	if serr != nil {
		if tpe, ok := serr.(*TopologyProtocolError); ok {
			a.writeTopologyError(w, tpe)
			return
		}
		a.writeError(w, 500, "NPS-SERVER-INTERNAL", ErrNodeUnavailable, "topology snapshot failed.", nil, nil)
		return
	}
	// NWP §12.2: every topology.snapshot response MUST carry the current cluster_epoch.
	a.epoch.StampSnapshot(snap)
	caps := map[string]any{"anchor_ref": snapshotAnchorRef, "count": 1, "data": []any{snap}}
	w.Header().Set("Content-Type", MimeCapsule)
	w.Header().Set(HeaderNodeType, "anchor")
	w.Header().Set(HeaderSchema, snapshotAnchorRef)
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(caps)
}

// ── /subscribe ───────────────────────────────────────────────────────────────

func (a *AnchorNodeApp) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	if !a.checkTopologyCapability(w, r) {
		return
	}
	body, err := readJSON(r)
	if err != nil {
		a.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrQueryFilterInvalid, err.Error(), nil, nil)
		return
	}
	// CR-0009 §3.2(a): fence first; a standby may still serve (stale) stream reads.
	if !a.guardInbound(w, body, false) {
		return
	}
	if body["type"] != typeStreamWire {
		t, _ := body["type"].(string)
		msg := "Anchor /subscribe requires a reserved type per NPS-2 §12."
		if t != "" {
			msg = "Reserved subscribe type '" + t + "' is not implemented by this Anchor Node."
		}
		a.writeError(w, 501, "NPS-SERVER-UNSUPPORTED", ErrReservedTypeUnsupported, msg, nil, nil)
		return
	}
	if a.topology == nil {
		a.writeError(w, 501, "NPS-SERVER-UNSUPPORTED", ErrNodeUnavailable,
			"topology.stream is not available — no topology service registered.", nil, nil)
		return
	}
	req, streamID, perr := parseStreamRequest(body)
	if perr != nil {
		a.writeTopologyError(w, perr)
		return
	}
	ch, serr := a.topology.Subscribe(r.Context(), req)
	if serr != nil {
		a.writeError(w, 500, "NPS-SERVER-INTERNAL", ErrNodeUnavailable, "topology stream failed.", nil, nil)
		return
	}

	w.Header().Set("Content-Type", MimeCapsule)
	w.Header().Set(HeaderNodeType, "anchor")
	w.WriteHeader(200)
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	writeLine := func(v any) {
		_ = enc.Encode(v) // Encode appends a newline
		if flusher != nil {
			flusher.Flush()
		}
	}
	ack := map[string]any{
		"kind": "ack", "stream_id": streamID, "status": "subscribed",
		"last_seq": 0, "resumed": req.SinceVersion != nil,
	}
	// NWP §12.2: every topology.stream response MUST carry the current cluster_epoch.
	if a.epoch != nil {
		ack["cluster_epoch"] = a.epoch.OwnEpoch()
	}
	writeLine(ack)
	for ev := range ch {
		writeLine(eventToEnvelope(streamID, ev))
		if ev.Kind == eventResyncWire {
			break
		}
	}
}

// ── /invoke ──────────────────────────────────────────────────────────────────

type invokeBody struct {
	ActionID  string          `json:"action_id"`
	Params    json.RawMessage `json:"params"`
	Async     bool            `json:"async"`
	TimeoutMs int             `json:"timeout_ms"`
}

func (a *AnchorNodeApp) handleInvoke(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		a.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid, err.Error(), nil, nil)
		return
	}
	var frame invokeBody
	if err := json.Unmarshal(raw, &frame); err != nil || frame.ActionID == "" {
		a.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid,
			"invalid ActionFrame: missing action_id.", nil, nil)
		return
	}

	spec, ok := a.opt.Actions[frame.ActionID]
	if !ok {
		a.writeError(w, 404, "NPS-CLIENT-NOT-FOUND", ErrActionNotFound,
			"Unknown action_id '"+frame.ActionID+"'.", nil, nil)
		return
	}
	if frame.Async && !spec.Async {
		a.writeError(w, 400, "NPS-CLIENT-BAD-REQUEST", ErrActionParamsInvalid,
			"action '"+frame.ActionID+"' does not support async execution.", nil, nil)
		return
	}

	// CR-0009 §3.2: the epoch fence applies to every inbound frame; the leader
	// check applies only to actions declared as topology-mutating writes.
	if a.epoch != nil {
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if !a.guardInbound(w, body, spec.TopologyWrite) {
			return
		}
	}

	agentNid := r.Header.Get(HeaderAgent)
	consumerKey := agentNid
	if consumerKey == "" {
		consumerKey = "anonymous"
	}
	effectiveTimeout := a.clampTimeout(frame.TimeoutMs, spec)
	budgetCgn := a.readEffectiveBudget(r)
	cgnCostHint := spec.EstimatedCgn

	rate := a.limiter.TryAcquire(consumerKey, cgnCostHint)
	if !rate.Allowed {
		var extra map[string]string
		if rate.RetryAfterSeconds > 0 {
			extra = map[string]string{"Retry-After": strconv.Itoa(rate.RetryAfterSeconds)}
		}
		reason := rate.Reason
		if reason == "" {
			reason = "rate limit exceeded."
		}
		a.writeError(w, 429, "NPS-LIMIT-RATE", ErrBudgetExceeded, reason, nil, extra)
		return
	}
	defer a.limiter.Release(consumerKey)

	assurance := extractIdentAssurance(r)
	if a.opt.ReputationPolicy != nil && a.evaluator != nil &&
		a.opt.ReputationPolicy.Enabled {
		decision, derr := a.evaluator.Evaluate(r.Context(), consumerKey, assurance.Wire, *a.opt.ReputationPolicy)
		if derr != nil {
			a.writeError(w, 500, "NPS-SERVER-INTERNAL", ErrNodeUnavailable, "reputation evaluation failed.", nil, nil)
			return
		}
		if a.applyReputation(w, decision, *a.opt.ReputationPolicy, assurance) {
			return
		}
	}

	if budgetCgn > 0 && cgnCostHint > 0 && cgnCostHint > budgetCgn {
		a.writeError(w, 400, "NPS-CLIENT-REQUEST-TOO-LARGE", ErrCgnLimitExceeded,
			"estimated CGN exceeds effective budget.",
			map[string]any{"effective_budget": budgetCgn, "estimated_cgn": cgnCostHint}, nil)
		return
	}

	if a.handler == nil {
		a.writeError(w, 501, "NPS-SERVER-UNSUPPORTED", ErrNodeUnavailable,
			"no invoke handler registered on this Anchor Node.", nil, nil)
		return
	}

	auto := a.opt.AutoInjectTraceContext == nil || *a.opt.AutoInjectTraceContext
	ic := InvokeContext{AgentNid: agentNid, EffectiveTimeoutMs: effectiveTimeout, BudgetCgn: budgetCgn}
	if auto {
		ic.TraceID = randomHex(16)
		ic.SpanID = randomHex(8)
	}

	if frame.Async {
		taskID := randomHex(16)
		go func() { _, _ = a.handler(context.Background(), frame.ActionID, frame.Params, ic) }()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(HeaderNodeType, "anchor")
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"task_id": taskID, "status": "pending", "poll_url": a.prefix + "/invoke",
		})
		return
	}

	result, herr := a.handler(r.Context(), frame.ActionID, frame.Params, ic)
	if herr != nil {
		if aae, ok := herr.(*AnchorActionError); ok {
			a.writeError(w, aae.HTTPStatus, aae.NpsStatus, aae.ErrorCode, aae.Message, aae.Details, nil)
			return
		}
		a.writeError(w, 500, "NPS-SERVER-INTERNAL", ErrNodeUnavailable, "anchor task execution failed.", nil, nil)
		return
	}

	count := 1
	data := []any{result}
	if result == nil {
		count = 0
		data = []any{}
	}
	caps := map[string]any{"anchor_ref": spec.ResultAnchor, "count": count, "data": data}
	w.Header().Set("Content-Type", MimeCapsule)
	w.Header().Set(HeaderNodeType, "anchor")
	if spec.ResultAnchor != "" {
		w.Header().Set(HeaderSchema, spec.ResultAnchor)
	}
	if spec.EstimatedCgn > 0 {
		w.Header().Set(HeaderTokens, strconv.Itoa(spec.EstimatedCgn))
	}
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(caps)
}

func (a *AnchorNodeApp) applyReputation(w http.ResponseWriter, d ReputationDecision, policy ReputationPolicy, assurance nip.AssuranceLevel) bool {
	// The reference evaluator carries the matched rule rather than separate incident/severity.
	incident, severity := "", ""
	if d.MatchedRule != nil {
		incident, severity = d.MatchedRule.Incident, d.MatchedRule.Severity
	}
	switch d.Outcome {
	case RepAccept:
		return false
	case RepBan:
		var details any
		msg := "Request rejected: NID temporarily banned."
		if incident != "" {
			details = map[string]any{"matched_incident": incident, "matched_severity": severity}
			msg = "Request rejected: " + incident + " (" + severity + ") — NID temporarily banned."
		}
		a.writeError(w, 403, "NPS-AUTH-FORBIDDEN", ErrReputationBanned, msg, details, nil)
		return true
	case RepReject:
		if d.ErrorCode == ErrAuthAssuranceTooLow {
			minLevel := policy.MinAssuranceLevel
			if minLevel == "" {
				minLevel = "anonymous"
			}
			a.writeError(w, 403, "NPS-AUTH-FORBIDDEN", ErrAuthAssuranceTooLow,
				"Assurance level too low: requires '"+minLevel+"', caller declared '"+assurance.Wire+"'.",
				map[string]any{"matched_incident": nil, "hint": a.opt.AssuranceHintURL}, nil)
			return true
		}
		var details any
		msg := "Request rejected by reputation policy."
		if incident != "" {
			msg = "Request rejected: " + incident + " (" + severity + ")."
			details = map[string]any{"matched_incident": incident, "matched_severity": severity}
		}
		a.writeError(w, 403, "NPS-AUTH-FORBIDDEN", ErrReputationRejected, msg, details, nil)
		return true
	case RepThrottle:
		var details any
		msg := "Request rate-limited by reputation policy."
		if incident != "" {
			msg = "Request rate-limited: " + incident + " (" + severity + ")."
			details = map[string]any{"matched_incident": incident, "matched_severity": severity}
		}
		a.writeError(w, 429, "NPS-CLIENT-RATE-LIMITED", ErrReputationThrottled, msg, details,
			map[string]string{"Retry-After": "60"})
		return true
	}
	return false
}

// reputationPolicyToMap serializes the reference ReputationPolicy to the snake_case NWM wire form.
func reputationPolicyToMap(p ReputationPolicy) map[string]any {
	rule := func(r ReputationRule) map[string]any {
		d := map[string]any{"incident": r.Incident, "severity": r.Severity}
		if r.WithinDays != nil {
			d["within_days"] = *r.WithinDays
		}
		if r.Count != 0 {
			d["count"] = r.Count
		}
		return d
	}
	rules := func(rs []ReputationRule) []map[string]any {
		out := make([]map[string]any, 0, len(rs))
		for _, r := range rs {
			out = append(out, rule(r))
		}
		return out
	}
	return map[string]any{
		"enabled":             p.Enabled,
		"log_sources":         p.LogSources,
		"min_assurance_level": p.MinAssuranceLevel,
		"cache_ttl_seconds":   p.CacheTtlSeconds,
		"ban_ttl_seconds":     p.BanTtlSeconds,
		"on_log_unavailable":  p.OnLogUnavailable,
		"throttle_on":         rules(p.ThrottleOn),
		"reject_on":           rules(p.RejectOn),
		"ban_on":              rules(p.BanOn),
	}
}

// ── Gates / helpers ────────────────────────────────────────────────────────────

func (a *AnchorNodeApp) checkTopologyCapability(w http.ResponseWriter, r *http.Request) bool {
	if !a.opt.RequireTopologyCapability {
		return true
	}
	raw := r.Header.Get(HeaderCapabilities)
	for _, c := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(c), "topology:read") {
			return true
		}
	}
	a.writeError(w, 403, "NPS-AUTH-FORBIDDEN", ErrTopologyUnauthorized,
		"Caller must declare 'topology:read' in X-NWP-Capabilities to access topology endpoints.", nil, nil)
	return false
}

func (a *AnchorNodeApp) clampTimeout(requested int, spec AnchorActionSpec) int {
	maxOpt := a.opt.MaxTimeoutMs
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
	if requested <= 0 {
		if spec.TimeoutMsDefault > 0 {
			return spec.TimeoutMsDefault
		}
		if a.opt.DefaultTimeoutMs > 0 {
			return a.opt.DefaultTimeoutMs
		}
		return 30000
	}
	if requested > hardMax {
		return hardMax
	}
	return requested
}

func (a *AnchorNodeApp) readEffectiveBudget(r *http.Request) int {
	agentBudget := a.opt.DefaultTokenBudget
	if raw := r.Header.Get(HeaderBudget); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			agentBudget = v
		}
	}
	cgnLimit := a.opt.CgnLimit
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

func (a *AnchorNodeApp) writeError(w http.ResponseWriter, status int, npsStatus, errorCode, message string, details any, extra map[string]string) {
	env := map[string]any{"status": npsStatus, "error": errorCode, "message": message}
	if details != nil {
		env["details"] = details
	}
	for k, v := range extra {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func (a *AnchorNodeApp) writeTopologyError(w http.ResponseWriter, e *TopologyProtocolError) {
	// The NPS status is authoritative for the HTTP status: NPS-CLIENT-CONFLICT
	// (both CR-0009 anchor faults) must surface as 409, not 400.
	status := 400
	if e.NpsStatus != "" {
		status = core.ToHttpStatus(e.NpsStatus)
	}
	a.writeError(w, status, e.NpsStatus, e.NwpErrorCode, e.Message, nil, nil)
}

// ── Manifest ───────────────────────────────────────────────────────────────────

func (a *AnchorNodeApp) actionsMap() map[string]any {
	out := map[string]any{}
	for id, spec := range a.opt.Actions {
		entry := map[string]any{"action_id": id, "async": spec.Async}
		if spec.Description != "" {
			entry["description"] = spec.Description
		}
		if spec.ParamsAnchor != "" {
			entry["params_anchor"] = spec.ParamsAnchor
		}
		if spec.ResultAnchor != "" {
			entry["result_anchor"] = spec.ResultAnchor
		}
		if spec.EstimatedCgn != 0 {
			entry["cgn_est"] = spec.EstimatedCgn
		}
		if spec.TimeoutMsDefault != 0 {
			entry["timeout_ms_default"] = spec.TimeoutMsDefault
		}
		if spec.TimeoutMsMax != 0 {
			entry["timeout_ms_max"] = spec.TimeoutMsMax
		}
		if spec.RequiredCapability != "" {
			entry["required_capability"] = spec.RequiredCapability
		}
		out[id] = entry
	}
	return out
}

func (a *AnchorNodeApp) buildManifest() map[string]any {
	o := a.opt
	base := a.prefix
	m := map[string]any{"nwp": "0.4", "node_id": o.NodeID, "node_type": "anchor"}
	if o.DisplayName != "" {
		m["display_name"] = o.DisplayName
	}
	m["wire_formats"] = []string{"ncp-capsule", "json"}
	m["preferred_format"] = "json"
	m["capabilities"] = map[string]any{
		"query": false, "stream": false, "subscribe": false,
		"vector_search": false, "token_budget_hint": true, "ext_frame": false,
	}
	auth := map[string]any{
		"required":      a.requireAuth(),
		"identity_type": "none",
	}
	if a.requireAuth() {
		auth["identity_type"] = "nip-cert"
	}
	if o.RequiredCapabilities != nil {
		auth["required_capabilities"] = o.RequiredCapabilities
	}
	m["auth"] = auth
	m["endpoints"] = map[string]any{"invoke": base + "/invoke", "schema": base + "/.schema"}
	if o.CgnLimit > 0 {
		m["token_budget"] = map[string]any{"cgn_limit": o.CgnLimit, "profile": "cgn.v1"}
	}
	if o.RateLimits != nil {
		m["rate_limits"] = o.RateLimits
	}
	if o.ReputationPolicy != nil && o.ReputationPolicy.Enabled {
		m["reputation_policy"] = reputationPolicyToMap(*o.ReputationPolicy)
	}
	if len(o.TrustAnchors) > 0 {
		m["trust_anchors"] = o.TrustAnchors
	}
	// actions as an ordered array (sorted by id for determinism)
	ids := make([]string, 0, len(a.opt.Actions))
	for id := range a.opt.Actions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	am := a.actionsMap()
	arr := make([]any, 0, len(ids))
	for _, id := range ids {
		arr = append(arr, am[id])
	}
	m["actions"] = arr
	return m
}

// ── Topology wire helpers ──────────────────────────────────────────────────────

const (
	typeSnapshotWire = "topology.snapshot"
	typeStreamWire   = "topology.stream"
	scopeClusterWire = "cluster"
	scopeMemberWire  = "member"
	eventResyncWire  = "resync_required"
)

func eventToEnvelope(streamID string, ev TopologyEvent) map[string]any {
	var payload map[string]any
	includeSeq := true
	switch ev.Kind {
	case "member_joined":
		payload = memberToMap(ev.MemberJoined.Member)
	case "member_left":
		payload = map[string]any{"nid": ev.MemberLeft.Nid}
	case "member_updated":
		payload = map[string]any{"nid": ev.MemberUpdated.Nid, "changes": ev.MemberUpdated.Changes}
	case "anchor_state":
		payload = map[string]any{"field": ev.AnchorState.Field, "details": ev.AnchorState.Details}
	case "resync_required":
		payload = map[string]any{"reason": ev.ResyncRequired.Reason}
		includeSeq = false
	default:
		payload = map[string]any{}
	}
	raw, _ := json.Marshal(payload)
	cgnEst := len(raw) / 4
	if cgnEst < 1 {
		cgnEst = 1
	}
	env := map[string]any{
		"stream_id":  streamID,
		"event_type": ev.Kind,
		"timestamp":  time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		"payload":    payload,
		"cgn_est":    cgnEst,
	}
	if includeSeq {
		env["seq"] = ev.Version
	}
	return env
}

func memberToMap(m MemberInfo) map[string]any {
	out := map[string]any{
		"nid":             m.Nid,
		"node_roles":      m.NodeRoles,
		"activation_mode": m.ActivationMode,
	}
	if m.ChildAnchor != nil {
		out["child_anchor"] = *m.ChildAnchor
	}
	if m.MemberCount != nil {
		out["member_count"] = *m.MemberCount
	}
	if m.Tags != nil {
		out["tags"] = m.Tags
	}
	if m.JoinedAt != nil {
		out["joined_at"] = *m.JoinedAt
	}
	if m.LastSeen != nil {
		out["last_seen"] = *m.LastSeen
	}
	if m.Capabilities != nil {
		out["capabilities"] = m.Capabilities
	}
	if m.Metrics != nil {
		out["metrics"] = m.Metrics
	}
	return out
}

func readJSON(r *http.Request) (map[string]any, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func parseSnapshotRequest(body map[string]any) (AnchorSnapshotRequest, *TopologyProtocolError) {
	topo, ok := body["topology"].(map[string]any)
	if !ok {
		return AnchorSnapshotRequest{}, &TopologyProtocolError{ErrTopologyUnsupportedScope, "NPS-CLIENT-BAD-PARAM",
			"topology.snapshot requires a 'topology' object per NPS-2 §12.1."}
	}
	scope, perr := parseScope(topo)
	if perr != nil {
		return AnchorSnapshotRequest{}, perr
	}
	include := parseInclude(topo)
	depth := parseDepth(topo)
	targetNid, _ := topo["target_nid"].(string)
	if scope == scopeMemberWire && targetNid == "" {
		return AnchorSnapshotRequest{}, &TopologyProtocolError{ErrTopologyUnsupportedScope, "NPS-CLIENT-BAD-PARAM",
			`topology.target_nid is required when topology.scope = "member".`}
	}
	return AnchorSnapshotRequest{Scope: scope, Include: include, Depth: depth, TargetNid: targetNid}, nil
}

func parseStreamRequest(body map[string]any) (AnchorStreamRequest, string, *TopologyProtocolError) {
	topo, ok := body["topology"].(map[string]any)
	if !ok {
		return AnchorStreamRequest{}, "", &TopologyProtocolError{ErrTopologyUnsupportedScope, "NPS-CLIENT-BAD-PARAM",
			"topology.stream requires a 'topology' object per NPS-2 §12.2."}
	}
	scope, perr := parseScope(topo)
	if perr != nil {
		return AnchorStreamRequest{}, "", perr
	}
	req := AnchorStreamRequest{Scope: scope}
	if f, ok := topo["filter"].(map[string]any); ok {
		if perr := validateFilterKeys(f); perr != nil {
			return AnchorStreamRequest{}, "", perr
		}
		req.Filter = &TopologyFilter{
			TagsAny:   toStringSlice(f["tags_any"]),
			TagsAll:   toStringSlice(f["tags_all"]),
			NodeRoles: toStringSlice(f["node_roles"]),
		}
	}
	if sv, ok := topo["since_version"].(float64); ok {
		v := uint64(sv)
		req.SinceVersion = &v
	} else if rfs, ok := body["resume_from_seq"].(float64); ok {
		v := uint64(rfs)
		req.SinceVersion = &v
	}
	streamID, _ := body["stream_id"].(string)
	if streamID == "" {
		streamID = randomHex(16)
	}
	return req, streamID, nil
}

func parseScope(topo map[string]any) (string, *TopologyProtocolError) {
	s, ok := topo["scope"].(string)
	if !ok || s == "" {
		return scopeClusterWire, nil
	}
	if s == scopeClusterWire || s == scopeMemberWire {
		return s, nil
	}
	return "", &TopologyProtocolError{ErrTopologyUnsupportedScope, "NPS-CLIENT-BAD-PARAM",
		"unknown topology.scope '" + s + "'."}
}

func parseInclude(topo map[string]any) map[string]bool {
	out := map[string]bool{}
	known := map[string]bool{"members": true, "capabilities": true, "tags": true, "metrics": true}
	if arr, ok := topo["include"].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok && known[s] {
				out[s] = true
			}
		}
	}
	if len(out) == 0 {
		out["members"] = true
	}
	return out
}

func parseDepth(topo map[string]any) int {
	if d, ok := topo["depth"].(float64); ok && d > 0 {
		return int(d)
	}
	return 1
}

func validateFilterKeys(f map[string]any) *TopologyProtocolError {
	for k := range f {
		switch k {
		case "tags_any", "tags_all", "node_roles":
			continue
		case "node_kind":
			return &TopologyProtocolError{ErrTopologyFilterUnsupported, "NPS-CLIENT-BAD-PARAM",
				"topology.filter.node_kind expired after alpha.5; use node_roles."}
		default:
			return &TopologyProtocolError{ErrTopologyFilterUnsupported, "NPS-CLIENT-BAD-PARAM",
				"topology.filter key '" + k + "' is not recognized."}
		}
	}
	return nil
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func extractIdentAssurance(r *http.Request) nip.AssuranceLevel {
	raw := r.Header.Get(HeaderIdent)
	if raw == "" {
		return nip.AssuranceAnonymous
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nip.AssuranceAnonymous
	}
	if lvl, ok := doc["assurance_level"].(string); ok {
		if a, err := nip.AssuranceFromWire(lvl); err == nil {
			return a
		}
	}
	return nip.AssuranceAnonymous
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
