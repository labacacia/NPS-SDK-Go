// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
//
// RFC-0005 reputation policy types and default in-process evaluator.

package nwp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ── Policy types ─────────────────────────────────────────────────────────────

// ReputationPolicy is the node-side reputation enforcement configuration
// (NPS-RFC-0005 §4.1). Set MemoryNodeOptions.ReputationPolicy to enable.
type ReputationPolicy struct {
	Enabled           bool
	LogSources        []string
	MinAssuranceLevel string // "anonymous" | "attested" | "verified"
	CacheTtlSeconds   uint
	BanTtlSeconds     uint
	OnLogUnavailable  string // "allow" | "deny"
	ThrottleOn        []ReputationRule
	RejectOn          []ReputationRule
	BanOn             []ReputationRule
}

// ReputationRule is a single ban_on / reject_on / throttle_on rule.
type ReputationRule struct {
	Incident   string // RFC-0004 incident type or "*"
	Severity   string // e.g. ">=minor" or "critical"
	WithinDays *uint  // nil = all time
	Count      uint   // minimum matching entries; default 1
}

// ReputationOutcome is the result of an evaluation.
type ReputationOutcome int

const (
	RepAccept ReputationOutcome = iota
	RepThrottle
	RepReject
	RepBan
)

// ReputationDecision is the evaluation result.
type ReputationDecision struct {
	Outcome     ReputationOutcome
	MatchedRule *ReputationRule
	ErrorCode   string
}

// IReputationEvaluator evaluates a requester NID against a policy.
type IReputationEvaluator interface {
	Evaluate(ctx context.Context, requesterNid, assuranceLevel string, policy ReputationPolicy) (ReputationDecision, error)
	ClearBan(nid string)
}

// ── Severity / assurance ordering ────────────────────────────────────────────

var severityOrder = []string{"info", "minor", "moderate", "major", "critical"}
var assuranceOrder = []string{"anonymous", "attested", "verified"}

func severityIndex(s string) int {
	s = strings.ToLower(s)
	for i, v := range severityOrder {
		if v == s {
			return i
		}
	}
	return -1
}

func assuranceIndex(s string) int {
	s = strings.ToLower(s)
	for i, v := range assuranceOrder {
		if v == s {
			return i
		}
	}
	return -1
}

// ── Default evaluator ─────────────────────────────────────────────────────────

type banEntry struct{ expiresAt time.Time }
type cacheEntry struct {
	expiresAt time.Time
	entries   []logEntry
}

// defaultReputationEvaluator is the package-level singleton (lazy-init).
var (
	globalEvalOnce sync.Once
	globalEval     *reputationEvaluator
)

// DefaultReputationEvaluator returns the package-level default evaluator.
// It uses the default http.DefaultClient and an in-memory ban/log cache.
func DefaultReputationEvaluator() IReputationEvaluator {
	globalEvalOnce.Do(func() { globalEval = &reputationEvaluator{} })
	return globalEval
}

type reputationEvaluator struct {
	banMu  sync.RWMutex
	banMap map[string]banEntry
	logMu  sync.RWMutex
	logMap map[string]cacheEntry
}

func (e *reputationEvaluator) Evaluate(ctx context.Context, nid, assurance string, p ReputationPolicy) (ReputationDecision, error) {
	if !p.Enabled {
		return ReputationDecision{Outcome: RepAccept}, nil
	}

	// Assurance floor
	if assuranceIndex(p.MinAssuranceLevel) > assuranceIndex(assurance) {
		return ReputationDecision{Outcome: RepReject, ErrorCode: "NWP-AUTH-ASSURANCE-TOO-LOW"}, nil
	}

	// Ban cache
	if e.isBanned(nid) {
		return ReputationDecision{Outcome: RepBan, ErrorCode: "NWP-AUTH-REPUTATION-BLOCKED"}, nil
	}

	entries, err := e.fetchEntries(ctx, nid, p)
	if err != nil {
		return ReputationDecision{Outcome: RepAccept}, err
	}

	// ban_on → reject_on → throttle_on
	for i := range p.BanOn {
		if ruleMatches(&p.BanOn[i], entries) {
			exp := time.Now().Add(time.Duration(p.BanTtlSeconds) * time.Second)
			e.setBan(nid, exp)
			return ReputationDecision{Outcome: RepBan, MatchedRule: &p.BanOn[i], ErrorCode: "NWP-AUTH-REPUTATION-BLOCKED"}, nil
		}
	}
	for i := range p.RejectOn {
		if ruleMatches(&p.RejectOn[i], entries) {
			return ReputationDecision{Outcome: RepReject, MatchedRule: &p.RejectOn[i], ErrorCode: "NWP-AUTH-REPUTATION-BLOCKED"}, nil
		}
	}
	for i := range p.ThrottleOn {
		if ruleMatches(&p.ThrottleOn[i], entries) {
			return ReputationDecision{Outcome: RepThrottle, MatchedRule: &p.ThrottleOn[i]}, nil
		}
	}
	return ReputationDecision{Outcome: RepAccept}, nil
}

func (e *reputationEvaluator) ClearBan(nid string) {
	e.banMu.Lock()
	defer e.banMu.Unlock()
	delete(e.banMap, nid)
}

func (e *reputationEvaluator) isBanned(nid string) bool {
	e.banMu.RLock()
	defer e.banMu.RUnlock()
	if e.banMap == nil {
		return false
	}
	b, ok := e.banMap[nid]
	return ok && b.expiresAt.After(time.Now())
}

func (e *reputationEvaluator) setBan(nid string, exp time.Time) {
	e.banMu.Lock()
	defer e.banMu.Unlock()
	if e.banMap == nil {
		e.banMap = make(map[string]banEntry)
	}
	e.banMap[nid] = banEntry{expiresAt: exp}
}

// ── Log fetching ──────────────────────────────────────────────────────────────

type logEntry struct {
	Incident  string    `json:"incident"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

type logQueryResponse struct {
	Entries []logEntry `json:"entries"`
}

func (e *reputationEvaluator) fetchEntries(ctx context.Context, nid string, p ReputationPolicy) ([]logEntry, error) {
	if p.CacheTtlSeconds > 0 {
		e.logMu.RLock()
		if e.logMap != nil {
			if c, ok := e.logMap[nid]; ok && c.expiresAt.After(time.Now()) {
				e.logMu.RUnlock()
				return c.entries, nil
			}
		}
		e.logMu.RUnlock()
	}

	var entries []logEntry
	for _, source := range p.LogSources {
		u := strings.TrimRight(source, "/") + "/entries?subject_nid=" + url.QueryEscape(nid)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var qr logQueryResponse
		if json.Unmarshal(body, &qr) == nil {
			entries = qr.Entries
			break
		}
	}

	if entries == nil && strings.EqualFold(p.OnLogUnavailable, "deny") {
		entries = []logEntry{{Incident: "*", Severity: "critical", Timestamp: time.Now()}}
	}

	if p.CacheTtlSeconds > 0 {
		e.logMu.Lock()
		if e.logMap == nil {
			e.logMap = make(map[string]cacheEntry)
		}
		e.logMap[nid] = cacheEntry{
			expiresAt: time.Now().Add(time.Duration(p.CacheTtlSeconds) * time.Second),
			entries:   entries,
		}
		e.logMu.Unlock()
	}
	return entries, nil
}

// ── Rule matching ─────────────────────────────────────────────────────────────

func ruleMatches(rule *ReputationRule, entries []logEntry) bool {
	var cutoff *time.Time
	if rule.WithinDays != nil {
		t := time.Now().AddDate(0, 0, -int(*rule.WithinDays))
		cutoff = &t
	}
	op, threshold := parseSeverityPredicate(rule.Severity)
	count := rule.Count
	if count == 0 {
		count = 1
	}
	var matched uint
	for _, e := range entries {
		if cutoff != nil && e.Timestamp.Before(*cutoff) {
			continue
		}
		if !incidentMatches(rule.Incident, e.Incident) {
			continue
		}
		if !severityMatches(op, threshold, e.Severity) {
			continue
		}
		matched++
		if matched >= count {
			return true
		}
	}
	return false
}

func incidentMatches(pattern, incident string) bool {
	return pattern == "*" || strings.EqualFold(pattern, incident)
}

func severityMatches(op string, threshold int, actual string) bool {
	idx := severityIndex(actual)
	if idx < 0 {
		return false
	}
	if op == ">=" {
		return idx >= threshold
	}
	return idx == threshold
}

func parseSeverityPredicate(s string) (op string, threshold int) {
	if strings.HasPrefix(s, ">=") {
		return ">=", severityIndex(s[2:])
	}
	return "=", severityIndex(s)
}
