// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nop

import (
	"encoding/json"
	"fmt"
)

// ── AggregateStrategy ─────────────────────────────────────────────────────────

const (
	AggregateStrategyMerge          = "merge"
	AggregateStrategyFirst          = "first"
	AggregateStrategyAll            = "all"
	AggregateStrategyFastestK       = "fastest_k"
	AggregateStrategyWeightedFirstK = "weighted_first_k"
	AggregateStrategyMergeAll       = "merge_all"
)

// ── CompensationPolicy ────────────────────────────────────────────────────────

const (
	// CompensationPolicyBestEffort runs compensation for completed predecessors on
	// failure; compensation failures are reported but non-fatal (NPS-5 §3.5).
	CompensationPolicyBestEffort = "best_effort"
	// CompensationPolicyStrict runs compensation on failure; any missing or failed
	// compensation step is terminal (NPS-5 §3.5).
	CompensationPolicyStrict = "strict"

	// Legacy aliases / non-standard extensions retained for alpha compatibility.
	CompensationPolicyNone      = "none"
	CompensationPolicyOnFailure = "on_failure"
	CompensationPolicyAlways    = "always"
)

// CompensationRunsOnFailure reports whether the policy runs compensation after failure.
func CompensationRunsOnFailure(policy string) bool {
	switch policy {
	case CompensationPolicyBestEffort, CompensationPolicyStrict,
		CompensationPolicyOnFailure, CompensationPolicyAlways:
		return true
	}
	return false
}

// CompensationRunsOnSuccess reports whether the policy runs compensation after success.
func CompensationRunsOnSuccess(policy string) bool { return policy == CompensationPolicyAlways }

// CompensationIsStrict reports whether missing/failed compensation is terminal.
func CompensationIsStrict(policy string) bool { return policy == CompensationPolicyStrict }

// ── TaskPriority ──────────────────────────────────────────────────────────────

const (
	TaskPriorityLow    = "low"
	TaskPriorityNormal = "normal"
	TaskPriorityHigh   = "high"
)

// ── TaskDag ───────────────────────────────────────────────────────────────────

// TaskDag is the typed DAG definition for a task (NPS-5 §3.1.1).
type TaskDag struct {
	Nodes []*DagNode `json:"nodes"`
	Edges []*DagEdge `json:"edges"`
}

// DagNode describes a single node (vertex) in a NOP task DAG (NPS-5 §3.1.1).
type DagNode struct {
	// ID is the node's unique identifier within the DAG.
	ID string `json:"id"`
	// Action is the operation URL (nwp://...).
	Action string `json:"action"`
	// Agent is the Worker Agent NID that executes this node.
	Agent string `json:"agent"`
	// InputFrom lists upstream node IDs this node depends on.
	InputFrom []string `json:"input_from,omitempty"`
	// InputMapping maps parameter name → JSONPath (string) or []JSONPath, as raw JSON.
	InputMapping map[string]json.RawMessage `json:"input_mapping,omitempty"`
	// TimeoutMs overrides TaskFrame.TimeoutMs for this node.
	TimeoutMs *uint64 `json:"timeout_ms,omitempty"`
	// RetryPolicy is the per-node retry strategy.
	RetryPolicy *RetryPolicy `json:"retry_policy,omitempty"`
	// Condition is a CEL-subset expression; when false the node is skipped.
	Condition string `json:"condition,omitempty"`
	// MinRequired is the K-of-N threshold on InputFrom; 0 means all deps must succeed.
	MinRequired uint64 `json:"min_required,omitempty"`
	// CompensateAction is the saga compensation action URL for this node.
	CompensateAction string `json:"compensate_action,omitempty"`
	// CompensateParamsMapping is the parameter mapping for the compensation call.
	CompensateParamsMapping map[string]json.RawMessage `json:"compensate_params_mapping,omitempty"`
}

// DagEdge is a directed edge in a task DAG (NPS-5 §3.1.1).
type DagEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// ── RetryPolicy ───────────────────────────────────────────────────────────────

// RetryPolicy is the per-node retry policy (NPS-5 §3.1.4).
type RetryPolicy struct {
	MaxRetries     uint32   `json:"max_retries,omitempty"`
	Backoff        string   `json:"backoff,omitempty"`
	InitialDelayMs uint64   `json:"initial_delay_ms,omitempty"`
	MaxDelayMs     uint64   `json:"max_delay_ms,omitempty"`
	RetryOn        []string `json:"retry_on,omitempty"`
}

// ComputeDelayMs computes the delay in ms for a 0-based attempt number.
func (p *RetryPolicy) ComputeDelayMs(attempt int) uint64 {
	initial := p.InitialDelayMs
	if initial == 0 {
		initial = 1000
	}
	maxDelay := p.MaxDelayMs
	if maxDelay == 0 {
		maxDelay = 30000
	}
	var factor float64
	switch p.Backoff {
	case BackoffStrategyFixed:
		factor = 1
	case BackoffStrategyLinear:
		factor = float64(attempt + 1)
	default: // exponential (default)
		factor = pow2(attempt)
	}
	delay := float64(initial) * factor
	if delay > float64(maxDelay) {
		return maxDelay
	}
	return uint64(delay)
}

func pow2(n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= 2
	}
	return r
}

// Backoff strategy wire identifiers (NPS-5 §3.1.4).
const (
	BackoffStrategyFixed       = "fixed"
	BackoffStrategyLinear      = "linear"
	BackoffStrategyExponential = "exponential"
)

// ── StreamError ───────────────────────────────────────────────────────────────

// StreamError is the typed error payload carried by an AlignStream final frame.
type StreamError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable,omitempty"`
}

// ── TaskContext ───────────────────────────────────────────────────────────────

// TaskContext is the transparent context propagated across sub-tasks, with W3C
// trace-context support (NPS-5 §3.1.2).
type TaskContext struct {
	SessionID  string            `json:"session_id,omitempty"`
	TraceID    string            `json:"trace_id,omitempty"`
	SpanID     string            `json:"span_id,omitempty"`
	TraceFlags *byte             `json:"trace_flags,omitempty"`
	Baggage    map[string]string `json:"baggage,omitempty"`
	Custom     json.RawMessage   `json:"custom,omitempty"`
}

// ── BackoffStrategy (legacy helper) ────────────────────────────────────────────

type BackoffStrategy int

const (
	BackoffFixed BackoffStrategy = iota
	BackoffLinear
	BackoffExponential
)

// ComputeDelayMs returns the retry delay in milliseconds for the given attempt.
func ComputeDelayMs(strategy BackoffStrategy, baseMs, maxMs int64, attempt int) int64 {
	var raw int64
	switch strategy {
	case BackoffFixed:
		raw = baseMs
	case BackoffLinear:
		raw = baseMs * int64(attempt+1)
	case BackoffExponential:
		raw = baseMs << uint(attempt) // baseMs * 2^attempt
	}
	if raw > maxMs {
		return maxMs
	}
	return raw
}

// ── TaskState ─────────────────────────────────────────────────────────────────

type TaskState string

const (
	TaskStatePending      TaskState = "pending"
	TaskStatePreflight    TaskState = "preflight"
	TaskStateRunning      TaskState = "running"
	TaskStateWaitingSync  TaskState = "waiting_sync"
	TaskStateCompleted    TaskState = "completed"
	TaskStateFailed       TaskState = "failed"
	TaskStateCancelled    TaskState = "cancelled"
	TaskStateSkipped      TaskState = "skipped"
	TaskStateCompensating TaskState = "compensating"
	TaskStateCompensated  TaskState = "compensated"
)

func TaskStateFromString(s string) (TaskState, error) {
	switch TaskState(s) {
	case TaskStatePending, TaskStatePreflight, TaskStateRunning, TaskStateWaitingSync,
		TaskStateCompleted, TaskStateFailed, TaskStateCancelled, TaskStateSkipped,
		TaskStateCompensating, TaskStateCompensated:
		return TaskState(s), nil
	}
	return "", fmt.Errorf("unknown task state: %s", s)
}

func (s TaskState) IsTerminal() bool {
	return s == TaskStateCompleted || s == TaskStateFailed || s == TaskStateCancelled
}

// ── NopTaskStatus ─────────────────────────────────────────────────────────────

type NopTaskStatus struct {
	raw map[string]any
}

func NewNopTaskStatus(raw map[string]any) *NopTaskStatus {
	return &NopTaskStatus{raw: raw}
}

func (s *NopTaskStatus) TaskID() string {
	v, _ := s.raw["task_id"].(string)
	return v
}

func (s *NopTaskStatus) State() TaskState {
	v, _ := s.raw["state"].(string)
	return TaskState(v)
}

func (s *NopTaskStatus) IsTerminal() bool { return s.State().IsTerminal() }

func (s *NopTaskStatus) ErrorCode() string {
	v, _ := s.raw["error_code"].(string)
	return v
}

func (s *NopTaskStatus) ErrorMessage() string {
	v, _ := s.raw["error_message"].(string)
	return v
}

func (s *NopTaskStatus) NodeResults() map[string]any {
	v, _ := s.raw["node_results"].(map[string]any)
	return v
}

func (s *NopTaskStatus) String() string {
	return fmt.Sprintf("NopTaskStatus(task_id=%s, state=%s)", s.TaskID(), s.State())
}
