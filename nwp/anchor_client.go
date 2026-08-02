// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Wire constants for topology reserved query types and event kinds (NPS-2 §12).
const (
	topologyScopeCluster = "cluster"
	topologyScopeMember  = "member"
	typeSnapshot         = "topology.snapshot"
	typeStream           = "topology.stream"
	eventMemberJoined    = "member_joined"
	eventMemberLeft      = "member_left"
	eventMemberUpdated   = "member_updated"
	eventAnchorState     = "anchor_state"
	eventResyncRequired  = "resync_required"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// MemberInfo is the per-member metadata returned in a TopologySnapshot or
// carried by MemberJoinedEvent / MemberUpdatedEvent (NPS-2 §12.1).
type MemberInfo struct {
	Nid            string          `json:"nid"`
	NodeRoles      []string        `json:"node_roles"`
	ActivationMode string          `json:"activation_mode"`
	ChildAnchor    *bool           `json:"child_anchor,omitempty"`
	MemberCount    *uint32         `json:"member_count,omitempty"`
	Tags           []string        `json:"tags,omitempty"`
	JoinedAt       *string         `json:"joined_at,omitempty"`
	LastSeen       *string         `json:"last_seen,omitempty"`
	Capabilities   json.RawMessage `json:"capabilities,omitempty"`
	Metrics        json.RawMessage `json:"metrics,omitempty"`
}

// TopologySnapshot is the result of a topology.snapshot reserved query
// (NPS-2 §12.1). It is deserialized from data[0] of the server's CapsFrame.
type TopologySnapshot struct {
	Version     uint64       `json:"version"`
	AnchorNid   string       `json:"anchor_nid"`
	ClusterSize uint32       `json:"cluster_size"`
	Members     []MemberInfo `json:"members"`
	Truncated   *bool        `json:"truncated,omitempty"`
	// ClusterEpoch is the epoch under which the responding Anchor owns its cluster
	// (NPS-CR-0009, NWP v0.18 §12.2). Absent means 1. Not signed.
	//
	// The wire key is declared explicitly on purpose: in the .NET reference this
	// member carries no JSON name attribute and lands on `cluster_epoch` only via
	// the host serializer's snake_case policy — a port trap.
	//
	// Per §12.2 every topology.snapshot / topology.stream response and every
	// topology-mutating write MUST carry the current cluster_epoch.
	ClusterEpoch *uint64 `json:"cluster_epoch,omitempty"`
}

// TopologyFilter is the optional subscriber-side filter for topology.stream
// (NPS-2 §12.2). All clauses are AND-combined.
type TopologyFilter struct {
	TagsAny   []string `json:"tags_any,omitempty"`
	TagsAll   []string `json:"tags_all,omitempty"`
	NodeRoles []string `json:"node_roles,omitempty"`
}

// MemberChanges holds the field-level diff carried by MemberUpdatedEvent.
type MemberChanges struct {
	NodeRoles      []string        `json:"node_roles,omitempty"`
	ActivationMode *string         `json:"activation_mode,omitempty"`
	Tags           []string        `json:"tags,omitempty"`
	MemberCount    *uint32         `json:"member_count,omitempty"`
	LastSeen       *string         `json:"last_seen,omitempty"`
	Capabilities   json.RawMessage `json:"capabilities,omitempty"`
	Metrics        json.RawMessage `json:"metrics,omitempty"`
}

// TopologyEvent is the base for all topology stream events (NPS-2 §12.2).
// Exactly one of the pointer fields is set, matching Kind.
type TopologyEvent struct {
	Kind    string // "member_joined" | "member_left" | "member_updated" | "anchor_state" | "resync_required"
	Version uint64
	// Only one of the following is set, matching Kind:
	MemberJoined   *MemberJoinedEvent
	MemberLeft     *MemberLeftEvent
	MemberUpdated  *MemberUpdatedEvent
	AnchorState    *AnchorStateEvent
	ResyncRequired *ResyncRequiredEvent
}

type MemberJoinedEvent struct{ Member MemberInfo }
type MemberLeftEvent struct{ Nid string }
type MemberUpdatedEvent struct {
	Nid     string
	Changes MemberChanges
}
type AnchorStateEvent struct {
	Field   string
	Details json.RawMessage
}
type ResyncRequiredEvent struct{ Reason string }

// AnchorTopologyError is returned when the Anchor server signals an error,
// either as a non-2xx HTTP response or as an in-stream error envelope.
type AnchorTopologyError struct {
	NwpErrorCode string
	NpsStatus    string
	Message      string
}

func (e *AnchorTopologyError) Error() string { return e.Message }

// ── AnchorNodeClient ─────────────────────────────────────────────────────────

// AnchorNodeClient is a typed HTTP client for an Anchor Node's reserved query
// types topology.snapshot and topology.stream (NPS-2 §12).
type AnchorNodeClient struct {
	baseURL    string
	pathPrefix string
	http       *http.Client
}

// NewAnchorNodeClient constructs an AnchorNodeClient for the given base URL.
// Apply functional options to override path prefix or HTTP client.
func NewAnchorNodeClient(baseURL string, opts ...func(*AnchorNodeClient)) *AnchorNodeClient {
	c := &AnchorNodeClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		pathPrefix: "",
		http:       http.DefaultClient,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// WithPathPrefix sets the path prefix for the Anchor middleware mount point
// (e.g. "/anchor"). The trailing slash is stripped automatically.
func WithPathPrefix(pfx string) func(*AnchorNodeClient) {
	return func(c *AnchorNodeClient) {
		c.pathPrefix = strings.TrimRight(pfx, "/")
	}
}

// WithHTTPClient replaces the default http.DefaultClient.
func WithHTTPClient(client *http.Client) func(*AnchorNodeClient) {
	return func(c *AnchorNodeClient) {
		c.http = client
	}
}

// ── GetSnapshot ───────────────────────────────────────────────────────────────

// snapshotTopologyPayload is the wire shape posted to /query for topology.snapshot.
type snapshotTopologyPayload struct {
	Scope     string   `json:"scope"`
	Include   []string `json:"include,omitempty"`
	Depth     int      `json:"depth,omitempty"`
	TargetNid string   `json:"target_nid,omitempty"`
}

type snapshotRequestBody struct {
	Type     string                  `json:"type"`
	Topology snapshotTopologyPayload `json:"topology"`
}

// capsFrameResponse is the minimal wrapper the Anchor returns for /query.
type capsFrameResponse struct {
	Data []json.RawMessage `json:"data"`
}

// GetSnapshot fetches the current cluster topology (NPS-2 §12.1).
//
// Defaults: scope="cluster", include=["members"], depth=1.
// Pass targetNid="" to omit that field.
func (c *AnchorNodeClient) GetSnapshot(
	ctx context.Context,
	scope string,
	include []string,
	depth int,
	targetNid string,
) (*TopologySnapshot, error) {
	if scope == "" {
		scope = topologyScopeCluster
	}
	if len(include) == 0 {
		include = []string{"members"}
	}
	if depth == 0 {
		depth = 1
	}

	topo := snapshotTopologyPayload{
		Scope:   scope,
		Include: include,
		Depth:   depth,
	}
	if targetNid != "" {
		topo.TargetNid = targetNid
	}

	reqBody := snapshotRequestBody{Type: typeSnapshot, Topology: topo}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := c.baseURL + c.pathPrefix + "/query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseErrorBody(body, resp.StatusCode)
	}

	var caps capsFrameResponse
	if err := json.Unmarshal(body, &caps); err != nil {
		return nil, fmt.Errorf("anchor: failed to decode CapsFrame: %w", err)
	}
	if len(caps.Data) == 0 {
		return nil, fmt.Errorf("anchor: topology.snapshot returned empty data array")
	}

	var snap TopologySnapshot
	if err := json.Unmarshal(caps.Data[0], &snap); err != nil {
		return nil, fmt.Errorf("anchor: failed to decode TopologySnapshot: %w", err)
	}
	return &snap, nil
}

// ── Subscribe ─────────────────────────────────────────────────────────────────

// streamTopologyPayload is the wire shape posted to /subscribe for topology.stream.
type streamTopologyPayload struct {
	Scope        string          `json:"scope"`
	Filter       *TopologyFilter `json:"filter,omitempty"`
	SinceVersion *uint64         `json:"since_version,omitempty"`
}

type streamRequestBody struct {
	Type     string                `json:"type"`
	Action   string                `json:"action"`
	StreamID string                `json:"stream_id"`
	Topology streamTopologyPayload `json:"topology"`
}

// eventEnvelope is the per-line wire shape for topology.stream events.
type eventEnvelope struct {
	StreamID  string          `json:"stream_id"`
	Seq       *uint64         `json:"seq"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	// Error fields — present only on error lines.
	Error   string `json:"error"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Subscribe opens a topology.stream subscription (NPS-2 §12.2).
// It returns a channel of TopologyEvents and a buffered error channel (cap 1).
// Both channels are closed when the goroutine exits.
//
// The caller MUST drain the event channel or cancel ctx to avoid goroutine leaks.
// After receiving a ResyncRequired event the event channel is closed; the caller
// MUST call GetSnapshot before resubscribing.
func (c *AnchorNodeClient) Subscribe(
	ctx context.Context,
	scope string,
	filter *TopologyFilter,
	sinceVersion *uint64,
) (<-chan TopologyEvent, <-chan error) {
	evCh := make(chan TopologyEvent, 16)
	errCh := make(chan error, 1)

	if scope == "" {
		scope = topologyScopeCluster
	}

	go func() {
		defer close(evCh)
		defer close(errCh)

		streamID := fmt.Sprintf("anchor-%d", time.Now().UnixNano())
		reqBody := streamRequestBody{
			Type:     typeStream,
			Action:   "subscribe",
			StreamID: streamID,
			Topology: streamTopologyPayload{
				Scope:        scope,
				Filter:       filter,
				SinceVersion: sinceVersion,
			},
		}
		data, err := json.Marshal(reqBody)
		if err != nil {
			errCh <- err
			return
		}

		url := c.baseURL + c.pathPrefix + "/subscribe"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			errCh <- err
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/x-ndjson")

		resp, err := c.http.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			errCh <- parseErrorBody(body, resp.StatusCode)
			return
		}

		scanner := bufio.NewScanner(resp.Body)

		// First line is the subscription ack — discard it.
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				errCh <- err
			}
			return
		}

		// Subsequent lines are event envelopes.
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}

			var env eventEnvelope
			if err := json.Unmarshal([]byte(line), &env); err != nil {
				// Malformed line — skip.
				continue
			}

			// Error line: has error+status but no event_type.
			if env.EventType == "" {
				if env.Error != "" || env.Status != "" {
					msg := env.Message
					if msg == "" {
						msg = fmt.Sprintf("anchor stream error: %s / %s", env.Error, env.Status)
					}
					errCh <- &AnchorTopologyError{
						NwpErrorCode: env.Error,
						NpsStatus:    env.Status,
						Message:      msg,
					}
					return
				}
				continue
			}

			ev, ok := parseTopologyEvent(env)
			if !ok {
				continue
			}

			select {
			case evCh <- ev:
			case <-ctx.Done():
				return
			}

			// After resync_required, close the stream — caller must re-snapshot.
			if ev.Kind == eventResyncRequired {
				return
			}
		}

		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			errCh <- err
		}
	}()

	return evCh, errCh
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func parseTopologyEvent(env eventEnvelope) (TopologyEvent, bool) {
	var version uint64
	if env.Seq != nil {
		version = *env.Seq
	}

	ev := TopologyEvent{Kind: env.EventType, Version: version}

	switch env.EventType {
	case eventMemberJoined:
		var m MemberInfo
		if err := json.Unmarshal(env.Payload, &m); err != nil {
			return ev, false
		}
		ev.MemberJoined = &MemberJoinedEvent{Member: m}

	case eventMemberLeft:
		var p struct {
			Nid string `json:"nid"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return ev, false
		}
		ev.MemberLeft = &MemberLeftEvent{Nid: p.Nid}

	case eventMemberUpdated:
		var p struct {
			Nid     string          `json:"nid"`
			Changes json.RawMessage `json:"changes"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return ev, false
		}
		var ch MemberChanges
		if err := json.Unmarshal(p.Changes, &ch); err != nil {
			return ev, false
		}
		ev.MemberUpdated = &MemberUpdatedEvent{Nid: p.Nid, Changes: ch}

	case eventAnchorState:
		var p struct {
			Field   string          `json:"field"`
			Details json.RawMessage `json:"details,omitempty"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return ev, false
		}
		ev.AnchorState = &AnchorStateEvent{Field: p.Field, Details: p.Details}

	case eventResyncRequired:
		var p struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			p.Reason = "unknown"
		}
		ev.ResyncRequired = &ResyncRequiredEvent{Reason: p.Reason}

	default:
		return ev, false
	}

	return ev, true
}

func parseErrorBody(body []byte, statusCode int) error {
	var e struct {
		Error   string `json:"error"`
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if jsonErr := json.Unmarshal(body, &e); jsonErr == nil && (e.Error != "" || e.Status != "") {
		msg := e.Message
		if msg == "" {
			msg = fmt.Sprintf("anchor: HTTP %d: %s / %s", statusCode, e.Error, e.Status)
		}
		return &AnchorTopologyError{
			NwpErrorCode: e.Error,
			NpsStatus:    e.Status,
			Message:      msg,
		}
	}
	return &AnchorTopologyError{
		NwpErrorCode: "UNKNOWN",
		NpsStatus:    fmt.Sprintf("HTTP-%d", statusCode),
		Message:      fmt.Sprintf("anchor: HTTP %d: %s", statusCode, string(body)),
	}
}
