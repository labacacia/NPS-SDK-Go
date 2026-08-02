// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/labacacia/NPS-sdk-go/core"
)

// NPS-CR-0010 §2.3 — the inbound gRPC Bridge service.
//
// TRANSPORT NOTE: this module intentionally takes no dependency on grpc-go or
// protobuf, so what lives here is the SERVICE LOGIC — the four RPC handlers over
// the backend abstraction, backend resolution, and the §16.3 status mapping —
// with plain Go request/response structs mirroring
// Protos/nwp_ingress.proto (package labacacia.grpc_ingress.v1). A deployment
// that wants the wire binding generates the stubs from the published .proto and
// forwards each generated request to the matching method here; the field names
// and semantics line up one-for-one.
//
// The .proto itself is carried over UNCHANGED from the published
// LabAcacia.GrpcIngress: clients hold generated stubs, so it is public API.
//
// All payloads are JSON-encoded NWP frame bodies carried as bytes — NWP schemas
// are runtime-declared via AnchorFrame, so a typed proto is impossible.

// GrpcUpstreamContext mirrors `UpstreamContext { upstream = 1; agent_nid = 2;
// idempotency_key = 3; traceparent = 4; }`.
type GrpcUpstreamContext struct {
	Upstream       string
	AgentNid       string
	IdempotencyKey string
	Traceparent    string
}

// GrpcManifestResponse mirrors `ManifestResponse { bytes nwm_json; string node_type; }`.
type GrpcManifestResponse struct {
	NwmJSON  json.RawMessage
	NodeType string // empty when the role is Unknown
}

// GrpcInvokeResponse mirrors `InvokeResponse { int32 http_status; bytes body_json; string task_id; }`.
type GrpcInvokeResponse struct {
	HTTPStatus int32
	BodyJSON   json.RawMessage
	TaskID     string
}

// GrpcQueryResponse mirrors `QueryResponse { int32 http_status; bytes body_json; }`.
type GrpcQueryResponse struct {
	HTTPStatus int32
	BodyJSON   json.RawMessage
}

// GrpcActionsResponse mirrors `ActionsResponse { bytes actions_json; }`.
type GrpcActionsResponse struct {
	ActionsJSON json.RawMessage
}

// GrpcError is the gRPC-shaped fault a handler returns; a transport binding maps
// it onto status.Error(codes.Code(e.Code), e.Message).
//
// The detail string is deliberately "{npsStatus} {nwpError}: {message}" so a
// caller can recover the EXACT NPS fault, not only the coarse gRPC class.
type GrpcError struct {
	Code    GrpcStatusCode
	Message string
}

func (e *GrpcError) Error() string { return fmt.Sprintf("grpc %d: %s", e.Code, e.Message) }

func grpcFault(res NwpResult) *GrpcError {
	return &GrpcError{
		Code:    BridgeToGrpcStatus(res.NpsStatus),
		Message: bridgeDetail(res.NpsStatus, res.NwpError, res.Message),
	}
}

// GrpcInboundService implements the NwpIngress service logic.
type GrpcInboundService struct {
	opts *BridgeInboundOptions
}

// NewGrpcInboundService constructs the inbound gRPC service.
func NewGrpcInboundService(opts *BridgeInboundOptions) *GrpcInboundService {
	return &GrpcInboundService{opts: opts}
}

// checkDirection is the §16.1.2 MUST-5 gate — the first thing in every RPC.
func (s *GrpcInboundService) checkDirection() *GrpcError {
	if s.opts.ServesInbound(BridgeProtocolGRPC) {
		return nil
	}
	return &GrpcError{
		Code: GrpcUnimplemented,
		Message: fmt.Sprintf(
			`%s %s: this Bridge Node does not declare "grpc" in bridge_inbound_protocols.`,
			core.NpsServerUnsupported, ErrBridgeDirectionUnsupported),
	}
}

// ResolveBackend picks the backend an RPC targets.
//
// When ctx.Upstream is empty AND exactly one backend is configured, that one is
// used; otherwise the name is matched against descriptor.Name case-insensitively.
func (s *GrpcInboundService) ResolveBackend(ctx context.Context, uctx GrpcUpstreamContext) (NwpBackend, NwpNodeDescriptor, *GrpcError) {
	name := strings.TrimSpace(uctx.Upstream)
	if name == "" && len(s.opts.Backends) == 1 {
		b := s.opts.Backends[0]
		d, _ := b.GetDescriptor(ctx)
		return b, d, nil
	}
	for _, b := range s.opts.Backends {
		d, err := b.GetDescriptor(ctx)
		if err != nil {
			continue
		}
		if strings.EqualFold(d.Name, name) {
			return b, d, nil
		}
	}
	return nil, NwpNodeDescriptor{}, &GrpcError{
		Code: GrpcNotFound,
		Message: fmt.Sprintf("%s %s: no NWP node named '%s' is fronted by this Bridge Node.",
			core.NpsClientNotFound, ErrBridgeServerToolNotFound, name),
	}
}

// GetManifest implements `rpc GetManifest(ManifestRequest) returns (ManifestResponse)`.
func (s *GrpcInboundService) GetManifest(ctx context.Context, uctx GrpcUpstreamContext) (*GrpcManifestResponse, *GrpcError) {
	if e := s.checkDirection(); e != nil {
		return nil, e
	}
	b, d, e := s.ResolveBackend(ctx, uctx)
	if e != nil {
		return nil, e
	}
	res := b.GetManifest(ctx)
	if !res.Ok {
		return nil, grpcFault(res)
	}
	nodeType := ""
	if d.Role != NwpRoleUnknown {
		nodeType = d.Role.String()
	}
	return &GrpcManifestResponse{NwmJSON: res.Payload, NodeType: nodeType}, nil
}

// Invoke implements `rpc Invoke(InvokeRequest) returns (InvokeResponse)`.
// The service always dispatches with async: false and reports http_status 200
// on success; task_id is lifted from the payload's `task_id`, else "".
func (s *GrpcInboundService) Invoke(ctx context.Context, uctx GrpcUpstreamContext, actionID string, paramsJSON json.RawMessage) (*GrpcInvokeResponse, *GrpcError) {
	if e := s.checkDirection(); e != nil {
		return nil, e
	}
	if strings.TrimSpace(actionID) == "" {
		return nil, &GrpcError{Code: GrpcInvalidArgument, Message: "action_id is required"}
	}
	b, _, e := s.ResolveBackend(ctx, uctx)
	if e != nil {
		return nil, e
	}

	res := b.Invoke(ctx, actionID, paramsJSON, false)
	if !res.Ok {
		return nil, grpcFault(res)
	}
	taskID := ""
	var body map[string]any
	if json.Unmarshal(res.Payload, &body) == nil {
		if v, ok := body["task_id"].(string); ok {
			taskID = v
		}
	}
	return &GrpcInvokeResponse{HTTPStatus: 200, BodyJSON: res.Payload, TaskID: taskID}, nil
}

// Query implements `rpc Query(QueryRequest) returns (QueryResponse)`.
// An empty query_json is treated as {}.
func (s *GrpcInboundService) Query(ctx context.Context, uctx GrpcUpstreamContext, queryJSON json.RawMessage) (*GrpcQueryResponse, *GrpcError) {
	if e := s.checkDirection(); e != nil {
		return nil, e
	}
	b, _, e := s.ResolveBackend(ctx, uctx)
	if e != nil {
		return nil, e
	}
	if len(queryJSON) == 0 {
		queryJSON = json.RawMessage("{}")
	}
	res := b.Query(ctx, queryJSON)
	if !res.Ok {
		return nil, grpcFault(res)
	}
	return &GrpcQueryResponse{HTTPStatus: 200, BodyJSON: res.Payload}, nil
}

// ListActions implements `rpc ListActions(ActionsRequest) returns (ActionsResponse)`,
// producing `{ "actions": { "<id>": { "description": ... } } }`.
func (s *GrpcInboundService) ListActions(ctx context.Context, uctx GrpcUpstreamContext) (*GrpcActionsResponse, *GrpcError) {
	if e := s.checkDirection(); e != nil {
		return nil, e
	}
	b, _, e := s.ResolveBackend(ctx, uctx)
	if e != nil {
		return nil, e
	}
	actions, err := b.GetActions(ctx)
	if err != nil {
		return nil, grpcFault(NwpDispatchFailed(err.Error()))
	}
	m := map[string]any{}
	for _, a := range actions {
		m[a.ActionID] = map[string]any{"description": a.Description}
	}
	raw, mErr := json.Marshal(map[string]any{"actions": m})
	if mErr != nil {
		return nil, grpcFault(NwpDispatchFailed(mErr.Error()))
	}
	return &GrpcActionsResponse{ActionsJSON: raw}, nil
}
