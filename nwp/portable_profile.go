// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"strings"

	"github.com/labacacia/NPS-sdk-go/core"
)

type NwpServerTransport string

const (
	NwpServerTransportHTTP   NwpServerTransport = "http"
	NwpServerTransportNative NwpServerTransport = "native"
)

type NwpPortableNodeRole string

const (
	NwpPortableNodeMemory  NwpPortableNodeRole = "memory"
	NwpPortableNodeAction  NwpPortableNodeRole = "action"
	NwpPortableNodeComplex NwpPortableNodeRole = "complex"
)

// NwpPortableNodeRequest is the input to NWP v0.20 portable Node admission.
type NwpPortableNodeRequest struct {
	Transport     NwpServerTransport  `json:"transport"`
	NodeRole      NwpPortableNodeRole `json:"node_role"`
	Method        string              `json:"method,omitempty"`
	Path          string              `json:"path,omitempty"`
	ContentType   string              `json:"content_type,omitempty"`
	Accept        string              `json:"accept,omitempty"`
	BodyBytes     uint64              `json:"body_bytes,omitempty"`
	MaxBodyBytes  uint64              `json:"max_body_bytes,omitempty"`
	FrameKind     string              `json:"frame_kind,omitempty"`
	BodyValid     bool                `json:"body_valid,omitempty"`
	Cancelled     bool                `json:"cancelled,omitempty"`
	CorrelationID string              `json:"correlation_id,omitempty"`
}

// NwpPortableNodeDecision is the terminal portable Node admission result.
type NwpPortableNodeDecision struct {
	Decision                string `json:"decision"`
	HTTPStatus              int    `json:"http_status,omitempty"`
	ContentType             string `json:"content_type,omitempty"`
	Status                  string `json:"status,omitempty"`
	Error                   string `json:"error,omitempty"`
	Allow                   string `json:"allow,omitempty"`
	ResponseFrame           string `json:"response_frame,omitempty"`
	CorrelationID           string `json:"correlation_id,omitempty"`
	TelemetryOutcome        string `json:"telemetry_outcome"`
	LegacyMediaTypeAccepted bool   `json:"legacy_media_type_accepted,omitempty"`
}

// EvaluatePortableNode applies admission without reading a stream or invoking a provider.
func EvaluatePortableNode(request NwpPortableNodeRequest) NwpPortableNodeDecision {
	if request.Cancelled {
		return nodeResult(request, "abort", "cancelled")
	}
	if request.Transport == NwpServerTransportNative {
		return evaluateNativeNode(request)
	}
	return evaluateHTTPNode(request)
}

func evaluateHTTPNode(request NwpPortableNodeRequest) NwpPortableNodeDecision {
	path := strings.ToLower(request.Path)
	method := strings.ToUpper(request.Method)
	if path == "/.nwm" {
		if method != "GET" {
			return methodNotAllowed(request, "GET")
		}
		result := nodeResult(request, "serve_manifest", "success")
		result.HTTPStatus = 200
		result.ContentType = MimeManifest
		return result
	}
	if path != "/query" && path != "/invoke" {
		return nodeReject(request, 404, core.NpsClientNotFound, ErrHttpFrameBodyMalformed)
	}
	if method != "POST" {
		return methodNotAllowed(request, "POST")
	}

	mediaType := baseMediaType(request.ContentType)
	legacy := mediaType == MimeLegacyFrame
	if !legacy && mediaType != MimeFrame {
		return nodeReject(request, 400, core.NpsClientBadFrame, ErrHttpContentTypeUnsupported)
	}
	if !acceptsMediaType(request.Accept, MimeCapsule) {
		return nodeReject(request, 400, core.NpsClientBadParam, ErrHttpAcceptUnsatisfiable)
	}
	maxBodyBytes := request.MaxBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = 1024 * 1024
	}
	if request.BodyBytes > maxBodyBytes {
		return nodeReject(request, 413, core.NpsLimitPayload, ErrHttpBodyTooLarge)
	}
	if !request.BodyValid {
		return nodeReject(request, 400, core.NpsClientBadFrame, ErrHttpFrameBodyMalformed)
	}

	frameKind := strings.ToLower(request.FrameKind)
	query := path == "/query" &&
		(request.NodeRole == NwpPortableNodeMemory || request.NodeRole == NwpPortableNodeComplex) &&
		frameKind == "query"
	action := path == "/invoke" &&
		(request.NodeRole == NwpPortableNodeAction || request.NodeRole == NwpPortableNodeComplex) &&
		frameKind == "action"
	if !query && !action {
		return nodeReject(request, 400, core.NpsClientBadFrame, ErrHttpFrameBodyMalformed)
	}
	decision := "dispatch_action"
	if query {
		decision = "dispatch_query"
	}
	result := nodeResult(request, decision, "success")
	result.HTTPStatus = 200
	result.ContentType = MimeCapsule
	result.LegacyMediaTypeAccepted = legacy
	return result
}

func evaluateNativeNode(request NwpPortableNodeRequest) NwpPortableNodeDecision {
	frameKind := strings.ToLower(request.FrameKind)
	query := frameKind == "query" &&
		(request.NodeRole == NwpPortableNodeMemory || request.NodeRole == NwpPortableNodeComplex)
	action := frameKind == "action" &&
		(request.NodeRole == NwpPortableNodeAction || request.NodeRole == NwpPortableNodeComplex)
	if request.BodyValid && (query || action) {
		decision := "dispatch_action"
		if query {
			decision = "dispatch_query"
		}
		result := nodeResult(request, decision, "success")
		result.ResponseFrame = "caps"
		return result
	}
	result := nodeResult(request, "error_frame", "rejected")
	result.Status = core.NpsClientBadFrame
	result.Error = "NWP-NATIVE-FRAME-UNSUPPORTED"
	result.ResponseFrame = "error"
	return result
}

func methodNotAllowed(request NwpPortableNodeRequest, allowedMethod string) NwpPortableNodeDecision {
	result := nodeResult(request, "reject", "rejected")
	result.HTTPStatus = 405
	result.Allow = allowedMethod
	return result
}

func nodeReject(request NwpPortableNodeRequest, httpStatus int, status, errorCode string) NwpPortableNodeDecision {
	result := nodeResult(request, "reject", "rejected")
	result.HTTPStatus = httpStatus
	result.ContentType = MimeError
	result.Status = status
	result.Error = errorCode
	return result
}

func nodeResult(request NwpPortableNodeRequest, decision, telemetry string) NwpPortableNodeDecision {
	return NwpPortableNodeDecision{
		Decision:         decision,
		CorrelationID:    request.CorrelationID,
		TelemetryOutcome: telemetry,
	}
}

// BridgeLifecycleRequest is the input to portable outbound Bridge preflight.
type BridgeLifecycleRequest struct {
	Protocol            string   `json:"protocol"`
	Endpoint            string   `json:"endpoint"`
	RegisteredProtocols []string `json:"registered_protocols"`
	AllowHTTP           bool     `json:"allow_http"`
	RejectPrivate       bool     `json:"reject_private"`
	AllowedPrefixes     []string `json:"allowed_prefixes,omitempty"`
	TimeoutMs           uint64   `json:"timeout_ms"`
	ElapsedMs           uint64   `json:"elapsed_ms"`
	Cancelled           bool     `json:"cancelled,omitempty"`
	CorrelationID       string   `json:"correlation_id,omitempty"`
	TaskMode            string   `json:"task_mode,omitempty"`
}

// BridgeLifecycleDecision is the terminal outbound Bridge lifecycle result.
type BridgeLifecycleDecision struct {
	Decision         string `json:"decision"`
	HTTPStatus       int    `json:"http_status,omitempty"`
	Status           string `json:"status,omitempty"`
	Error            string `json:"error,omitempty"`
	CorrelationID    string `json:"correlation_id,omitempty"`
	TaskMode         string `json:"task_mode,omitempty"`
	TelemetryOutcome string `json:"telemetry_outcome"`
}

// EvaluateBridgeLifecycle performs preflight without making an upstream connection.
func EvaluateBridgeLifecycle(request BridgeLifecycleRequest) BridgeLifecycleDecision {
	if request.Cancelled {
		return bridgeLifecycleResult(request, "abort", "cancelled")
	}
	if strings.TrimSpace(request.Protocol) == "" || strings.TrimSpace(request.Endpoint) == "" {
		result := bridgeLifecycleResult(request, "reject", "rejected")
		result.HTTPStatus = 422
		result.Status = core.NpsClientUnprocessable
		result.Error = ErrBridgeTargetInvalid
		return result
	}
	registered := false
	for _, protocol := range request.RegisteredProtocols {
		if strings.EqualFold(protocol, request.Protocol) {
			registered = true
			break
		}
	}
	if !registered {
		result := bridgeLifecycleResult(request, "reject", "rejected")
		result.HTTPStatus = 501
		result.Status = core.NpsServerUnsupported
		result.Error = ErrBridgeProtocolUnsupported
		return result
	}

	if message := ValidateComplexChildURL(
		request.Endpoint,
		request.AllowedPrefixes,
		request.RejectPrivate,
		request.AllowHTTP,
	); message != "" {
		result := bridgeLifecycleResult(request, "reject", "rejected")
		result.HTTPStatus = 422
		result.Status = core.NpsClientUnprocessable
		result.Error = ErrBridgeEndpointInvalid
		return result
	}

	if request.TimeoutMs == 0 {
		panic("timeout_ms must be positive")
	}
	if request.ElapsedMs >= request.TimeoutMs {
		result := bridgeLifecycleResult(request, "reject", "timeout")
		result.HTTPStatus = 504
		result.Status = core.NpsServerTimeout
		result.Error = ErrBridgeUpstreamFailed
		return result
	}

	taskMode := "sync"
	if strings.EqualFold(request.TaskMode, "async") {
		taskMode = "async"
	}
	result := bridgeLifecycleResult(request, "dispatch", "success")
	result.TaskMode = taskMode
	result.Status = core.NpsOk
	if taskMode == "async" {
		result.Status = core.NpsOkAccepted
	}
	return result
}

func bridgeLifecycleResult(request BridgeLifecycleRequest, decision, telemetry string) BridgeLifecycleDecision {
	return BridgeLifecycleDecision{
		Decision:         decision,
		CorrelationID:    request.CorrelationID,
		TelemetryOutcome: telemetry,
	}
}

func baseMediaType(value string) string {
	return strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
}

func acceptsMediaType(accept, responseType string) bool {
	if strings.TrimSpace(accept) == "" {
		return true
	}
	for _, value := range strings.Split(accept, ",") {
		mediaType := baseMediaType(value)
		if mediaType == "*/*" || mediaType == "application/*" || mediaType == responseType {
			return true
		}
	}
	return false
}
