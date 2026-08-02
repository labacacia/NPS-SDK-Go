// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import "encoding/json"

// JSON-RPC 2.0 envelope types shared by the inbound MCP and A2A servers.

// BridgeJsonRpcRequest is an inbound JSON-RPC 2.0 request.
type BridgeJsonRpcRequest struct {
	JsonRpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// BridgeJsonRpcError is a JSON-RPC 2.0 error object.
type BridgeJsonRpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// BridgeJsonRpcResponse is a JSON-RPC 2.0 response. Exactly one of Result / Error
// is populated: an error response MUST NOT also carry a result.
type BridgeJsonRpcResponse struct {
	JsonRpc string              `json:"jsonrpc"`
	ID      json.RawMessage     `json:"id"`
	Result  any                 `json:"result,omitempty"`
	Error   *BridgeJsonRpcError `json:"error,omitempty"`
}

func jsonRpcOK(id json.RawMessage, result any) BridgeJsonRpcResponse {
	return BridgeJsonRpcResponse{JsonRpc: "2.0", ID: id, Result: result}
}

func jsonRpcErr(id json.RawMessage, code int, message string, data any) BridgeJsonRpcResponse {
	return BridgeJsonRpcResponse{
		JsonRpc: "2.0", ID: id,
		Error: &BridgeJsonRpcError{Code: code, Message: message, Data: data},
	}
}

func jsonRpcErrObj(id json.RawMessage, e *BridgeJsonRpcError) BridgeJsonRpcResponse {
	return BridgeJsonRpcResponse{JsonRpc: "2.0", ID: id, Error: e}
}

// nullID is the `id: null` used when the request could not be parsed far enough
// to recover its id.
var nullID = json.RawMessage("null")

func requestID(r *BridgeJsonRpcRequest) json.RawMessage {
	if r == nil || len(r.ID) == 0 {
		return nullID
	}
	return r.ID
}

// bridgeFailurePayload is the {status, error, message} body a DOMAIN failure
// (an NPS-CLIENT-* class) is reported with, inside a successful result.
func bridgeFailurePayload(res NwpResult) map[string]any {
	return map[string]any{
		"status":  res.NpsStatus,
		"error":   res.NwpError,
		"message": res.Message,
	}
}
