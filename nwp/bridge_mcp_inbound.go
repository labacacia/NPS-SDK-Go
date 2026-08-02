// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// NPS-CR-0010 §2.1 — the inbound MCP (JSON-RPC 2.0) Bridge server.

// McpRequiredMethods is the NORMATIVE required method set, exported as data.
//
// §16.1.2 MUST-3: an inbound MCP Bridge that omits resources/* is NOT
// conformant. Serving resources/* over an EMPTY SET *is* conformant — the
// requirement is on the METHODS, not on a Memory Node existing behind them.
var McpRequiredMethods = []string{
	"initialize", "ping", "tools/list", "tools/call", "resources/list", "resources/read",
}

// McpInboundServer translates inbound MCP JSON-RPC into NWP backend calls.
type McpInboundServer struct {
	opts *BridgeInboundOptions
}

// NewMcpInboundServer constructs the inbound MCP server over the
// transport-independent options.
func NewMcpInboundServer(opts *BridgeInboundOptions) *McpInboundServer {
	return &McpInboundServer{opts: opts}
}

// Dispatch handles one JSON-RPC request.
func (s *McpInboundServer) Dispatch(ctx context.Context, req *BridgeJsonRpcRequest) BridgeJsonRpcResponse {
	if req == nil {
		return jsonRpcErr(nullID, JsonRpcInvalidRequest, "JSON-RPC request is required.", nil)
	}
	id := requestID(req)

	// §16.1.2 MUST-5: the direction gate is the FIRST thing in dispatch.
	if !s.opts.ServesInbound(BridgeProtocolMCP) {
		return jsonRpcErrObj(id, s.opts.directionUnsupported(BridgeProtocolMCP))
	}

	switch req.Method {
	case "initialize":
		return jsonRpcOK(id, map[string]any{
			"serverInfo": map[string]any{
				"name":    s.opts.serverName(),
				"version": s.opts.serverVersion(),
			},
			// BOTH capabilities are always advertised, even with no Memory Node behind.
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
		})
	case "ping":
		return jsonRpcOK(id, map[string]any{})
	case "tools/list":
		return s.toolsList(ctx, id)
	case "tools/call":
		return s.toolsCall(ctx, id, req.Params)
	case "resources/list":
		return s.resourcesList(ctx, id)
	case "resources/read":
		return s.resourcesRead(ctx, id, req.Params)
	default:
		return jsonRpcErr(id, JsonRpcMethodNotFound,
			fmt.Sprintf("MCP method '%s' is not supported by this Bridge Node.", req.Method),
			map[string]any{"error": ErrBridgeDirectionUnsupported})
	}
}

func (s *McpInboundServer) toolsList(ctx context.Context, id json.RawMessage) BridgeJsonRpcResponse {
	tools := []any{}
	for _, m := range bridgeAllInvokableActions(ctx, s.opts.Backends) {
		tool := map[string]any{
			"name":        m.QualifiedName,
			"inputSchema": m.Action.EffectiveInputSchema(),
		}
		if m.Action.Description != "" {
			tool["description"] = m.Action.Description
		}
		tools = append(tools, tool)
	}
	return jsonRpcOK(id, map[string]any{"tools": tools})
}

func (s *McpInboundServer) toolsCall(ctx context.Context, id json.RawMessage, params json.RawMessage) BridgeJsonRpcResponse {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return jsonRpcErr(id, JsonRpcInvalidParams, err.Error(), nil)
		}
	}
	if strings.TrimSpace(p.Name) == "" {
		return jsonRpcErr(id, JsonRpcInvalidParams, "MCP tools/call requires params.name.", nil)
	}

	match, candidates := BridgeResolveTool(ctx, s.opts.Backends, p.Name)
	if match == nil {
		// Unknown tool is -32601 (Method not found). -32002 is RETIRED and MUST
		// NOT be emitted. When the name was ambiguous the candidates are named so
		// the caller can disambiguate rather than have one guessed at.
		data := map[string]any{"error": ErrBridgeServerToolNotFound, "tool": p.Name}
		if len(candidates) > 0 {
			data["candidates"] = candidates
		}
		return jsonRpcErr(id, JsonRpcMethodNotFound,
			fmt.Sprintf("MCP tool '%s' is not exposed by this Bridge Node.", p.Name), data)
	}

	res := match.Backend.Invoke(ctx, match.Action.ActionID, p.Arguments, false)
	return s.projectToolResult(id, res, false)
}

// projectToolResult applies the §16.3 split to a backend result.
func (s *McpInboundServer) projectToolResult(id json.RawMessage, res NwpResult, resourceRead bool) BridgeJsonRpcResponse {
	if res.Ok {
		return jsonRpcOK(id, map[string]any{
			"isError": false,
			"content": []any{map[string]any{"type": "text", "text": string(res.Payload)}},
		})
	}
	if BridgeMustBeProtocolError(res.NpsStatus) {
		// Infrastructure failure — the tool DID NOT RUN. Reporting it as a
		// successful result with isError: true would let the client mistake a 403
		// for a tool that merely returned unhappy text.
		return jsonRpcErr(id, BridgeToJsonRpc(res.NpsStatus, resourceRead), res.Message,
			map[string]any{"error": res.NwpError, "status": res.NpsStatus})
	}
	// Tool-DOMAIN failure — this is exactly what MCP's isError flag is for.
	body, _ := json.Marshal(bridgeFailurePayload(res))
	return jsonRpcOK(id, map[string]any{
		"isError": true,
		"content": []any{map[string]any{"type": "text", "text": string(body)}},
	})
}

func (s *McpInboundServer) resourcesList(ctx context.Context, id json.RawMessage) BridgeJsonRpcResponse {
	// An EMPTY array is conformant: the MUST is on serving the method.
	resources := []any{}
	for _, q := range bridgeQueryableBackends(ctx, s.opts.Backends) {
		name := q.Descriptor.DisplayName
		if name == "" {
			name = q.Descriptor.Name
		}
		description := q.Descriptor.Description
		if description == "" {
			description = fmt.Sprintf("NWP %s Node '%s' — read to query.",
				q.Descriptor.Role, q.Descriptor.Name)
		}
		resources = append(resources, map[string]any{
			"uri":         "nwp://" + q.Descriptor.Name + "/",
			"name":        name,
			"description": description,
			"mimeType":    "application/json",
		})
	}
	return jsonRpcOK(id, map[string]any{"resources": resources})
}

func (s *McpInboundServer) resourcesRead(ctx context.Context, id json.RawMessage, params json.RawMessage) BridgeJsonRpcResponse {
	var p struct {
		URI string `json:"uri"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return jsonRpcErr(id, JsonRpcInvalidParams, err.Error(), nil)
		}
	}
	if strings.TrimSpace(p.URI) == "" {
		return jsonRpcErr(id, JsonRpcInvalidParams, "MCP resources/read requires params.uri.", nil)
	}

	u, err := url.Parse(p.URI)
	if err != nil || !u.IsAbs() || !strings.EqualFold(u.Scheme, "nwp") || u.Host == "" {
		return jsonRpcErr(id, JsonRpcInvalidParams,
			fmt.Sprintf("Resource URI '%s' must be of the form nwp://<node>/.", p.URI), nil)
	}

	for _, q := range bridgeQueryableBackends(ctx, s.opts.Backends) {
		if !strings.EqualFold(q.Descriptor.Name, u.Host) {
			continue
		}
		query, _ := json.Marshal(map[string]any{"limit": s.opts.readLimit()})
		res := q.Backend.Query(ctx, query)
		if !res.Ok {
			// resourceRead == true: an unknown URI is a PARAM fault (-32602), the
			// only param-sensitive row in the §16.3 table.
			return s.projectToolResult(id, res, true)
		}
		return jsonRpcOK(id, map[string]any{
			"contents": []any{map[string]any{
				"uri":      p.URI,
				"mimeType": "application/json",
				"text":     string(res.Payload),
			}},
		})
	}

	// An unknown HOST is -32602 (Invalid params), NOT -32601: the URI is a parameter.
	return jsonRpcErr(id, JsonRpcInvalidParams,
		fmt.Sprintf("Resource URI '%s' must be of the form nwp://<node>/.", p.URI),
		map[string]any{"error": ErrBridgeServerToolNotFound, "uri": p.URI})
}

// ── stdio transport ──────────────────────────────────────────────────────────

// RunStdio serves line-delimited JSON-RPC over a reader/writer pair.
//
// The stdio transport is part of the inbound PROFILE, not an extra: an MCP
// client that speaks stdio must be able to reach the Bridge without a web host.
// One line of JSON-RPC in, one line out per request; blank lines are skipped;
// EOF ends the loop; a request that deserializes to nothing is -32600; a parse
// error is -32700 with id: null. The writer is flushed after each response.
func (s *McpInboundServer) RunStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	w := bufio.NewWriter(out)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var req BridgeJsonRpcRequest
		var resp BridgeJsonRpcResponse
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			resp = jsonRpcErr(nullID, JsonRpcParseError, err.Error(), nil)
		} else if req.Method == "" && len(req.ID) == 0 {
			resp = jsonRpcErr(nullID, JsonRpcInvalidRequest, "JSON-RPC request is required.", nil)
		} else {
			resp = s.Dispatch(ctx, &req)
		}

		raw, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		if _, err := w.Write(append(raw, '\n')); err != nil {
			return err
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return scanner.Err()
}
