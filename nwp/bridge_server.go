// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// NPS-CR-0010 §7 — the inbound Bridge HTTP hosting layer, as an http.Handler
// (the same binding shape as AnchorNodeApp).
//
// BridgeServerOptions is the HOSTING half of the configuration — paths, the
// HTTP-context-bound verifier, limits — and is deliberately a SEPARATE type from
// BridgeInboundOptions. The protocol servers never see any of this.

// BridgeNidVerifier decides whether a caller NID may use this Bridge. It takes
// the full *http.Request on purpose, so a deployment can bind the NID to a NIP
// client certificate off the connection.
type BridgeNidVerifier func(ctx context.Context, agentNid string, r *http.Request) bool

// BridgeServerOptions configures the HTTP hosting of the inbound Bridge.
type BridgeServerOptions struct {
	PathPrefix       string // default ""
	McpPath          string // default "/mcp"
	A2aPath          string // default "/a2a"
	A2aAgentCardPath string // default "/.well-known/agent.json"

	// RequireAuth defaults to TRUE. With auth required and no Verifier
	// configured, EVERY request is denied — fail closed.
	RequireAuth *bool
	Verifier    BridgeNidVerifier

	// MaxRequestBodyBytes caps the request body. 0 disables; default 1 MiB.
	MaxRequestBodyBytes int64
	// DispatchTimeoutMs bounds a single dispatch. 0 disables; default 30_000.
	DispatchTimeoutMs int

	// Logger receives server-side detail that is deliberately NOT leaked to the
	// foreign client. nil means log.Default().
	Logger *log.Logger
}

const (
	bridgeDefaultMaxBody   int64 = 1 << 20 // 1 MiB
	bridgeDefaultTimeoutMs       = 30_000
	bridgeBodyChunk              = 80 * 1024 // 80 KiB streaming accumulate
)

// BridgeServerApp is the inbound Bridge http.Handler.
type BridgeServerApp struct {
	inbound *BridgeInboundOptions
	opt     BridgeServerOptions
	mcp     *McpInboundServer
	a2a     *A2aInboundServer
	log     *log.Logger
}

// NewBridgeServerApp builds the inbound Bridge HTTP handler.
func NewBridgeServerApp(inbound *BridgeInboundOptions, opt BridgeServerOptions) *BridgeServerApp {
	if opt.McpPath == "" {
		opt.McpPath = "/mcp"
	}
	if opt.A2aPath == "" {
		opt.A2aPath = "/a2a"
	}
	if opt.A2aAgentCardPath == "" {
		opt.A2aAgentCardPath = "/.well-known/agent.json"
	}
	if opt.MaxRequestBodyBytes == 0 {
		opt.MaxRequestBodyBytes = bridgeDefaultMaxBody
	}
	if opt.DispatchTimeoutMs == 0 {
		opt.DispatchTimeoutMs = bridgeDefaultTimeoutMs
	}
	lg := opt.Logger
	if lg == nil {
		lg = log.Default()
	}
	return &BridgeServerApp{
		inbound: inbound,
		opt:     opt,
		mcp:     NewMcpInboundServer(inbound),
		a2a:     NewA2aInboundServer(inbound),
		log:     lg,
	}
}

// McpServer exposes the protocol server for stdio or direct in-process use.
func (a *BridgeServerApp) McpServer() *McpInboundServer { return a.mcp }

// A2aServer exposes the protocol server for direct in-process use.
func (a *BridgeServerApp) A2aServer() *A2aInboundServer { return a.a2a }

func (a *BridgeServerApp) requireAuth() bool {
	return a.opt.RequireAuth == nil || *a.opt.RequireAuth
}

func (a *BridgeServerApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := strings.TrimRight(a.opt.PathPrefix, "/")
	path := r.URL.Path
	if prefix != "" {
		if !strings.HasPrefix(path, prefix) {
			http.NotFound(w, r)
			return
		}
		path = path[len(prefix):]
	}
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}

	switch {
	case path == a.opt.A2aAgentCardPath || path == strings.TrimRight(a.opt.A2aAgentCardPath, "/"):
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !a.authorize(w, r) {
			return
		}
		a.writeJSON(w, 200, a.a2a.BuildAgentCard(r.Context(), a.endpointURL(r)))

	case path == a.opt.McpPath || path == a.opt.McpPath+"/sse":
		a.serveJsonRpc(w, r, a.mcp.Dispatch)

	case path == a.opt.A2aPath:
		a.serveJsonRpc(w, r, a.a2a.Dispatch)

	default:
		http.NotFound(w, r)
	}
}

type bridgeDispatcher func(ctx context.Context, req *BridgeJsonRpcRequest) BridgeJsonRpcResponse

func (a *BridgeServerApp) serveJsonRpc(w http.ResponseWriter, r *http.Request, dispatch bridgeDispatcher) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !a.authorize(w, r) {
		return
	}

	body, tooLarge := a.readBounded(r)
	if tooLarge {
		// HTTP 413 + a JSON-RPC error body.
		a.writeJsonRpcError(w, 413, JsonRpcInvalidRequest, "Request body exceeds the configured limit.")
		return
	}

	var req BridgeJsonRpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		a.writeJsonRpcError(w, 400, JsonRpcParseError, err.Error())
		return
	}

	ctx := r.Context()
	var cancel context.CancelFunc
	if a.opt.DispatchTimeoutMs > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(a.opt.DispatchTimeoutMs)*time.Millisecond)
		defer cancel()
	}

	done := make(chan BridgeJsonRpcResponse, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				// The catch-all arm logs server-side and returns a FIXED string:
				// no exception detail leaks to the foreign client.
				a.log.Printf("bridge: inbound dispatch panicked: %v", rec)
				done <- jsonRpcErr(requestID(&req), JsonRpcInternalError, "Bridge server request failed.", nil)
			}
		}()
		done <- dispatch(ctx, &req)
	}()

	select {
	case resp := <-done:
		a.writeJSON(w, 200, resp)
	case <-ctx.Done():
		if r.Context().Err() != nil {
			// A client abort is distinguished from a dispatch timeout.
			return
		}
		// The orphaned dispatch is drained out-of-band so its fault is logged
		// rather than lost.
		go func() {
			if late := <-done; late.Error != nil {
				a.log.Printf("bridge: orphaned dispatch finished with error %d: %s", late.Error.Code, late.Error.Message)
			}
		}()
		a.writeJsonRpcError(w, 504, JsonRpcUpstreamError, "Bridge dispatch timed out.")
	}
}

// authorize applies the §7 auth gate. Fail-closed: with auth required and no
// verifier configured, every request is denied.
func (a *BridgeServerApp) authorize(w http.ResponseWriter, r *http.Request) bool {
	if !a.requireAuth() {
		return true
	}
	agents := r.Header.Values(HeaderAgent)
	if len(agents) != 1 || strings.TrimSpace(agents[0]) == "" {
		a.deny(w)
		return false
	}
	nid := strings.TrimSpace(agents[0])
	if !BridgeIsValidAgentNid(nid) {
		a.deny(w)
		return false
	}
	if a.opt.Verifier == nil || !a.opt.Verifier(r.Context(), nid, r) {
		a.deny(w)
		return false
	}
	return true
}

func (a *BridgeServerApp) deny(w http.ResponseWriter) {
	a.writeJsonRpcError(w, 401, JsonRpcInvalidRequest, "Caller NID is missing or not authorized.")
}

// BridgeIsValidAgentNid is the syntactic X-NWP-Agent check: the
// `urn:nps:agent:` prefix, total length <= 512, then `{domain}:{identifier}`
// with domain chars [A-Za-z0-9.-], identifier chars [A-Za-z0-9._~:@/-], both
// segments non-empty.
func BridgeIsValidAgentNid(nid string) bool {
	const prefix = "urn:nps:agent:"
	if len(nid) > 512 || !strings.HasPrefix(nid, prefix) {
		return false
	}
	rest := nid[len(prefix):]
	i := strings.Index(rest, ":")
	if i <= 0 || i == len(rest)-1 {
		return false
	}
	domain, identifier := rest[:i], rest[i+1:]
	for _, c := range domain {
		if !isAlnum(c) && c != '.' && c != '-' {
			return false
		}
	}
	for _, c := range identifier {
		if !isAlnum(c) && !strings.ContainsRune("._~:@/-", c) {
			return false
		}
	}
	return true
}

func isAlnum(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// readBounded enforces MaxRequestBodyBytes TWICE: a Content-Length pre-check AND
// a streaming chunked accumulate that aborts as soon as the running total would
// exceed the cap. A lying or absent Content-Length therefore cannot bypass it.
func (a *BridgeServerApp) readBounded(r *http.Request) ([]byte, bool) {
	limit := a.opt.MaxRequestBodyBytes
	if limit <= 0 {
		raw, _ := io.ReadAll(r.Body)
		return raw, false
	}
	if cl := r.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n > limit {
			return nil, true
		}
	}

	var out []byte
	buf := make([]byte, bridgeBodyChunk)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			if int64(len(out))+int64(n) > limit {
				return nil, true
			}
			out = append(out, buf[:n]...)
		}
		if err != nil {
			return out, false
		}
	}
}

func (a *BridgeServerApp) endpointURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + r.Host + strings.TrimRight(a.opt.PathPrefix, "/") + a.opt.A2aPath
}

func (a *BridgeServerApp) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		a.log.Printf("bridge: failed to write response: %v", err)
	}
}

func (a *BridgeServerApp) writeJsonRpcError(w http.ResponseWriter, httpStatus, code int, message string) {
	a.writeJSON(w, httpStatus, jsonRpcErr(nullID, code, message, nil))
}
