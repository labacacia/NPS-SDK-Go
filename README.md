English | [中文版](./README.cn.md)

# NPS Go SDK v1.0.0-alpha.18

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../../LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.0--alpha.18-orange.svg)](../../CHANGELOG.md)
[![NCP](https://img.shields.io/badge/NCP-v0.11-5b8cff.svg)]()
[![NWP](https://img.shields.io/badge/NWP-v0.21-4af0b0.svg)]()
[![NIP](https://img.shields.io/badge/NIP-v0.14-7b61ff.svg)]()
[![NDP](https://img.shields.io/badge/NDP-v0.12-f0a050.svg)]()
[![NOP](https://img.shields.io/badge/NOP-v0.9-ff8c42.svg)]()

Go reference implementation of the Neural Protocol Suite (NPS) — covers all five sub-protocols: **NCP · NWP · NIP · NDP · NOP** plus full NPS-RFC-0002 X.509 + ACME `agent-01` NID certificate primitives.

| | |
|---|---|
| **Module** | `github.com/labacacia/NPS-sdk-go` |
| **Go** | 1.26.5+ |
| **Tests** | Full suite and shared Alpha.18 fixtures passing |
| **License** | Apache 2.0 |

Alpha.15 additions: typed remote NIP CA client (`nip.NipCaClient`), native-mode NWP serving helper (`nwp.NwpNativeNodeServer`), and TC-N1/TC-N2 conformance manifest helpers (`conformance`).

---

## Packages

| Package | Protocol | Description |
|---------|----------|-------------|
| `core` | NCP | Frame types, header codec, registry, AnchorFrame cache |
| `ncp` | NCP | AnchorFrame, DiffFrame, StreamFrame, CapsFrame, HelloFrame, ErrorFrame |
| `nwp` | NWP | QueryFrame, ActionFrame, NwpClient (HTTP mode), NwpNativeNodeServer |
| `nip` | NIP | IdentFrame (v2 dual-trust), TrustFrame, RevokeFrame, NipIdentity (Ed25519), NipIdentVerifier (RFC-0002 §8.1 dual-trust), AssuranceLevel (RFC-0003) |
| `nip/x509` | NIP / RFC-0002 | `IssueLeaf` / `IssueRoot` / `Verify` — NPS X.509 NID certificates on stdlib `crypto/x509` |
| `nip/acme` | NIP / RFC-0002 | `Client` + `Server` (in-process) + JWS / messages — ACME `agent-01` flow |
| `ndp` | NDP | AnnounceFrame, ResolveFrame, GraphFrame, InMemoryNdpRegistry, NdpAnnounceValidator |
| `nop` | NOP | TaskFrame, DelegateFrame, SyncFrame, AlignStreamFrame, NopClient |
| `conformance` | CI / certification | TC-N1/TC-N2 conformance catalog, manifest builder, and validator |
| `daemon/observability` | Runtime | Health, readiness, metrics, structured logging, and graceful shutdown helpers |
| `telemetry` | Runtime | Lightweight counters, histograms, and span recording |

---

## Alpha.18 portable profiles

- NCP 0.11 bounded native-server handshake and deterministic Caps negotiation.
- NWP 0.21 portable Node/Bridge serving and bridge lifecycle.
- NIP 0.14 portable CA, live revocation, signed CRL, and verification policy.
- NDP 0.12 signed Announce admission and registry conflict/liveness policy.
- NOP 0.9 deterministic orchestration, callback security, delegation, leases,
  and CR-0007 runtime decisions.

All five profiles consume the language-neutral fixtures under
[`spec/conformance`](../../spec/conformance/).

## Installation

```bash
go get github.com/labacacia/NPS-sdk-go
```

---

## Quick Start

### NCP — Frame Codec

```go
import (
    "github.com/labacacia/NPS-sdk-go/core"
    "github.com/labacacia/NPS-sdk-go/ncp"
)

// Create a full registry (all 5 protocols)
reg := core.CreateFullRegistry()
codec := core.NewNpsFrameCodec(reg)

// Build and encode an AnchorFrame
frame := &ncp.AnchorFrame{
    AnchorID: "sha256:abc...",
    Schema:   core.FrameDict{"type": "object", "version": "1"},
    TTL:      3600,
}
wire, err := codec.Encode(frame.FrameType(), frame.ToDict(), core.EncodingTierMsgPack, true)
// wire is ready to send over the network

// Decode on the receiving end
ft, dict, err := codec.Decode(wire)
received := ncp.AnchorFrameFromDict(dict)
```

### NCP — AnchorFrame Cache

```go
cache := core.NewAnchorFrameCache()

// Store with TTL
schema := core.FrameDict{"type": "object", "fields": []any{"name", "value"}}
anchorID, err := cache.Set(schema, 3600) // 1-hour TTL

// Retrieve (returns nil if expired)
schema, err = cache.GetRequired(anchorID)
```

### NWP — HTTP Client

```go
import "github.com/labacacia/NPS-sdk-go/nwp"

client := nwp.NewNwpClient("http://node.example.com:17433")

// Query
qf := &nwp.QueryFrame{AnchorRef: "sha256:abc...", Filters: map[string]any{"status": "active"}}
capsFrame, err := client.Query(ctx, qf)

// Streaming
frames, err := client.Stream(ctx, qf)
for _, sf := range frames {
    fmt.Println(sf.Payload)
}

// Invoke (sync action)
af := &nwp.ActionFrame{Action: "create", Payload: map[string]any{"name": "item"}}
result, err := client.Invoke(ctx, af)

// Async invoke
af.Async = true
result, err = client.Invoke(ctx, af)
fmt.Println(result.Async.TaskID)
```

### NWP — Native Serving

```go
import (
    "context"

    "github.com/labacacia/NPS-sdk-go/ncp"
    "github.com/labacacia/NPS-sdk-go/nwp"
)

server := nwp.NewNwpNativeNodeServer()
server.QueryHandler = func(ctx context.Context, query *nwp.QueryFrame) (*ncp.CapsFrame, error) {
    return ncp.NewCapsFrame("native:orders", []any{map[string]any{"id": 42}}), nil
}
server.ActionHandler = func(ctx context.Context, action *nwp.ActionFrame) (any, error) {
    return map[string]any{"action": action.Action}, nil
}

// `rw` is already past NCP preamble, TLS, and Hello negotiation.
err := server.Serve(ctx, rw)
```

Native serving keeps decode/encode on the negotiated default tier, accepts
Tier-3 `binary_vector.v1` only when negotiated for QueryFrame payloads, and
rejects malformed BinaryVector payloads, including NaN/Inf float32 values.

### NIP — Identity & Signing

```go
import "github.com/labacacia/NPS-sdk-go/nip"

// Generate a new identity
id, err := nip.Generate()
fmt.Println(id.PubKeyString()) // "ed25519:<hex>"

// Sign a frame dict
payload := core.FrameDict{"nid": "urn:nps:node:example.com:agent", "pub_key": id.PubKeyString()}
sig := id.Sign(payload)

// Verify
ok := id.Verify(payload, sig)

// Verify with just the public key string (no private key needed)
ok = nip.VerifyWithPubKeyStr(payload, "ed25519:<hex>", sig)

// Save / Load (AES-256-GCM + PBKDF2-SHA256, 600k iterations)
err = id.Save("/path/to/identity.json", "my-passphrase")
loaded, err := nip.Load("/path/to/identity.json", "my-passphrase")
```

### NIP — Remote CA Client

```go
import "github.com/labacacia/NPS-sdk-go/nip"

ca := nip.NewNipCaClientFull("https://ca.example.com", "/nip", nil)
discovery, err := ca.GetDiscovery(ctx)
ident, err := ca.RegisterAgent(ctx, nip.NipCaRegisterRequest{
    Identifier:   "agent-a",
    PubKey:       "ed25519:<pub>",
    Capabilities: []string{"nwp:query"},
}, "token")
status, err := ca.VerifyAgent(ctx, ident.NID)
```

### Conformance Manifest

```go
import "github.com/labacacia/NPS-sdk-go/conformance"

cases, err := conformance.CatalogForProfile(conformance.NodeL1)
results := make([]conformance.CaseResult, 0, len(cases))
for _, c := range cases {
    results = append(results, conformance.CaseResult{ID: c.ID, Result: "pass"})
}
manifest := conformance.NewManifest(
    conformance.NodeL1,
    "my-node",
    "1.0.0-alpha.18",
    "urn:nps:node:example.com:my-node",
    "labacacia-fixture",
    "1.0.0-alpha.18",
    results,
    "ci",
)
validation := conformance.ValidateManifest(manifest)
```

### NDP — Discovery Registry

```go
import "github.com/labacacia/NPS-sdk-go/ndp"

registry := ndp.NewInMemoryNdpRegistry()

// Announce a node
frame := &ndp.AnnounceFrame{
    NID:       "urn:nps:node:example.com:agent",
    Addresses: []map[string]any{{"host": "example.com", "port": uint64(17433), "protocol": "nps"}},
    Caps:      []string{"nwp", "nop"},
    TTL:       300,
    Timestamp: time.Now().UTC().Format(time.RFC3339),
}
registry.Announce(frame)

// Resolve a target URL
result := registry.Resolve("nwp://example.com/agent")
// result.Host, result.Port, result.Protocol

// Validate announce signature
validator := ndp.NewNdpAnnounceValidator()
validator.RegisterPublicKey("urn:nps:node:example.com:agent", "ed25519:<hex>")
frame.Signature = id.Sign(frame.UnsignedDict())
result := validator.Validate(frame)
// result.IsValid, result.ErrorCode, result.Message
```

### NOP — Orchestration Client

```go
import "github.com/labacacia/NPS-sdk-go/nop"

client := nop.NewNopClient("http://orchestrator.example.com:17433")

// Submit a DAG task
tf := &nop.TaskFrame{
    TaskID:    "task-" + uuid,
    DAG:       map[string]any{...},
    TimeoutMs: &timeout,
}
taskID, err := client.Submit(ctx, tf)

// Poll status
status, err := client.GetStatus(ctx, taskID)
fmt.Println(status.State()) // "running"

// Wait for completion (polls every 500ms)
status, err = client.Wait(ctx, taskID, nil)
fmt.Println(status.State())        // "completed"
fmt.Println(status.NodeResults())  // map[string]any

// Cancel
err = client.Cancel(ctx, taskID)
```

---

## Frame Types

| Frame | Type Code | Package |
|-------|-----------|---------|
| AnchorFrame | 0x01 | `ncp` |
| DiffFrame | 0x02 | `ncp` |
| StreamFrame | 0x03 | `ncp` |
| CapsFrame | 0x04 | `ncp` |
| HelloFrame | 0x06 | `ncp` |
| QueryFrame | 0x10 | `nwp` |
| ActionFrame | 0x11 | `nwp` |
| IdentFrame | 0x20 | `nip` |
| TrustFrame | 0x21 | `nip` |
| RevokeFrame | 0x22 | `nip` |
| AnnounceFrame | 0x30 | `ndp` |
| ResolveFrame | 0x31 | `ndp` |
| GraphFrame | 0x32 | `ndp` |
| TaskFrame | 0x40 | `nop` |
| DelegateFrame | 0x41 | `nop` |
| SyncFrame | 0x42 | `nop` |
| AlignStreamFrame | 0x43 | `nop` |
| ErrorFrame | 0xFE | `ncp` |

---

## Encoding

| Tier | Constant | Notes |
|------|----------|-------|
| JSON | `core.EncodingTierJSON` | Human-readable, Tier-1 |
| MsgPack | `core.EncodingTierMsgPack` | ~60% size reduction, Tier-2 (default) |
| BinaryVector | `core.EncodingTierBinaryVector` | `binary_vector.v1`, Tier-3 for vector-heavy frames |

---

## Backoff Strategies (NOP)

```go
delay := nop.ComputeDelayMs(nop.BackoffExponential, 100, 5000, attempt)
// BackoffFixed, BackoffLinear, BackoffExponential
```

---

## Running Tests

```bash
go test ./...
```

---

## License

Apache 2.0 — Copyright 2026 INNO LOTUS PTY LTD
