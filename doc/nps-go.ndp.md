English | [中文版](./nps-go.ndp.cn.md)

# `github.com/labacacia/NPS-sdk-go/ndp` — Reference

> Spec: [NPS-4 NDP v0.8](https://github.com/labacacia/NPS/blob/main/spec/NPS-4-NDP.md)

Discovery layer — the NPS analogue of DNS. Three frames, an in-memory TTL
registry, and a signature validator.

---

## Table of contents

- [`AnnounceFrame` (0x30)](#announceframe-0x30)
- [`ResolveFrame` (0x31)](#resolveframe-0x31)
- [`GraphFrame` (0x32)](#graphframe-0x32)
- [`InMemoryNdpRegistry`](#inmemoryndpregistry)
- [`ResolveResult`](#resolveresult)
- [`NdpAnnounceValidator`](#ndpannouncevalidator)
- [`NdpAnnounceResult`](#ndpannounceresult)

---

## `AnnounceFrame` (0x30)

Publishes a node's physical reachability and TTL (NPS-4 §3.1).

```go
type AnnounceFrame struct {
    NID       string
    Addresses []map[string]any       // [{"host","port","protocol"}, …]
    Caps      []string
    TTL       uint64                 // seconds; 0 = shutdown
    Timestamp string                 // ISO 8601 UTC
    Signature string                 // "ed25519:{base64}"
    NodeType  *string
}

func (f *AnnounceFrame) UnsignedDict() core.FrameDict   // canonical (sorted) + signature stripped
func (f *AnnounceFrame) ToDict()       core.FrameDict
func AnnounceFrameFromDict(d core.FrameDict) *AnnounceFrame
```

`UnsignedDict()` returns a sorted dict (keys inserted in lexical order),
so signing via `nip.NipIdentity.Sign` is a single call — the canonical
JSON and the dict you sign share the same key order. `AnnounceFrameFromDict`
defaults `TTL` to `300` when absent / zero.

Publishing `TTL = 0` SHOULD precede a graceful shutdown so subscribers
evict the entry promptly.

---

## `ResolveFrame` (0x31)

Request / response envelope for resolving an `nwp://` URL.

```go
type ResolveFrame struct {
    Target       string             // "nwp://..."
    RequesterNID *string
    Resolved     map[string]any     // set on response
}
```

---

## `GraphFrame` (0x32)

Topology sync between registries.

```go
type GraphFrame struct {
    Seq         uint64             // strictly monotonic per publisher
    InitialSync bool                // full snapshot flag
    Nodes       []any               // full dump when InitialSync = true
    Patch       []any               // RFC 6902 ops for incremental sync
}
```

Gaps in `Seq` trigger a re-sync request signalled with
`NDP-GRAPH-SEQ-GAP` (see
[`error-codes.md`](https://github.com/labacacia/NPS/blob/main/spec/error-codes.md)).

---

## `InMemoryNdpRegistry`

In-memory, concurrency-safe registry with TTL expiry evaluated **lazily**
on every read. Uses an internal `sync.RWMutex`; a single instance is safe
for concurrent use.

```go
type InMemoryNdpRegistry struct {
    Clock func() time.Time          // injectable; default time.Now
    // internal fields …
}

func NewInMemoryNdpRegistry() *InMemoryNdpRegistry

func (r *InMemoryNdpRegistry) Announce  (frame *AnnounceFrame)
func (r *InMemoryNdpRegistry) GetByNID  (nid string)      *AnnounceFrame   // nil if missing/expired
func (r *InMemoryNdpRegistry) Resolve   (target string)   *ResolveResult   // nil if unresolved
func (r *InMemoryNdpRegistry) GetAll    ()                []*AnnounceFrame // live entries only

// Package-level helper.
func NwpTargetMatchesNID(nid, target string) bool
```

### Behaviour

- `Announce` with `TTL == 0` evicts the NID immediately. Otherwise the
  entry is stored with an absolute expiry of `Clock() + TTL seconds` —
  subsequent announces refresh the entry in place.
- `GetByNID` / `Resolve` / `GetAll` skip expired entries without mutating
  the store.
- `Resolve` scans live entries, finds the **first** NID that covers
  `target`, and returns its **first** advertised address as a
  `*ResolveResult`.

### `NwpTargetMatchesNID(nid, target)`

Covering rule — free-standing package-level helper:

```
NID:    urn:nps:node:{authority}:{path}
Target: nwp://{authority}/{path}[/sub/path]
```

A node NID covers a target when:

1. `target` starts with `"nwp://"`.
2. The NID authority equals the target authority (exact,
   case-sensitive).
3. The target path equals `{path}` exactly, or starts with `{path}/`
   (sibling prefixes like `"data"` vs `"dataset"` do **not** match).

Returns `false` on malformed inputs — never panics.

### Injectable clock

```go
fake := time.Unix(1_700_000_000, 0)
registry := ndp.NewInMemoryNdpRegistry()
registry.Clock = func() time.Time { return fake }
```

---

## `ResolveResult`

```go
type ResolveResult struct {
    Host     string
    Port     uint64
    Protocol string
}
```

Fields are extracted directly from the first `map[string]any` in
`AnnounceFrame.Addresses` — missing / typed-mismatched values surface as
zero (`""`, `0`) rather than defaults.

---

## `NdpAnnounceValidator`

Verifies an `AnnounceFrame.Signature` against a registered Ed25519 public
key. Uses an internal `sync.RWMutex`; a single instance is safe for
concurrent use.

```go
type NdpAnnounceValidator struct { /* … */ }

func NewNdpAnnounceValidator() *NdpAnnounceValidator

func (v *NdpAnnounceValidator) RegisterPublicKey(nid, pubKey string)
func (v *NdpAnnounceValidator) RemovePublicKey  (nid string)
func (v *NdpAnnounceValidator) KnownPublicKeys  () map[string]string   // snapshot copy

func (v *NdpAnnounceValidator) Validate(frame *AnnounceFrame) NdpAnnounceResult
```

Validation sequence (NPS-4 §7.1):

1. Look up `frame.NID` in the registered keys. Missing →
   `NdpAnnounceResult{IsValid:false, ErrorCode:"NDP-ANNOUNCE-NID-MISMATCH"}`.
   Expected workflow: verify the announcer's `IdentFrame` first, then
   `RegisterPublicKey(nid, ident.PubKey)`.
2. `Signature` MUST start with `"ed25519:"`, else
   `NDP-ANNOUNCE-SIG-INVALID`.
3. Rebuild the signing payload from `frame.UnsignedDict()` (already
   sorted) and call
   [`nip.VerifyWithPubKeyStr`](./nps-go.nip.md#nipidentity).
4. Return `NdpAnnounceResult{IsValid:true}` on success, else
   `NDP-ANNOUNCE-SIG-INVALID`.

Register keys using the exact string produced by
`NipIdentity.PubKeyString()` — i.e. `"ed25519:{hex}"`.

---

## `NdpAnnounceResult`

```go
type NdpAnnounceResult struct {
    IsValid   bool
    ErrorCode string       // "" when IsValid
    Message   string
}
```

---

## End-to-end

```go
import (
    "time"
    "github.com/labacacia/NPS-sdk-go/ndp"
    "github.com/labacacia/NPS-sdk-go/nip"
)

id, _ := nip.Generate()
nid   := "urn:nps:node:api.example.com:products"

// Build + sign the announce
nodeType := "memory"
unsigned := &ndp.AnnounceFrame{
    NID: nid,
    Addresses: []map[string]any{
        {"host": "10.0.0.5", "port": uint64(17433), "protocol": "nwp+tls"},
    },
    Caps:      []string{"nwp:query", "nwp:stream"},
    TTL:       300,
    Timestamp: time.Now().UTC().Format(time.RFC3339),
    NodeType:  &nodeType,
}
unsigned.Signature = id.Sign(unsigned.UnsignedDict())

// Validate + register
validator := ndp.NewNdpAnnounceValidator()
validator.RegisterPublicKey(nid, id.PubKeyString())
result := validator.Validate(unsigned)
_ = result.IsValid   // true

// Resolve
registry := ndp.NewInMemoryNdpRegistry()
registry.Announce(unsigned)
resolved := registry.Resolve("nwp://api.example.com/products/items/42")
if resolved != nil {
    _ = resolved.Host    // "10.0.0.5"
    _ = resolved.Port    // 17433
}
```
