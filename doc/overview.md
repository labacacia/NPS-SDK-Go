English | [中文版](./overview.cn.md)

# NPS Go SDK — API Reference

> Go client library for the Neural Protocol Suite. Module path:
> `github.com/labacacia/NPS-sdk-go`, Go 1.23+ (recommended 1.25+).

This directory is the package-and-function reference for the Go SDK.
For a narrative walkthrough see [`sdk-usage.md`](./sdk-usage.md)
(English) / [`sdk-usage.cn.md`](./sdk-usage.cn.md) (中文).

---

## Packages

| Import suffix | Purpose | Reference |
|---------------|---------|-----------|
| `/core` | Frame header, codec (Tier-1 JSON / Tier-2 MsgPack), registry, anchor cache, errors | [`nps-go.core.md`](./nps-go.core.md) |
| `/ncp`  | NCP frames — `AnchorFrame`, `DiffFrame`, `StreamFrame`, `CapsFrame`, `ErrorFrame` | [`nps-go.ncp.md`](./nps-go.ncp.md) |
| `/nwp`  | NWP frames + HTTP `NwpClient` | [`nps-go.nwp.md`](./nps-go.nwp.md) |
| `/nip`  | NIP frames + `NipIdentity` (Ed25519, AES-256-GCM key store) | [`nps-go.nip.md`](./nps-go.nip.md) |
| `/ndp`  | NDP frames + `InMemoryNdpRegistry` + `NdpAnnounceValidator` | [`nps-go.ndp.md`](./nps-go.ndp.md) |
| `/nop`  | NOP frames + `BackoffStrategy` + `NopTaskStatus` + `NopClient` | [`nps-go.nop.md`](./nps-go.nop.md) |

Module root is `github.com/labacacia/NPS-sdk-go`; every package above is
imported as `"github.com/labacacia/NPS-sdk-go/{core,ncp,nwp,nip,ndp,nop}"`.

---

## Install

```bash
go get github.com/labacacia/NPS-sdk-go@v1.0.0-alpha.13
```

Runtime dependencies (resolved by `go mod tidy`):

- `github.com/vmihailenco/msgpack/v5` — MsgPack codec
- `golang.org/x/crypto/pbkdf2` — key derivation for `NipIdentity`
- `crypto/ed25519`, `crypto/aes`, `crypto/cipher` — stdlib

---

## Minimal encode / decode

```go
import (
    "github.com/labacacia/NPS-sdk-go/core"
    "github.com/labacacia/NPS-sdk-go/ncp"
)

codec := core.NewNpsFrameCodec(core.CreateFullRegistry())

schema := core.FrameDict{
    "fields": []any{
        map[string]any{"name": "id",    "type": "uint64"},
        map[string]any{"name": "price", "type": "decimal"},
    },
}
anchorID := core.ComputeAnchorID(schema)
frame := &ncp.AnchorFrame{AnchorID: anchorID, Schema: schema, TTL: 3600}

wire, err := codec.Encode(
    frame.FrameType(),
    frame.ToDict(),
    core.EncodingTierMsgPack,
    true, // isFinal
)
if err != nil { /* … */ }

ft, dict, err := codec.Decode(wire)
if err != nil { /* … */ }
if ft == core.FrameTypeAnchor {
    back := ncp.AnchorFrameFromDict(dict)
    _ = back
}
```

The codec is dict-oriented: each frame struct exposes
`FrameType() core.FrameType` + `ToDict() core.FrameDict`, and each
package ships a `{Frame}FromDict(core.FrameDict) *{Frame}` constructor.
Call these explicitly around `codec.Encode` / `codec.Decode`.

---

## Encoding tiers

| Tier | Constant | Wire flag (bit 7) | Notes |
|------|----------|-------------------|-------|
| Tier-1 JSON    | `core.EncodingTierJSON`    | `0` | UTF-8 JSON, debug / interop |
| Tier-2 MsgPack | `core.EncodingTierMsgPack` | `1` | `msgpack/v5`, production default |

**Flag byte layout** (matches the Rust SDK; differs from Java / Python / TS):

| Bit | Mask   | Meaning |
|-----|--------|---------|
| 7   | `0x80` | TIER — `1` = MsgPack, `0` = JSON |
| 6   | `0x40` | FINAL — last frame in a stream |
| 0   | `0x01` | EXT — 8-byte extended header (payload > 65 535 bytes) |

Header sizes: 4 bytes default, 8 bytes when `EXT = 1`
(`[type][flags][0][0][len_b3..len_b0]`). Max payload defaults to 10 MiB
(`core.DefaultMaxPayload`) — raise by setting `codec.MaxPayload` after
construction.

---

## HTTP clients

- `NwpClient` (`/nwp`) uses `net/http`, `Content-Type: application/x-nps-frame`.
- `NopClient` (`/nop`) uses `net/http`, `Content-Type: application/json`
  (tasks are submitted as plain JSON dicts, not framed NPS payloads).
- Both constructors accept an optional `*http.Client`; pass `nil` to
  use `http.DefaultClient`.
- Every public method takes a `context.Context` — cancellation /
  deadlines propagate through to the underlying HTTP request.

---

## Errors

`core/errors.go` defines pointer error types — use
`errors.As` to unwrap:

| Type | Raised by |
|------|-----------|
| `*core.ErrFrame`          | Unknown / unregistered frame types, missing fields |
| `*core.ErrCodec`          | JSON / MsgPack encode / decode failure, payload oversized |
| `*core.ErrAnchorNotFound` | `AnchorFrameCache.GetRequired` on missing / expired anchor |
| `*core.ErrAnchorPoison`   | `AnchorFrameCache.Set` with schema mismatch for same `anchor_id` |
| `*core.ErrIdentity`       | Key gen / save / load / PBKDF2 / AES-GCM failure |

Non-2xx HTTP responses surface as `fmt.Errorf` with the pattern
`"NWP /{path} failed: HTTP {status}"` or
`"NOP {op} failed: HTTP {status}"`.

---

## Spec links

- [NPS-0 Overview](https://github.com/labacacia/NPS/blob/main/spec/NPS-0-Overview.md)
- [NPS-1 NCP](https://github.com/labacacia/NPS/blob/main/spec/NPS-1-NCP.md)
- [NPS-2 NWP](https://github.com/labacacia/NPS/blob/main/spec/NPS-2-NWP.md)
- [NPS-3 NIP](https://github.com/labacacia/NPS/blob/main/spec/NPS-3-NIP.md)
- [NPS-4 NDP](https://github.com/labacacia/NPS/blob/main/spec/NPS-4-NDP.md)
- [NPS-5 NOP](https://github.com/labacacia/NPS/blob/main/spec/NPS-5-NOP.md)
- [Frame registry](https://github.com/labacacia/NPS/blob/main/spec/frame-registry.yaml)
- [Error codes](https://github.com/labacacia/NPS/blob/main/spec/error-codes.md)
