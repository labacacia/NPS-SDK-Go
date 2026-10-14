English | [中文版](./nps-go.ncp.cn.md)

# `github.com/labacacia/NPS-sdk-go/ncp` — Reference

> Spec: [NPS-1 NCP v0.7](https://github.com/labacacia/NPS/blob/main/spec/NPS-1-NCP.md)

The five NCP frame types. Every struct exposes the same trio:

```go
func (f *XxxFrame) FrameType() core.FrameType
func (f *XxxFrame) ToDict()    core.FrameDict
func XxxFrameFromDict(d core.FrameDict) *XxxFrame
```

> **Note — Go frame shapes.** The Go NCP structs carry a slightly different
> field set from the Java / Python / .NET / TS SDKs — the layouts below are
> authoritative for this module.

---

## Table of contents

- [`AnchorFrame` (0x01)](#anchorframe-0x01)
- [`DiffFrame` (0x02)](#diffframe-0x02)
- [`StreamFrame` (0x03)](#streamframe-0x03)
- [`CapsFrame` (0x04)](#capsframe-0x04)
- [`ErrorFrame` (0xFE)](#errorframe-0xfe)

---

## `AnchorFrame` (0x01)

Publishes a schema anchor + TTL.

```go
type AnchorFrame struct {
    AnchorID    string
    Schema      core.FrameDict
    Namespace   *string
    Description *string
    NodeType    *string          // e.g. "memory" | "action" | …
    TTL         uint64           // seconds; from_dict defaults to 3600
}
```

`Schema` is stored as a free-form `core.FrameDict` — typically
`{"fields": [ {"name": …, "type": …}, … ]}` but any shape your nodes and
clients agree on is valid. `AnchorFrameFromDict` falls back to `TTL = 3600`
when the field is missing / zero.

To produce the content-addressed `AnchorID` deterministically use
[`core.ComputeAnchorID`](./nps-go.core.md#anchorframecache).

---

## `DiffFrame` (0x02)

Schema evolution between two anchors.

```go
type DiffFrame struct {
    AnchorID    string        // old anchor
    NewAnchorID string        // new anchor
    Patch       []any         // JSON-Patch-shaped ops (free-form)
}
```

`Patch` is serialized verbatim — this module does not validate the ops; the
receiver is expected to know the patch dialect (NPS-1 §5.2 uses
RFC 6902-compatible shape).

---

## `StreamFrame` (0x03)

One chunk of a streamed response. Multiple `StreamFrame`s tile out a
result; the final chunk sets `IsLast = true`.

```go
type StreamFrame struct {
    AnchorID string
    Seq      uint64
    Payload  any        // opaque — any JSON-representable value
    IsLast   bool
}
```

The wire-level `FINAL` flag (bit 6 of the header) is **separate** from
`IsLast`. `IsLast` is an in-payload business marker used by
[`NwpClient.Stream`](./nps-go.nwp.md#nwpclient) to stop iterating.

---

## `CapsFrame` (0x04)

Node capability / response-envelope frame.

```go
type CapsFrame struct {
    NodeID    string
    Caps      []string          // capability URIs
    AnchorRef *string           // anchor being answered against
    Payload   any               // opaque response data
}
```

In the Go SDK `CapsFrame` is the **default response envelope** for NWP:
`NwpClient.Query` returns a `*CapsFrame` directly (it reads `AnchorRef` +
`Payload`). Caps-advertisement usage and response usage share the same
struct — differentiate by inspecting `Caps` vs `Payload`.

`CapsFrameFromDict` accepts either `[]string` or `[]any` for the `caps`
field — MsgPack-decoded payloads typically surface as `[]any`, JSON
payloads as `[]any` of strings; both are normalised to `[]string`.

---

## `ErrorFrame` (0xFE)

Unified protocol-level error.

```go
type ErrorFrame struct {
    ErrorCode string        // "NWP-QUERY-ANCHOR-UNKNOWN", …
    Message   string
    Detail    any           // free-form extra context
}
```

See [`error-codes.md`](https://github.com/labacacia/NPS/blob/main/spec/error-codes.md)
for the namespace.

---

## End-to-end

```go
import (
    "github.com/labacacia/NPS-sdk-go/core"
    "github.com/labacacia/NPS-sdk-go/ncp"
)

codec := core.NewNpsFrameCodec(core.CreateDefaultRegistry())

schema := core.FrameDict{
    "fields": []any{
        map[string]any{"name": "id", "type": "uint64"},
    },
}
namespace  := "example.products"
description := "product catalog v1"
nodeType   := "memory"

frame := &ncp.AnchorFrame{
    AnchorID:    core.ComputeAnchorID(schema),
    Schema:      schema,
    Namespace:   &namespace,
    Description: &description,
    NodeType:    &nodeType,
    TTL:         3600,
}

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
    _ = back.TTL   // 3600
}
```
