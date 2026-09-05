English | [中文版](./nps-go.core.cn.md)

# `github.com/labacacia/NPS-sdk-go/core` — Reference

> Spec: [NPS-1 NCP v0.7](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-1-NCP.md)

Foundation package — wire header, encoding tiers, registry-validated
codec, anchor cache, typed errors.

---

## Table of contents

- [`Version`](#version)
- [`FrameType`](#frametype)
- [`EncodingTier`](#encodingtier)
- [`FrameHeader`](#frameheader)
- [`FrameDict`](#framedict)
- [`NpsFrameCodec`](#npsframecodec)
- [`FrameRegistry`](#frameregistry)
- [`AnchorFrameCache`](#anchorframecache)
- [Error types](#error-types)

---

## `Version`

```go
const Version = "1.0.0-alpha.18"
```

`Version` is the suite version compiled into the Go SDK. Release preparation
updates it together with the repository `VERSION` file, and the test suite
fails if they diverge.

---

## `FrameType`

```go
type FrameType uint8

const (
    FrameTypeAnchor      FrameType = 0x01
    FrameTypeDiff        FrameType = 0x02
    FrameTypeStream      FrameType = 0x03
    FrameTypeCaps        FrameType = 0x04
    FrameTypeQuery       FrameType = 0x10
    FrameTypeAction      FrameType = 0x11
    FrameTypeIdent       FrameType = 0x20
    FrameTypeTrust       FrameType = 0x21
    FrameTypeRevoke      FrameType = 0x22
    FrameTypeAnnounce    FrameType = 0x30
    FrameTypeResolve     FrameType = 0x31
    FrameTypeGraph       FrameType = 0x32
    FrameTypeTask        FrameType = 0x40
    FrameTypeDelegate    FrameType = 0x41
    FrameTypeSync        FrameType = 0x42
    FrameTypeAlignStream FrameType = 0x43
    FrameTypeError       FrameType = 0xFE
)

func FrameTypeFromByte(b byte) (FrameType, error)   // error on unknown
```

---

## `EncodingTier`

```go
type EncodingTier uint8

const (
    EncodingTierJSON    EncodingTier = 0
    EncodingTierMsgPack EncodingTier = 1
)
```

The value is the bit-7 state of the flags byte.

---

## `FrameHeader`

```go
type FrameHeader struct {
    FrameType     FrameType
    Flags         uint8
    PayloadLength uint64
    IsExtended    bool
}

func NewFrameHeader(ft FrameType, tier EncodingTier,
                    isFinal bool, payloadLen uint64) FrameHeader

func (h FrameHeader) EncodingTier() EncodingTier   // bit 7
func (h FrameHeader) IsFinal() bool                // bit 6
func (h FrameHeader) HeaderSize() int              // 4 or 8
func (h FrameHeader) ToBytes() []byte

func ParseFrameHeader(wire []byte) (FrameHeader, error)
```

### Flags byte

| Bit | Mask   | Meaning |
|-----|--------|---------|
| 7   | `0x80` | TIER — `1` = MsgPack, `0` = JSON |
| 6   | `0x40` | FINAL — last frame in a stream |
| 0   | `0x01` | EXT — 8-byte extended header |

### Wire layout

```
Default (EXT=0, 4 bytes):
  [frame_type][flags][len_hi][len_lo]           — u16 big-endian length

Extended (EXT=1, 8 bytes):
  [frame_type][flags][0][0][len_b3..len_b0]     — u32 big-endian length
```

`NewFrameHeader` auto-enables EXT when `payloadLen > 0xFFFF`.

---

## `FrameDict`

```go
type FrameDict = map[string]any
```

Every frame type round-trips through `FrameDict`. The underlying map
carries whatever the codec pulled out of JSON / MsgPack — typical
value types are `string`, `bool`, `float64`, `int64`, `uint64`,
`[]any`, `map[string]any`. Frame-specific helpers (in the protocol
packages) normalise these into typed fields.

---

## `NpsFrameCodec`

```go
const DefaultMaxPayload = 10 * 1024 * 1024   // 10 MiB

type NpsFrameCodec struct {
    Registry   *FrameRegistry
    MaxPayload int64
}

func NewNpsFrameCodec(reg *FrameRegistry) *NpsFrameCodec

func (c *NpsFrameCodec) Encode(
    ft       FrameType,
    dict     FrameDict,
    tier     EncodingTier,
    isFinal  bool,
) ([]byte, error)

func (c *NpsFrameCodec) Decode(wire []byte) (FrameType, FrameDict, error)

func PeekHeader(wire []byte) (FrameHeader, error)
```

- `Encode` fails with `*ErrCodec` if the serialised payload exceeds
  `c.MaxPayload`.
- `Decode` fails with `*ErrFrame` if the header's frame type is not
  registered against this codec's `FrameRegistry`.
- `PeekHeader` is a package-level function (no receiver) — call it
  before allocating to know the full frame length.

Adjust the payload cap by setting `codec.MaxPayload = …` directly on
the instance.

---

## `FrameRegistry`

```go
type FrameRegistry struct { /* … */ }

func NewFrameRegistry() *FrameRegistry                      // empty
func (r *FrameRegistry) Register(ft FrameType)
func (r *FrameRegistry) IsRegistered(ft FrameType) bool

func CreateDefaultRegistry() *FrameRegistry                 // NCP only
func CreateFullRegistry()    *FrameRegistry                 // NCP+NWP+NIP+NDP+NOP
```

`CreateDefaultRegistry` covers only the NCP frames
(`Anchor / Diff / Stream / Caps / Error`). Use `CreateFullRegistry`
when decoding NWP / NIP / NDP / NOP payloads or when routing a
response that may carry any frame type.

---

## `AnchorFrameCache`

Thread-safe anchor-schema cache with lazy TTL expiry. Uses an internal
`sync.RWMutex`; a single instance is safe for concurrent use.

```go
type AnchorFrameCache struct {
    Clock func() time.Time   // injectable; default time.Now
    // internal fields …
}

func NewAnchorFrameCache() *AnchorFrameCache

// SHA-256 hex of canonical (sorted-key) JSON, prefixed "sha256:".
func ComputeAnchorID(schema FrameDict) string

func (c *AnchorFrameCache) Set(schema FrameDict, ttlSecs int64) (string, error)
func (c *AnchorFrameCache) Get(id string) FrameDict                       // nil if missing/expired
func (c *AnchorFrameCache) GetRequired(id string) (FrameDict, error)
func (c *AnchorFrameCache) Invalidate(id string)
func (c *AnchorFrameCache) Len() int                                      // live count only
```

### Poisoning

`Set` returns `*ErrAnchorPoison` when the same `anchor_id` is already
cached with a **different** schema and still live. Re-inserts with an
identical schema simply refresh the TTL.

### Lazy expiry

`Get` / `GetRequired` / `Len` filter by `expires > clock()` without
mutating the store. There is no explicit `EvictExpired()` — expired
entries are overwritten on next `Set`.

### Injectable clock

```go
fake := time.Unix(1_700_000_000, 0)
cache := core.NewAnchorFrameCache()
cache.Clock = func() time.Time { return fake }
```

---

## Error types

```go
type ErrFrame          struct{ Msg string }
type ErrCodec          struct{ Msg string }
type ErrAnchorNotFound struct{ ID  string }
type ErrAnchorPoison   struct{ ID  string }
type ErrIdentity       struct{ Msg string }
```

All five implement `error` via a pointer receiver. Use `errors.As` to
discriminate:

```go
var notFound *core.ErrAnchorNotFound
if errors.As(err, &notFound) {
    log.Printf("missing anchor: %s", notFound.ID)
}
```
