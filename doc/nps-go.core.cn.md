[English Version](./nps-go.core.md) | 中文版

# `github.com/labacacia/NPS-sdk-go/core` — 参考

> 规范：[NPS-1 NCP v0.7](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-1-NCP.md)

基础包 —— 线路帧头、编码 tier、注册表校验的编解码器、
anchor 缓存、类型化错误。

---

## 目录

- [`Version`](#version)
- [`FrameType`](#frametype)
- [`EncodingTier`](#encodingtier)
- [`FrameHeader`](#frameheader)
- [`FrameDict`](#framedict)
- [`NpsFrameCodec`](#npsframecodec)
- [`FrameRegistry`](#frameregistry)
- [`AnchorFrameCache`](#anchorframecache)
- [错误类型](#错误类型)

---

## `Version`

```go
const Version = "1.0.0-alpha.18"
```

`Version` 是编译进 Go SDK 的套件版本。Release preparation 会将它和仓库
`VERSION` 文件一并更新；若二者发生漂移，测试套件将失败。

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

func FrameTypeFromByte(b byte) (FrameType, error)   // 未知时返回 error
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

其值为 flags 字节的 bit-7 状态。

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
func (h FrameHeader) HeaderSize() int              // 4 或 8
func (h FrameHeader) ToBytes() []byte

func ParseFrameHeader(wire []byte) (FrameHeader, error)
```

### Flags 字节

| Bit | Mask   | 含义 |
|-----|--------|------|
| 7   | `0x80` | TIER —— `1` = MsgPack，`0` = JSON |
| 6   | `0x40` | FINAL —— 流中最后一帧 |
| 0   | `0x01` | EXT —— 8 字节扩展帧头 |

### 线路布局

```
默认（EXT=0，4 字节）：
  [frame_type][flags][len_hi][len_lo]           — u16 大端长度

扩展（EXT=1，8 字节）：
  [frame_type][flags][0][0][len_b3..len_b0]     — u32 大端长度
```

`NewFrameHeader` 在 `payloadLen > 0xFFFF` 时自动启用 EXT。

---

## `FrameDict`

```go
type FrameDict = map[string]any
```

每个帧类型都通过 `FrameDict` 往返。底层 map 承载编解码器从 JSON /
MsgPack 解出的内容 —— 典型值类型有 `string`、`bool`、`float64`、
`int64`、`uint64`、`[]any`、`map[string]any`。协议包中的帧专属辅助
把它们归一化成有类型字段。

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

- 若序列化 payload 超过 `c.MaxPayload`，`Encode` 以 `*ErrCodec` 失败。
- 若帧头的 frame type 未在此编解码器的 `FrameRegistry` 中注册，
  `Decode` 以 `*ErrFrame` 失败。
- `PeekHeader` 是包级函数（无 receiver）—— 在分配前调用以得知完整
  帧长度。

通过直接在实例上设置 `codec.MaxPayload = …` 调整 payload 上限。

---

## `FrameRegistry`

```go
type FrameRegistry struct { /* … */ }

func NewFrameRegistry() *FrameRegistry                      // 空
func (r *FrameRegistry) Register(ft FrameType)
func (r *FrameRegistry) IsRegistered(ft FrameType) bool

func CreateDefaultRegistry() *FrameRegistry                 // 仅 NCP
func CreateFullRegistry()    *FrameRegistry                 // NCP+NWP+NIP+NDP+NOP
```

`CreateDefaultRegistry` 仅涵盖 NCP 帧
（`Anchor / Diff / Stream / Caps / Error`）。当解码 NWP / NIP / NDP / NOP
payload 或路由可能携带任意帧类型的响应时，使用 `CreateFullRegistry`。

---

## `AnchorFrameCache`

线程安全的 anchor-schema 缓存，带惰性 TTL 过期。内部使用
`sync.RWMutex`；单实例可安全并发使用。

```go
type AnchorFrameCache struct {
    Clock func() time.Time   // 可注入；默认 time.Now
    // 内部字段 …
}

func NewAnchorFrameCache() *AnchorFrameCache

// 规范（键排序）JSON 的 SHA-256 hex，前缀 "sha256:"。
func ComputeAnchorID(schema FrameDict) string

func (c *AnchorFrameCache) Set(schema FrameDict, ttlSecs int64) (string, error)
func (c *AnchorFrameCache) Get(id string) FrameDict                       // 缺失/过期时返回 nil
func (c *AnchorFrameCache) GetRequired(id string) (FrameDict, error)
func (c *AnchorFrameCache) Invalidate(id string)
func (c *AnchorFrameCache) Len() int                                      // 仅活跃数量
```

### 投毒

当同一 `anchor_id` 已以**不同** schema 缓存且仍然活跃时，`Set` 返回
`*ErrAnchorPoison`。以相同 schema 重新插入仅刷新 TTL。

### 惰性过期

`Get` / `GetRequired` / `Len` 按 `expires > clock()` 过滤，不改动
存储。无显式 `EvictExpired()` —— 过期条目在下次 `Set` 时被覆盖。

### 可注入 clock

```go
fake := time.Unix(1_700_000_000, 0)
cache := core.NewAnchorFrameCache()
cache.Clock = func() time.Time { return fake }
```

---

## 错误类型

```go
type ErrFrame          struct{ Msg string }
type ErrCodec          struct{ Msg string }
type ErrAnchorNotFound struct{ ID  string }
type ErrAnchorPoison   struct{ ID  string }
type ErrIdentity       struct{ Msg string }
```

全部五种通过指针 receiver 实现 `error`。用 `errors.As` 判别：

```go
var notFound *core.ErrAnchorNotFound
if errors.As(err, &notFound) {
    log.Printf("missing anchor: %s", notFound.ID)
}
```
