[English Version](./nps-go.ndp.md) | 中文版

# `github.com/labacacia/NPS-sdk-go/ndp` — 参考

> 规范：[NPS-4 NDP v0.8](https://github.com/labacacia/NPS/blob/main/spec/NPS-4-NDP.md)

发现层 —— NPS 对应 DNS 的组件。三个帧、一个内存 TTL 注册表，以及
签名校验器。

---

## 目录

- [`AnnounceFrame` (0x30)](#announceframe-0x30)
- [`ResolveFrame` (0x31)](#resolveframe-0x31)
- [`GraphFrame` (0x32)](#graphframe-0x32)
- [`InMemoryNdpRegistry`](#inmemoryndpregistry)
- [`ResolveResult`](#resolveresult)
- [`NdpAnnounceValidator`](#ndpannouncevalidator)
- [`NdpAnnounceResult`](#ndpannounceresult)

---

## `AnnounceFrame` (0x30)

发布节点的物理可达性与 TTL（NPS-4 §3.1）。

```go
type AnnounceFrame struct {
    NID       string
    Addresses []map[string]any       // [{"host","port","protocol"}, …]
    Caps      []string
    TTL       uint64                 // 秒；0 = 下线
    Timestamp string                 // ISO 8601 UTC
    Signature string                 // "ed25519:{base64}"
    NodeType  *string
}

func (f *AnnounceFrame) UnsignedDict() core.FrameDict   // 规范（排序）+ 去除 signature
func (f *AnnounceFrame) ToDict()       core.FrameDict
func AnnounceFrameFromDict(d core.FrameDict) *AnnounceFrame
```

`UnsignedDict()` 返回按字典序插入键的有序 dict，所以经
`nip.NipIdentity.Sign` 签名是单次调用 —— 规范 JSON 与待签 dict 共用
同一键顺序。`AnnounceFrameFromDict` 在 `TTL` 缺失 / 为零时缺省 `300`。

发布 `TTL = 0` 应先于优雅下线，以便订阅者及时清除条目。

---

## `ResolveFrame` (0x31)

解析 `nwp://` URL 的请求 / 响应信封。

```go
type ResolveFrame struct {
    Target       string             // "nwp://..."
    RequesterNID *string
    Resolved     map[string]any     // 响应时设置
}
```

---

## `GraphFrame` (0x32)

注册表之间的拓扑同步。

```go
type GraphFrame struct {
    Seq         uint64             // 每个发布者严格单调
    InitialSync bool                // 全量快照标志
    Nodes       []any               // 当 InitialSync = true 时为全量
    Patch       []any               // 增量同步的 RFC 6902 ops
}
```

`Seq` 跳号触发重新同步请求，信号为 `NDP-GRAPH-SEQ-GAP`
（见 [`error-codes.md`](https://github.com/labacacia/NPS/blob/main/spec/error-codes.md)）。

---

## `InMemoryNdpRegistry`

内存、并发安全注册表，TTL 过期在每次读取时**惰性**评估。
内部使用 `sync.RWMutex`；单实例可安全并发使用。

```go
type InMemoryNdpRegistry struct {
    Clock func() time.Time          // 可注入；默认 time.Now
    // 内部字段 …
}

func NewInMemoryNdpRegistry() *InMemoryNdpRegistry

func (r *InMemoryNdpRegistry) Announce  (frame *AnnounceFrame)
func (r *InMemoryNdpRegistry) GetByNID  (nid string)      *AnnounceFrame   // 缺失/过期为 nil
func (r *InMemoryNdpRegistry) Resolve   (target string)   *ResolveResult   // 未解析为 nil
func (r *InMemoryNdpRegistry) GetAll    ()                []*AnnounceFrame // 仅活跃条目

// 包级辅助。
func NwpTargetMatchesNID(nid, target string) bool
```

### 行为

- `Announce` 若 `TTL == 0` 立即清除该 NID。否则以绝对过期
  `Clock() + TTL 秒` 存储条目 —— 后续 announce 就地刷新条目。
- `GetByNID` / `Resolve` / `GetAll` 跳过过期条目且不改动存储。
- `Resolve` 扫描活跃条目，找到覆盖 `target` 的**第一个** NID，
  返回其**第一个**广告地址作为 `*ResolveResult`。

### `NwpTargetMatchesNID(nid, target)`

覆盖规则 —— 独立包级辅助：

```
NID:    urn:nps:node:{authority}:{path}
Target: nwp://{authority}/{path}[/sub/path]
```

节点 NID 覆盖某 target 的条件：

1. `target` 以 `"nwp://"` 开头。
2. NID authority 等于 target authority（精确，区分大小写）。
3. Target path 精确等于 `{path}`，或以 `{path}/` 开头
   （像 `"data"` vs `"dataset"` 这样的兄弟前缀**不**匹配）。

输入格式错误时返回 `false` —— 从不 panic。

### 可注入 clock

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

字段直接从 `AnnounceFrame.Addresses` 的第一个 `map[string]any` 中抽取
—— 缺失 / 类型不匹配时以零值（`""`、`0`）浮现，而非默认值。

---

## `NdpAnnounceValidator`

依据已注册的 Ed25519 公钥校验 `AnnounceFrame.Signature`。内部使用
`sync.RWMutex`；单实例可安全并发使用。

```go
type NdpAnnounceValidator struct { /* … */ }

func NewNdpAnnounceValidator() *NdpAnnounceValidator

func (v *NdpAnnounceValidator) RegisterPublicKey(nid, pubKey string)
func (v *NdpAnnounceValidator) RemovePublicKey  (nid string)
func (v *NdpAnnounceValidator) KnownPublicKeys  () map[string]string   // 快照拷贝

func (v *NdpAnnounceValidator) Validate(frame *AnnounceFrame) NdpAnnounceResult
```

校验顺序（NPS-4 §7.1）：

1. 在已注册密钥中查 `frame.NID`。缺失 →
   `NdpAnnounceResult{IsValid:false, ErrorCode:"NDP-ANNOUNCE-NID-MISMATCH"}`。
   期望的工作流程：先校验广告方的 `IdentFrame`，然后
   `RegisterPublicKey(nid, ident.PubKey)`。
2. `Signature` 必须以 `"ed25519:"` 开头，否则
   `NDP-ANNOUNCE-SIG-INVALID`。
3. 从 `frame.UnsignedDict()`（已排序）重建签名 payload 并调用
   [`nip.VerifyWithPubKeyStr`](./nps-go.nip.cn.md#nipidentity)。
4. 成功返回 `NdpAnnounceResult{IsValid:true}`，否则
   `NDP-ANNOUNCE-SIG-INVALID`。

注册密钥请使用 `NipIdentity.PubKeyString()` 产生的精确字符串 ——
即 `"ed25519:{hex}"`。

---

## `NdpAnnounceResult`

```go
type NdpAnnounceResult struct {
    IsValid   bool
    ErrorCode string       // IsValid 时为 ""
    Message   string
}
```

---

## 端到端

```go
import (
    "time"
    "github.com/labacacia/NPS-sdk-go/ndp"
    "github.com/labacacia/NPS-sdk-go/nip"
)

id, _ := nip.Generate()
nid   := "urn:nps:node:api.example.com:products"

// 构造 + 签名 announce
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

// 校验 + 注册
validator := ndp.NewNdpAnnounceValidator()
validator.RegisterPublicKey(nid, id.PubKeyString())
result := validator.Validate(unsigned)
_ = result.IsValid   // true

// 解析
registry := ndp.NewInMemoryNdpRegistry()
registry.Announce(unsigned)
resolved := registry.Resolve("nwp://api.example.com/products/items/42")
if resolved != nil {
    _ = resolved.Host    // "10.0.0.5"
    _ = resolved.Port    // 17433
}
```
