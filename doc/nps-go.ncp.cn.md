[English Version](./nps-go.ncp.md) | 中文版

# `github.com/labacacia/NPS-sdk-go/ncp` — 参考

> 规范：[NPS-1 NCP v0.7](https://github.com/labacacia/NPS/blob/main/spec/NPS-1-NCP.md)

五种 NCP 帧类型。每个 struct 都暴露同一组三件套：

```go
func (f *XxxFrame) FrameType() core.FrameType
func (f *XxxFrame) ToDict()    core.FrameDict
func XxxFrameFromDict(d core.FrameDict) *XxxFrame
```

> **注 —— Go 帧形状。** Go NCP struct 的字段集与 Java / Python / .NET / TS
> SDK 略有差异 —— 下列布局是本模块的权威定义。

---

## 目录

- [`AnchorFrame` (0x01)](#anchorframe-0x01)
- [`DiffFrame` (0x02)](#diffframe-0x02)
- [`StreamFrame` (0x03)](#streamframe-0x03)
- [`CapsFrame` (0x04)](#capsframe-0x04)
- [`ErrorFrame` (0xFE)](#errorframe-0xfe)

---

## `AnchorFrame` (0x01)

发布 schema 锚点 + TTL。

```go
type AnchorFrame struct {
    AnchorID    string
    Schema      core.FrameDict
    Namespace   *string
    Description *string
    NodeType    *string          // 如 "memory" | "action" | …
    TTL         uint64           // 秒；from_dict 缺省 3600
}
```

`Schema` 以自由形式 `core.FrameDict` 存储 —— 通常为
`{"fields": [ {"name": …, "type": …}, … ]}`，但节点和客户端同意的
任何形状都合法。当字段缺失 / 为零时，`AnchorFrameFromDict` 回退到
`TTL = 3600`。

要确定性生成内容寻址的 `AnchorID`，使用
[`core.ComputeAnchorID`](./nps-go.core.cn.md#anchorframecache)。

---

## `DiffFrame` (0x02)

两个 anchor 之间的 schema 演进。

```go
type DiffFrame struct {
    AnchorID    string        // 旧 anchor
    NewAnchorID string        // 新 anchor
    Patch       []any         // JSON-Patch 形状 ops（自由形式）
}
```

`Patch` 原样序列化 —— 本模块不校验 ops；接收方需了解 patch 方言
（NPS-1 §5.2 使用 RFC 6902 兼容形状）。

---

## `StreamFrame` (0x03)

流式响应的一个分块。多个 `StreamFrame` 拼出结果；最后一个分块设
`IsLast = true`。

```go
type StreamFrame struct {
    AnchorID string
    Seq      uint64
    Payload  any        // 不透明 —— 任何可 JSON 表示的值
    IsLast   bool
}
```

线路级 `FINAL` flag（帧头 bit 6）与 `IsLast` **分离**。`IsLast` 是
payload 内业务标记，由
[`NwpClient.Stream`](./nps-go.nwp.cn.md#nwpclient) 用来停止迭代。

---

## `CapsFrame` (0x04)

节点能力 / 响应信封帧。

```go
type CapsFrame struct {
    NodeID    string
    Caps      []string          // 能力 URI
    AnchorRef *string           // 被应答的 anchor
    Payload   any               // 不透明响应数据
}
```

在 Go SDK 中 `CapsFrame` 是 NWP 的**默认响应信封**：`NwpClient.Query`
直接返回 `*CapsFrame`（读取 `AnchorRef` + `Payload`）。Caps 广告用法
和响应用法共用同一 struct —— 通过检查 `Caps` 与 `Payload` 区分。

`CapsFrameFromDict` 接受 `caps` 字段为 `[]string` 或 `[]any` —— MsgPack
解码的 payload 通常以 `[]any` 浮现，JSON payload 以字符串 `[]any`
浮现；两者都归一化为 `[]string`。

---

## `ErrorFrame` (0xFE)

统一协议级错误。

```go
type ErrorFrame struct {
    ErrorCode string        // "NWP-QUERY-ANCHOR-UNKNOWN", …
    Message   string
    Detail    any           // 自由形式附加上下文
}
```

命名空间见
[`error-codes.md`](https://github.com/labacacia/NPS/blob/main/spec/error-codes.md)。

---

## 端到端

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
