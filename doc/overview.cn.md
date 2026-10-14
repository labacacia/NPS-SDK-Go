[English Version](./overview.md) | 中文版

# NPS Go SDK — API 参考

> Neural Protocol Suite 的 Go 客户端库。模块路径：
> `github.com/labacacia/NPS-sdk-go`，Go 1.23+（推荐 1.25+）。

本目录是 Go SDK 的包与函数参考。叙事性教程参见
[`sdk-usage.md`](./sdk-usage.md)（English）/
[`sdk-usage.cn.md`](./sdk-usage.cn.md)（中文）。

---

## 包

| 引用后缀 | 用途 | 参考文档 |
|----------|------|----------|
| `/core` | 帧头、编解码（Tier-1 JSON / Tier-2 MsgPack）、注册表、AnchorFrame 缓存、错误类型 | [`nps-go.core.cn.md`](./nps-go.core.cn.md) |
| `/ncp`  | NCP 帧 —— `AnchorFrame`、`DiffFrame`、`StreamFrame`、`CapsFrame`、`ErrorFrame` | [`nps-go.ncp.cn.md`](./nps-go.ncp.cn.md) |
| `/nwp`  | NWP 帧 + HTTP `NwpClient` | [`nps-go.nwp.cn.md`](./nps-go.nwp.cn.md) |
| `/nip`  | NIP 帧 + `NipIdentity`（Ed25519、AES-256-GCM 密钥存储） | [`nps-go.nip.cn.md`](./nps-go.nip.cn.md) |
| `/ndp`  | NDP 帧 + `InMemoryNdpRegistry` + `NdpAnnounceValidator` | [`nps-go.ndp.cn.md`](./nps-go.ndp.cn.md) |
| `/nop`  | NOP 帧 + `BackoffStrategy` + `NopTaskStatus` + `NopClient` | [`nps-go.nop.cn.md`](./nps-go.nop.cn.md) |

模块根是 `github.com/labacacia/NPS-sdk-go`，上述所有包以
`"github.com/labacacia/NPS-sdk-go/{core,ncp,nwp,nip,ndp,nop}"` 方式引用。

---

## 安装

```bash
go get github.com/labacacia/NPS-sdk-go@v1.0.0-alpha.13
```

运行时依赖（由 `go mod tidy` 解析）：

- `github.com/vmihailenco/msgpack/v5` —— MsgPack 编解码
- `golang.org/x/crypto/pbkdf2` —— `NipIdentity` 密钥派生
- `crypto/ed25519`、`crypto/aes`、`crypto/cipher` —— 标准库

---

## 最小编解码示例

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

编解码器是基于 dict 的：每个帧结构都提供
`FrameType() core.FrameType` + `ToDict() core.FrameDict`，并且每个
包都配套一个 `{Frame}FromDict(core.FrameDict) *{Frame}` 构造函数。
围绕 `codec.Encode` / `codec.Decode` 显式调用它们。

---

## 编码分层

| Tier | 常量 | 线缆标志（bit 7） | 备注 |
|------|------|--------------------|------|
| Tier-1 JSON    | `core.EncodingTierJSON`    | `0` | UTF-8 JSON，调试 / 互操作 |
| Tier-2 MsgPack | `core.EncodingTierMsgPack` | `1` | `msgpack/v5`，生产默认 |

**标志字节布局**（与 Rust SDK 一致；与 Java / Python / TS 不同）：

| Bit | 掩码   | 含义 |
|-----|--------|------|
| 7   | `0x80` | TIER —— `1` = MsgPack，`0` = JSON |
| 6   | `0x40` | FINAL —— 流中最后一帧 |
| 0   | `0x01` | EXT —— 8 字节扩展帧头（负载 > 65 535 字节） |

帧头大小：默认 4 字节，`EXT = 1` 时为 8 字节
（`[type][flags][0][0][len_b3..len_b0]`）。负载上限默认为 10 MiB
（`core.DefaultMaxPayload`）—— 构造后通过设置 `codec.MaxPayload` 调整。

---

## HTTP 客户端

- `NwpClient`（`/nwp`）使用 `net/http`，`Content-Type: application/x-nps-frame`。
- `NopClient`（`/nop`）使用 `net/http`，`Content-Type: application/json`
  （任务以纯 JSON dict 提交，而不是封帧后的 NPS 负载）。
- 两个构造函数都接受一个可选的 `*http.Client`；传 `nil` 将使用
  `http.DefaultClient`。
- 所有公开方法都接受 `context.Context` —— 取消 / 截止时间
  会向下传递到底层 HTTP 请求。

---

## 错误

`core/errors.go` 定义了指针型错误类型 —— 使用
`errors.As` 进行解包：

| 类型 | 抛出场景 |
|------|----------|
| `*core.ErrFrame`          | 未知 / 未注册的帧类型、缺失字段 |
| `*core.ErrCodec`          | JSON / MsgPack 编解码失败、负载过大 |
| `*core.ErrAnchorNotFound` | `AnchorFrameCache.GetRequired` 命中缺失 / 过期 AnchorFrame |
| `*core.ErrAnchorPoison`   | `AnchorFrameCache.Set` 在同一 `anchor_id` 下 schema 不一致 |
| `*core.ErrIdentity`       | 密钥生成 / 保存 / 加载 / PBKDF2 / AES-GCM 失败 |

非 2xx HTTP 响应会被包装为 `fmt.Errorf`，格式为
`"NWP /{path} failed: HTTP {status}"` 或
`"NOP {op} failed: HTTP {status}"`。

---

## 规范链接

- [NPS-0 Overview](https://github.com/labacacia/NPS/blob/main/spec/NPS-0-Overview.cn.md)
- [NPS-1 NCP](https://github.com/labacacia/NPS/blob/main/spec/NPS-1-NCP.cn.md)
- [NPS-2 NWP](https://github.com/labacacia/NPS/blob/main/spec/NPS-2-NWP.cn.md)
- [NPS-3 NIP](https://github.com/labacacia/NPS/blob/main/spec/NPS-3-NIP.cn.md)
- [NPS-4 NDP](https://github.com/labacacia/NPS/blob/main/spec/NPS-4-NDP.cn.md)
- [NPS-5 NOP](https://github.com/labacacia/NPS/blob/main/spec/NPS-5-NOP.cn.md)
- [帧注册表](https://github.com/labacacia/NPS/blob/main/spec/frame-registry.yaml)
- [错误码](https://github.com/labacacia/NPS/blob/main/spec/error-codes.cn.md)
