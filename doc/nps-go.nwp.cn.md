[English Version](./nps-go.nwp.md) | 中文版

# `github.com/labacacia/NPS-sdk-go/nwp` — 参考

> 规范：[NPS-2 NWP v0.13](https://github.com/labacacia/NPS/blob/main/spec/NPS-2-NWP.md)

面向 Agent 的 HTTP 层。两种帧类型 + 基于 `net/http` 的客户端。

---

## 目录

- [`QueryFrame` (0x10)](#queryframe-0x10)
- [`ActionFrame` (0x11)](#actionframe-0x11)
- [`AsyncActionResponse`](#asyncactionresponse)
- [`NwpClient`](#nwpclient)
- [`InvokeResult`](#invokeresult)

---

## `QueryFrame` (0x10)

针对 Memory Node 的分页 / 过滤查询。

```go
type QueryFrame struct {
    AnchorRef   string        // 必填
    Filter      any           // NPS-2 §4 过滤 DSL（自由形式）
    Order       any           // 如 [{"field":"id","dir":"asc"}]
    TokenBudget *uint64       // CGN Budget 上限（Cognon Budget 规范）
    Limit       *uint64
    Offset      *uint64
}
```

`AnchorRef` 非可选。Go `QueryFrame` 不携带 Java / Python / TS SDK
的 `vector_search` / `fields` / `depth` 字段 —— 用 `Filter` / `Order`
表达等价逻辑，并在 anchor schema 中声明向量检索方言。

指针字段（`*uint64`）以 `nil` 编码"缺席"。仅在调用方希望该字段出现
在线路上时设置指针。

---

## `ActionFrame` (0x11)

在节点上调用动作。

```go
type ActionFrame struct {
    Action    string
    Params    any
    AnchorRef *string
    Async     bool             // 线路上序列化为 "async"
}
```

`IdempotencyKey` / `TimeoutMs` 未作为 struct 字段建模 —— 若远端动作
支持，通过 `Params` 附加。

---

## `AsyncActionResponse`

当请求帧 `Async == true` 时由 `NwpClient.Invoke` 返回（通过
`InvokeResult.Async` 暴露）。

```go
type AsyncActionResponse struct {
    TaskID      string
    StatusURL   *string
    CallbackURL *string
}

func AsyncActionResponseFromDict(d core.FrameDict) *AsyncActionResponse
```

轮询 `StatusURL` 或把 `TaskID` 交给
[`NopClient.Wait`](./nps-go.nop.cn.md#nopclient) 以到达终态。

---

## `NwpClient`

HTTP 模式 NWP 客户端。

```go
type NwpClient struct { /* … */ }

func NewNwpClient(baseURL string) *NwpClient

func NewNwpClientFull(
    baseURL    string,
    tier       core.EncodingTier,
    reg        *core.FrameRegistry,
    httpClient *http.Client,     // 传 nil 以使用 http.DefaultClient
) *NwpClient

func (c *NwpClient) SendAnchor(ctx context.Context, f *ncp.AnchorFrame) error
func (c *NwpClient) Query     (ctx context.Context, f *QueryFrame)    (*ncp.CapsFrame, error)
func (c *NwpClient) Stream    (ctx context.Context, f *QueryFrame)    ([]*ncp.StreamFrame, error)
func (c *NwpClient) Invoke    (ctx context.Context, f *ActionFrame)   (*InvokeResult, error)
```

### 默认值

- `baseURL` 尾 `/` 被剥离；每次调用 POST 到 `{baseURL}/{route}`。
- `NewNwpClient` 使用 `core.EncodingTierMsgPack` 和
  `core.CreateFullRegistry()` —— 查询与动作可抵达以 NCP、NIP、NDP、
  NOP 帧响应的节点。
- `NewNwpClientFull` 暴露 tier / registry / HTTP 客户端覆盖。
  `httpClient` 传 `nil` 以降级到 `http.DefaultClient`。
- 每个方法接收 `context.Context` —— 取消 / 截止传播到底层
  `http.Request`。

### HTTP 路由

| 方法         | 路径      | 请求体                        | 响应体 |
|--------------|-----------|-------------------------------|--------|
| `SendAnchor` | `/anchor` | 编码的 `AnchorFrame`          | —（仅 2xx）|
| `Query`      | `/query`  | 编码的 `QueryFrame`           | 编码的 `CapsFrame` |
| `Stream`     | `/stream` | 编码的 `QueryFrame`           | 拼接的 `StreamFrame` 序列 |
| `Invoke`     | `/invoke` | 编码的 `ActionFrame`          | 编码帧、JSON（异步）或回退 JSON |

请求头：`Content-Type: application/x-nps-frame`，
`Accept: application/x-nps-frame`。

### `Stream` 行为

缓冲：响应体读入 `[]byte`，然后通过 `core.ParseFrameHeader` 逐帧切分。
当某帧报告 `IsLast == true`（payload 内标志 —— 非线路 FINAL bit）
时，迭代停止。

### `Invoke` 分派

| 请求 | 响应 Content-Type | 返回字段 |
|------|-------------------|----------|
| `Async == true`  | 任意                                 | `InvokeResult{Async: …}`           |
| `Async == false` | 包含 `application/x-nps-frame`       | `InvokeResult{Frame: &dict}`       |
| `Async == false` | 其他                                 | `InvokeResult{JSON: map[string]any}` |

### 错误

- 非 2xx HTTP → `fmt.Errorf("NWP /{path} failed: HTTP {status}")`。
- 传输失败 → 原样返回自 `http.Client.Do`。
- Payload 解码失败 → `*core.ErrCodec`（经 `codec.Decode`）。
- 意外帧类型（如 `Query` 返回非 Caps）→
  `fmt.Errorf("expected CapsFrame, got 0x%02X", ft)`。

---

## `InvokeResult`

```go
type InvokeResult struct {
    Frame *core.FrameDict          // NPS 编码响应（已解码为 dict）
    Async *AsyncActionResponse     // 202 风格异步句柄
    JSON  map[string]any           // JSON 响应（非 NPS content-type）
}
```

每次结果中三个字段恰有一个非 nil。与 Rust SDK 的 `InvokeResult` enum
不同，Go 类型是普通 struct —— 直接检查字段而非模式匹配。若需从
`Frame` 得到有类型 NCP 帧，调用相应的 `XxxFrameFromDict(*r.Frame)`。

---

## 端到端

```go
import (
    "context"
    "github.com/labacacia/NPS-sdk-go/nwp"
    "github.com/labacacia/NPS-sdk-go/ncp"
)

client := nwp.NewNwpClient("http://node.example.com:17433")
ctx    := context.Background()

// 查询
limit := uint64(50)
caps, err := client.Query(ctx, &nwp.QueryFrame{
    AnchorRef: "sha256:abc123",
    Filter:    map[string]any{"active": true},
    Limit:     &limit,
})
if err != nil { /* … */ }
_ = caps.Caps

// 调用
result, err := client.Invoke(ctx, &nwp.ActionFrame{
    Action: "summarise",
    Params: map[string]any{"max_tokens": 500},
    Async:  false,
})
if err != nil { /* … */ }
switch {
case result.Frame != nil:
    back := ncp.CapsFrameFromDict(*result.Frame)
    _ = back
case result.Async != nil:
    _ = result.Async.TaskID
case result.JSON != nil:
    _ = result.JSON
}
```
