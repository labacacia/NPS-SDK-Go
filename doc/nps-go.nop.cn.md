[English Version](./nps-go.nop.md) | 中文版

# `github.com/labacacia/NPS-sdk-go/nop` — 参考

> 规范：[NPS-5 NOP v0.6](https://github.com/labacacia/NPS/blob/main/spec/NPS-5-NOP.md)

编排层 —— DAG 提交、fan-in 屏障、流式进度、异步状态轮询。

---

## 目录

- [`BackoffStrategy`](#backoffstrategy)
- [`TaskState`](#taskstate)
- [`NopTaskStatus`](#noptaskstatus)
- [`TaskFrame` (0x40)](#taskframe-0x40)
- [`DelegateFrame` (0x41)](#delegateframe-0x41)
- [`SyncFrame` (0x42)](#syncframe-0x42)
- [`AlignStreamFrame` (0x43)](#alignstreamframe-0x43)
- [`NopClient`](#nopclient)

---

## `BackoffStrategy`

```go
type BackoffStrategy int

const (
    BackoffFixed BackoffStrategy = iota
    BackoffLinear
    BackoffExponential
)

// 包级函数 —— 非方法。
func ComputeDelayMs(strategy BackoffStrategy, baseMs, maxMs int64, attempt int) int64
```

`ComputeDelayMs`（`attempt` 从 0 起）：

| 策略                  | 公式                          |
|-----------------------|-------------------------------|
| `BackoffFixed`       | `baseMs`                       |
| `BackoffLinear`      | `baseMs * (attempt + 1)`       |
| `BackoffExponential` | `baseMs << attempt`（≡ `baseMs * 2^attempt`）|

结果以 `maxMs` 为上限。

---

## `TaskState`

```go
type TaskState string

const (
    TaskStatePending   TaskState = "pending"
    TaskStateRunning   TaskState = "running"
    TaskStateCompleted TaskState = "completed"
    TaskStateFailed    TaskState = "failed"
    TaskStateCancelled TaskState = "cancelled"
)

func TaskStateFromString(s string) (TaskState, error)   // 未知时返回 error
func (s TaskState) IsTerminal() bool                    // Completed | Failed | Cancelled
```

> Go SDK 仅暴露上述五种通用状态。携带 `"preflight"`、`"waiting_sync"` 或
> `"skipped"` 的编排器响应仍可通过 `NopTaskStatus.State()` 解码，但返回
> 的 `TaskState` 值不会匹配任何声明的常量。需要时使用
> `NopTaskStatus.String()` / 原始 payload 检查原始字符串。

---

## `NopTaskStatus`

编排器 JSON 状态 payload 的薄视图。

```go
type NopTaskStatus struct { /* raw map[string]any */ }

func NewNopTaskStatus(raw map[string]any) *NopTaskStatus

func (s *NopTaskStatus) TaskID()       string
func (s *NopTaskStatus) State()        TaskState
func (s *NopTaskStatus) IsTerminal()   bool
func (s *NopTaskStatus) ErrorCode()    string
func (s *NopTaskStatus) ErrorMessage() string
func (s *NopTaskStatus) NodeResults()  map[string]any
func (s *NopTaskStatus) String()       string             // "NopTaskStatus(task_id=…, state=…)"
```

内部 `raw` map 不暴露 —— 底层字段缺失或类型错配时，访问器返回零值
（`""`、`nil`）。

---

## `TaskFrame` (0x40)

提交 DAG 供执行。DAG 本身保留为匹配 NPS-5 线路形状
（`{"nodes": [...], "edges": [...]}`）的自由形式 `any` 值。

```go
type TaskFrame struct {
    TaskID      string
    DAG         any                  // 自由形式 DAG JSON
    TimeoutMs   *uint64
    CallbackURL *string               // 编排器做 SSRF 校验
    Context     any                   // { "session_key", "requester_nid", "trace_id" }
    Priority    *string               // "low" | "normal" | "high"
    Depth       *int64                // 委托链深度，最大 3
}
```

编排器强制的规范限制（NPS-5 §8.2）：每 DAG 最多 32 节点、
委托链最多 3 层、超时上限 3 600 000 ms（1 小时）。

---

## `DelegateFrame` (0x41)

编排器向每个 agent 发出的逐节点调用。

```go
type DelegateFrame struct {
    TaskID         string
    SubtaskID      string
    Action         string
    TargetNID      string
    Inputs         any
    Config         any
    IdempotencyKey *string
}
```

> 字段命名与其他 SDK 不同：Go SDK 用 `TargetNID` + `Config`，而
> .NET / Python / Java SDK 用 `agent_nid` + `params`。线路 payload
> 遵循上述字段名（`target_nid` / `config`）。

---

## `SyncFrame` (0x42)

Fan-in 屏障 —— 等待 K-of-N 上游子任务。

```go
type SyncFrame struct {
    TaskID      string
    SyncID      string
    SubtaskIDs  []string
    MinRequired int64               // 0 = 严格 all-of
    Aggregate   string              // "merge" | "first" | "fastest_k" | "all"
    TimeoutMs   *uint64
}
```

`SyncFrameFromDict` 在字段缺失时将 `Aggregate` 缺省为 `"merge"`。

`MinRequired` 语义：

| 值    | 含义 |
|-------|------|
| `0`   | 等待 `SubtaskIDs` 全部（严格 fan-in）。 |
| `K`   | 只要 K 个上游子任务完成即继续。 |

---

## `AlignStreamFrame` (0x43)

委托子任务的流式进度 / 部分结果帧。

```go
type AlignStreamFrame struct {
    SyncID     string
    TaskID     string
    SubtaskID  string
    Seq        uint64
    IsFinal    bool
    SourceNID  *string
    Result     any                  // 不透明 payload
    Error      map[string]any       // { "error_code", "message" }
    WindowSize *uint64
}

func (f *AlignStreamFrame) ErrorCode()    string   // Error["error_code"] 的快捷方法
func (f *AlignStreamFrame) ErrorMessage() string   // Error["message"] 的快捷方法
```

`AlignStreamFrame` 替代已弃用的 `AlignFrame (0x05)` —— 它携带任务
上下文（`TaskID` + `SubtaskID` + `SyncID`）并把流绑定到 `SourceNID`。

---

## `NopClient`

HTTP 模式 NOP 客户端。

```go
type NopClient struct { /* … */ }

func NewNopClient    (baseURL string)                              *NopClient
func NewNopClientFull(baseURL string, httpClient *http.Client)    *NopClient

func (c *NopClient) Submit   (ctx context.Context, frame *TaskFrame)  (string, error)          // → task_id
func (c *NopClient) GetStatus(ctx context.Context, taskID string)     (*NopTaskStatus, error)
func (c *NopClient) Cancel   (ctx context.Context, taskID string)      error

func (c *NopClient) Wait(
    ctx     context.Context,
    taskID  string,
    opts    *WaitOptions,      // 传 nil 使用默认
) (*NopTaskStatus, error)

type WaitOptions struct {
    PollInterval time.Duration   // 默认 500ms
    MaxAttempts  int             // 0 = 不限（依赖 ctx 做超时）
}
```

### HTTP 路由

| 名称         | 方法   | 路径                      | 请求体                         | 响应 |
|--------------|--------|---------------------------|--------------------------------|------|
| `Submit`     | POST   | `/tasks`                  | `TaskFrame.ToDict()` 的 JSON   | JSON `{ "task_id": … }` |
| `GetStatus`  | GET    | `/tasks/{id}`             | —                              | JSON 状态 dict |
| `Cancel`     | POST   | `/tasks/{id}/cancel`      | `{"task_id","action":"cancel"}`| — |
| `Wait`       | 轮询 `GetStatus` 直到终态 / ctx 取消 / 超过 `MaxAttempts`；轮询间隔为 `time.After(PollInterval)` |

> `Cancel` 使用 `POST /tasks/{id}/cancel` —— 与 Rust SDK 使用
> `DELETE /tasks/{id}` 不同。路由写死在 Go 客户端中，不可配置。

请求使用 `Content-Type: application/json` —— NOP 客户端以纯 JSON
提交任务 dict，而非框定为 `application/x-nps-frame` payload。

`Wait` 若 context 取消则返回 `ctx.Err()`；成功时返回终态
`*NopTaskStatus`；达到 `opts.MaxAttempts > 0` 时返回最近非终态状态
加上类似 `"NOP Wait: exceeded N poll attempts …"` 的错误。

### 错误

- 非 2xx HTTP → `fmt.Errorf("NOP %s failed: HTTP %d", op, status)`，其中
  `op` 为 `"Submit"` / `"GetStatus"` / `"Cancel"`。
- 若 `Submit` 收到 2xx 响应但 body 中无 `task_id`，客户端回退到返回
  `frame.TaskID`。
- 传输故障由 `http.Client.Do` / `json.Decoder` 浮现。

---

## 端到端

```go
import (
    "context"
    "time"
    "github.com/labacacia/NPS-sdk-go/nop"
)

dag := map[string]any{
    "nodes": []any{
        map[string]any{
            "id":     "fetch",
            "action": "fetch",
            "agent":  "urn:nps:node:ingest.example.com:http",
        },
        map[string]any{
            "id":         "classify",
            "action":     "classify",
            "agent":      "urn:nps:node:ml.example.com:classifier",
            "input_from": []any{"fetch"},
            "retry_policy": map[string]any{
                "max_retries":   3,
                "backoff":       "exponential",
                "base_delay_ms": 500,
            },
        },
    },
    "edges": []any{
        map[string]any{"from": "fetch", "to": "classify"},
    },
}

timeoutMs := uint64(60_000)
priority  := "normal"

client := nop.NewNopClient("http://orchestrator.example.com:17433")
ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
defer cancel()

tid, err := client.Submit(ctx, &nop.TaskFrame{
    TaskID:    "job-42",
    DAG:       dag,
    TimeoutMs: &timeoutMs,
    Priority:  &priority,
})
if err != nil { /* … */ }

status, err := client.Wait(ctx, tid, &nop.WaitOptions{
    PollInterval: 500 * time.Millisecond,
})
if err != nil { /* … */ }
_ = status.String()

// Backoff 计算
delay := nop.ComputeDelayMs(nop.BackoffExponential, 500, 30_000, 2)  // → 2000
_ = delay
```
