English | [中文版](./nps-go.nop.cn.md)

# `github.com/labacacia/NPS-sdk-go/nop` — Reference

> Spec: [NPS-5 NOP v0.6](https://github.com/labacacia/NPS/blob/main/spec/NPS-5-NOP.md)

Orchestration layer — DAG submission, fan-in barriers, streaming
progress, async status polling.

---

## Table of contents

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

// Package-level function — not a method.
func ComputeDelayMs(strategy BackoffStrategy, baseMs, maxMs int64, attempt int) int64
```

`ComputeDelayMs` (0-indexed `attempt`):

| Strategy             | Formula                     |
|----------------------|-----------------------------|
| `BackoffFixed`       | `baseMs`                    |
| `BackoffLinear`      | `baseMs * (attempt + 1)`    |
| `BackoffExponential` | `baseMs << attempt` (≡ `baseMs * 2^attempt`) |

Result is clamped at `maxMs`.

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

func TaskStateFromString(s string) (TaskState, error)   // errors on unknown
func (s TaskState) IsTerminal() bool                    // Completed | Failed | Cancelled
```

> The Go SDK exposes only the five common states above. Orchestrator
> responses carrying `"preflight"`, `"waiting_sync"` or `"skipped"` will
> still decode via `NopTaskStatus.State()` but the returned `TaskState`
> value will not match any of the declared constants. Use
> `NopTaskStatus.String()` / the raw payload to inspect the original
> string when needed.

---

## `NopTaskStatus`

Thin view over the orchestrator's JSON status payload.

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

The internal `raw` map is not exposed — accessors return zero-values
(`""`, `nil`) when the underlying field is missing or mis-typed.

---

## `TaskFrame` (0x40)

Submit a DAG for execution. The DAG itself is kept as a free-form `any`
value that matches the NPS-5 wire shape (`{"nodes": [...], "edges": [...]}`).

```go
type TaskFrame struct {
    TaskID      string
    DAG         any                  // free-form DAG JSON
    TimeoutMs   *uint64
    CallbackURL *string               // SSRF-validated by orchestrator
    Context     any                   // { "session_key", "requester_nid", "trace_id" }
    Priority    *string               // "low" | "normal" | "high"
    Depth       *int64                // delegate chain depth, max 3
}
```

Spec limits the orchestrator enforces (NPS-5 §8.2): max 32 nodes per DAG,
max 3 levels of delegate chain, max timeout 3 600 000 ms (1 h).

---

## `DelegateFrame` (0x41)

Per-node invocation emitted by the orchestrator to each agent.

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

> Field naming differs from other SDKs: the Go SDK uses `TargetNID` +
> `Config` where the .NET / Python / Java SDKs use `agent_nid` +
> `params`. Wire payloads follow the field names above (`target_nid` /
> `config`).

---

## `SyncFrame` (0x42)

Fan-in barrier — waits for K-of-N upstream subtasks.

```go
type SyncFrame struct {
    TaskID      string
    SyncID      string
    SubtaskIDs  []string
    MinRequired int64               // 0 = strict all-of
    Aggregate   string              // "merge" | "first" | "fastest_k" | "all"
    TimeoutMs   *uint64
}
```

`SyncFrameFromDict` defaults `Aggregate` to `"merge"` when the field is
missing.

`MinRequired` semantics:

| Value | Meaning |
|-------|---------|
| `0`   | Wait for all of `SubtaskIDs` (strict fan-in). |
| `K`   | Proceed as soon as K upstream subtasks have completed. |

---

## `AlignStreamFrame` (0x43)

Streaming progress / partial result frame for a delegated subtask.

```go
type AlignStreamFrame struct {
    SyncID     string
    TaskID     string
    SubtaskID  string
    Seq        uint64
    IsFinal    bool
    SourceNID  *string
    Result     any                  // opaque payload
    Error      map[string]any       // { "error_code", "message" }
    WindowSize *uint64
}

func (f *AlignStreamFrame) ErrorCode()    string   // shortcut for Error["error_code"]
func (f *AlignStreamFrame) ErrorMessage() string   // shortcut for Error["message"]
```

`AlignStreamFrame` replaces the deprecated `AlignFrame (0x05)` — it
carries task context (`TaskID` + `SubtaskID` + `SyncID`) and binds the
stream to a `SourceNID`.

---

## `NopClient`

HTTP-mode NOP client.

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
    opts    *WaitOptions,      // pass nil for defaults
) (*NopTaskStatus, error)

type WaitOptions struct {
    PollInterval time.Duration   // default 500ms
    MaxAttempts  int             // 0 = unlimited (rely on ctx for timeout)
}
```

### HTTP routes

| Method       | Method | Path                      | Request body                   | Response |
|--------------|--------|---------------------------|--------------------------------|----------|
| `Submit`     | POST   | `/tasks`                  | JSON of `TaskFrame.ToDict()`   | JSON `{ "task_id": … }` |
| `GetStatus`  | GET    | `/tasks/{id}`             | —                              | JSON status dict |
| `Cancel`     | POST   | `/tasks/{id}/cancel`      | `{"task_id","action":"cancel"}`| — |
| `Wait`       | polls `GetStatus` until terminal / ctx cancelled / `MaxAttempts` exceeded; `time.After(PollInterval)` between polls |

> `Cancel` uses `POST /tasks/{id}/cancel` — this differs from the Rust
> SDK which uses `DELETE /tasks/{id}`. The route is encoded in the Go
> client and is not configurable.

Requests use `Content-Type: application/json` — the NOP client submits
the task dict as plain JSON, not as a framed `application/x-nps-frame`
payload.

`Wait` returns `ctx.Err()` if the context is cancelled; returns the
terminal `*NopTaskStatus` on success; returns the most recent non-terminal
status plus an error like `"NOP Wait: exceeded N poll attempts …"` when
`opts.MaxAttempts > 0` is reached.

### Errors

- Non-2xx HTTP → `fmt.Errorf("NOP %s failed: HTTP %d", op, status)` where
  `op` is `"Submit"` / `"GetStatus"` / `"Cancel"`.
- If `Submit` gets a 2xx response with no `task_id` in the body, the
  client falls back to returning `frame.TaskID`.
- Transport failures surface from `http.Client.Do` / `json.Decoder`.

---

## End-to-end

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

// Backoff computation
delay := nop.ComputeDelayMs(nop.BackoffExponential, 500, 30_000, 2)  // → 2000
_ = delay
```
