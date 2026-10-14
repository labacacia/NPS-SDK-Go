English | [中文版](./nps-go.nwp.cn.md)

# `github.com/labacacia/NPS-sdk-go/nwp` — Reference

> Spec: [NPS-2 NWP v0.13](https://github.com/labacacia/NPS/blob/main/spec/NPS-2-NWP.md)

Agent-facing HTTP layer. Two frame types + a `net/http`-based client.

---

## Table of contents

- [`QueryFrame` (0x10)](#queryframe-0x10)
- [`ActionFrame` (0x11)](#actionframe-0x11)
- [`AsyncActionResponse`](#asyncactionresponse)
- [`NwpClient`](#nwpclient)
- [`InvokeResult`](#invokeresult)

---

## `QueryFrame` (0x10)

Paginated / filtered query against a Memory Node.

```go
type QueryFrame struct {
    AnchorRef   string        // required
    Filter      any           // NPS-2 §4 filter DSL (free-form)
    Order       any           // e.g. [{"field":"id","dir":"asc"}]
    TokenBudget *uint64       // CGN Budget cap (Cognon Budget spec)
    Limit       *uint64
    Offset      *uint64
}
```

`AnchorRef` is non-optional. The Go `QueryFrame` does not carry the
`vector_search` / `fields` / `depth` fields of the Java / Python / TS SDKs
— use `Filter` / `Order` for the equivalent logic and advertise the
vector-search dialect in the anchor schema.

Pointer fields (`*uint64`) encode "absent" as `nil`. Only set the pointer
when the caller wants the field on the wire.

---

## `ActionFrame` (0x11)

Invoke an action on a node.

```go
type ActionFrame struct {
    Action    string
    Params    any
    AnchorRef *string
    Async     bool             // serialises to "async" on the wire
}
```

`IdempotencyKey` / `TimeoutMs` are not modelled as struct fields — attach
them via `Params` if the remote action supports them.

---

## `AsyncActionResponse`

Returned by `NwpClient.Invoke` when the request frame has `Async == true`
(surfaced via `InvokeResult.Async`).

```go
type AsyncActionResponse struct {
    TaskID      string
    StatusURL   *string
    CallbackURL *string
}

func AsyncActionResponseFromDict(d core.FrameDict) *AsyncActionResponse
```

Poll `StatusURL` or hand `TaskID` to
[`NopClient.Wait`](./nps-go.nop.md#nopclient) to reach a terminal state.

---

## `NwpClient`

HTTP-mode NWP client.

```go
type NwpClient struct { /* … */ }

func NewNwpClient(baseURL string) *NwpClient

func NewNwpClientFull(
    baseURL    string,
    tier       core.EncodingTier,
    reg        *core.FrameRegistry,
    httpClient *http.Client,     // pass nil to use http.DefaultClient
) *NwpClient

func (c *NwpClient) SendAnchor(ctx context.Context, f *ncp.AnchorFrame) error
func (c *NwpClient) Query     (ctx context.Context, f *QueryFrame)    (*ncp.CapsFrame, error)
func (c *NwpClient) Stream    (ctx context.Context, f *QueryFrame)    ([]*ncp.StreamFrame, error)
func (c *NwpClient) Invoke    (ctx context.Context, f *ActionFrame)   (*InvokeResult, error)
```

### Defaults

- Trailing `/` is stripped from `baseURL`; every call POSTs to
  `{baseURL}/{route}`.
- `NewNwpClient` uses `core.EncodingTierMsgPack` and
  `core.CreateFullRegistry()` — queries and actions can reach nodes that
  respond with NCP, NIP, NDP or NOP frames.
- `NewNwpClientFull` exposes tier / registry / HTTP-client overrides. Pass
  `nil` for `httpClient` to fall back to `http.DefaultClient`.
- Every method takes a `context.Context` — cancellation / deadlines
  propagate to the underlying `http.Request`.

### HTTP routes

| Method       | Path      | Request body                 | Response body |
|--------------|-----------|------------------------------|---------------|
| `SendAnchor` | `/anchor` | encoded `AnchorFrame`        | — (2xx only) |
| `Query`      | `/query`  | encoded `QueryFrame`         | encoded `CapsFrame` |
| `Stream`     | `/stream` | encoded `QueryFrame`         | concatenated `StreamFrame`s |
| `Invoke`     | `/invoke` | encoded `ActionFrame`        | encoded frame, JSON (async), or fallback JSON |

Request headers: `Content-Type: application/x-nps-frame`,
`Accept: application/x-nps-frame`.

### `Stream` behaviour

Buffered: the response body is read into a `[]byte`, then sliced
frame-by-frame via `core.ParseFrameHeader`. Iteration stops when a frame
reports `IsLast == true` (the in-payload flag — not the wire FINAL bit).

### `Invoke` dispatch

| Request | Response Content-Type | Returned field |
|---------|-----------------------|----------------|
| `Async == true`  | any                                  | `InvokeResult{Async: …}`           |
| `Async == false` | contains `application/x-nps-frame`   | `InvokeResult{Frame: &dict}`       |
| `Async == false` | anything else                        | `InvokeResult{JSON: map[string]any}` |

### Errors

- Non-2xx HTTP → `fmt.Errorf("NWP /{path} failed: HTTP {status}")`.
- Transport failure → returned verbatim from `http.Client.Do`.
- Payload decode failure → `*core.ErrCodec` (via `codec.Decode`).
- Unexpected frame type (e.g. `Query` returns non-Caps) →
  `fmt.Errorf("expected CapsFrame, got 0x%02X", ft)`.

---

## `InvokeResult`

```go
type InvokeResult struct {
    Frame *core.FrameDict          // NPS-encoded response (already decoded to dict)
    Async *AsyncActionResponse     // 202-style async handle
    JSON  map[string]any           // JSON response (non-NPS content-type)
}
```

Exactly one of the three fields is non-nil per result. Unlike the Rust
SDK's `InvokeResult` enum, the Go type is a plain struct — inspect the
fields directly rather than pattern-matching. If you need a typed NCP
frame from `Frame`, call the relevant `XxxFrameFromDict(*r.Frame)`.

---

## End-to-end

```go
import (
    "context"
    "github.com/labacacia/NPS-sdk-go/nwp"
    "github.com/labacacia/NPS-sdk-go/ncp"
)

client := nwp.NewNwpClient("http://node.example.com:17433")
ctx    := context.Background()

// Query
limit := uint64(50)
caps, err := client.Query(ctx, &nwp.QueryFrame{
    AnchorRef: "sha256:abc123",
    Filter:    map[string]any{"active": true},
    Limit:     &limit,
})
if err != nil { /* … */ }
_ = caps.Caps

// Invoke
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
