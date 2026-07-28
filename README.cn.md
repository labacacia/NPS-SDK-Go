[English Version](./README.md) | 中文版

# NPS Go SDK v1.0.0-alpha.17

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../../LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.0--alpha.17-orange.svg)](../../CHANGELOG.cn.md)
[![NCP](https://img.shields.io/badge/NCP-v0.9-5b8cff.svg)]()
[![NWP](https://img.shields.io/badge/NWP-v0.14-4af0b0.svg)]()
[![NIP](https://img.shields.io/badge/NIP-v0.10-7b61ff.svg)]()
[![NDP](https://img.shields.io/badge/NDP-v0.9-f0a050.svg)]()
[![NOP](https://img.shields.io/badge/NOP-v0.7-ff8c42.svg)]()

Neural Protocol Suite (NPS) 的 Go 参考实现 —— 覆盖五个子协议：**NCP · NWP · NIP · NDP · NOP**，外加完整的 NPS-RFC-0002 X.509 + ACME `agent-01` NID 证书原语。

| | |
|---|---|
| **Module** | `github.com/labacacia/NPS-sdk-go` |
| **Go** | 1.26.5+ |
| **测试** | 434 通过 |
| **许可证** | Apache 2.0 |

Alpha.14 候选新增：远程 NIP CA 类型化客户端（`nip.NipCaClient`）、native-mode NWP 服务端 helper（`nwp.NwpNativeNodeServer`）和 TC-N1/TC-N2 一致性 manifest helper（`conformance`）。

---

## 包

| Package | 协议 | 说明 |
|---------|------|------|
| `core` | NCP | 帧类型、帧头编解码、注册表、AnchorFrame 缓存 |
| `ncp` | NCP | AnchorFrame、DiffFrame、StreamFrame、CapsFrame、HelloFrame、ErrorFrame |
| `nwp` | NWP | QueryFrame、ActionFrame、NwpClient（HTTP 模式）、NwpNativeNodeServer |
| `nip` | NIP | IdentFrame（v2 双信任）、TrustFrame、RevokeFrame、NipIdentity（Ed25519）、NipIdentVerifier（RFC-0002 §8.1 双信任）、AssuranceLevel（RFC-0003） |
| `nip/x509` | NIP / RFC-0002 | `IssueLeaf` / `IssueRoot` / `Verify` —— 基于 stdlib `crypto/x509` 的 NPS X.509 NID 证书 |
| `nip/acme` | NIP / RFC-0002 | `Client` + `Server`（进程内） + JWS / messages —— ACME `agent-01` 流程 |
| `ndp` | NDP | AnnounceFrame、ResolveFrame、GraphFrame、InMemoryNdpRegistry、NdpAnnounceValidator |
| `nop` | NOP | TaskFrame、DelegateFrame、SyncFrame、AlignStreamFrame、NopClient |
| `conformance` | CI / 认证 | TC-N1/TC-N2 一致性用例目录、manifest 构造器和校验器 |
| `daemon/observability` | Runtime | 健康检查、就绪检查、指标、结构化日志与优雅停机 helper |
| `telemetry` | Runtime | 轻量级 counter、histogram 与 span 记录 |

---

## Alpha.17 候选版

此候选版携带计划在下一套件版本发布的 **alpha.17 服务端能力对齐**：

- **NOP 编排引擎** —— DAG 校验器、条件求值器、输入映射、结果聚合、任务存储、Worker 客户端、回调校验、instrumentation
- **NCP 原生模式传输** —— server、session、client、帧 IO、握手 caps、编码策略、patch 格式
- **NIP CA 服务** —— CA router + RA 准入模型、SQL CA store、TrustFrame 校验器、完整六步 §7 `VerifyFull` 验证器
- **NWP 服务端面**扩展（memory/complex node 服务）
- **Daemon observability**（health / metrics / logging / shutdown）与 **telemetry**

## 安装

```bash
go get github.com/labacacia/NPS-sdk-go
```

---

## 快速开始

### NCP —— 帧编解码

```go
import (
    "github.com/labacacia/NPS-sdk-go/core"
    "github.com/labacacia/NPS-sdk-go/ncp"
)

// 创建完整注册表（5 个协议）
reg := core.CreateFullRegistry()
codec := core.NewNpsFrameCodec(reg)

// 构造并编码 AnchorFrame
frame := &ncp.AnchorFrame{
    AnchorID: "sha256:abc...",
    Schema:   core.FrameDict{"type": "object", "version": "1"},
    TTL:      3600,
}
wire, err := codec.Encode(frame.FrameType(), frame.ToDict(), core.EncodingTierMsgPack, true)
// wire 已可发送

// 接收端解码
ft, dict, err := codec.Decode(wire)
received := ncp.AnchorFrameFromDict(dict)
```

### NCP —— AnchorFrame 缓存

```go
cache := core.NewAnchorFrameCache()

// 带 TTL 存储
schema := core.FrameDict{"type": "object", "fields": []any{"name", "value"}}
anchorID, err := cache.Set(schema, 3600) // 1 小时 TTL

// 读取（过期返回 nil）
schema, err = cache.GetRequired(anchorID)
```

### NWP —— HTTP 客户端

```go
import "github.com/labacacia/NPS-sdk-go/nwp"

client := nwp.NewNwpClient("http://node.example.com:17433")

// 查询
qf := &nwp.QueryFrame{AnchorRef: "sha256:abc...", Filters: map[string]any{"status": "active"}}
capsFrame, err := client.Query(ctx, qf)

// 流式
frames, err := client.Stream(ctx, qf)
for _, sf := range frames {
    fmt.Println(sf.Payload)
}

// 同步 Action 调用
af := &nwp.ActionFrame{Action: "create", Payload: map[string]any{"name": "item"}}
result, err := client.Invoke(ctx, af)

// 异步 Action 调用
af.Async = true
result, err = client.Invoke(ctx, af)
fmt.Println(result.Async.TaskID)
```

### NWP —— Native 服务端

```go
import (
    "context"

    "github.com/labacacia/NPS-sdk-go/ncp"
    "github.com/labacacia/NPS-sdk-go/nwp"
)

server := nwp.NewNwpNativeNodeServer()
server.QueryHandler = func(ctx context.Context, query *nwp.QueryFrame) (*ncp.CapsFrame, error) {
    return ncp.NewCapsFrame("native:orders", []any{map[string]any{"id": 42}}), nil
}
server.ActionHandler = func(ctx context.Context, action *nwp.ActionFrame) (any, error) {
    return map[string]any{"action": action.Action}, nil
}

// `rw` 已完成 NCP preamble、TLS 和 Hello negotiation。
err := server.Serve(ctx, rw)
```

### NIP —— 身份与签名

```go
import "github.com/labacacia/NPS-sdk-go/nip"

// 生成新身份
id, err := nip.Generate()
fmt.Println(id.PubKeyString()) // "ed25519:<hex>"

// 对帧 dict 签名
payload := core.FrameDict{"nid": "urn:nps:node:example.com:agent", "pub_key": id.PubKeyString()}
sig := id.Sign(payload)

// 验签
ok := id.Verify(payload, sig)

// 仅凭公钥字符串验签（无需私钥）
ok = nip.VerifyWithPubKeyStr(payload, "ed25519:<hex>", sig)

// 保存 / 加载（AES-256-GCM + PBKDF2-SHA256，600k 轮）
err = id.Save("/path/to/identity.json", "my-passphrase")
loaded, err := nip.Load("/path/to/identity.json", "my-passphrase")
```

### NIP —— 远程 CA Client

```go
import "github.com/labacacia/NPS-sdk-go/nip"

ca := nip.NewNipCaClientFull("https://ca.example.com", "/nip", nil)
discovery, err := ca.GetDiscovery(ctx)
ident, err := ca.RegisterAgent(ctx, nip.NipCaRegisterRequest{
    Identifier:   "agent-a",
    PubKey:       "ed25519:<pub>",
    Capabilities: []string{"nwp:query"},
}, "token")
status, err := ca.VerifyAgent(ctx, ident.NID)
```

### 一致性 Manifest

```go
import "github.com/labacacia/NPS-sdk-go/conformance"

cases, err := conformance.CatalogForProfile(conformance.NodeL1)
results := make([]conformance.CaseResult, 0, len(cases))
for _, c := range cases {
    results = append(results, conformance.CaseResult{ID: c.ID, Result: "pass"})
}
manifest := conformance.NewManifest(
    conformance.NodeL1,
    "my-node",
    "1.0.0-alpha.17",
    "urn:nps:node:example.com:my-node",
    "labacacia-fixture",
    "1.0.0-alpha.17",
    results,
    "ci",
)
validation := conformance.ValidateManifest(manifest)
```

### NDP —— 发现注册表

```go
import "github.com/labacacia/NPS-sdk-go/ndp"

registry := ndp.NewInMemoryNdpRegistry()

// 公告节点
frame := &ndp.AnnounceFrame{
    NID:       "urn:nps:node:example.com:agent",
    Addresses: []map[string]any{{"host": "example.com", "port": uint64(17433), "protocol": "nps"}},
    Caps:      []string{"nwp", "nop"},
    TTL:       300,
    Timestamp: time.Now().UTC().Format(time.RFC3339),
}
registry.Announce(frame)

// 解析目标 URL
result := registry.Resolve("nwp://example.com/agent")
// result.Host、result.Port、result.Protocol

// 校验 announce 签名
validator := ndp.NewNdpAnnounceValidator()
validator.RegisterPublicKey("urn:nps:node:example.com:agent", "ed25519:<hex>")
frame.Signature = id.Sign(frame.UnsignedDict())
result := validator.Validate(frame)
// result.IsValid、result.ErrorCode、result.Message
```

### NOP —— 编排客户端

```go
import "github.com/labacacia/NPS-sdk-go/nop"

client := nop.NewNopClient("http://orchestrator.example.com:17433")

// 提交 DAG 任务
tf := &nop.TaskFrame{
    TaskID:    "task-" + uuid,
    DAG:       map[string]any{...},
    TimeoutMs: &timeout,
}
taskID, err := client.Submit(ctx, tf)

// 轮询状态
status, err := client.GetStatus(ctx, taskID)
fmt.Println(status.State()) // "running"

// 等待完成（每 500ms 轮询一次）
status, err = client.Wait(ctx, taskID, nil)
fmt.Println(status.State())        // "completed"
fmt.Println(status.NodeResults())  // map[string]any

// 取消
err = client.Cancel(ctx, taskID)
```

---

## 帧类型

| 帧 | 类型码 | 包 |
|----|--------|----|
| AnchorFrame | 0x01 | `ncp` |
| DiffFrame | 0x02 | `ncp` |
| StreamFrame | 0x03 | `ncp` |
| CapsFrame | 0x04 | `ncp` |
| HelloFrame | 0x06 | `ncp` |
| QueryFrame | 0x10 | `nwp` |
| ActionFrame | 0x11 | `nwp` |
| IdentFrame | 0x20 | `nip` |
| TrustFrame | 0x21 | `nip` |
| RevokeFrame | 0x22 | `nip` |
| AnnounceFrame | 0x30 | `ndp` |
| ResolveFrame | 0x31 | `ndp` |
| GraphFrame | 0x32 | `ndp` |
| TaskFrame | 0x40 | `nop` |
| DelegateFrame | 0x41 | `nop` |
| SyncFrame | 0x42 | `nop` |
| AlignStreamFrame | 0x43 | `nop` |
| ErrorFrame | 0xFE | `ncp` |

---

## 编码

| Tier | 常量 | 备注 |
|------|------|------|
| JSON | `core.EncodingTierJSON` | 可读，Tier-1 |
| MsgPack | `core.EncodingTierMsgPack` | 约 60% 体积削减，Tier-2（默认） |
| BinaryVector | `core.EncodingTierBinaryVector` | `binary_vector.v1`，用于向量密集型帧的 Tier-3 |

---

## 退避策略（NOP）

```go
delay := nop.ComputeDelayMs(nop.BackoffExponential, 100, 5000, attempt)
// BackoffFixed、BackoffLinear、BackoffExponential
```

---

## 运行测试

```bash
go test ./...
```

---

## 许可证

Apache 2.0 —— Copyright 2026 INNO LOTUS PTY LTD
