[English Version](./nps-go.nip.md) | 中文版

# `github.com/labacacia/NPS-sdk-go/nip` — 参考

> 规范：[NPS-3 NIP v0.9](https://github.com/labacacia/NPS/blob/main/spec/NPS-3-NIP.md)

身份层。三个帧 + 一个 Ed25519 辅助类，支持 AES-256-GCM 加密的磁盘
持久化。

---

## 目录

- [`IdentFrame` (0x20)](#identframe-0x20)
- [`TrustFrame` (0x21)](#trustframe-0x21)
- [`RevokeFrame` (0x22)](#revokeframe-0x22)
- [`NipIdentity`](#nipidentity)
- [密钥文件格式](#密钥文件格式)

---

## `IdentFrame` (0x20)

节点身份声明。

```go
type IdentFrame struct {
    NID       string                // "urn:nps:node:{authority}:{name}"
    PubKey    string                // "ed25519:{hex}"
    Meta      map[string]any
    Signature *string               // "ed25519:{base64}"
}

func (f *IdentFrame) UnsignedDict() core.FrameDict    // 剥离 `signature`
func (f *IdentFrame) ToDict()       core.FrameDict
func IdentFrameFromDict(d core.FrameDict) *IdentFrame
```

签名流程：

1. 构造时 `Signature: nil`。
2. `sig := id.Sign(frame.UnsignedDict())` → `"ed25519:{base64}"`。
3. 编码前赋值 `frame.Signature = &sig`。

---

## `TrustFrame` (0x21)

委托 / 信任声明。

```go
type TrustFrame struct {
    IssuerNID  string
    SubjectNID string
    Scopes     []string
    ExpiresAt  *string            // ISO 8601 UTC
    Signature  *string            // "ed25519:{base64}"
}
```

签名约定相同：对去除 `signature` 字段后的 dict 取规范 JSON。
`TrustFrameFromDict` 接受 `scopes` 字段为 `[]string` 或 `[]any`
（MsgPack 解码器通常发出 `[]any`）。

---

## `RevokeFrame` (0x22)

吊销一个 NID —— 先于或伴随 `TTL == 0` 的 `AnnounceFrame`。

```go
type RevokeFrame struct {
    NID       string
    Reason    *string
    RevokedAt *string
}
```

---

## `NipIdentity`

Ed25519 密钥对加规范 JSON sign / verify。

```go
type NipIdentity struct { /* … */ }

func Generate() (*NipIdentity, error)

func (id *NipIdentity) PubKeyString() string                          // "ed25519:{hex}"

func (id *NipIdentity) Sign  (payload core.FrameDict) string          // "ed25519:{base64}"
func (id *NipIdentity) Verify(payload core.FrameDict, signature string) bool

// 包级辅助：解析 "ed25519:{hex}" 公钥字符串并针对 `payload` 验证。
func VerifyWithPubKeyStr(payload core.FrameDict, pubKey, signature string) bool

func (id *NipIdentity) Save(path, passphrase string) error
func Load(path, passphrase string) (*NipIdentity, error)
```

### 规范签名 payload

`Sign` 和 `Verify` 都按键字典序排序并经 `encoding/json` 序列化
payload —— 无空白、按键序。这与 .NET / Python / Java / TS / Rust SDK
共用的键排序规范器一致；**不使用 RFC 8785 JCS**。

### 验证

- `Verify(payload, sig)` 针对实例自身公钥验证。
- `VerifyWithPubKeyStr` 是
  [`NdpAnnounceValidator`](./nps-go.ndp.cn.md#ndpannouncevalidator) 使用
  的独立辅助 —— 解析 `"ed25519:{hex}"` → 32 字节公钥 → 经
  `crypto/ed25519` 验证。

两个验证器遇到任何解析、长度或签名不匹配错误时返回 `false` ——
从不 panic。

---

## 密钥文件格式

`Save` 写入加密 JSON 信封（mode `0600`）：

```json
{
  "version":    1,
  "algorithm":  "ed25519",
  "pub_key":    "ed25519:<hex>",
  "salt":       "<hex 16 字节>",
  "nonce":      "<hex 12 字节>",
  "ciphertext": "<hex — 64 字节 ed25519.PrivateKey 的 AES-256-GCM 密文>"
}
```

| 参数              | 值 |
|-------------------|-----|
| PBKDF2 算法        | `PBKDF2-HMAC-SHA256`（`golang.org/x/crypto/pbkdf2`）|
| PBKDF2 迭代        | 600 000 |
| 派生密钥           | 32 字节（256-bit）|
| Salt              | 16 字节（随机，`crypto/rand`）|
| Nonce             | 12 字节（随机，`crypto/rand`）|
| Cipher            | `AES-256-GCM`（`crypto/aes` + `crypto/cipher`）|
| 明文              | 原始 `ed25519.PrivateKey` 字节（64 B：seed \|\| 公钥）|

`Load` 重新计算 PBKDF2 密钥并解密；passphrase 错误以
`*core.ErrIdentity{Msg: "decryption failed — wrong passphrase?"}` 浮现。

> **跨 SDK 注。** Go 信封存储完整 64 字节 Go stdlib
> `ed25519.PrivateKey`。Rust 信封存储 32 字节 seed；Java 信封存储
> PKCS#8 / X.509 DER。三种格式**不**逐字节互换 —— 对跨 SDK 互操作
> 请使用 `PubKeyString()` + `Sign` 输出，而非加载另一 SDK 的密钥
> 文件。

---

## 端到端

```go
import (
    "github.com/labacacia/NPS-sdk-go/core"
    "github.com/labacacia/NPS-sdk-go/nip"
)

id, err := nip.Generate()
if err != nil { /* … */ }
nid := "urn:nps:node:api.example.com:products"

// 签名 payload
payload := core.FrameDict{
    "action": "announce",
    "nid":    nid,
}
sig := id.Sign(payload)
ok  := id.Verify(payload, sig)
_ = ok // true

// 跨密钥验证（如经 NDP announce 校验器）
ok = nip.VerifyWithPubKeyStr(payload, id.PubKeyString(), sig)

// 加密持久化
if err := id.Save("node.key", "my-passphrase"); err != nil { /* … */ }
loaded, err := nip.Load("node.key", "my-passphrase")
if err != nil { /* … */ }
_ = loaded.PubKeyString() == id.PubKeyString()   // true
```
