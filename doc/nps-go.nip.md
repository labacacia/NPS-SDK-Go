English | [中文版](./nps-go.nip.cn.md)

# `github.com/labacacia/NPS-sdk-go/nip` — Reference

> Spec: [NPS-3 NIP v0.9](https://github.com/labacacia/NPS/blob/main/spec/NPS-3-NIP.md)

Identity layer. Three frames + an Ed25519 helper with
AES-256-GCM-encrypted on-disk persistence.

---

## Table of contents

- [`IdentFrame` (0x20)](#identframe-0x20)
- [`TrustFrame` (0x21)](#trustframe-0x21)
- [`RevokeFrame` (0x22)](#revokeframe-0x22)
- [`NipIdentity`](#nipidentity)
- [Key file format](#key-file-format)

---

## `IdentFrame` (0x20)

Node identity declaration.

```go
type IdentFrame struct {
    NID       string                // "urn:nps:node:{authority}:{name}"
    PubKey    string                // "ed25519:{hex}"
    Meta      map[string]any
    Signature *string               // "ed25519:{base64}"
}

func (f *IdentFrame) UnsignedDict() core.FrameDict    // strips `signature`
func (f *IdentFrame) ToDict()       core.FrameDict
func IdentFrameFromDict(d core.FrameDict) *IdentFrame
```

Signing workflow:

1. Construct with `Signature: nil`.
2. `sig := id.Sign(frame.UnsignedDict())` → `"ed25519:{base64}"`.
3. Assign `frame.Signature = &sig` before encoding.

---

## `TrustFrame` (0x21)

Delegation / trust assertion.

```go
type TrustFrame struct {
    IssuerNID  string
    SubjectNID string
    Scopes     []string
    ExpiresAt  *string            // ISO 8601 UTC
    Signature  *string            // "ed25519:{base64}"
}
```

Same signing convention: canonical-JSON of the dict minus the `signature`
field. `TrustFrameFromDict` accepts either `[]string` or `[]any` for the
`scopes` field (MsgPack decoders typically emit `[]any`).

---

## `RevokeFrame` (0x22)

Revokes an NID — precede or accompany an `AnnounceFrame` with `TTL == 0`.

```go
type RevokeFrame struct {
    NID       string
    Reason    *string
    RevokedAt *string
}
```

---

## `NipIdentity`

Ed25519 keypair plus canonical-JSON sign / verify.

```go
type NipIdentity struct { /* … */ }

func Generate() (*NipIdentity, error)

func (id *NipIdentity) PubKeyString() string                          // "ed25519:{hex}"

func (id *NipIdentity) Sign  (payload core.FrameDict) string          // "ed25519:{base64}"
func (id *NipIdentity) Verify(payload core.FrameDict, signature string) bool

// Package-level helper: parse an "ed25519:{hex}" public key string and
// verify against `payload`.
func VerifyWithPubKeyStr(payload core.FrameDict, pubKey, signature string) bool

func (id *NipIdentity) Save(path, passphrase string) error
func Load(path, passphrase string) (*NipIdentity, error)
```

### Canonical signing payload

Both `Sign` and `Verify` serialise the payload by sorting keys
lexicographically and marshalling through `encoding/json` — no
whitespace, lexical key order. This matches the sorted-keys canonicaliser
shared with the .NET / Python / Java / TS / Rust SDKs;
**RFC 8785 JCS is NOT used**.

### Verification

- `Verify(payload, sig)` verifies against the instance's own public key.
- `VerifyWithPubKeyStr` is the free-standing helper used by
  [`NdpAnnounceValidator`](./nps-go.ndp.md#ndpannouncevalidator) — it
  parses `"ed25519:{hex}"` → 32-byte public key → verifies via
  `crypto/ed25519`.

Both verifiers return `false` on any parsing, length, or signature
mismatch error — they never panic.

---

## Key file format

`Save` writes an encrypted JSON envelope (mode `0600`):

```json
{
  "version":    1,
  "algorithm":  "ed25519",
  "pub_key":    "ed25519:<hex>",
  "salt":       "<hex 16 bytes>",
  "nonce":      "<hex 12 bytes>",
  "ciphertext": "<hex — AES-256-GCM of the 64-byte ed25519.PrivateKey>"
}
```

| Parameter | Value |
|-----------|-------|
| PBKDF2 algorithm  | `PBKDF2-HMAC-SHA256` (`golang.org/x/crypto/pbkdf2`) |
| PBKDF2 iterations | 600 000 |
| Derived key       | 32 bytes (256-bit) |
| Salt              | 16 bytes (random, `crypto/rand`) |
| Nonce             | 12 bytes (random, `crypto/rand`) |
| Cipher            | `AES-256-GCM` (`crypto/aes` + `crypto/cipher`) |
| Plaintext         | Raw `ed25519.PrivateKey` bytes (64 B: seed \|\| public key) |

`Load` recomputes the PBKDF2 key and decrypts; a wrong passphrase surfaces
as `*core.ErrIdentity{Msg: "decryption failed — wrong passphrase?"}`.

> **Cross-SDK note.** The Go envelope stores the full 64-byte Go-stdlib
> `ed25519.PrivateKey`. The Rust envelope stores the 32-byte seed; the
> Java envelope stores PKCS#8 / X.509 DER. The three formats are **not**
> interchangeable byte-for-byte — use `PubKeyString()` + `Sign` output
> for cross-SDK interop instead of loading another SDK's key file.

---

## End-to-end

```go
import (
    "github.com/labacacia/NPS-sdk-go/core"
    "github.com/labacacia/NPS-sdk-go/nip"
)

id, err := nip.Generate()
if err != nil { /* … */ }
nid := "urn:nps:node:api.example.com:products"

// Sign a payload
payload := core.FrameDict{
    "action": "announce",
    "nid":    nid,
}
sig := id.Sign(payload)
ok  := id.Verify(payload, sig)
_ = ok // true

// Cross-key verification (e.g. via NDP announce validator)
ok = nip.VerifyWithPubKeyStr(payload, id.PubKeyString(), sig)

// Encrypted persistence
if err := id.Save("node.key", "my-passphrase"); err != nil { /* … */ }
loaded, err := nip.Load("node.key", "my-passphrase")
if err != nil { /* … */ }
_ = loaded.PubKeyString() == id.PubKeyString()   // true
```
