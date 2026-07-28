// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"golang.org/x/crypto/pbkdf2"

	"github.com/labacacia/NPS-sdk-go/core"
)

const (
	pbkdf2Iters = 600_000
	saltLen     = 16
	nonceLen    = 12
	keyLen      = 32
)

// NipIdentity holds an Ed25519 signing keypair.
type NipIdentity struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

// Generate creates a new random NipIdentity.
func Generate() (*NipIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, &core.ErrIdentity{Msg: err.Error()}
	}
	return &NipIdentity{privKey: priv, pubKey: pub}, nil
}

// PubKeyString returns "ed25519:<base64url(raw 32-byte public key)>".
// Encoding is RFC 4648 base64url, unpadded — matching the .NET reference
// (NipSigner.EncodePublicKey) so IdentFrame pub_key fields are wire-compatible.
func (id *NipIdentity) PubKeyString() string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(id.pubKey)
}

// Sign signs a FrameDict using canonical JSON (sorted keys).
// The signature is encoded as "ed25519:<base64url>" (unpadded), matching the
// .NET reference (NipSigner.Sign).
func (id *NipIdentity) Sign(payload core.FrameDict) string {
	canonical := canonicalJSON(payload)
	sig := ed25519.Sign(id.privKey, []byte(canonical))
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(sig)
}

// Verify verifies a signature string against a FrameDict.
func (id *NipIdentity) Verify(payload core.FrameDict, signature string) bool {
	return VerifyWithPubKeyStr(payload, id.PubKeyString(), signature)
}

// VerifyWithPubKeyStr verifies a signature using a "ed25519:<base64url>" public key string.
func VerifyWithPubKeyStr(payload core.FrameDict, pubKeyStr, signature string) bool {
	pubB64 := ""
	if len(pubKeyStr) > 8 && pubKeyStr[:8] == "ed25519:" {
		pubB64 = pubKeyStr[8:]
	} else {
		return false
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}

	sigB64 := ""
	if len(signature) > 8 && signature[:8] == "ed25519:" {
		sigB64 = signature[8:]
	} else {
		return false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}

	canonical := canonicalJSON(payload)
	return ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(canonical), sigBytes)
}

// Save persists the identity to a file encrypted with AES-256-GCM + PBKDF2.
func (id *NipIdentity) Save(path, passphrase string) error {
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return &core.ErrIdentity{Msg: err.Error()}
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return &core.ErrIdentity{Msg: err.Error()}
	}

	dk := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iters, keyLen, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return &core.ErrIdentity{Msg: err.Error()}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return &core.ErrIdentity{Msg: err.Error()}
	}

	plaintext := []byte(id.privKey) // ed25519.PrivateKey is []byte (seed + pub)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	envelope := map[string]any{
		"version":    1,
		"algorithm":  "ed25519",
		"pub_key":    id.PubKeyString(),
		"salt":       hex.EncodeToString(salt),
		"nonce":      hex.EncodeToString(nonce),
		"ciphertext": hex.EncodeToString(ciphertext),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return &core.ErrIdentity{Msg: err.Error()}
	}
	return os.WriteFile(path, data, 0600)
}

// Load reads and decrypts an identity from a file.
func Load(path, passphrase string) (*NipIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &core.ErrIdentity{Msg: err.Error()}
	}
	var envelope map[string]any
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, &core.ErrIdentity{Msg: err.Error()}
	}

	saltHex, _ := envelope["salt"].(string)
	nonceHex, _ := envelope["nonce"].(string)
	ctHex, _ := envelope["ciphertext"].(string)

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, &core.ErrIdentity{Msg: fmt.Sprintf("salt decode: %v", err)}
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, &core.ErrIdentity{Msg: fmt.Sprintf("nonce decode: %v", err)}
	}
	ct, err := hex.DecodeString(ctHex)
	if err != nil {
		return nil, &core.ErrIdentity{Msg: fmt.Sprintf("ciphertext decode: %v", err)}
	}

	dk := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iters, keyLen, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, &core.ErrIdentity{Msg: err.Error()}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &core.ErrIdentity{Msg: err.Error()}
	}

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, &core.ErrIdentity{Msg: "decryption failed — wrong passphrase?"}
	}

	privKey := ed25519.PrivateKey(plaintext)
	return &NipIdentity{privKey: privKey, pubKey: privKey.Public().(ed25519.PublicKey)}, nil
}

// canonicalJSON produces deterministic JSON with sorted keys.
func canonicalJSON(d core.FrameDict) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]any, len(d))
	for _, k := range keys {
		ordered[k] = d[k]
	}
	b, _ := json.Marshal(ordered)
	return string(b)
}
