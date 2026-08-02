// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ndp

import (
	"fmt"
	"strings"
	"sync"

	"github.com/labacacia/NPS-sdk-go/nip"
)

// NdpAnnounceResult holds the outcome of an announce validation.
type NdpAnnounceResult struct {
	IsValid   bool
	ErrorCode string
	Message   string
}

func resultOK() NdpAnnounceResult {
	return NdpAnnounceResult{IsValid: true}
}

func resultFail(code, msg string) NdpAnnounceResult {
	return NdpAnnounceResult{IsValid: false, ErrorCode: code, Message: msg}
}

// NdpAnnounceValidator verifies NDP announce frame signatures.
type NdpAnnounceValidator struct {
	mu   sync.RWMutex
	keys map[string]string // nid → "ed25519:<hex>"
}

func NewNdpAnnounceValidator() *NdpAnnounceValidator {
	return &NdpAnnounceValidator{keys: make(map[string]string)}
}

func (v *NdpAnnounceValidator) RegisterPublicKey(nid, pubKey string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys[nid] = pubKey
}

func (v *NdpAnnounceValidator) RemovePublicKey(nid string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.keys, nid)
}

func (v *NdpAnnounceValidator) KnownPublicKeys() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make(map[string]string, len(v.keys))
	for k, val := range v.keys {
		out[k] = val
	}
	return out
}

func (v *NdpAnnounceValidator) Validate(frame *AnnounceFrame) NdpAnnounceResult {
	v.mu.RLock()
	pubKey, ok := v.keys[frame.NID]
	v.mu.RUnlock()

	if !ok {
		return resultFail(ErrAnnounceNidMismatch,
			fmt.Sprintf("no public key registered for NID %s", frame.NID))
	}
	if !strings.HasPrefix(frame.Signature, "ed25519:") {
		return resultFail(ErrAnnounceSignatureInvalid, "signature must have ed25519: prefix")
	}

	unsigned := frame.UnsignedDict()
	if VerifyAnnounceSignature(frame.ToDict(), pubKey, frame.Signature) ||
		nip.VerifyWithPubKeyStr(unsigned, pubKey, frame.Signature) {
		return resultOK()
	}
	return resultFail(ErrAnnounceSignatureInvalid, "signature verification failed")
}
