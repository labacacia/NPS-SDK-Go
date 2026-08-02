// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import (
	"fmt"

	"github.com/labacacia/NPS-sdk-go/core"
)

func str(d core.FrameDict, k string) string {
	if v, ok := d[k].(string); ok {
		return v
	}
	return ""
}
func optStr(d core.FrameDict, k string) *string {
	if v, ok := d[k].(string); ok {
		return &v
	}
	return nil
}

// ── IdentReputationPolicyHint ─────────────────────────────────────────────────

// IdentReputationPolicyHint carries optional hints for reputation-log sourcing (alpha.10).
type IdentReputationPolicyHint struct {
	LogSources []string `json:"log_sources,omitempty"`
	Consent    bool     `json:"consent,omitempty"`
}

// ── IdentFrame ────────────────────────────────────────────────────────────────

type IdentFrame struct {
	NID       string
	PubKey    string
	Meta      map[string]any
	Signature *string
	Scope     map[string]any
	Lineage   map[string]any
	IssuedBy  string
	IssuedAt  string
	ExpiresAt string
	Serial    string

	// NPS-RFC-0003 — optional assurance level.
	AssuranceLevel *AssuranceLevel
	// NPS-RFC-0002 — optional v2 X.509 dual-trust extensions.
	// CertFormat is the wire form (CertFormatV1Proprietary | CertFormatV2X509).
	CertFormat *string
	// CertChain is base64url(DER), [leaf, intermediates..., root].
	CertChain []string
	// OCSPStaple is a base64-encoded OCSP response stapled to this identity frame (alpha.11).
	OCSPStaple string
	// NodeRoles is a list of self-declared node-role tags (NIP v0.10 alpha.13).
	// Excluded from the v1 signed payload, matching the reference impl.
	NodeRoles []string
	// Capabilities is the set of capabilities this identity claims. NIP v0.12
	// §7.5 Phase-3 enforcement checks it is a subset of the CA-attested
	// id-nps-capabilities extension. Unlike NodeRoles it IS part of the v1 signed
	// payload (the reference NipSigner excludes node_roles but not capabilities);
	// it is emitted only when non-empty, so frames that omit it canonicalize
	// exactly as before.
	Capabilities []string
}

func (f *IdentFrame) FrameType() core.FrameType { return core.FrameTypeIdent }

// UnsignedDict returns the dict the v1 Ed25519 signature covers.
// Deliberately excludes cert_format / cert_chain so the v1 sig stays
// covering exactly the same payload as before NPS-RFC-0002.
func (f *IdentFrame) UnsignedDict() core.FrameDict {
	d := core.FrameDict{"nid": f.NID, "pub_key": f.PubKey}
	if f.Meta != nil {
		d["metadata"] = f.Meta
	}
	if f.AssuranceLevel != nil {
		d["assurance_level"] = f.AssuranceLevel.Wire
	}
	if len(f.Capabilities) > 0 {
		d["capabilities"] = f.Capabilities
	}
	if f.Scope != nil {
		d["scope"] = f.Scope
	}
	if f.Lineage != nil {
		d["lineage"] = f.Lineage
	}
	if f.IssuedBy != "" {
		d["issued_by"] = f.IssuedBy
	}
	if f.IssuedAt != "" {
		d["issued_at"] = f.IssuedAt
	}
	if f.ExpiresAt != "" {
		d["expires_at"] = f.ExpiresAt
	}
	if f.Serial != "" {
		d["serial"] = f.Serial
	}
	return d
}

func (f *IdentFrame) ToDict() core.FrameDict {
	d := f.UnsignedDict()
	if f.Signature != nil {
		d["signature"] = *f.Signature
	}
	if f.CertFormat != nil {
		d["cert_format"] = *f.CertFormat
	}
	if f.CertChain != nil {
		d["cert_chain"] = f.CertChain
	}
	if f.OCSPStaple != "" {
		d["ocsp_staple"] = f.OCSPStaple
	}
	if f.NodeRoles != nil {
		d["node_roles"] = f.NodeRoles
	}
	// capabilities is already emitted by UnsignedDict (it is inside the signed body).
	return d
}

func IdentFrameFromDict(d core.FrameDict) *IdentFrame {
	var meta map[string]any
	if v, ok := d["metadata"].(map[string]any); ok {
		meta = v
	}
	var scope map[string]any
	if v, ok := d["scope"].(map[string]any); ok {
		scope = v
	}
	var lineage map[string]any
	if v, ok := d["lineage"].(map[string]any); ok {
		lineage = v
	}
	var assurance *AssuranceLevel
	if v, ok := d["assurance_level"].(string); ok {
		if l, err := AssuranceFromWire(v); err == nil {
			assurance = &l
		}
	}
	var chain []string
	switch v := d["cert_chain"].(type) {
	case []string:
		chain = v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				chain = append(chain, s)
			}
		}
	}
	nodeRoles := stringSlice(d["node_roles"])
	capabilities := stringSlice(d["capabilities"])
	return &IdentFrame{
		NID:            str(d, "nid"),
		PubKey:         str(d, "pub_key"),
		Meta:           meta,
		Signature:      optStr(d, "signature"),
		Scope:          scope,
		Lineage:        lineage,
		IssuedBy:       str(d, "issued_by"),
		IssuedAt:       str(d, "issued_at"),
		ExpiresAt:      str(d, "expires_at"),
		Serial:         str(d, "serial"),
		AssuranceLevel: assurance,
		CertFormat:     optStr(d, "cert_format"),
		CertChain:      chain,
		OCSPStaple:     str(d, "ocsp_staple"),
		NodeRoles:      nodeRoles,
		Capabilities:   capabilities,
	}
}

// ── TrustFrame ────────────────────────────────────────────────────────────────

type TrustFrame struct {
	GrantorNID string
	GranteeCA  string
	TrustScope []string
	Nodes      []string
	IssuedAt   string
	ExpiresAt  string
	Serial     string
	SignerNID  string
	Signature  string
}

func (f *TrustFrame) FrameType() core.FrameType { return core.FrameTypeTrust }

func (f *TrustFrame) UnsignedDict() core.FrameDict {
	return core.FrameDict{
		"frame":       "0x21",
		"grantor_nid": f.GrantorNID,
		"grantee_ca":  f.GranteeCA,
		"trust_scope": f.TrustScope,
		"nodes":       f.Nodes,
		"issued_at":   f.IssuedAt,
		"expires_at":  f.ExpiresAt,
		"serial":      f.Serial,
		"signer_nid":  f.SignerNID,
	}
}

func (f *TrustFrame) ToDict() core.FrameDict {
	d := f.UnsignedDict()
	d["signature"] = f.Signature
	return d
}

func TrustFrameFromDict(d core.FrameDict) *TrustFrame {
	var trustScope []string
	switch v := first(d, "trust_scope", "scopes").(type) {
	case []string:
		trustScope = v
	case []any:
		for _, s := range v {
			if sv, ok := s.(string); ok {
				trustScope = append(trustScope, sv)
			}
		}
	}
	nodes := stringSlice(d["nodes"])
	return &TrustFrame{
		GrantorNID: strAny(d, "grantor_nid", "issuer_nid"),
		GranteeCA:  strAny(d, "grantee_ca", "subject_nid"),
		TrustScope: trustScope,
		Nodes:      nodes,
		IssuedAt:   str(d, "issued_at"),
		ExpiresAt:  str(d, "expires_at"),
		Serial:     str(d, "serial"),
		SignerNID:  strAny(d, "signer_nid", "grantor_nid", "issuer_nid"),
		Signature:  str(d, "signature"),
	}
}

// ── RevokeFrame ───────────────────────────────────────────────────────────────

type RevokeFrame struct {
	TargetNID string
	Serial    *string
	Reason    string
	RevokedAt string
	ParentNID *string
	SignerNID string
	Signature string
}

func (f *RevokeFrame) FrameType() core.FrameType { return core.FrameTypeRevoke }

func (f *RevokeFrame) Validate() error {
	if f.Reason == "parent_revoked" {
		if f.ParentNID == nil || *f.ParentNID == "" {
			return fmt.Errorf("%s: parent_nid is required when reason=parent_revoked", ErrRevokeFrameInvalid)
		}
	} else if f.ParentNID != nil {
		return fmt.Errorf("%s: parent_nid must be omitted unless reason=parent_revoked", ErrRevokeFrameInvalid)
	}
	return nil
}

func (f *RevokeFrame) UnsignedDict() core.FrameDict {
	d := core.FrameDict{
		"frame":      "0x22",
		"target_nid": f.TargetNID,
		"reason":     f.Reason,
		"revoked_at": f.RevokedAt,
		"signer_nid": f.SignerNID,
	}
	if f.Serial != nil {
		d["serial"] = *f.Serial
	}
	if f.ParentNID != nil {
		d["parent_nid"] = *f.ParentNID
	}
	return d
}

func (f *RevokeFrame) ToDict() core.FrameDict {
	d := f.UnsignedDict()
	d["signature"] = f.Signature
	return d
}

func RevokeFrameFromDict(d core.FrameDict) *RevokeFrame {
	return &RevokeFrame{
		TargetNID: strAny(d, "target_nid", "nid"),
		Serial:    optStr(d, "serial"),
		Reason:    str(d, "reason"),
		RevokedAt: str(d, "revoked_at"),
		ParentNID: optStr(d, "parent_nid"),
		SignerNID: str(d, "signer_nid"),
		Signature: str(d, "signature"),
	}
}

func first(d core.FrameDict, keys ...string) any {
	for _, key := range keys {
		if value, ok := d[key]; ok {
			return value
		}
	}
	return nil
}

func strAny(d core.FrameDict, keys ...string) string {
	for _, key := range keys {
		if v, ok := d[key].(string); ok {
			return v
		}
	}
	return ""
}

func stringSlice(value any) []string {
	var out []string
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
