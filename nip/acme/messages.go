// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package acme

// DirectoryMeta — optional metadata in a Directory (RFC 8555 §7.1.1).
type DirectoryMeta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CaaIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

// Directory — root ACME service catalog.
type Directory struct {
	NewNonce   string         `json:"newNonce"`
	NewAccount string         `json:"newAccount"`
	NewOrder   string         `json:"newOrder"`
	RevokeCert string         `json:"revokeCert,omitempty"`
	KeyChange  string         `json:"keyChange,omitempty"`
	Meta       *DirectoryMeta `json:"meta,omitempty"`
}

type NewAccountPayload struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
	Contact              []string `json:"contact,omitempty"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
}

type Account struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders,omitempty"`
}

type Identifier struct {
	Type  string `json:"type"` // "nid" per NPS-RFC-0002 §4.4
	Value string `json:"value"`
}

type NewOrderPayload struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore,omitempty"`
	NotAfter    string       `json:"notAfter,omitempty"`
}

type ProblemDetail struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
	Status int    `json:"status,omitempty"`
}

type Order struct {
	Status         string         `json:"status"`
	Expires        string         `json:"expires,omitempty"`
	Identifiers    []Identifier   `json:"identifiers"`
	Authorizations []string       `json:"authorizations"`
	Finalize       string         `json:"finalize"`
	Certificate    string         `json:"certificate,omitempty"`
	Error          *ProblemDetail `json:"error,omitempty"`
}

type Challenge struct {
	Type      string         `json:"type"` // "agent-01" per NPS-RFC-0002 §4.4
	URL       string         `json:"url"`
	Status    string         `json:"status"`
	Token     string         `json:"token"`
	Validated string         `json:"validated,omitempty"`
	Error     *ProblemDetail `json:"error,omitempty"`
}

type Authorization struct {
	Status     string      `json:"status"`
	Expires    string      `json:"expires,omitempty"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
}

type ChallengeRespondPayload struct {
	// AgentSignature is base64url(Ed25519(token)) per NPS-RFC-0002 §4.4.
	AgentSignature string `json:"agent_signature"`
}

type FinalizePayload struct {
	// CSR is base64url(CSR DER).
	CSR string `json:"csr"`
}
