// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import "fmt"

type NipRevocationMode string

const (
	NipRevocationIfConfigured NipRevocationMode = "if_configured"
	NipRevocationRequired     NipRevocationMode = "required"
)

type NipRevocationSource string

const (
	NipRevocationLocalCrl NipRevocationSource = "local_crl"
	NipRevocationCallback NipRevocationSource = "callback"
	NipRevocationCaStore  NipRevocationSource = "ca_store"
	NipRevocationOcsp     NipRevocationSource = "ocsp"
)

type NipRevocationOutcome string

const (
	NipRevocationGood        NipRevocationOutcome = "good"
	NipRevocationRevoked     NipRevocationOutcome = "revoked"
	NipRevocationUnavailable NipRevocationOutcome = "unavailable"
)

// NipRevocationPolicy incrementally evaluates NIP v0.13 Step 4.
type NipRevocationPolicy struct {
	mode             NipRevocationMode
	ocspFailOpen     bool
	consultedSources []NipRevocationSource
}

func NewNipRevocationPolicy(mode NipRevocationMode, ocspFailOpen bool) *NipRevocationPolicy {
	if mode == "" {
		mode = NipRevocationIfConfigured
	}
	return &NipRevocationPolicy{mode: mode, ocspFailOpen: ocspFailOpen}
}

func (p *NipRevocationPolicy) ConsultedSources() []NipRevocationSource {
	result := make([]NipRevocationSource, len(p.consultedSources))
	copy(result, p.consultedSources)
	return result
}

// Observe records one configured source. Nil means evaluation may continue.
func (p *NipRevocationPolicy) Observe(source NipRevocationSource, outcome NipRevocationOutcome) *IdentVerifyResult {
	p.consultedSources = append(p.consultedSources, source)
	if source == NipRevocationOcsp && outcome == NipRevocationUnavailable && p.ocspFailOpen {
		return nil
	}
	switch outcome {
	case NipRevocationGood:
		return nil
	case NipRevocationRevoked:
		result := fail(4, ErrCertRevoked,
			fmt.Sprintf("revocation source %s reports the certificate revoked", source))
		return &result
	default:
		result := fail(4, ErrOcspUnavailable,
			fmt.Sprintf("revocation source %s is unavailable", source))
		return &result
	}
}

func (p *NipRevocationPolicy) Complete() IdentVerifyResult {
	if p.mode == NipRevocationRequired && len(p.consultedSources) == 0 {
		return fail(4, ErrOcspUnavailable,
			"revocation mode is required, but no revocation source is configured")
	}
	return IdentVerifyResult{Valid: true}
}
