// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip_test

import (
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
	npsnip "github.com/labacacia/NPS-sdk-go/nip"
)

func TestAlpha17PortableRevocationPolicyVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			ID    string `json:"id"`
			Input struct {
				Mode         npsnip.NipRevocationMode `json:"revocation_mode"`
				OcspFailOpen bool                     `json:"ocsp_fail_open"`
				Sources      []struct {
					Source  npsnip.NipRevocationSource  `json:"source"`
					Outcome npsnip.NipRevocationOutcome `json:"outcome"`
				} `json:"sources"`
			} `json:"input"`
			Expected struct {
				Valid            bool                         `json:"valid"`
				FailedStep       int                          `json:"failed_step"`
				Error            string                       `json:"error"`
				ConsultedSources []npsnip.NipRevocationSource `json:"consulted_sources"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	readNipFixture(t, "revocation_policy_vectors.json", &fixture)
	for _, vector := range fixture.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			policy := npsnip.NewNipRevocationPolicy(
				vector.Input.Mode, vector.Input.OcspFailOpen)
			var result *npsnip.IdentVerifyResult
			for _, item := range vector.Input.Sources {
				result = policy.Observe(item.Source, item.Outcome)
				if result != nil {
					break
				}
			}
			if result == nil {
				completed := policy.Complete()
				result = &completed
			}
			if result.Valid != vector.Expected.Valid ||
				result.StepFailed != vector.Expected.FailedStep ||
				result.ErrorCode != vector.Expected.Error {
				t.Fatalf("result mismatch: got %#v want %#v", result, vector.Expected)
			}
			if !reflect.DeepEqual(policy.ConsultedSources(), vector.Expected.ConsultedSources) {
				t.Fatalf("consulted mismatch: got %v want %v",
					policy.ConsultedSources(), vector.Expected.ConsultedSources)
			}
		})
	}
}

func TestAlpha17PortableSignedCrlVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			ID    string `json:"id"`
			Input struct {
				PublicKey string          `json:"public_key"`
				Body      json.RawMessage `json:"body"`
				Signature string          `json:"signature"`
			} `json:"input"`
			Expected struct {
				SignatureValid bool `json:"signature_valid"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	readNipFixture(t, "signed_crl_vectors.json", &fixture)
	for _, vector := range fixture.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			var crl npsnip.NipCaCrl
			if err := json.Unmarshal(vector.Input.Body, &crl); err != nil {
				t.Fatal(err)
			}
			crl.Signature = vector.Input.Signature
			if got := npsnip.VerifyCrlSignature(&crl, vector.Input.PublicKey); got != vector.Expected.SignatureValid {
				t.Fatalf("signature valid = %v, want %v", got, vector.Expected.SignatureValid)
			}
		})
	}
}

func readNipFixture(t *testing.T, name string, out any) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path, err := testfixture.ConformanceFile(file, "nip", name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
}
