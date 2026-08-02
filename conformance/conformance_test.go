// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package conformance

import "testing"

func TestCatalogContainsExpectedCases(t *testing.T) {
	if len(NodeL1Cases) != 20 {
		t.Fatalf("NodeL1 len = %d", len(NodeL1Cases))
	}
	if len(NodeL2Cases) != 16 {
		t.Fatalf("NodeL2 len = %d", len(NodeL2Cases))
	}
	if NodeL1Cases[0].ID != "TC-N1-NCP-01" {
		t.Fatalf("unexpected first case %s", NodeL1Cases[0].ID)
	}
}

func TestValidatorAcceptsCompleteL1Manifest(t *testing.T) {
	results := make([]CaseResult, 0, len(NodeL1Cases))
	for _, c := range NodeL1Cases {
		result := "pass"
		if c.Optional {
			result = "na"
		}
		results = append(results, CaseResult{ID: c.ID, Result: result})
	}
	manifest := NewManifest(NodeL1, "node", "0.1.0", "urn:nps:node:example.test:node-1", "reference", "1.0.0-alpha.17", results, "")

	if validation := ValidateManifest(manifest); !validation.Valid {
		t.Fatalf("expected valid manifest: %s", validation.Message)
	}
}

func TestValidatorRejectsMissingCase(t *testing.T) {
	results := make([]CaseResult, 0, len(NodeL1Cases)-1)
	for _, c := range NodeL1Cases[:len(NodeL1Cases)-1] {
		results = append(results, CaseResult{ID: c.ID, Result: "pass"})
	}
	manifest := NewManifest(NodeL1, "node", "0.1.0", "urn:nps:node:example.test:node-1", "reference", "1.0.0-alpha.17", results, "")

	if validation := ValidateManifest(manifest); validation.Valid {
		t.Fatal("expected invalid manifest")
	}
}
