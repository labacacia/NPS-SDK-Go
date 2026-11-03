// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package conformance

import (
	"strings"
	"testing"
)

func TestCatalogContainsExpectedCases(t *testing.T) {
	if len(NodeL1Cases) != 20 {
		t.Fatalf("NodeL1 len = %d", len(NodeL1Cases))
	}
	if len(NodeL2Cases) != 38 {
		t.Fatalf("NodeL2 len = %d", len(NodeL2Cases))
	}
	if NodeL1Cases[0].ID != "TC-N1-NCP-01" {
		t.Fatalf("unexpected first case %s", NodeL1Cases[0].ID)
	}
}

func TestValidatorEnforcesL2AllOrNothingFamilies(t *testing.T) {
	results := make([]CaseResult, 0, len(NodeL2Cases))
	for _, c := range NodeL2Cases {
		result := "na"
		if strings.HasPrefix(c.ID, "TC-N2-AaaS-") || strings.HasPrefix(c.ID, "TC-N2-Anchor") || c.ID == "TC-N2-HA-09" {
			result = "pass"
		}
		results = append(results, CaseResult{ID: c.ID, Result: result})
	}
	manifest := NewManifest(NodeL2, "single-anchor", "0.1.0", "urn:nps:node:example.test:anchor-1", "reference", "1.0.0-alpha.18", results, "")
	if manifest.ProfileVersion != "0.7" {
		t.Fatalf("profile version = %s", manifest.ProfileVersion)
	}
	if validation := ValidateManifest(manifest); !validation.Valid {
		t.Fatalf("expected valid manifest: %s", validation.Message)
	}

	manifest.Cases[19].Result = "pass"
	manifest.Summary.Pass++
	manifest.Summary.NotApplicable--
	if validation := ValidateManifest(manifest); validation.Valid || !strings.Contains(validation.Message, "must be all pass or all na") {
		t.Fatalf("expected partial-family rejection, got %+v", validation)
	}

	manifest.Cases[19].Result = "na"
	manifest.Cases[len(manifest.Cases)-1].Result = "na"
	manifest.Summary.Pass -= 2
	manifest.Summary.NotApplicable += 2
	if validation := ValidateManifest(manifest); validation.Valid || !strings.Contains(validation.Message, "opposite applicability") {
		t.Fatalf("expected HA applicability rejection, got %+v", validation)
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
	manifest := NewManifest(NodeL1, "node", "0.1.0", "urn:nps:node:example.test:node-1", "reference", "1.0.0-alpha.18", results, "")

	if validation := ValidateManifest(manifest); !validation.Valid {
		t.Fatalf("expected valid manifest: %s", validation.Message)
	}
}

func TestValidatorRequiresReasonForAaaSShouldException(t *testing.T) {
	results := make([]CaseResult, 0, len(NodeL2Cases))
	for _, c := range NodeL2Cases {
		result := "na"
		if strings.HasPrefix(c.ID, "TC-N2-AaaS-") || strings.HasPrefix(c.ID, "TC-N2-Anchor") || c.ID == "TC-N2-HA-09" {
			result = "pass"
		}
		results = append(results, CaseResult{ID: c.ID, Result: result})
	}
	results[5] = CaseResult{ID: "TC-N2-AaaS-06", Result: "na"}
	missingReason := NewManifest(NodeL2, "service", "0.1.0", "urn:nps:node:example.test:anchor-1", "reference", "1.0.0-alpha.18", results, "")
	if validation := ValidateManifest(missingReason); validation.Valid || !strings.Contains(validation.Message, "requires a non-empty message") {
		t.Fatalf("expected missing-reason rejection, got %+v", validation)
	}
	results[5].Message = "Synchronous-only deployment"
	reasoned := NewManifest(NodeL2, "service", "0.1.0", "urn:nps:node:example.test:anchor-1", "reference", "1.0.0-alpha.18", results, "")
	if validation := ValidateManifest(reasoned); !validation.Valid {
		t.Fatalf("expected reasoned exception to pass: %s", validation.Message)
	}
}

func TestValidatorRejectsMissingCase(t *testing.T) {
	results := make([]CaseResult, 0, len(NodeL1Cases)-1)
	for _, c := range NodeL1Cases[:len(NodeL1Cases)-1] {
		results = append(results, CaseResult{ID: c.ID, Result: "pass"})
	}
	manifest := NewManifest(NodeL1, "node", "0.1.0", "urn:nps:node:example.test:node-1", "reference", "1.0.0-alpha.18", results, "")

	if validation := ValidateManifest(manifest); validation.Valid {
		t.Fatal("expected invalid manifest")
	}
}
