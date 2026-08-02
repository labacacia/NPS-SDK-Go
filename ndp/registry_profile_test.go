// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ndp

import (
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
)

type vectorSuite struct {
	Vectors []map[string]any `json:"vectors"`
}

func loadProfileVectors(t *testing.T, name string) []map[string]any {
	t.Helper()
	_, current, _, _ := runtime.Caller(0)
	path, err := testfixture.ConformanceFile(current, "ndp", name)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.UseNumber()
	var suite vectorSuite
	if err := decoder.Decode(&suite); err != nil {
		t.Fatal(err)
	}
	return suite.Vectors
}

func TestSharedAnnounceCanonicalizationVectors(t *testing.T) {
	vectors := loadProfileVectors(t, "announce_canonicalization_vectors.json")
	if len(vectors) != 3 {
		t.Fatalf("expected 3 vectors, got %d", len(vectors))
	}
	for _, vector := range vectors {
		input := vector["input"].(map[string]any)
		expected := vector["expected"].(map[string]any)
		frame := input["frame"].(map[string]any)
		canonical, err := CanonicalAnnounceJSON(frame)
		if err != nil {
			t.Fatal(err)
		}
		if canonical != expected["canonical_json"] {
			t.Errorf("%s canonical mismatch", vector["id"])
		}
		if VerifyAnnounceSignature(
			frame,
			input["public_key"].(string),
			input["signature"].(string),
		) != expected["signature_valid"].(bool) {
			t.Errorf("%s signature mismatch", vector["id"])
		}
		wire := cloneMap(frame)
		wire["signature"] = input["signature"]
		model := AnnounceFrameFromDict(core.FrameDict(wire))
		validator := NewNdpAnnounceValidator()
		validator.RegisterPublicKey(model.NID, input["public_key"].(string))
		if validator.Validate(model).IsValid != expected["signature_valid"].(bool) {
			t.Errorf("%s validator mismatch", vector["id"])
		}
	}
}

func TestSharedRegistryConsistencyVectors(t *testing.T) {
	vectors := loadProfileVectors(t, "registry_consistency_vectors.json")
	if len(vectors) != 16 {
		t.Fatalf("expected 16 vectors, got %d", len(vectors))
	}
	for _, vector := range vectors {
		input := vector["input"].(map[string]any)
		expected := vector["expected"].(map[string]any)
		now, _ := time.Parse(time.RFC3339, input["now"].(string))
		registry := NewNdpRegistryProfile(input["profile"].(string))
		var decisions []any
		var errors []any
		for _, raw := range input["announces"].([]any) {
			announce := raw.(map[string]any)
			receivedAt := now
			if value, ok := announce["received_at"].(string); ok {
				receivedAt, _ = time.Parse(time.RFC3339, value)
			}
			result := registry.ApplyAnnounce(
				announce["frame"].(map[string]any),
				announce["signature_valid"].(bool),
				receivedAt,
			)
			decisions = append(decisions, string(result.Decision))
			if result.ErrorCode == "" {
				errors = append(errors, nil)
			} else {
				errors = append(errors, result.ErrorCode)
			}
		}
		if !reflect.DeepEqual(decisions, expected["decisions"]) {
			t.Errorf("%s decisions: got %v want %v", vector["id"], decisions, expected["decisions"])
		}
		if !reflect.DeepEqual(errors, expected["errors"]) {
			t.Errorf("%s errors: got %v want %v", vector["id"], errors, expected["errors"])
		}
		if !reflect.DeepEqual(toAnyStrings(registry.LiveNIDs(now)), expected["live_nids"]) {
			t.Errorf("%s live nids mismatch", vector["id"])
		}
		expectedSequences := expected["highest_sequences"].(map[string]any)
		if len(expectedSequences) != len(registry.HighestSequences()) {
			t.Errorf("%s sequence count mismatch", vector["id"])
		}
		for nid, value := range expectedSequences {
			want, _ := uintValue(value)
			if registry.HighestSequences()[nid] != want {
				t.Errorf("%s sequence %s mismatch", vector["id"], nid)
			}
		}

		if cluster, ok := input["cluster_query"].(string); ok {
			selected := registry.ResolveCluster(cluster, now)
			if selected.NID != optionalString(expected["selected_nid"]) ||
				selected.Epoch != optionalUint(expected["selected_epoch"]) ||
				selected.ErrorCode != optionalString(expected["cluster_error"]) {
				t.Errorf("%s cluster selection mismatch: %+v", vector["id"], selected)
			}
		}
		if queries, ok := input["bridge_queries"].([]any); ok {
			actual := make([]any, 0, len(queries))
			for _, raw := range queries {
				query := raw.(map[string]any)
				result, err := registry.DiscoverBridges(
					query["direction"].(string),
					query["protocol"].(string),
					now,
				)
				if err != nil {
					t.Fatal(err)
				}
				actual = append(actual, toAnyStrings(result))
			}
			if !reflect.DeepEqual(actual, expected["bridge_results"]) {
				t.Errorf("%s bridge results mismatch", vector["id"])
			}
		}
		if _, ok := expected["resolve_error"]; ok && !registry.HasStaleEntry(now) {
			t.Errorf("%s expected stale entry", vector["id"])
		}
	}
}

func toAnyStrings(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func optionalString(value any) string {
	text, _ := value.(string)
	return text
}

func optionalUint(value any) uint64 {
	number, _ := uintValue(value)
	return number
}
