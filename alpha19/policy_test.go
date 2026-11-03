// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package alpha19

import (
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
)

func TestSharedAlpha19Vectors(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	type suite struct {
		protocol, name string
		evaluate       func(string, Input) Output
	}
	suites := []suite{
		{"ncp", "runtime_hardening_vectors.json", func(_ string, in Input) Output { return NCP(in) }},
		{"nwp", "alpha19_hardening_vectors.json", func(id string, in Input) Output {
			if strings.Contains(id, ".metadata.") {
				return NWPMetadata(in)
			}
			return NWPSubscription(in)
		}},
		{"nip", "renewal_revocation_vectors.json", func(id string, in Input) Output {
			if strings.Contains(id, ".renewal.") {
				return NIPRenewal(in)
			}
			if strings.Contains(id, ".revocation.") {
				return NIPRevocation(in)
			}
			return NIPAdvisory(in)
		}},
		{"ndp", "recovery_fence_vectors.json", func(_ string, in Input) Output { return NDP(in) }},
		{"nop", "replay_retention_vectors.json", func(_ string, in Input) Output { return NOP(in) }},
	}
	seen := map[string]bool{}
	for _, s := range suites {
		path, err := testfixture.ConformanceFile(current, s.protocol, s.name)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Vectors []struct {
				ID       string `json:"id"`
				Input    Input  `json:"input"`
				Expected Output `json:"expected"`
			} `json:"vectors"`
		}
		if err = json.Unmarshal(raw, &fixture); err != nil {
			t.Fatal(err)
		}
		for _, v := range fixture.Vectors {
			if seen[v.ID] {
				t.Fatalf("duplicate %s", v.ID)
			}
			seen[v.ID] = true
			got := s.evaluate(v.ID, v.Input)
			if !reflect.DeepEqual(got, v.Expected) {
				t.Fatalf("%s\n got %#v\nwant %#v", v.ID, got, v.Expected)
			}
		}
	}
	if len(seen) != 47 {
		t.Fatalf("executed %d cases", len(seen))
	}
}

func TestBoundaryBranches(t *testing.T) {
	if got := NCP(Input{"client_ping_ms": float64(0), "server_ping_ms": float64(2500)}); got["effective_interval_ms"] != float64(2500) {
		t.Fatal(got)
	}
	if got := NOP(Input{"terminal_commit_ms": float64(1000), "result_ttl_seconds": float64(2), "query_at_ms": float64(2999)}); got["result"] != "retained" {
		t.Fatal(got)
	}
}
