// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nop_test

import (
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
	"github.com/labacacia/NPS-sdk-go/nop"
)

type portableFixture struct {
	Vectors []struct {
		ID       string         `json:"id"`
		Category string         `json:"category"`
		Input    map[string]any `json:"input"`
		Expected map[string]any `json:"expected"`
	} `json:"vectors"`
}

func TestPortableOrchestratorSharedVectors(t *testing.T) {
	fixture := loadPortableFixture(t, "orchestrator_transcripts.json")
	if len(fixture.Vectors) != 10 {
		t.Fatalf("got %d vectors, want 10", len(fixture.Vectors))
	}
	for _, vector := range fixture.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			assertPortableJSONEqual(t, nop.EvaluateOrchestration(vector.Input), vector.Expected)
		})
	}
}

func TestPortableRuntimeSharedVectors(t *testing.T) {
	fixture := loadPortableFixture(t, "runtime_security_vectors.json")
	if len(fixture.Vectors) != 22 {
		t.Fatalf("got %d vectors, want 22", len(fixture.Vectors))
	}
	for _, vector := range fixture.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			assertPortableJSONEqual(t, nop.EvaluateRuntime(vector.Category, vector.Input), vector.Expected)
		})
	}
}

func loadPortableFixture(t *testing.T, name string) portableFixture {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file")
	}
	path, err := testfixture.ConformanceFile(file, "nop", name)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture portableFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func assertPortableJSONEqual(t *testing.T, got, want any) {
	t.Helper()
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var normalized any
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalized, want) {
		t.Fatalf("got %#v\nwant %#v", normalized, want)
	}
}
