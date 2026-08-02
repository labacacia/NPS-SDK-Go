// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp_test

import (
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
	"github.com/labacacia/NPS-sdk-go/nwp"
)

type portableFixture[T any] struct {
	Vectors []struct {
		ID       string         `json:"id"`
		Input    T              `json:"input"`
		Expected map[string]any `json:"expected"`
	} `json:"vectors"`
}

func TestPortableNodeServerVectors(t *testing.T) {
	fixture := readNwpFixture[nwp.NwpPortableNodeRequest](
		t, "portable_node_server_vectors.json")
	for _, vector := range fixture.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			assertPortableExpected(
				t, nwp.EvaluatePortableNode(vector.Input), vector.Expected)
		})
	}
}

func TestBridgeLifecycleVectors(t *testing.T) {
	fixture := readNwpFixture[nwp.BridgeLifecycleRequest](
		t, "bridge_lifecycle_vectors.json")
	for _, vector := range fixture.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			assertPortableExpected(
				t, nwp.EvaluateBridgeLifecycle(vector.Input), vector.Expected)
		})
	}
}

func readNwpFixture[T any](t *testing.T, name string) portableFixture[T] {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path, err := testfixture.ConformanceFile(file, "nwp", name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture portableFixture[T]
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func assertPortableExpected(t *testing.T, actual any, expected map[string]any) {
	t.Helper()
	raw, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	for key, want := range expected {
		if key == "response" {
			continue
		}
		if !reflect.DeepEqual(values[key], want) {
			t.Fatalf("%s: got %#v want %#v", key, values[key], want)
		}
	}
}
