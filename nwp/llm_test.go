// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"testing"

	"github.com/labacacia/NPS-sdk-go/core"
)

func TestLlmStatefulRequestCanonicalRoundTrip(t *testing.T) {
	ttl := uint32(600)
	request := LlmCompleteActionRequest{
		Model:    "willow-small",
		Messages: []LlmMessageDto{{Role: "user"}},
		Context:  &LlmContextRequestDto{Operation: LlmContextCreate, TTLSeconds: &ttl},
	}
	wire, err := request.ToMap()
	if err != nil {
		t.Fatal(err)
	}
	if wire["kind"] != LlmCompleteActionID {
		t.Fatalf("kind=%v", wire["kind"])
	}
	context := wire["context"].(map[string]any)
	if context["operation"] != "create" || context["ttl_seconds"] != float64(600) {
		t.Fatalf("unexpected context: %#v", context)
	}
	decoded, err := LlmCompleteRequestFromMap(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Context == nil || decoded.Context.Operation != LlmContextCreate {
		t.Fatal("context not decoded")
	}
}

func TestLlmContextErrorStatusMapping(t *testing.T) {
	if NwpErrorToNpsStatus[ErrLlmContextLimitExceeded] != core.NpsLimitResource {
		t.Fatal("context limit mapping drift")
	}
	if core.ToHttpStatus(core.NpsLimitResource) != 429 {
		t.Fatal("resource limit must map to HTTP 429")
	}
}

func TestLlmLifecycleActionFrames(t *testing.T) {
	key := "create-1"
	status, err := LlmContextStatusActionFrame(LlmContextStatusRequestDto{IdempotencyKey: &key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status.Action != LlmContextStatusActionID {
		t.Fatalf("action=%s", status.Action)
	}

	release, err := LlmContextReleaseActionFrame(LlmContextReleaseRequestDto{
		ContextID: "AQIDBAUGBwgJCgsMDQ4PEA", BaseVersion: 7,
	}, "release-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if release.Action != LlmContextReleaseActionID || release.IdempotencyKey == nil || *release.IdempotencyKey != "release-1" {
		t.Fatalf("unexpected release frame: %#v", release)
	}
}
