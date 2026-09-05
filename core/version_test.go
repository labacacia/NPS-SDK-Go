// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labacacia/NPS-sdk-go/core"
)

func TestVersionMatchesDistributionFile(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}

	if got := core.Version; got != strings.TrimSpace(string(want)) {
		t.Fatalf("core.Version = %q, VERSION = %q", got, strings.TrimSpace(string(want)))
	}
}
