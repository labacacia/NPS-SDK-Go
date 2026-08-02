// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

package testfixture

import (
	"fmt"
	"os"
	"path/filepath"
)

// ConformanceFile locates a shared fixture in either a standalone SDK or the
// source monorepo containing that SDK.
func ConformanceFile(startFile string, segments ...string) (string, error) {
	current := filepath.Dir(startFile)
	for {
		parts := append([]string{current, "spec", "conformance"}, segments...)
		candidate := filepath.Join(parts...)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", fmt.Errorf(
		"unable to locate conformance fixture %s",
		filepath.Join(segments...),
	)
}
