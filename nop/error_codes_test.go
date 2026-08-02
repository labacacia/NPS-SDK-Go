// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nop

import (
	"testing"

	"github.com/labacacia/NPS-sdk-go/core"
)

func TestNopErrorStatusMapCoversCompleteSurface(t *testing.T) {
	expected := map[string]string{
		ErrCompensationPartialFailed: core.NpsClientUnprocessable,
		ErrCallbackInvalid:           core.NpsClientBadParam,
		ErrCallbackHmacInvalid:       core.NpsAuthUnauthenticated,
		ErrClaimConflict:             core.NpsClientConflict,
		ErrSpawnSpecInvalid:          core.NpsClientBadParam,
		ErrRuntimeIdleTimeout:        core.NpsServerTimeout,
		ErrRuntimeMaxRuntime:         core.NpsServerTimeout,
		ErrTaskResultExpired:         core.NpsClientNotFound,
		ErrStreamNakUnresolvable:     core.NpsStreamSeqGap,
	}
	for code, status := range expected {
		if got := NopErrorToNpsStatus[code]; got != status {
			t.Errorf("%s maps to %q, want %q", code, got, status)
		}
	}
}
