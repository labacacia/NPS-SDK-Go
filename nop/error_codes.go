// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nop

import "github.com/labacacia/NPS-sdk-go/core"

// NOP error code wire constants — mirror of spec/error-codes.md NOP section.
const (
	ErrTaskNotFound              = "NOP-TASK-NOT-FOUND"
	ErrTaskTimeout               = "NOP-TASK-TIMEOUT"
	ErrTaskDagInvalid            = "NOP-TASK-DAG-INVALID"
	ErrTaskDagCycle              = "NOP-TASK-DAG-CYCLE"
	ErrTaskDagTooLarge           = "NOP-TASK-DAG-TOO-LARGE"
	ErrTaskAlreadyCompleted      = "NOP-TASK-ALREADY-COMPLETED"
	ErrTaskCancelled             = "NOP-TASK-CANCELLED"
	ErrDelegateScopeViolation    = "NOP-DELEGATE-SCOPE-VIOLATION"
	ErrDelegateRejected          = "NOP-DELEGATE-REJECTED"
	ErrDelegateChainTooDeep      = "NOP-DELEGATE-CHAIN-TOO-DEEP"
	ErrDelegateTimeout           = "NOP-DELEGATE-TIMEOUT"
	ErrSyncTimeout               = "NOP-SYNC-TIMEOUT"
	ErrSyncDependencyFailed      = "NOP-SYNC-DEPENDENCY-FAILED"
	ErrStreamSeqGap              = "NOP-STREAM-SEQ-GAP"
	ErrStreamNidMismatch         = "NOP-STREAM-NID-MISMATCH"
	ErrResourceInsufficient      = "NOP-RESOURCE-INSUFFICIENT"
	ErrConditionEvalError        = "NOP-CONDITION-EVAL-ERROR"
	ErrInputMappingError         = "NOP-INPUT-MAPPING-ERROR"
	ErrCompensationFailed        = "NOP-COMPENSATION-FAILED"
	ErrCompensationPartialFailed = "NOP-COMPENSATION-PARTIAL-FAILED"
	ErrCompensationNotSupported  = "NOP-COMPENSATION-NOT-SUPPORTED"

	// Additional codes referenced in task description.
	ErrStreamNak           = "NOP-STREAM-NAK"
	ErrCallbackHmacMissing = "NOP-CALLBACK-HMAC-MISSING"
	// v0.7
	ErrTaskResultExpired     = "NOP-TASK-RESULT-EXPIRED"
	ErrStreamNakUnresolvable = "NOP-STREAM-NAK-UNRESOLVABLE"
)

// NopErrorToNpsStatus maps each NOP error code to its NPS status code.
var NopErrorToNpsStatus = map[string]string{
	ErrTaskNotFound:              core.NpsClientNotFound,
	ErrTaskTimeout:               core.NpsServerTimeout,
	ErrTaskDagInvalid:            core.NpsClientBadFrame,
	ErrTaskDagCycle:              core.NpsClientBadFrame,
	ErrTaskDagTooLarge:           core.NpsClientBadFrame,
	ErrTaskAlreadyCompleted:      core.NpsClientConflict,
	ErrTaskCancelled:             core.NpsClientConflict,
	ErrDelegateScopeViolation:    core.NpsAuthForbidden,
	ErrDelegateRejected:          core.NpsClientUnprocessable,
	ErrDelegateChainTooDeep:      core.NpsClientBadParam,
	ErrDelegateTimeout:           core.NpsServerTimeout,
	ErrSyncTimeout:               core.NpsServerTimeout,
	ErrSyncDependencyFailed:      core.NpsClientUnprocessable,
	ErrStreamSeqGap:              core.NpsStreamSeqGap,
	ErrStreamNidMismatch:         core.NpsAuthUnauthenticated,
	ErrResourceInsufficient:      core.NpsServerUnavailable,
	ErrConditionEvalError:        core.NpsClientBadParam,
	ErrInputMappingError:         core.NpsClientUnprocessable,
	ErrCompensationFailed:        core.NpsClientUnprocessable,
	ErrCompensationPartialFailed: core.NpsClientUnprocessable,
	ErrCompensationNotSupported:  core.NpsClientUnprocessable,
	ErrStreamNak:                 core.NpsStreamSeqGap,
	ErrCallbackHmacMissing:       core.NpsAuthUnauthenticated,
	ErrTaskResultExpired:         core.NpsClientNotFound,
	ErrStreamNakUnresolvable:     core.NpsStreamSeqGap,
}
