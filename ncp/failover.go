// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ncp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
)

// NPS-CR-0009 §3.3 — failover reconnect / session continuity on the NCP native path.
//
// There is no NCP client or session type in this SDK, so the connector is
// generic in the session type and takes BOTH the resolver and the connect step
// as injected functions. That is deliberate, not a Go workaround: it is what
// lets the same connector wrap a TCP dial, a TLS dial, or a test double
// identically, and it keeps NCP free of any NDP dependency.

// NcpEndpoint is a resolved Anchor address.
type NcpEndpoint struct {
	Host string
	Port uint16
}

func (e NcpEndpoint) String() string { return fmt.Sprintf("%s:%d", e.Host, e.Port) }

// ResolveActiveFunc yields the CURRENT active Anchor for the cluster.
//
// It is an injected delegate so it composes with either NDP highest-epoch
// resolution (§3.1) or a `successor_nid` lifted from a received anchor_failover
// event — the connector itself knows about neither.
type ResolveActiveFunc func(ctx context.Context) (NcpEndpoint, error)

// ConnectFunc establishes one session to a resolved endpoint.
type ConnectFunc[TSession any] func(ctx context.Context, ep NcpEndpoint) (TSession, error)

// NcpProtocolError carries an NCP/NPS protocol error code, so a caller can tell
// NCP-NID-MISMATCH (a failover trigger) from, say, NCP-FRAME-FLAGS-INVALID
// (a hard fault that must not be retried).
type NcpProtocolError struct {
	Code      string
	NpsStatus string
	Message   string
}

func (e *NcpProtocolError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// ProtocolErrorCode returns the NCP wire error code.
func (e *NcpProtocolError) ProtocolErrorCode() string { return e.Code }

// NewNcpProtocolError builds a protocol error, filling in the NPS status from
// the code's registered mapping.
func NewNcpProtocolError(code, message string) *NcpProtocolError {
	return &NcpProtocolError{Code: code, NpsStatus: NcpErrorToNpsStatus[code], Message: message}
}

// FailoverConnector reconnects across an Anchor ownership transfer.
type FailoverConnector[TSession any] struct {
	resolveActive ResolveActiveFunc
	connect       ConnectFunc[TSession]
	maxAttempts   int
}

// NewFailoverConnector builds a connector. Both delegates are required and
// maxAttempts must be >= 1; pass 0 for the default of 2.
func NewFailoverConnector[TSession any](
	resolveActive ResolveActiveFunc,
	connect ConnectFunc[TSession],
	maxAttempts int,
) (*FailoverConnector[TSession], error) {
	if resolveActive == nil {
		return nil, errors.New("ncp: resolveActive is required")
	}
	if connect == nil {
		return nil, errors.New("ncp: connect is required")
	}
	if maxAttempts == 0 {
		maxAttempts = 2
	}
	if maxAttempts < 1 {
		return nil, fmt.Errorf("ncp: maxAttempts must be >= 1, got %d", maxAttempts)
	}
	return &FailoverConnector[TSession]{resolveActive: resolveActive, connect: connect, maxAttempts: maxAttempts}, nil
}

// MaxAttempts returns the configured attempt budget.
func (c *FailoverConnector[TSession]) MaxAttempts() int { return c.maxAttempts }

// Connect establishes a session, re-resolving the active Anchor before EVERY
// attempt including the first.
//
// That re-resolution is the whole mechanism: it is what picks up the new active
// Anchor after an ownership transfer, so maxAttempts=2 performs exactly two
// resolutions on a single failure.
//
//   - Failover-shaped failures (see IsFailoverShaped) are retried until the
//     attempt budget is exhausted, at which point the LAST captured failure is
//     returned with its original type preserved.
//   - Any other failure propagates IMMEDIATELY, unwrapped, with no further
//     resolution and no retry.
//   - A resolver failure likewise propagates immediately: it is not a connect
//     failure, and retrying a resolver that just failed is not what §3.3 asks for.
func (c *FailoverConnector[TSession]) Connect(ctx context.Context) (TSession, error) {
	var zero TSession
	var lastErr error

	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}

		// RE-RESOLVED EVERY ATTEMPT, including the first.
		ep, err := c.resolveActive(ctx)
		if err != nil {
			return zero, err
		}

		session, err := c.connect(ctx, ep)
		if err == nil {
			return session, nil
		}
		if !IsFailoverShaped(err) {
			// No retry, no wrapping.
			return zero, err
		}
		lastErr = err
	}

	// Rethrow the LAST failure, preserving its original type.
	return zero, lastErr
}

// IsFailoverShaped reports whether an error means "the Anchor moved; re-resolve
// and try again" rather than "this request is wrong".
//
// The shape is: a socket/network error, an I/O error, or an NCP protocol error
// whose code is NCP-NID-MISMATCH — the native-path signal that the session
// reached an Anchor that is no longer the one it was bound to.
func IsFailoverShaped(err error) bool {
	if err == nil {
		return false
	}

	var protoErr *NcpProtocolError
	if errors.As(err, &protoErr) {
		return protoErr.Code == ErrNidMismatch
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}
