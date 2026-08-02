// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ncp_test

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/labacacia/NPS-sdk-go/ncp"
)

// fakeSession stands in for a real NCP session — the connector is generic in the
// session type on purpose, so a test double wraps identically to a TLS dial.
type fakeSession struct{ Host string }

// resolverQueue yields a scripted sequence of endpoints, counting calls.
type resolverQueue struct {
	endpoints []ncp.NcpEndpoint
	calls     int
}

func (q *resolverQueue) resolve(context.Context) (ncp.NcpEndpoint, error) {
	i := q.calls
	q.calls++
	if i >= len(q.endpoints) {
		return ncp.NcpEndpoint{}, errors.New("resolver exhausted")
	}
	return q.endpoints[i], nil
}

func ep(host string) ncp.NcpEndpoint { return ncp.NcpEndpoint{Host: host, Port: 17433} }

func connRefused() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
}

type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

// ── Brief A §5.3 ──────────────────────────────────────────────────────────────

func TestFailoverConnector_ReresolvesAndReconnectsAfterNidMismatch(t *testing.T) {
	q := &resolverQueue{endpoints: []ncp.NcpEndpoint{ep("old-anchor"), ep("new-anchor")}}

	c, err := ncp.NewFailoverConnector(q.resolve,
		func(_ context.Context, e ncp.NcpEndpoint) (*fakeSession, error) {
			if e.Host == "old-anchor" {
				return nil, ncp.NewNcpProtocolError(ncp.ErrNidMismatch, "session NID no longer matches")
			}
			return &fakeSession{Host: e.Host}, nil
		}, 0)
	if err != nil {
		t.Fatal(err)
	}

	s, err := c.Connect(context.Background())
	if err != nil {
		t.Fatalf("expected a session, got %v", err)
	}
	if s.Host != "new-anchor" {
		t.Errorf("session host = %s, want new-anchor", s.Host)
	}
	if q.calls != 2 {
		t.Errorf("BOTH resolutions must be consumed — re-resolution is what picks up the new active Anchor; got %d", q.calls)
	}
}

func TestFailoverConnector_ReresolvesAfterSocketLoss(t *testing.T) {
	q := &resolverQueue{endpoints: []ncp.NcpEndpoint{ep("anchor-1"), ep("anchor-2")}}

	c, _ := ncp.NewFailoverConnector(q.resolve,
		func(_ context.Context, e ncp.NcpEndpoint) (*fakeSession, error) {
			if e.Host == "anchor-1" {
				return nil, connRefused()
			}
			return &fakeSession{Host: e.Host}, nil
		}, 0)

	s, err := c.Connect(context.Background())
	if err != nil {
		t.Fatalf("expected a session, got %v", err)
	}
	if s.Host != "anchor-2" {
		t.Errorf("session host = %s", s.Host)
	}
	if q.calls != 2 {
		t.Errorf("resolve must be called exactly twice, got %d", q.calls)
	}
}

func TestFailoverConnector_NonFailoverErrorsPropagateImmediately(t *testing.T) {
	q := &resolverQueue{endpoints: []ncp.NcpEndpoint{ep("a1"), ep("a2")}}
	hard := ncp.NewNcpProtocolError(ncp.ErrFrameFlagsInvalid, "bad flags")

	c, _ := ncp.NewFailoverConnector(q.resolve,
		func(context.Context, ncp.NcpEndpoint) (*fakeSession, error) { return nil, hard }, 0)

	_, err := c.Connect(context.Background())
	if !errors.Is(err, error(hard)) {
		t.Fatalf("the original error must propagate UNWRAPPED, got %v", err)
	}
	if q.calls != 1 {
		t.Errorf("a non-failover error must not trigger a second resolution, got %d calls", q.calls)
	}
}

func TestFailoverConnector_ExhaustedAttemptsRethrowTheLastFailure(t *testing.T) {
	q := &resolverQueue{endpoints: []ncp.NcpEndpoint{ep("a1"), ep("a2"), ep("a3")}}
	timeouts := 0

	c, _ := ncp.NewFailoverConnector(q.resolve,
		func(context.Context, ncp.NcpEndpoint) (*fakeSession, error) {
			timeouts++
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: fakeTimeout{}}
		}, 3)

	_, err := c.Connect(context.Background())
	if err == nil {
		t.Fatal("expected the last failure to propagate")
	}
	// The ORIGINAL type is preserved.
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("the socket-typed error must be preserved, got %T", err)
	}
	if timeouts != 3 || q.calls != 3 {
		t.Errorf("maxAttempts=3 means 3 resolutions and 3 connects, got %d / %d", q.calls, timeouts)
	}
}

// ── Construction contract ────────────────────────────────────────────────────

func TestFailoverConnector_ConstructionValidation(t *testing.T) {
	ok := func(context.Context, ncp.NcpEndpoint) (*fakeSession, error) { return &fakeSession{}, nil }
	res := func(context.Context) (ncp.NcpEndpoint, error) { return ep("a"), nil }

	if _, err := ncp.NewFailoverConnector[*fakeSession](nil, ok, 0); err == nil {
		t.Error("a nil resolver must be rejected")
	}
	if _, err := ncp.NewFailoverConnector[*fakeSession](res, nil, 0); err == nil {
		t.Error("a nil connect must be rejected")
	}
	if _, err := ncp.NewFailoverConnector(res, ok, -1); err == nil {
		t.Error("maxAttempts < 1 must be rejected")
	}
	c, err := ncp.NewFailoverConnector(res, ok, 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxAttempts() != 2 {
		t.Errorf("the default attempt budget is 2, got %d", c.MaxAttempts())
	}
}

func TestFailoverConnector_ResolvesOncePerAttemptIncludingTheFirst(t *testing.T) {
	q := &resolverQueue{endpoints: []ncp.NcpEndpoint{ep("a1")}}
	c, _ := ncp.NewFailoverConnector(q.resolve,
		func(_ context.Context, e ncp.NcpEndpoint) (*fakeSession, error) {
			return &fakeSession{Host: e.Host}, nil
		}, 0)

	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q.calls != 1 {
		t.Errorf("a first-attempt success still resolves exactly once, got %d", q.calls)
	}
}

func TestFailoverConnector_CancellationIsHonoured(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	q := &resolverQueue{endpoints: []ncp.NcpEndpoint{ep("a1")}}
	c, _ := ncp.NewFailoverConnector(q.resolve,
		func(context.Context, ncp.NcpEndpoint) (*fakeSession, error) { return &fakeSession{}, nil }, 0)

	if _, err := c.Connect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if q.calls != 0 {
		t.Errorf("a cancelled context must be checked before resolving, got %d calls", q.calls)
	}
}

// ── IsFailoverShaped ─────────────────────────────────────────────────────────

func TestIsFailoverShaped(t *testing.T) {
	shaped := []error{
		connRefused(),
		&net.OpError{Op: "read", Err: fakeTimeout{}},
		syscall.ECONNRESET,
		net.ErrClosed,
		ncp.NewNcpProtocolError(ncp.ErrNidMismatch, ""),
	}
	notShaped := []error{
		nil,
		errors.New("some other failure"),
		ncp.NewNcpProtocolError(ncp.ErrFrameFlagsInvalid, ""),
		ncp.NewNcpProtocolError(ncp.ErrAnchorNotFound, ""),
	}
	for _, e := range shaped {
		if !ncp.IsFailoverShaped(e) {
			t.Errorf("expected failover-shaped: %v", e)
		}
	}
	for _, e := range notShaped {
		if ncp.IsFailoverShaped(e) {
			t.Errorf("expected NOT failover-shaped: %v", e)
		}
	}
}

func TestNcpNidMismatch_ErrorCodeAndStatus(t *testing.T) {
	if ncp.ErrNidMismatch != "NCP-NID-MISMATCH" {
		t.Errorf("wire value: %s", ncp.ErrNidMismatch)
	}
	if got := ncp.NcpErrorToNpsStatus[ncp.ErrNidMismatch]; got != "NPS-AUTH-UNAUTHENTICATED" {
		t.Errorf("NCP-NID-MISMATCH maps to %s, want NPS-AUTH-UNAUTHENTICATED", got)
	}
	e := ncp.NewNcpProtocolError(ncp.ErrNidMismatch, "boom")
	if e.ProtocolErrorCode() != "NCP-NID-MISMATCH" || e.Error() != "NCP-NID-MISMATCH: boom" {
		t.Errorf("error shape: %s / %s", e.ProtocolErrorCode(), e.Error())
	}
}
