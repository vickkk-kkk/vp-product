// SPDX-License-Identifier: GPL-3.0-or-later
// Package memory provides a bounded lifecycle around an in-process starter.
// It does not establish a VPN, protect sockets, or validate forwarding.
package memory

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"unicode/utf8"
)

var (
	ErrInvalid   = errors.New("invalid request")
	ErrBusy      = errors.New("session busy")
	ErrStart     = errors.New("start failed; cleanup required")
	ErrStop      = errors.New("stop not confirmed")
	ErrCancelled = errors.New("request cancelled")
)

type State uint8

const (
	Idle State = iota
	Starting
	StartedUnverified
	Stopping
	StopUncertain
)

// Session never stores a config. Go and the upstream service can retain string
// copies; callers must not assume memory erasure. The started state is NOT a
// connectivity, DNS, TUN or leak verification.
type Session struct {
	mu    sync.Mutex
	state State
	start func(context.Context, string) error
	stop  func() error
}

func newSession(start func(context.Context, string) error, stop func() error) (*Session, error) {
	if start == nil || stop == nil {
		return nil, ErrInvalid
	}
	return &Session{start: start, stop: stop}, nil
}

// NewVerified refuses to treat a successful stop call as proof of cleanup.
// The host must independently verify that its exact engine and TUN are absent.
func NewVerified(start func(context.Context, string) error, stop func() error, confirmClosed func() bool) (*Session, error) {
	if stop == nil || confirmClosed == nil {
		return nil, ErrInvalid
	}
	return newSession(start, func() error {
		if err := stop(); err != nil {
			return err
		}
		if !confirmClosed() {
			return ErrStop
		}
		return nil
	})
}
func (s *Session) State() State { s.mu.Lock(); defer s.mu.Unlock(); return s.state }

// Start serializes lifecycle actions. A failed/panicking start cannot be
// retried until explicit Stop confirms cleanup. Upstream error text is redacted.
// Cancellation is checked before calling the backend, but does not guarantee
// interruption of a backend already starting; the caller must stop explicitly.
func (s *Session) Start(ctx context.Context, config []byte) (err error) {
	if ctx == nil || len(config) == 0 || len(config) > 1_048_576 || !utf8.Valid(config) || !json.Valid(config) {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	s.mu.Lock()
	if s.state != Idle {
		s.mu.Unlock()
		return ErrBusy
	}
	if ctx.Err() != nil {
		s.mu.Unlock()
		return ErrCancelled
	}
	s.state = Starting
	s.mu.Unlock()
	failed := invokeStart(s.start, ctx, string(config))
	s.mu.Lock()
	defer s.mu.Unlock()
	if failed {
		s.state = StopUncertain
		return ErrStart
	}
	s.state = StartedUnverified
	return nil
}

// Stop is explicit. Failure leaves the session blocked until a later Stop
// confirms cleanup; it never switches to another engine.
func (s *Session) Stop() (err error) {
	s.mu.Lock()
	if s.state == Idle {
		s.mu.Unlock()
		return nil
	}
	if s.state != StartedUnverified && s.state != StopUncertain {
		s.mu.Unlock()
		return ErrBusy
	}
	s.state = Stopping
	s.mu.Unlock()
	failed := invokeStop(s.stop)
	s.mu.Lock()
	defer s.mu.Unlock()
	if failed {
		s.state = StopUncertain
		return ErrStop
	}
	s.state = Idle
	return nil
}

func invokeStart(f func(context.Context, string) error, ctx context.Context, config string) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()
	return f(ctx, config) != nil
}
func invokeStop(f func() error) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()
	return f() != nil
}
