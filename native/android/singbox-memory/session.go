// SPDX-License-Identifier: GPL-3.0-or-later
// Package memory provides a bounded lifecycle around an in-process starter.
// It does not establish a VPN, protect sockets, or validate forwarding.
package memory

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid     = errors.New("invalid request")
	ErrBusy        = errors.New("session busy")
	ErrStart       = errors.New("start failed; cleanup required")
	ErrStop        = errors.New("stop not confirmed")
	ErrStopPending = errors.New("stop requested while starting")
	ErrCancelled   = errors.New("request cancelled")
)

type State uint8

const (
	Idle State = iota
	Preparing
	Starting
	StartedUnverified
	Stopping
	StopUncertain
)

// Session never stores a config. Go and the upstream service can retain string
// copies; callers must not assume memory erasure. The started state is NOT a
// connectivity, DNS, TUN or leak verification.
type Session struct {
	mu              sync.Mutex
	state           State
	start           func(context.Context, string) error
	stop            func() error
	validate        func(string) error
	cancelRequested bool
	interruptDone   chan struct{}
	startDone       chan struct{}
	cancelStart     context.CancelFunc
}

func newSession(start func(context.Context, string) error, stop func() error, validate func(string) error) (*Session, error) {
	if start == nil || stop == nil || validate == nil {
		return nil, ErrInvalid
	}
	return &Session{start: start, stop: stop, validate: validate}, nil
}

// NewVerified refuses to treat a successful stop call as proof of cleanup.
// The host must independently verify that its exact engine and TUN are absent.
func NewVerified(start func(context.Context, string) error, stop func() error, confirmClosed func() bool, validate func(string) error) (*Session, error) {
	if start == nil || stop == nil || confirmClosed == nil || validate == nil {
		return nil, ErrInvalid
	}
	if !invokeConfirm(confirmClosed) {
		return nil, ErrStop
	}
	return newSession(start, func() error {
		if err := stop(); err != nil {
			return err
		}
		if !confirmClosed() {
			return ErrStop
		}
		return nil
	}, validate)
}

func invokeConfirm(f func() bool) (confirmed bool) {
	defer func() {
		if recover() != nil {
			confirmed = false
		}
	}()
	return f()
}
func (s *Session) State() State { s.mu.Lock(); defer s.mu.Unlock(); return s.state }

// Start serializes lifecycle actions. A failed/panicking start cannot be
// retried until explicit Stop confirms cleanup. Upstream error text is redacted.
// Cancellation is checked before calling the backend, but does not guarantee
// interruption of a backend already starting; the caller must stop explicitly.
func (s *Session) Start(ctx context.Context, config []byte) (err error) {
	if ctx == nil || len(config) == 0 || len(config) > 1_048_576 {
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
	s.state = Preparing
	s.cancelRequested = false
	s.mu.Unlock()
	// Validate and start from the same private copy, never from a mutable caller
	// buffer after validation. Best-effort clear; upstream Go strings can remain.
	snapshot := append([]byte(nil), config...)
	defer clear(snapshot)
	content := string(snapshot)
	invalid := !utf8.Valid(snapshot) || !json.Valid(snapshot) || invokeValidate(s.validate, content)
	s.mu.Lock()
	if s.cancelRequested || ctx.Err() != nil {
		s.state = Idle
		s.mu.Unlock()
		return ErrCancelled
	}
	if invalid {
		s.state = Idle
		s.mu.Unlock()
		return ErrInvalid
	}
	s.state = Starting
	s.interruptDone = nil
	startDone := make(chan struct{})
	s.startDone = startDone
	runCtx, cancel := context.WithCancel(ctx)
	s.cancelStart = cancel
	s.mu.Unlock()
	failed := invokeStart(s.start, runCtx, content)
	close(startDone)
	s.mu.Lock()
	if s.cancelRequested {
		s.cancelStart = nil
		cancel()
		done := s.interruptDone
		s.state = Stopping
		s.mu.Unlock()
		// The interrupt can race ahead of the actual start. Wait for both the
		// start and interrupt to return, then stop and verify again.
		<-done
		stopFailed := invokeStop(s.stop)
		s.mu.Lock()
		defer s.mu.Unlock()
		if stopFailed {
			s.state = StopUncertain
			return ErrStop
		}
		s.state = Idle
		return ErrCancelled
	}
	defer s.mu.Unlock()
	if failed {
		s.cancelStart = nil
		cancel()
		s.state = StopUncertain
		return ErrStart
	}
	s.state = StartedUnverified
	return nil
}

func invokeValidate(f func(string) error, config string) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()
	return f(config) != nil
}

// Stop is explicit. Failure leaves the session blocked until a later Stop
// confirms cleanup; it never switches to another engine.
func (s *Session) Stop() (err error) {
	s.mu.Lock()
	if s.state == Idle {
		s.mu.Unlock()
		return nil
	}
	if s.state == Preparing {
		s.cancelRequested = true
		s.mu.Unlock()
		return ErrStopPending
	}
	if s.state == Starting {
		if !s.cancelRequested {
			s.cancelRequested = true
			if s.cancelStart != nil {
				s.cancelStart()
			}
			done := make(chan struct{})
			s.interruptDone = done
			startDone := s.startDone
			// Upstream CloseService first requests start interruption. Its
			// result is not treated as teardown proof; final cleanup follows.
			// Retry if the first interrupt ran before the backend actually
			// entered start. No new session may start while this worker runs.
			go func() {
				defer close(done)
				for {
					invokeStop(s.stop)
					select {
					case <-startDone:
						return
					case <-time.After(time.Second):
					}
				}
			}()
		}
		s.mu.Unlock()
		return ErrStopPending
	}
	if s.state != StartedUnverified && s.state != StopUncertain {
		s.mu.Unlock()
		return ErrBusy
	}
	if s.cancelStart != nil {
		s.cancelStart()
		s.cancelStart = nil
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
