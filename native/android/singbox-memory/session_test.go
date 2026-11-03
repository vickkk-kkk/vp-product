// SPDX-License-Identifier: GPL-3.0-or-later
package memory

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func newTestSession(start func(context.Context, string) error, stop func() error) (*Session, error) {
	return NewVerified(start, stop, func() bool { return true }, func(string) error { return nil })
}

func waitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for signal")
	}
}
func waitResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for result")
		return nil
	}
}

func TestStartStopAndRejectSecondStart(t *testing.T) {
	var starts, stops int
	s, err := newTestSession(func(_ context.Context, input string) error {
		starts++
		if input != `{}` {
			t.Fatal("unexpected input")
		}
		return nil
	}, func() error { stops++; return nil })
	if err != nil || s.State() != Idle {
		t.Fatal("initial state")
	}
	if s.Start(context.Background(), []byte(`{}`)) != nil || s.State() != StartedUnverified {
		t.Fatal("start")
	}
	if s.Start(context.Background(), []byte(`{}`)) != ErrBusy || starts != 1 {
		t.Fatal("duplicate")
	}
	if s.Stop() != nil || stops != 1 || s.State() != Idle {
		t.Fatal("stop")
	}
}
func TestFailuresRequireConfirmedStopAndHideDetails(t *testing.T) {
	failStop := true
	s, _ := newTestSession(func(context.Context, string) error { return errors.New("synthetic-secret") }, func() error {
		if failStop {
			return errors.New("synthetic-secret")
		}
		return nil
	})
	if s.Start(context.Background(), []byte(`{}`)) != ErrStart || s.State() != StopUncertain {
		t.Fatal("start failure")
	}
	if s.Start(context.Background(), []byte(`{}`)) != ErrBusy {
		t.Fatal("retry allowed")
	}
	if s.Stop() != ErrStop || s.State() != StopUncertain {
		t.Fatal("stop failure")
	}
	failStop = false
	if s.Stop() != nil || s.State() != Idle {
		t.Fatal("reconcile")
	}
}
func TestRejectInvalidAndCancelledWithoutCallingBackend(t *testing.T) {
	n := 0
	s, _ := newTestSession(func(context.Context, string) error { n++; return nil }, func() error { return nil })
	if s.Start(context.Background(), []byte("bad")) != ErrInvalid {
		t.Fatal("invalid accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.Start(ctx, []byte(`{}`)) != ErrCancelled || n != 0 {
		t.Fatal("cancelled ran")
	}
}
func TestPanicIsRedactedAndRequiresCleanup(t *testing.T) {
	s, _ := newTestSession(func(context.Context, string) error { panic("synthetic-secret") }, func() error { return nil })
	if s.Start(context.Background(), []byte(`{}`)) != ErrStart || s.State() != StopUncertain {
		t.Fatal("panic handling")
	}
	if s.Stop() != nil || s.State() != Idle {
		t.Fatal("cleanup")
	}
}
func TestConcurrentStopDoesNotBlockDuringStart(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s, _ := newTestSession(func(context.Context, string) error { close(entered); <-release; return nil }, func() error { return nil })
	done := make(chan error, 1)
	go func() { done <- s.Start(context.Background(), []byte(`{}`)) }()
	waitSignal(t, entered)
	if s.State() != Starting || s.Stop() != ErrStopPending {
		t.Fatal("start concurrency")
	}
	close(release)
	if waitResult(t, done) != ErrCancelled || s.State() != Idle || s.Stop() != nil {
		t.Fatal("completion")
	}
}

func TestStopCallAloneIsNotTeardownEvidence(t *testing.T) {
	closed := true
	s, err := NewVerified(func(context.Context, string) error { return nil }, func() error { return nil }, func() bool { return closed }, func(string) error { return nil })
	if err != nil || s.Start(context.Background(), []byte(`{}`)) != nil {
		t.Fatal("start")
	}
	closed = false
	if s.Stop() != ErrStop || s.State() != StopUncertain {
		t.Fatal("unconfirmed stop accepted")
	}
	closed = true
	if s.Stop() != nil || s.State() != Idle {
		t.Fatal("confirmed stop rejected")
	}
	if _, err := NewVerified(func(context.Context, string) error { return nil }, func() error { return nil }, nil, func(string) error { return nil }); err != ErrInvalid {
		t.Fatal("missing verifier accepted")
	}
}

func TestUnsafeConfigAndValidatorPanicDoNotStart(t *testing.T) {
	starts := 0
	start := func(context.Context, string) error { starts++; return nil }
	stop := func() error { return nil }
	if _, err := NewVerified(start, stop, func() bool { return true }, nil); err != ErrInvalid {
		t.Fatal("missing validation accepted")
	}
	s, _ := NewVerified(start, stop, func() bool { return true }, func(string) error { return errors.New("synthetic-secret") })
	if s.Start(context.Background(), []byte(`{}`)) != ErrInvalid || starts != 0 || s.State() != Idle {
		t.Fatal("invalid config started")
	}
	s, _ = NewVerified(start, stop, func() bool { return true }, func(string) error { panic("synthetic-secret") })
	if s.Start(context.Background(), []byte(`{}`)) != ErrInvalid || starts != 0 || s.State() != Idle {
		t.Fatal("validator panic started")
	}
}

func TestValidatedCopyIsExactlyWhatBackendReceives(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var got string
	s, _ := NewVerified(func(_ context.Context, content string) error { got = content; return nil }, func() error { return nil }, func() bool { return true }, func(string) error { close(entered); <-release; return nil })
	config := []byte(`{"value":"a"}`)
	done := make(chan error, 1)
	go func() { done <- s.Start(context.Background(), config) }()
	waitSignal(t, entered) // the private copy has already been made
	config[len(config)-3] = 'b'
	close(release)
	if waitResult(t, done) != nil || got != `{"value":"a"}` {
		t.Fatal("validated and executed configs differ")
	}
}

func TestStopPanicAndConfirmationPanicFailClosed(t *testing.T) {
	start := func(context.Context, string) error { return nil }
	validate := func(string) error { return nil }
	for _, stop := range []func() error{
		func() error { panic("synthetic-secret") },
		func() error { return nil },
	} {
		first := true
		confirm := func() bool {
			if first {
				first = false
				return true
			}
			panic("synthetic-secret")
		}
		s, _ := NewVerified(start, stop, confirm, validate)
		if s.Start(context.Background(), []byte(`{}`)) != nil || s.Stop() != ErrStop || s.State() != StopUncertain {
			t.Fatal("panic did not fail closed")
		}
	}
}

func TestInitialAbsenceMustBeConfirmed(t *testing.T) {
	start := func(context.Context, string) error { return nil }
	stop := func() error { return nil }
	validate := func(string) error { return nil }
	if _, err := NewVerified(start, stop, func() bool { return false }, validate); err != ErrStop {
		t.Fatal("unconfirmed initial state accepted")
	}
	if _, err := NewVerified(start, stop, func() bool { panic("synthetic-secret") }, validate); err != ErrStop {
		t.Fatal("initial verifier panic accepted")
	}
}

func TestConcurrentStopsDoNotRunTwice(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s, _ := newTestSession(func(context.Context, string) error { return nil }, func() error { close(entered); <-release; return nil })
	if s.Start(context.Background(), []byte(`{}`)) != nil {
		t.Fatal("start")
	}
	done := make(chan error, 1)
	go func() { done <- s.Stop() }()
	waitSignal(t, entered)
	if s.Stop() != ErrBusy || s.Start(context.Background(), []byte(`{}`)) != ErrBusy {
		t.Fatal("overlap allowed")
	}
	close(release)
	if waitResult(t, done) != nil || s.State() != Idle {
		t.Fatal("stop")
	}
}

func TestStopDuringValidationPreventsStart(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	starts := 0
	s, _ := NewVerified(func(context.Context, string) error { starts++; return nil }, func() error { return nil }, func() bool { return true }, func(string) error { close(entered); <-release; return nil })
	done := make(chan error, 1)
	go func() { done <- s.Start(context.Background(), []byte(`{}`)) }()
	waitSignal(t, entered)
	if s.State() != Preparing || s.Stop() != ErrStopPending {
		t.Fatal("validation cancellation")
	}
	close(release)
	if waitResult(t, done) != ErrCancelled || starts != 0 || s.State() != Idle {
		t.Fatal("cancelled validation started backend")
	}
}

func TestEarlyInterruptCannotReportIdleBeforeStartReturns(t *testing.T) {
	entered, release, interrupted := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s, _ := newTestSession(func(context.Context, string) error { close(entered); <-release; return nil }, func() error {
		if calls.Add(1) == 1 {
			close(interrupted)
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- s.Start(context.Background(), []byte(`{}`)) }()
	waitSignal(t, entered)
	if s.Stop() != ErrStopPending {
		t.Fatal("stop was not requested")
	}
	waitSignal(t, interrupted)
	if s.State() != Starting {
		t.Fatal("reported stopped while start still running")
	}
	close(release)
	if waitResult(t, done) != ErrCancelled || calls.Load() < 2 || s.State() != Idle {
		t.Fatal("final stop not verified")
	}
}

func TestInterruptRetriesWhenFirstRunsBeforeBackendStart(t *testing.T) {
	entered, allowRealStart, firstInterrupt, secondInterrupt := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s, _ := newTestSession(func(context.Context, string) error {
		close(entered)
		<-allowRealStart
		<-secondInterrupt
		return nil
	}, func() error {
		switch calls.Add(1) {
		case 1:
			close(firstInterrupt)
		case 2:
			close(secondInterrupt)
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- s.Start(context.Background(), []byte(`{}`)) }()
	waitSignal(t, entered)
	if s.Stop() != ErrStopPending {
		t.Fatal("stop request")
	}
	waitSignal(t, firstInterrupt)
	close(allowRealStart)
	select {
	case <-secondInterrupt:
	case <-time.After(5 * time.Second):
		t.Fatal("no retry")
	}
	select {
	case result := <-done:
		if result != ErrCancelled || s.State() != Idle {
			t.Fatal("cleanup")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start stuck")
	}
}

func TestFailedCleanupAfterInterruptedStartBlocksRestart(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s, _ := newTestSession(func(context.Context, string) error { close(entered); <-release; return nil }, func() error { return errors.New("synthetic-secret") })
	done := make(chan error, 1)
	go func() { done <- s.Start(context.Background(), []byte(`{}`)) }()
	waitSignal(t, entered)
	if s.Stop() != ErrStopPending {
		t.Fatal("stop request")
	}
	close(release)
	if waitResult(t, done) != ErrStop || s.State() != StopUncertain || s.Start(context.Background(), []byte(`{}`)) != ErrBusy {
		t.Fatal("unsafe restart allowed")
	}
}
