// SPDX-License-Identifier: GPL-3.0-or-later
package memory

import (
	"context"
	"errors"
	"testing"
)

func newTestSession(start func(context.Context, string) error, stop func() error) (*Session, error) {
	return NewVerified(start, stop, func() bool { return true }, func(string) error { return nil })
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
	<-entered
	if s.State() != Starting || s.Stop() != ErrStopPending {
		t.Fatal("start concurrency")
	}
	close(release)
	if <-done != ErrCancelled || s.State() != Idle || s.Stop() != nil {
		t.Fatal("completion")
	}
}

func TestStopCallAloneIsNotTeardownEvidence(t *testing.T) {
	closed := false
	s, err := NewVerified(func(context.Context, string) error { return nil }, func() error { return nil }, func() bool { return closed }, func(string) error { return nil })
	if err != nil || s.Start(context.Background(), []byte(`{}`)) != nil {
		t.Fatal("start")
	}
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
	<-entered // the private copy has already been made
	config[len(config)-3] = 'b'
	close(release)
	if <-done != nil || got != `{"value":"a"}` {
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
		confirm := func() bool { panic("synthetic-secret") }
		s, _ := NewVerified(start, stop, confirm, validate)
		if s.Start(context.Background(), []byte(`{}`)) != nil || s.Stop() != ErrStop || s.State() != StopUncertain {
			t.Fatal("panic did not fail closed")
		}
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
	<-entered
	if s.Stop() != ErrBusy || s.Start(context.Background(), []byte(`{}`)) != ErrBusy {
		t.Fatal("overlap allowed")
	}
	close(release)
	if <-done != nil || s.State() != Idle {
		t.Fatal("stop")
	}
}
