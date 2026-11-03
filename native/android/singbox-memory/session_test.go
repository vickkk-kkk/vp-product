// SPDX-License-Identifier: GPL-3.0-or-later
package memory

import (
	"context"
	"errors"
	"testing"
)

func newTestSession(start func(context.Context, string) error, stop func() error) (*Session, error) {
	return NewVerified(start, stop, func() bool { return true })
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
	if s.State() != Starting || s.Stop() != ErrBusy {
		t.Fatal("start concurrency")
	}
	close(release)
	if <-done != nil || s.Stop() != nil {
		t.Fatal("completion")
	}
}

func TestStopCallAloneIsNotTeardownEvidence(t *testing.T) {
	closed := false
	s, err := NewVerified(func(context.Context, string) error { return nil }, func() error { return nil }, func() bool { return closed })
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
	if _, err := NewVerified(func(context.Context, string) error { return nil }, func() error { return nil }, nil); err != ErrInvalid {
		t.Fatal("missing verifier accepted")
	}
}
