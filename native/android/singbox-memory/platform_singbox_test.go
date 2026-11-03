//go:build singbox

// SPDX-License-Identifier: GPL-3.0-or-later
package memory

import (
	"errors"
	"github.com/sagernet/sing-box/experimental/libbox"
	"testing"
)

type fakeOptions struct{ libbox.TunOptions }
type fakeHost struct {
	protect       bool
	tun           int32
	registerError bool
	panicProtect  bool
}

func (h *fakeHost) Protect(int32) bool {
	if h.panicProtect {
		panic("synthetic-secret")
	}
	return h.protect
}
func (h *fakeHost) OpenTun(libbox.TunOptions) (int32, error)                 { return h.tun, nil }
func (h *fakeHost) StartDefaultMonitor(libbox.InterfaceUpdateListener) error { return nil }
func (h *fakeHost) CloseDefaultMonitor(libbox.InterfaceUpdateListener) error { return nil }
func (h *fakeHost) Interfaces() (libbox.NetworkInterfaceIterator, error) {
	return nil, errors.New("synthetic-secret")
}
func (h *fakeHost) RegisterTunName(string) error {
	if h.registerError {
		return errors.New("synthetic-secret")
	}
	return nil
}

func TestPlatformRejectsProtectionFailureAndPoisons(t *testing.T) {
	var missing *fakeHost
	if _, err := NewAndroidPlatform(missing); err != ErrPlatform {
		t.Fatal("typed nil accepted")
	}
	h := &fakeHost{protect: true, tun: 42}
	p, err := NewAndroidPlatform(h)
	if err != nil || p.AutoDetectInterfaceControl(9) != nil || !p.Healthy() {
		t.Fatal("protect success")
	}
	fd, err := p.OpenTun(&fakeOptions{})
	if err != nil || fd != 42 {
		t.Fatal("borrowed fd")
	}
	h.protect = false
	if p.AutoDetectInterfaceControl(9) != ErrPlatform || p.Healthy() {
		t.Fatal("protect failure accepted")
	}
	h.protect = true
	if p.AutoDetectInterfaceControl(9) != ErrPlatform {
		t.Fatal("poisoned guard resumed")
	}
}

func TestPlatformRedactsAndPoisonsHostFailure(t *testing.T) {
	h := &fakeHost{protect: true, tun: 42, registerError: true}
	p, _ := NewAndroidPlatform(h)
	p.RegisterMyInterface("tun0")
	if p.Healthy() || p.AutoDetectInterfaceControl(9) != ErrPlatform {
		t.Fatal("registration failure ignored")
	}
	p, _ = NewAndroidPlatform(&fakeHost{protect: true, tun: 42})
	if _, err := p.GetInterfaces(); err != ErrPlatform || p.Healthy() {
		t.Fatal("host failure exposed or ignored")
	}
	p, _ = NewAndroidPlatform(&fakeHost{panicProtect: true})
	if p.AutoDetectInterfaceControl(9) != ErrPlatform || p.Healthy() {
		t.Fatal("protect panic ignored")
	}
	p, _ = NewAndroidPlatform(&fakeHost{protect: true, tun: 42})
	p.ClearDNSCache()
	if p.Healthy() {
		t.Fatal("unimplemented cache invalidation reported healthy")
	}
}
