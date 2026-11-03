//go:build singbox

// SPDX-License-Identifier: GPL-3.0-or-later
package memory

import (
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"testing"
)

func TestBindRequiresAbsentAndUniqueServer(t *testing.T) {
	server := &libbox.CommandServer{StartedService: &daemon.StartedService{}}
	platform, _ := NewAndroidPlatform(&fakeHost{protect: true, tun: 42})
	validate := func(string) error { return nil }
	if _, err := bindUnverified(server, platform, func() bool { return false }, validate); err != ErrStop {
		t.Fatal("unconfirmed server accepted")
	}
	if _, err := bindUnverified(server, platform, func() bool { panic("synthetic-secret") }, validate); err != ErrStop {
		t.Fatal("confirmation panic accepted")
	}
	if _, err := bindUnverified(server, platform, func() bool { return true }, validate); err != nil {
		t.Fatal("first claim rejected")
	}
	alias := &libbox.CommandServer{StartedService: server.StartedService}
	if _, err := bindUnverified(alias, platform, func() bool { return true }, validate); err != ErrBusy {
		t.Fatal("duplicate claim accepted")
	}
}
