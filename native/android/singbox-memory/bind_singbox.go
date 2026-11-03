//go:build singbox

// SPDX-License-Identifier: GPL-3.0-or-later
package memory

import (
	"context"
	"github.com/sagernet/sing-box/experimental/libbox"
	"sync"
)

// Keep one claim per server for this process. No automatic release: until a
// complete server-destruction protocol exists, reuse is intentionally denied.
var claimedServers sync.Map

// bindUnverified selects the exported StartedService method directly. Unlike libbox's
// CommandServer.StartOrReloadService wrapper, that method does not itself call
// saveConfigSnapshot. Other upstream logging/reporting and platform paths still
// require independent audit; this function does not claim memory-only behavior
// for the entire sing-box process. Upstream CloseService discards instance
// close errors, so the host must independently prove engine and TUN teardown.
// The caller transfers exclusive control and must not invoke server methods
// elsewhere; a caller retaining and using the pointer cannot be prevented here.
// This is private until construction proves this exact platform was installed
// in the server and full server teardown is implemented.
func bindUnverified(server *libbox.CommandServer, platform *AndroidPlatform, confirmClosed func() bool, validate func(string) error) (*Session, error) {
	if server == nil || server.StartedService == nil || platform == nil || !platform.Healthy() || confirmClosed == nil || validate == nil {
		return nil, ErrInvalid
	}
	key := server.StartedService
	if _, loaded := claimedServers.LoadOrStore(key, struct{}{}); loaded {
		return nil, ErrBusy
	}
	session, err := NewVerified(func(ctx context.Context, config string) error {
		if !platform.Healthy() {
			return ErrPlatform
		}
		if err := key.StartOrReloadService(ctx, config, nil); err != nil {
			return err
		}
		if !platform.Healthy() {
			return ErrPlatform
		}
		return nil
	}, key.CloseService, confirmClosed, validate)
	if err != nil {
		claimedServers.Delete(key)
		return nil, err
	}
	return session, nil
}
