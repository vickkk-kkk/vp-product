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

// Bind selects the exported StartedService method directly. Unlike libbox's
// CommandServer.StartOrReloadService wrapper, that method does not itself call
// saveConfigSnapshot. Other upstream logging/reporting and platform paths still
// require independent audit; this function does not claim memory-only behavior
// for the entire sing-box process. Upstream CloseService discards instance
// close errors, so the host must independently prove engine and TUN teardown.
// The caller transfers exclusive control and must not invoke server methods
// elsewhere; a caller retaining and using the pointer cannot be prevented here.
func Bind(server *libbox.CommandServer, confirmClosed func() bool, validate func(string) error) (*Session, error) {
	if server == nil || server.StartedService == nil || confirmClosed == nil || validate == nil {
		return nil, ErrInvalid
	}
	key := server.StartedService
	if _, loaded := claimedServers.LoadOrStore(key, struct{}{}); loaded {
		return nil, ErrBusy
	}
	session, err := NewVerified(func(ctx context.Context, config string) error {
		return key.StartOrReloadService(ctx, config, nil)
	}, key.CloseService, confirmClosed, validate)
	if err != nil {
		claimedServers.Delete(key)
		return nil, err
	}
	return session, nil
}
