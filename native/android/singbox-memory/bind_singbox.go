//go:build singbox

// SPDX-License-Identifier: GPL-3.0-or-later
package memory

import (
	"context"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// Bind selects the exported StartedService method directly. Unlike libbox's
// CommandServer.StartOrReloadService wrapper, that method does not itself call
// saveConfigSnapshot. Other upstream logging/reporting and platform paths still
// require independent audit; this function does not claim memory-only behavior
// for the entire sing-box process. Upstream CloseService discards instance
// close errors, so the host must independently prove engine and TUN teardown.
func Bind(server *libbox.CommandServer, confirmClosed func() bool) (*Session, error) {
	if server == nil || server.StartedService == nil || confirmClosed == nil {
		return nil, ErrInvalid
	}
	return NewVerified(func(ctx context.Context, config string) error {
		return server.StartedService.StartOrReloadService(ctx, config, nil)
	}, server.CloseService, confirmClosed)
}
