//go:build singbox

// SPDX-License-Identifier: GPL-3.0-or-later
package memory

import (
	"errors"
	"reflect"
	"sync/atomic"

	"github.com/sagernet/sing-box/experimental/libbox"
)

var ErrPlatform = errors.New("Android platform operation failed")

// AndroidHost must own the original TUN, implement the actual Android network
// monitor, validate the requested TUN routes/DNS, and protect every socket.
// OpenTun returns a borrowed FD that remains
// owned by the host; libbox duplicates it. No implementation is provided here.
type AndroidHost interface {
	Protect(fd int32) bool
	OpenTun(options libbox.TunOptions) (int32, error)
	StartDefaultMonitor(listener libbox.InterfaceUpdateListener) error
	CloseDefaultMonitor(listener libbox.InterfaceUpdateListener) error
	Interfaces() (libbox.NetworkInterfaceIterator, error)
	RegisterTunName(name string) error
}

type AndroidPlatform struct {
	host     AndroidHost
	poisoned atomic.Bool
}

var _ libbox.PlatformInterface = (*AndroidPlatform)(nil)

func NewAndroidPlatform(host AndroidHost) (*AndroidPlatform, error) {
	if nilValue(host) {
		return nil, ErrPlatform
	}
	return &AndroidPlatform{host: host}, nil
}
func nilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func (p *AndroidPlatform) Healthy() bool                               { return !p.poisoned.Load() }
func (p *AndroidPlatform) LocalDNSTransport() libbox.LocalDNSTransport { return nil }
func (p *AndroidPlatform) UsePlatformAutoDetectInterfaceControl() bool { return true }
func (p *AndroidPlatform) AutoDetectInterfaceControl(fd int32) (err error) {
	defer func() {
		if recover() != nil {
			p.poisoned.Store(true)
			err = ErrPlatform
		}
	}()
	if !p.Healthy() || fd < 0 || !p.host.Protect(fd) {
		p.poisoned.Store(true)
		return ErrPlatform
	}
	return nil
}
func (p *AndroidPlatform) OpenTun(options libbox.TunOptions) (fd int32, err error) {
	defer func() {
		if recover() != nil {
			p.poisoned.Store(true)
			fd = -1
			err = ErrPlatform
		}
	}()
	if !p.Healthy() || nilValue(options) {
		p.poisoned.Store(true)
		return -1, ErrPlatform
	}
	fd, err = p.host.OpenTun(options)
	if err != nil || fd < 0 {
		p.poisoned.Store(true)
		return -1, ErrPlatform
	}
	return fd, nil
}
func (p *AndroidPlatform) StartDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) (err error) {
	defer func() {
		if recover() != nil {
			p.poisoned.Store(true)
			err = ErrPlatform
		}
	}()
	if !p.Healthy() || nilValue(listener) || p.host.StartDefaultMonitor(listener) != nil {
		p.poisoned.Store(true)
		return ErrPlatform
	}
	return nil
}
func (p *AndroidPlatform) CloseDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) (err error) {
	defer func() {
		if recover() != nil {
			p.poisoned.Store(true)
			err = ErrPlatform
		}
	}()
	if nilValue(listener) || p.host.CloseDefaultMonitor(listener) != nil {
		p.poisoned.Store(true)
		return ErrPlatform
	}
	return nil
}
func (p *AndroidPlatform) GetInterfaces() (interfaces libbox.NetworkInterfaceIterator, err error) {
	defer func() {
		if recover() != nil {
			p.poisoned.Store(true)
			interfaces = nil
			err = ErrPlatform
		}
	}()
	if !p.Healthy() {
		return nil, ErrPlatform
	}
	interfaces, err = p.host.Interfaces()
	if err != nil || nilValue(interfaces) {
		p.poisoned.Store(true)
		return nil, ErrPlatform
	}
	return interfaces, nil
}
func (p *AndroidPlatform) RegisterMyInterface(name string) {
	defer func() {
		if recover() != nil {
			p.poisoned.Store(true)
		}
	}()
	if !p.Healthy() || name == "" || p.host.RegisterTunName(name) != nil {
		p.poisoned.Store(true)
	}
}
func (p *AndroidPlatform) FindConnectionOwner(int32, string, int32, string, int32) (*libbox.ConnectionOwner, error) {
	return nil, ErrPlatform
}
func (p *AndroidPlatform) UnderNetworkExtension() bool      { return false }
func (p *AndroidPlatform) IncludeAllNetworks() bool         { return false }
func (p *AndroidPlatform) ReadWIFIState() *libbox.WIFIState { return nil }

// There is no implemented platform DNS-cache invalidation yet. Poison rather
// than silently claim it succeeded; the host must stop an unhealthy engine.
func (p *AndroidPlatform) ClearDNSCache()                              { p.poisoned.Store(true) }
func (p *AndroidPlatform) SendNotification(*libbox.Notification) error { return ErrPlatform }
func (p *AndroidPlatform) CancelNotification(string, int32) error      { return ErrPlatform }
func (p *AndroidPlatform) StartNeighborMonitor(libbox.NeighborUpdateListener) error {
	return ErrPlatform
}
func (p *AndroidPlatform) CloseNeighborMonitor(libbox.NeighborUpdateListener) error {
	return ErrPlatform
}
func (p *AndroidPlatform) UsePlatformShell() bool    { return false }
func (p *AndroidPlatform) CheckPlatformShell() error { return ErrPlatform }
func (p *AndroidPlatform) OpenShellSession(*libbox.PlatformUser, string, libbox.StringIterator, string, int32, int32) (libbox.ShellSession, error) {
	return nil, ErrPlatform
}
func (p *AndroidPlatform) LookupUser(string) (*libbox.PlatformUser, error) { return nil, ErrPlatform }
func (p *AndroidPlatform) LookupSFTPServer() (string, error)               { return "", ErrPlatform }
func (p *AndroidPlatform) ReadSystemSSHHostKey() (string, error)           { return "", ErrPlatform }
func (p *AndroidPlatform) TailscaleHostname() string                       { return "" }
func (p *AndroidPlatform) UsePlatformBridge() bool                         { return false }
func (p *AndroidPlatform) CreateBridge(*libbox.BridgeOptions) (libbox.BridgeSession, error) {
	return nil, ErrPlatform
}
