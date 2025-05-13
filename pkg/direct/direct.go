package direct

import (
	"context"
	"net"
	"time"

	"github.com/cirrusj/wiressh/pkg/config"
	"github.com/cirrusj/wiressh/pkg/manager"
)

// Manager handles direct connections
type Manager struct {
	debug bool
}

// NewManager creates a new direct manager
func NewManager(debug bool) *Manager {
	return &Manager{
		debug: debug,
	}
}

// Start starts the direct manager
func (m *Manager) Start(cfg *config.WireSshConfig) error {
	return nil
}

// Stop stops the direct manager
func (m *Manager) Stop() error {
	return nil
}

// DialTimeout dials a connection with a timeout
func (m *Manager) DialTimeout(addr string, port string, timeout time.Duration) (net.Conn, error) {
	return manager.DialWithTimeout(
		m.debug,
		nil,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		},
		addr, port, timeout, "Direct",
	)
}

// Dial dials a connection
func (m *Manager) Dial(addr string, port string) (net.Conn, error) {
	return manager.DialWithTimeout(
		m.debug,
		nil,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		},
		addr, port, 0, "Direct",
	)
}
