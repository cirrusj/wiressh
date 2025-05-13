package manager

import (
	"net"
	"time"

	"github.com/cirrusj/wiressh/pkg/config"
)

// Manager is an interface implemented by tunnel managers (WireGuard, Tailscale, Direct).
// It provides methods to start, stop, and dial connections over the tunnel.
type Manager interface {
	// Start initializes and starts the tunnel using the provided WireSshConfig.
	// Returns an error if the tunnel setup fails.
	Start(*config.WireSshConfig) error
	// Stop terminates the tunnel and performs any necessary cleanup operations.
	// Returns an error if the shutdown process fails.
	Stop() error
	// Dial establishes a connection to the specified address and port over the tunnel.
	// Returns a net.Conn object representing the connection and an error if the dialing fails.
	Dial(addr string, port string) (net.Conn, error)
	// DialTimeout establishes a connection to the specified address and port over the tunnel,
	// with a timeout specified by the timeout parameter. Returns a net.Conn object
	// representing the connection and an error if the dialing fails or times out.
	DialTimeout(addr string, port string, timeout time.Duration) (net.Conn, error)
}
