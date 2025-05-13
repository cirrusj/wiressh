package tailscale

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cirrusj/wiressh/pkg/config"
	"github.com/cirrusj/wiressh/pkg/manager"
	"github.com/cirrusj/wiressh/pkg/path"
	"tailscale.com/envknob"
	"tailscale.com/logtail"
	"tailscale.com/tsnet"
)

// Manager handles Tailscale tunnel operations.
type Manager struct {
	server *tsnet.Server
	debug  bool
}

// NewManager creates a new Tailscale manager with the given debug flag.
func NewManager(debug bool) *Manager {
	return &Manager{
		debug: debug,
	}
}

// Start creates and configures a Tailscale tunnel using the provided configuration.
func (m *Manager) Start(cfg *config.WireSshConfig) error {
	logtail.Disable()
	envknob.SetNoLogsNoSupport() // This does not seem to do anything.
	if m.debug {
		log.Println("Starting Tailscale server with auth key")
	}
	// Create Tailscale server directory - needed to support multiple instances
	tsDir, err := path.CreateConfigDir(m.debug)
	if err != nil {
		log.Println("Error:", err)
		os.Exit(1)
	}
	// Create Tailscale server
	m.server = &tsnet.Server{
		AuthKey:  cfg.TailscaleConfig.AuthKey,
		Hostname: "wiressh",
		Dir:      tsDir,
		// Store:     nil,
		Ephemeral: true,
		Logf:      m.getLogFunc(),
	}
	if m.debug {
		log.Println("Tailscale server started successfully")
	}

	return nil
}

// getLogFunc returns a logger function for Tailscale. If debug is true, it will log to the console.
func (m *Manager) getLogFunc() func(format string, args ...any) {
	if m.debug {
		return log.Printf
	}
	return func(string, ...any) {}
}

// Stop shuts down the Tailscale tunnel and releases resources.
func (m *Manager) Stop() error {
	fmt.Println("Stopping Tailscale tunnel...")

	if m.server != nil {
		// Remove Tailscale server directory
		if m.debug {
			log.Println("Should cleanup tsnet directory:", m.server.Dir)
		}

		// Close the server first
		err := m.server.Close()

		// Then remove the directory
		if m.server.Dir != "" {
			// removeErr := os.RemoveAll(m.server.Dir)
			// if removeErr != nil && m.debug {
			// log.Printf("Warning: Failed to remove tsnet directory %s: %v", m.server.Dir, removeErr)
			// }
		}

		return err
	}
	return nil
}

// GetNetwork returns the Tailscale server instance for the tunnel.
func (m *Manager) GetNetwork() *tsnet.Server {
	return m.server
}

// PrintStatus prints the status of the Tailscale tunnel to stdout.
func (m *Manager) PrintStatus() {
	client, err := m.server.LocalClient()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, err := client.Status(ctx)
	if err != nil {
		return
	}
	fmt.Println("status:", status)
}

// DialTimeout dials a connection over the Tailscale tunnel with a timeout.
func (m *Manager) DialTimeout(addr string, port string, timeout time.Duration) (net.Conn, error) {
	return manager.DialWithTimeout(
		m.debug,
		func() error {
			fmt.Println("Starting Tailscale tunnel...")
			_, err := m.server.Up(context.Background())
			return err
		},
		m.server.Dial,
		addr, port, timeout, "Tailscale",
	)
}

// Dial establishes a connection over the Tailscale tunnel.
func (m *Manager) Dial(addr string, port string) (net.Conn, error) {
	return manager.DialWithTimeout(
		m.debug,
		func() error {
			fmt.Println("Starting Tailscale tunnel...")
			_, err := m.server.Up(context.Background())
			return err
		},
		m.server.Dial,
		addr, port, 0, "Tailscale",
	)
}
