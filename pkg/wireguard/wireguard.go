package wireguard

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/cirrusj/wiressh/pkg/config"
	"github.com/cirrusj/wiressh/pkg/manager"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/netstack"
)

// Manager handles WireGuard tunnel operations.
type Manager struct {
	device *device.Device
	tnet   *netstack.Net
	debug  bool
}

// NewManager creates a new WireGuard manager with the given debug flag.
func NewManager(debug bool) *Manager {
	return &Manager{
		debug: debug,
	}
}

// Start creates and configures a WireGuard tunnel using the provided configuration.
func (m *Manager) Start(cfg *config.WireSshConfig) error {
	var err error

	if m.debug {
		log.Println("Creating TUN device with IP:", cfg.WireguardConfig.IPAddress, "and DNS:", cfg.WireguardConfig.DNSServer)
	}

	// Create TUN device
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{cfg.WireguardConfig.IPAddress},
		[]netip.Addr{cfg.WireguardConfig.DNSServer},
		1420,
	)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}

	// Create WireGuard device
	logLevel := device.LogLevelError
	if m.debug {
		logLevel = device.LogLevelVerbose
		log.Println("Starting WireGuard device with verbose logging")
	} else {
		fmt.Println("Starting WireGuard tunnel...")
	}
	m.device = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	m.tnet = tnet

	// Configure device
	wgConf := fmt.Sprintf("private_key=%s\n", cfg.WireguardConfig.PrivateKey)
	wgConf += fmt.Sprintf("public_key=%s\n", cfg.WireguardConfig.PublicKey)
	if cfg.WireguardConfig.PresharedKey != "" {
		wgConf += fmt.Sprintf("preshared_key=%s\n", cfg.WireguardConfig.PresharedKey)
	}

	// Format endpoint correctly for IPv6
	endpointHost := cfg.WireguardConfig.WGServerIP.String()
	if cfg.WireguardConfig.WGServerIP.To4() == nil && cfg.WireguardConfig.WGServerIP.To16() != nil {
		// IPv6 address, must be in brackets
		endpointHost = "[" + endpointHost + "]"
	}
	wgConf += fmt.Sprintf("endpoint=%s:%s\n", endpointHost, cfg.WireguardConfig.WGPort)
	wgConf += fmt.Sprintf("allowed_ip=%s\n", cfg.WireguardConfig.AllowedIP)

	if m.debug {
		// Redact sensitive keys for logging
		redactedConf := wgConf
		redactedConf = strings.ReplaceAll(redactedConf, cfg.WireguardConfig.PrivateKey, "[REDACTED]")
		redactedConf = strings.ReplaceAll(redactedConf, cfg.WireguardConfig.PublicKey, "[REDACTED]")
		if cfg.WireguardConfig.PresharedKey != "" {
			redactedConf = strings.ReplaceAll(redactedConf, cfg.WireguardConfig.PresharedKey, "[REDACTED]")
		}
		log.Println("[DEBUG] WireGuard configuration (keys redacted):", redactedConf)
	}

	if err := m.device.IpcSet(wgConf); err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}

	// Start device
	if err := m.device.Up(); err != nil {
		return fmt.Errorf("failed to start device: %w", err)
	}

	if m.debug {
		log.Println("WireGuard tunnel started successfully")
	}

	return nil
}

// Stop shuts down the WireGuard tunnel and releases resources.
func (m *Manager) Stop() error {
	fmt.Println("Stopping WireGuard tunnel...")
	if m.device != nil {
		err := m.device.Down()
		m.device.Close()
		return err
	}
	return nil
}

// GetNetwork returns the network stack for the WireGuard tunnel.
func (m *Manager) GetNetwork() *netstack.Net {
	return m.tnet
}

// DialTimeout dials a connection over the WireGuard tunnel with a timeout.
func (m *Manager) DialTimeout(addr string, port string, timeout time.Duration) (net.Conn, error) {
	return manager.DialWithTimeout(
		m.debug,
		nil,
		m.tnet.DialContext,
		addr, port, timeout, "WireGuard",
	)
}

// Dial establishes a connection over the WireGuard tunnel.
func (m *Manager) Dial(addr string, port string) (net.Conn, error) {
	return manager.DialWithTimeout(
		m.debug,
		nil,
		m.tnet.DialContext,
		addr, port, 0, "WireGuard",
	)
}
