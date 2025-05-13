package wireguard

import (
	"net/netip"
	"testing"

	"github.com/cirrusj/wiressh/pkg/config"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/netstack"
)

// createTestDevice creates a test WireGuard device with a test configuration
func createTestDevice() (*device.Device, *netstack.Net, error) {
	// Create a test TUN device
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		1420,
	)
	if err != nil {
		return nil, nil, err
	}

	// Create a test bind
	bind := conn.NewDefaultBind()

	// Create a test device
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelError, "test"))

	// Set up a test configuration
	config := `private_key=0000000000000000000000000000000000000000000000000000000000000000
public_key=0000000000000000000000000000000000000000000000000000000000000000
endpoint=192.168.1.1:51820
allowed_ip=0.0.0.0/0
persistent_keepalive_interval=25`

	if err := dev.IpcSet(config); err != nil {
		return nil, nil, err
	}

	return dev, tnet, nil
}

func TestNewManager(t *testing.T) {
	tests := []struct {
		name  string
		debug bool
	}{
		{
			name:  "debug enabled",
			debug: true,
		},
		{
			name:  "debug disabled",
			debug: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(tt.debug)
			if mgr == nil {
				t.Error("NewManager() returned nil")
			}
			if mgr != nil && mgr.debug != tt.debug {
				t.Errorf("NewManager() debug = %v, want %v", mgr.debug, tt.debug)
			}
		})
	}
}

func TestManager_StartStop(t *testing.T) {
	// Create a test configuration
	cfg := &config.WireSshConfig{
		WireguardConfig: config.WireguardConfig{
			PrivateKey: "0000000000000000000000000000000000000000000000000000000000000000",
			PublicKey:  "0000000000000000000000000000000000000000000000000000000000000000",
			IPAddress:  netip.MustParseAddr("10.0.0.1"),
			DNSServer:  netip.MustParseAddr("8.8.8.8"),
			AllowedIP:  "0.0.0.0/0",
			WGServer:   "wireguard.example.com:51820",
			WGServerIP: netip.MustParseAddr("192.168.1.1").AsSlice(),
			WGPort:     "51820",
		},
	}

	tests := []struct {
		name    string
		debug   bool
		wantErr bool
	}{
		// {
		// 	name:    "debug enabled",
		// 	debug:   true,
		// 	wantErr: false,
		// },
		{
			name:    "debug disabled",
			debug:   false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(tt.debug)

			// Create test device and network stack
			dev, tnet, err := createTestDevice()
			if err != nil {
				t.Fatalf("Failed to create test device: %v", err)
			}
			mgr.device = dev
			mgr.tnet = tnet

			// Test Start
			err = mgr.Start(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Manager.Start() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if mgr.device == nil {
					t.Error("Manager.Start() did not set device")
				}
				if mgr.tnet == nil {
					t.Error("Manager.Start() did not set network stack")
				}
			}

			// Test Stop
			err = mgr.Stop()
			if err != nil {
				t.Errorf("Manager.Stop() error = %v", err)
			}
		})
	}
}

func TestManager_GetNetwork(t *testing.T) {
	mgr := NewManager(false)
	if mgr.GetNetwork() != nil {
		t.Error("GetNetwork() should return nil before Start()")
	}

	// Create a test configuration
	cfg := &config.WireSshConfig{
		WireguardConfig: config.WireguardConfig{
			PrivateKey: "0000000000000000000000000000000000000000000000000000000000000000",
			PublicKey:  "0000000000000000000000000000000000000000000000000000000000000000",
			IPAddress:  netip.MustParseAddr("10.0.0.1"),
			DNSServer:  netip.MustParseAddr("8.8.8.8"),
			AllowedIP:  "0.0.0.0/0",
			WGServer:   "wireguard.example.com:51820",
			WGServerIP: netip.MustParseAddr("192.168.1.1").AsSlice(),
			WGPort:     "51820",
		},
	}

	// Create test device and network stack
	dev, tnet, err := createTestDevice()
	if err != nil {
		t.Fatalf("Failed to create test device: %v", err)
	}
	mgr.device = dev
	mgr.tnet = tnet

	if err := mgr.Start(cfg); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer mgr.Stop()

	if mgr.GetNetwork() == nil {
		t.Error("GetNetwork() should not return nil after Start()")
	}
}
