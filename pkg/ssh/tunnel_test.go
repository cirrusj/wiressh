package ssh

import (
	"testing"

	"github.com/cirrusj/wiressh/pkg/config"
)

// TestStartTunnelNetwork covers error and type handling for StartTunnelNetwork
func TestStartTunnelNetwork(t *testing.T) {
	cfg := &config.WireSshConfig{Type: config.ConfigType(-1)}
	client := NewClient(cfg, false, false)
	_, err := client.StartTunnelNetwork()
	if err == nil {
		t.Error("expected error for unsupported tunnel type")
	}
}
