package tailscale

import (
	"os"
	"testing"

	"github.com/cirrusj/wiressh/pkg/config"
)

func TestNewManager(t *testing.T) {
	mgr := NewManager(true)
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if !mgr.debug {
		t.Error("NewManager did not set debug flag")
	}
}

func TestManager_Start_Stop_GetNetwork(t *testing.T) {
	mgr := NewManager(false)

	cfg := &config.WireSshConfig{
		TailscaleConfig: config.TailscaleConfig{
			AuthKey: "dummy",
		},
	}
	// Use a temp dir for the test
	os.Setenv("XDG_CONFIG_HOME", os.TempDir())
	if err := mgr.Start(cfg); err != nil {
		t.Errorf("Start failed: %v", err)
	}

	if mgr.GetNetwork() == nil {
		t.Error("GetNetwork returned nil after Start")
	}

	// Stop should not panic even if server is nil
	mgr2 := NewManager(false)
	if err := mgr2.Stop(); err != nil {
		t.Errorf("Stop failed with nil server: %v", err)
	}
}
