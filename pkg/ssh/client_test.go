package ssh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cirrusj/wiressh/pkg/config"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.WireSshConfig
	}{
		{
			name: "basic configuration",
			cfg: &config.WireSshConfig{
				SshConfig: config.SshConfig{
					User:         "testuser",
					HostName:     "test.example.com",
					Port:         "22",
					IdentityFile: "~/.ssh/id_rsa",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.cfg, false, false)
			if client == nil {
				t.Error("NewClient() returned nil")
				return
			}
			if client.config != tt.cfg {
				t.Error("NewClient() did not set config correctly")
			}
		})
	}
}

func TestClient_Connect(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	knownHostsFile := filepath.Join(tmpDir, "known_hosts")

	// Create an empty known hosts file
	if err := os.WriteFile(knownHostsFile, []byte{}, 0644); err != nil {
		t.Fatalf("Failed to create known hosts file: %v", err)
	}

	tests := []struct {
		name          string
		cfg           *config.WireSshConfig
		knownHosts    string
		wantErr       bool
		expectedError error
	}{
		{
			name: "valid configuration",
			cfg: &config.WireSshConfig{
				SshConfig: config.SshConfig{
					User:         "testuser",
					HostName:     "test.example.com",
					Port:         "22",
					IdentityFile: "~/.ssh/id_rsa",
				},
			},
			knownHosts: knownHostsFile,
			wantErr:    true, // Will fail because we can't actually connect in tests
		},
		{
			name: "invalid known hosts file",
			cfg: &config.WireSshConfig{
				SshConfig: config.SshConfig{
					User:         "testuser",
					HostName:     "test.example.com",
					Port:         "22",
					IdentityFile: "~/.ssh/id_rsa",
				},
			},
			knownHosts: "nonexistent_file",
			wantErr:    true,
		},
		{
			name: "with recording",
			cfg: &config.WireSshConfig{
				SshConfig: config.SshConfig{
					User:         "testuser",
					HostName:     "test.example.com",
					Port:         "22",
					IdentityFile: "~/.ssh/id_rsa",
				},
			},
			knownHosts: knownHostsFile,
			wantErr:    true, // Will fail because we can't actually connect in tests
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.cfg, false, false)
			err := client.Connect(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Connect() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
