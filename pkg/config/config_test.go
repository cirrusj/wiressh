package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kevinburke/ssh_config"
)

func TestLoadConfig(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()
	wireConfigFile := filepath.Join(tmpDir, "wireguard_config")
	// Create a blank identity file
	identityFile := filepath.Join(tmpDir, "id_rsa")
	if err := os.WriteFile(identityFile, []byte{}, 0644); err != nil {
		t.Fatalf("Failed to create identity file: %v", err)
	}

	// Write test configurations
	wireConfig := `Host test_wireguard
	Type wireguard
	PrivateKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
	PublicKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
	IPAddress 10.0.0.1
	DNSServer 8.8.8.8
	WGServer 127.0.0.1:51820
	User testuser
	HostName test.example.com
	Port 22
	IdentityFile ` + identityFile + `

Host test_wireguard_missing_ipaddress
	Type wireguard
	PublicKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
	PrivateKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
	DNSServer 8.8.8.8
	WGServer 127.0.0.1:51820
	User testuser
	HostName test.example.com
	Port 22
	IdentityFile ` + identityFile + `

Host test_tailscale
	Type tailscale
	AuthKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
	User testuser
	HostName test.example.com
	Port 22
	IdentityFile ` + identityFile + `

Host test_tailscale_missing_authkey
	Type tailscale
	User testuser
	HostName test.example.com
	Port 22
	IdentityFile ` + identityFile + `
	`

	if err := os.WriteFile(wireConfigFile, []byte(wireConfig), 0644); err != nil {
		t.Fatalf("Failed to write wireguard config: %v", err)
	}

	tests := []struct {
		name          string
		host          string
		configType    ConfigType
		wireConfig    string
		wantErr       bool
		expectedError error
	}{
		{
			name:       "valid wireguard configuration",
			host:       "test_wireguard",
			configType: ConfigTypeWireGuard,
			wireConfig: wireConfigFile,
			wantErr:    false,
		},
		{
			name:       "valid tailscale configuration",
			host:       "test_tailscale",
			configType: ConfigTypeTailscale,
			wireConfig: wireConfigFile,
			wantErr:    false,
		},
		{
			name:          "non-existent host",
			host:          "nonexistent",
			configType:    ConfigTypeWireGuard,
			wireConfig:    wireConfigFile,
			wantErr:       true,
			expectedError: fmt.Errorf("host not found in config: nonexistent"),
		},
		{
			name:          "non existent config file",
			host:          "test_wireguard",
			configType:    ConfigTypeWireGuard,
			wireConfig:    "nonexistent_file",
			wantErr:       true,
			expectedError: fmt.Errorf("failed to load wiressh config: open %s: no such file or directory", "nonexistent_file"),
		},
		{
			name:          "invalid wireguard config",
			host:          "test_wireguard_missing_ipaddress",
			configType:    ConfigTypeWireGuard,
			wireConfig:    wireConfigFile,
			wantErr:       true,
			expectedError: fmt.Errorf("failed to load wireguard config: IPAddress not found"),
		},
		{
			name:          "invalid tailscale config",
			host:          "test_tailscale_missing_authkey",
			configType:    ConfigTypeTailscale,
			wireConfig:    wireConfigFile,
			wantErr:       true,
			expectedError: fmt.Errorf("failed to load tailscale config: failed to get AuthKey: AuthKey not found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadConfig(tt.host, tt.wireConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = '%v', wantErr '%v'", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.expectedError != nil {
					if err.Error() != tt.expectedError.Error() {
						t.Errorf("LoadConfig() error = '%v', want '%v'", err, tt.expectedError)
					}
				}
				return
			}
			if cfg == nil {
				t.Error("LoadConfig() returned nil config")
				return
			}
			if cfg.Type != tt.configType {
				t.Errorf("LoadConfig() returned wrong config type: '%v'", cfg.Type)
			}
		})
	}
}

func TestEncodeBase64ToHex(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid base64",
			input:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 bytes of zeros in base64
			want:    "0000000000000000000000000000000000000000000000000000000000000000",
			wantErr: false,
		},
		{
			name:    "invalid base64",
			input:   "invalid_base64",
			wantErr: true,
		},
		{
			name:    "wrong length",
			input:   "dGVzdA==", // "test" is only 4 bytes
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeBase64ToHex(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeBase64ToHex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("EncodeBase64ToHex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadSshConfig_Errors(t *testing.T) {
	tmpDir := t.TempDir()
	identityFile := filepath.Join(tmpDir, "id_rsa")
	os.WriteFile(identityFile, []byte{}, 0644)

	// Minimal ssh_config file with missing HostKey
	sshConfigContent := `Host test
User testuser
HostName test.example.com
Port 22
IdentityFile ` + identityFile + `
`
	sshConfigFile := filepath.Join(tmpDir, "ssh_config")
	os.WriteFile(sshConfigFile, []byte(sshConfigContent), 0644)
	f, _ := os.Open(sshConfigFile)
	cfg, _ := ssh_config.Decode(f)
	f.Close()

	_, err := loadSshConfig(cfg, "test")
	if err != nil {
		t.Errorf("Expected no error for missing HostKey, got: %v", err)
	}

	// Test missing identity file: should NOT error if agent is used
	missingIdentityFile := filepath.Join(tmpDir, "doesnotexist")
	sshConfigContentMissingIdentity := `Host test
User testuser
HostName test.example.com
Port 22
IdentityFile ` + missingIdentityFile + `
`
	sshConfigFileMissingIdentity := filepath.Join(tmpDir, "ssh_config_missing_identity")
	os.WriteFile(sshConfigFileMissingIdentity, []byte(sshConfigContentMissingIdentity), 0644)
	f, _ = os.Open(sshConfigFileMissingIdentity)
	cfg, _ = ssh_config.Decode(f)
	f.Close()
	_, err = loadSshConfig(cfg, "test")
	if err != nil {
		t.Errorf("Expected no error for missing identity file when using agent, got: %v", err)
	}
}

func TestGetRequiredConfigValue(t *testing.T) {
	// Create a minimal ssh_config.Config
	pat, err := ssh_config.NewPattern("test")
	if err != nil {
		t.Fatalf("Failed to create pattern: %v", err)
	}
	cfg := &ssh_config.Config{
		Hosts: []*ssh_config.Host{{
			Patterns: []*ssh_config.Pattern{pat},
			Nodes:    []ssh_config.Node{},
		}},
	}
	_, err = getRequiredConfigValue(cfg, "test", "MissingKey")
	if err == nil || !strings.Contains(err.Error(), "MissingKey not found") {
		t.Errorf("Expected error for missing key, got: %v", err)
	}
}

func TestLoadConfig_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	// Before the default values test, ensure ~/.ssh/id_rsa exists in the temp HOME
	sshDir := filepath.Join(tmpDir, ".ssh")
	os.MkdirAll(sshDir, 0700)
	identityFile := filepath.Join(sshDir, "id_rsa")
	os.WriteFile(identityFile, []byte{}, 0644)
	os.Setenv("HOME", tmpDir) // So ~ expands to tmpDir

	t.Run("invalid IPAddress", func(t *testing.T) {
		configFile := filepath.Join(tmpDir, "config_invalid_ip")
		config := `Host test
Type wireguard
PrivateKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PublicKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
IPAddress not_an_ip
DNSServer 8.8.8.8
WGServer 127.0.0.1:51820
IdentityFile ` + identityFile + `
`
		os.WriteFile(configFile, []byte(config), 0644)
		_, err := LoadConfig("test", configFile)
		if err == nil || !strings.Contains(err.Error(), "invalid IPAddress") {
			t.Errorf("Expected error for invalid IPAddress, got: %v", err)
		}
	})

	t.Run("invalid DNSServer", func(t *testing.T) {
		configFile := filepath.Join(tmpDir, "config_invalid_dns")
		config := `Host test
Type wireguard
PrivateKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PublicKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
IPAddress 10.0.0.1
DNSServer not_a_dns
WGServer 127.0.0.1:51820
IdentityFile ` + identityFile + `
`
		os.WriteFile(configFile, []byte(config), 0644)
		_, err := LoadConfig("test", configFile)
		if err == nil || !strings.Contains(err.Error(), "invalid DNSServer") {
			t.Errorf("Expected error for invalid DNSServer, got: %v", err)
		}
	})

	t.Run("invalid WGServer format", func(t *testing.T) {
		configFile := filepath.Join(tmpDir, "config_invalid_wgserver")
		config := `Host test
Type wireguard
PrivateKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PublicKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
IPAddress 10.0.0.1
DNSServer 8.8.8.8
WGServer not_a_hostport
IdentityFile ` + identityFile + `
`
		os.WriteFile(configFile, []byte(config), 0644)
		_, err := LoadConfig("test", configFile)
		if err == nil || !strings.Contains(err.Error(), "invalid WGServer format") {
			t.Errorf("Expected error for invalid WGServer format, got: %v", err)
		}
	})

	t.Run("WGServer DNS resolution failure", func(t *testing.T) {
		configFile := filepath.Join(tmpDir, "config_unresolvable_wgserver")
		config := `Host test
Type wireguard
PrivateKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PublicKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
IPAddress 10.0.0.1
DNSServer 8.8.8.8
WGServer unresolvablehost:51820
IdentityFile ` + identityFile + `
`
		os.WriteFile(configFile, []byte(config), 0644)
		_, err := LoadConfig("test", configFile)
		if err == nil || !strings.Contains(err.Error(), "could not resolve WGServer host") {
			t.Errorf("Expected error for unresolvable WGServer host, got: %v", err)
		}
	})

	t.Run("WGServer resolves to zero IPs", func(t *testing.T) {
		configFile := filepath.Join(tmpDir, "config_zero_ips")
		config := `Host test
Type wireguard
PrivateKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PublicKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
IPAddress 10.0.0.1
DNSServer 8.8.8.8
WGServer invalid.invalid:51820
IdentityFile ` + identityFile + `
`
		os.WriteFile(configFile, []byte(config), 0644)
		_, err := LoadConfig("test", configFile)
		if err == nil || !(strings.Contains(err.Error(), "host resolves to no IPs") || strings.Contains(err.Error(), "could not resolve WGServer host")) {
			t.Errorf("Expected error for zero IPs, got: %v", err)
		}
	})

	t.Run("ConfigTypeDirect", func(t *testing.T) {
		configFile := filepath.Join(tmpDir, "config_direct")
		config := `Host test
Type direct
IdentityFile ` + identityFile + `
`
		os.WriteFile(configFile, []byte(config), 0644)
		cfg, err := LoadConfig("test", configFile)
		if err != nil {
			t.Errorf("Expected no error for direct config, got: %v", err)
		}
		if cfg.Type != ConfigTypeDirect {
			t.Errorf("Expected ConfigTypeDirect, got: %v", cfg.Type)
		}
	})

	t.Run("default AllowedIP, Port, IdentityFile", func(t *testing.T) {
		configFile := filepath.Join(tmpDir, "config_defaults")
		config := `Host test
Type wireguard
PrivateKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PublicKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
IPAddress 10.0.0.1
DNSServer 8.8.8.8
WGServer 127.0.0.1:51820
`
		os.WriteFile(configFile, []byte(config), 0644)
		cfg, err := LoadConfig("test", configFile)
		if err != nil {
			t.Errorf("Expected no error for config with defaults, got: %v", err)
		}
		if cfg.WireguardConfig.AllowedIP != DefaultAllowedIP {
			t.Errorf("Expected default AllowedIP, got: %v", cfg.WireguardConfig.AllowedIP)
		}
		if cfg.SshConfig.Port != DefaultPort {
			t.Errorf("Expected default Port, got: %v", cfg.SshConfig.Port)
		}
		if cfg.SshConfig.IdentityFile != DefaultIdentityFile {
			t.Errorf("Expected default IdentityFile, got: %v", cfg.SshConfig.IdentityFile)
		}
	})

	t.Run("valid HostKey parsing", func(t *testing.T) {
		configFile := filepath.Join(tmpDir, "config_valid_hostkey")
		// Use a valid public key format (ecdsa-sha2-nistp256 with dummy data)
		validHostKey := "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg="
		config := `Host test
Type wireguard
PrivateKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PublicKey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
IPAddress 10.0.0.1
DNSServer 8.8.8.8
WGServer 127.0.0.1:51820
HostKey ` + validHostKey + `
IdentityFile ` + identityFile + `
`
		os.WriteFile(configFile, []byte(config), 0644)
		cfg, err := LoadConfig("test", configFile)
		if err != nil {
			t.Errorf("Expected no error for valid HostKey, got: %v", err)
		}
		if cfg.SshConfig.HostKey == nil {
			t.Errorf("Expected HostKey to be parsed, got nil")
		}
	})
}
