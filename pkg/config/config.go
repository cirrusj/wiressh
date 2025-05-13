package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"time"

	"github.com/cirrusj/wiressh/pkg/path"
	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
)

type ConfigType int

const (
	ConfigTypeWireGuard ConfigType = iota
	ConfigTypeTailscale
	ConfigTypeDirect
)

type SshConfig struct {
	// SSH settings
	User         string        // SSH user
	HostName     string        // SSH host to connect to
	Port         string        // SSH port to connect to
	IdentityFile string        // Path to SSH identity file
	HostKey      ssh.PublicKey // SSH host key
	LocalForward string        // Local forward
	Timeout      time.Duration // SSH connection timeout
}

type WireguardConfig struct {
	// WireGuard settings
	PrivateKey   string     // WireGuard private key
	PublicKey    string     // WireGuard public key
	PresharedKey string     // WireGuard preshared key
	IPAddress    netip.Addr // WireGuard IP address
	DNSServer    netip.Addr // WireGuard DNS server
	AllowedIP    string     // WireGuard allowed IP
	WGServer     string     // WireGuard server
	WGServerIP   net.IP     // WireGuard server IP
	WGPort       string     // WireGuard port
}

type TailscaleConfig struct {
	// Tailscale settings
	AuthKey string // Tailscale auth key
}

// WireSshConfig represents the configuration for a WireGuard, Tailscale, or Direct tunnel.
type WireSshConfig struct {
	Type            ConfigType // Tunnel type
	SshConfig       SshConfig
	WireguardConfig WireguardConfig
	TailscaleConfig TailscaleConfig
}

// loadWireguardConfig loads the WireGuard configuration from the config file
// Returns a WireguardConfig or an error if loading or validation fails.
// Keys for wireguard are: IPAddress, PrivateKey, PublicKey, PresharedKey,
// DNSServer, AllowedIP, WGServer
func loadWireguardConfig(configFile *ssh_config.Config, host string) (WireguardConfig, error) {
	wireguardConfig := WireguardConfig{}

	ipAddressStr, err := getRequiredConfigValue(configFile, host, "IPAddress")
	if err != nil {
		return wireguardConfig, err
	}
	if wireguardConfig.IPAddress, err = netip.ParseAddr(ipAddressStr); err != nil {
		return wireguardConfig, fmt.Errorf("invalid IPAddress %s: %w", ipAddressStr, err)
	}
	if wireguardConfig.PrivateKey, err = getRequiredConfigValue(configFile, host, "PrivateKey"); err != nil {
		return wireguardConfig, fmt.Errorf("failed to get PrivateKey: %w", err)
	}
	wireguardConfig.PrivateKey, err = EncodeBase64ToHex(wireguardConfig.PrivateKey)
	if err != nil {
		return wireguardConfig, fmt.Errorf("failed to decode PrivateKey: %w", err)
	}
	if wireguardConfig.PublicKey, err = getRequiredConfigValue(configFile, host, "PublicKey"); err != nil {
		return wireguardConfig, fmt.Errorf("failed to get PublicKey: %w", err)
	}
	wireguardConfig.PublicKey, err = EncodeBase64ToHex(wireguardConfig.PublicKey)
	if err != nil {
		return wireguardConfig, fmt.Errorf("failed to decode PublicKey: %w", err)
	}
	wireguardConfig.PresharedKey, err = configFile.Get(host, "PresharedKey")
	if err != nil {
		return wireguardConfig, fmt.Errorf("failed to get PresharedKey: %w", err)
	}
	if wireguardConfig.PresharedKey != "" {
		wireguardConfig.PresharedKey, err = EncodeBase64ToHex(wireguardConfig.PresharedKey)
		if err != nil {
			return wireguardConfig, fmt.Errorf("failed to decode PresharedKey: %w", err)
		}
	}
	dnsServerStr, err := getRequiredConfigValue(configFile, host, "DNSServer")
	if err != nil {
		return wireguardConfig, fmt.Errorf("failed to get DNSServer: %w", err)
	}
	if wireguardConfig.DNSServer, err = netip.ParseAddr(dnsServerStr); err != nil {
		return wireguardConfig, fmt.Errorf("invalid DNSServer %s: %w", dnsServerStr, err)
	}
	wireguardConfig.AllowedIP, err = configFile.Get(host, "AllowedIP")
	if err != nil {
		return wireguardConfig, fmt.Errorf("failed to get AllowedIP: %w", err)
	}
	if wireguardConfig.AllowedIP == "" {
		wireguardConfig.AllowedIP = DefaultAllowedIP
	}
	wgServerPort, err := getRequiredConfigValue(configFile, host, "WGServer")
	if err != nil {
		return wireguardConfig, fmt.Errorf("failed to get WGServer: %w", err)
	}
	wgServerString, wgPort, err := net.SplitHostPort(wgServerPort)
	if err != nil {
		return wireguardConfig, fmt.Errorf("invalid WGServer format: %w", err)
	}
	wgServerIPs, err := net.LookupIP(wgServerString)
	if err != nil {
		return wireguardConfig, fmt.Errorf("could not resolve WGServer host: %w", err)
	}
	if len(wgServerIPs) == 0 {
		return wireguardConfig, fmt.Errorf("host resolves to no IPs: %v", wgServerString)
	} else if len(wgServerIPs) > 1 {
		fmt.Printf("Warning: WGServer host resolves to multiple IPs (%v). Using the first: %v\n", wgServerIPs, wgServerIPs[0])
	}
	wireguardConfig.WGServer = wgServerPort
	wireguardConfig.WGServerIP = wgServerIPs[0]
	wireguardConfig.WGPort = wgPort
	return wireguardConfig, nil
}

// loadTailscaleConfig loads the Tailscale configuration from the config file
// Returns a TailscaleConfig or an error if loading or validation fails.
// Keys for tailscale are: AuthKey
func loadTailscaleConfig(configFile *ssh_config.Config, host string) (TailscaleConfig, error) {
	tailscaleConfig := TailscaleConfig{}
	authKey, err := getRequiredConfigValue(configFile, host, "AuthKey")
	if err != nil {
		return tailscaleConfig, fmt.Errorf("failed to get AuthKey: %w", err)
	}
	tailscaleConfig.AuthKey = authKey
	return tailscaleConfig, nil
}

// loadSshConfig loads the SSH settings from the config file
func loadSshConfig(configFile *ssh_config.Config, host string) (SshConfig, error) {
	sshConfig := SshConfig{}
	// Keys for SSH are: User, HostName, Port, IdentityFile, HostKey
	usr, err := configFile.Get(host, "User")
	if err != nil {
		return sshConfig, fmt.Errorf("failed to get User: %w", err)
	}
	if usr == "" {
		if currentUser, err := user.Current(); err == nil {
			sshConfig.User = currentUser.Username
		} else {
			return sshConfig, fmt.Errorf("failed to get current user: %w", err)
		}
	} else {
		sshConfig.User = usr
	}
	sshConfig.HostName = host
	// If HostName is defined it will override the host name given on the command line
	hostname, err := configFile.Get(host, "HostName")
	if err != nil {
		return sshConfig, fmt.Errorf("failed to get HostName: %w", err)
	}
	if hostname != "" {
		sshConfig.HostName = hostname
	}
	sshConfig.Port, err = configFile.Get(host, "Port")
	if err != nil {
		return sshConfig, fmt.Errorf("failed to get Port: %w", err)
	}
	if sshConfig.Port == "" {
		sshConfig.Port = DefaultPort
	}
	sshConfig.IdentityFile, err = configFile.Get(host, "IdentityFile")
	if err != nil {
		return sshConfig, fmt.Errorf("failed to get IdentityFile: %w", err)
	}
	if sshConfig.IdentityFile == "" {
		sshConfig.IdentityFile = DefaultIdentityFile
	}
	hostKey, err := configFile.Get(host, "HostKey")
	if err != nil {
		return sshConfig, fmt.Errorf("failed to get HostKey: %w", err)
	}
	if hostKey != "" {
		sshConfig.HostKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(hostKey))
		if err != nil {
			return sshConfig, fmt.Errorf("failed to parse HostKey: %w", err)
		}
	}
	localForward, err := configFile.Get(host, "LocalForward")
	if err != nil {
		return sshConfig, fmt.Errorf("failed to get LocalForward: %w", err)
	}
	sshConfig.LocalForward = localForward
	return sshConfig, nil
}

// LoadConfig loads and validates the configuration for the given host from the specified config file.
// Returns a WireSshConfig or an error if loading or validation fails.
func LoadConfig(host, wireSshConfigFile string) (*WireSshConfig, error) {
	wireSshConfigFile, err := path.ExpandHomeDir(wireSshConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to expand wiressh config file: %w", err)
	}

	configRead, err := os.Open(wireSshConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load wiressh config: %w", err)
	}
	defer configRead.Close()

	configFile, err := ssh_config.Decode(configRead)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wiressh config: %w", err)
	}

	// See if the host has any matches in the config
	matchedHost := false
	for _, cfgHost := range configFile.Hosts[1:] { // Not sure why 0 is blank and matches all
		if cfgHost.Matches(host) {
			matchedHost = true
			break
		}
	}
	// If the host is not found in the config, return an error
	if !matchedHost {
		return nil, fmt.Errorf("host not found in config: %s", host)
	}

	// Initialize the config with the host name from the command line
	cfg := &WireSshConfig{
		SshConfig: SshConfig{
			HostName: host,
			Timeout:  DefaultTimeout,
		},
	}

	// Load and validate required fields
	if configType, err := getRequiredConfigValue(configFile, host, "Type"); err != nil {
		return nil, err
	} else {
		switch configType {
		case "wireguard":
			cfg.Type = ConfigTypeWireGuard
			wireguardConfig, err := loadWireguardConfig(configFile, host)
			if err != nil {
				return nil, fmt.Errorf("failed to load wireguard config: %w", err)
			}
			cfg.WireguardConfig = wireguardConfig
		case "tailscale":
			cfg.Type = ConfigTypeTailscale
			tailscaleConfig, err := loadTailscaleConfig(configFile, host)
			if err != nil {
				return nil, fmt.Errorf("failed to load tailscale config: %w", err)
			}
			cfg.TailscaleConfig = tailscaleConfig
		case "direct":
			cfg.Type = ConfigTypeDirect
		default:
			return nil, fmt.Errorf("invalid config type: %s", configType)
		}
	}
	sshConfig, err := loadSshConfig(configFile, host)
	if err != nil {
		return nil, fmt.Errorf("failed to load SSH settings: %w", err)
	}
	cfg.SshConfig = sshConfig
	return cfg, nil
}

// EncodeBase64ToHex encodes a base64 string to a hex string as required by WireGuard
func EncodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("invalid base64 string: %w", err)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("key should be 32 bytes")
	}
	return hex.EncodeToString(decoded), nil
}

// getRequiredConfigValue returns the value of a required config key
func getRequiredConfigValue(config *ssh_config.Config, host, key string) (string, error) {
	value, err := config.Get(host, key)
	if err != nil {
		return "", fmt.Errorf("failed to get %s: %w", key, err)
	}
	if value == "" {
		return "", fmt.Errorf("%s not found", key)
	}
	return value, nil
}
