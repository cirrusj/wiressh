package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cirrusj/wiressh/pkg/config"
	"github.com/cirrusj/wiressh/pkg/manager"
	"github.com/cirrusj/wiressh/pkg/path"
	"github.com/cirrusj/wiressh/pkg/signal"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// Client handles SSH connections and tunnel management.
type Client struct {
	config      *config.WireSshConfig
	debug       bool
	debugTunnel bool
}

// Patchable for testing
var expandHomeDir = path.ExpandHomeDir
var readFile = os.ReadFile

// NewClient creates a new SSH client with the given configuration and debug flags.
func NewClient(cfg *config.WireSshConfig, debug bool, debugTunnel bool) *Client {
	return &Client{
		config:      cfg,
		debug:       debug,
		debugTunnel: debugTunnel,
	}
}

// StartTunnelNetwork starts the appropriate tunnel (WireGuard, Tailscale, or Direct) based on the configuration.
// Returns a manager.Manager for the tunnel, or an error if setup fails.
func (c *Client) StartTunnelNetwork() (manager manager.Manager, err error) {
	if c.config.Type == config.ConfigTypeWireGuard {
		// Create and start WireGuard tunnel
		wgManager := WireGuardManagerCtor(c.debugTunnel)
		if err := wgManager.Start(c.config); err != nil {
			// Failed to start WireGuard tunnel
			return nil, err
		}
		return wgManager, nil
	} else if c.config.Type == config.ConfigTypeTailscale {
		// Create and start Tailscale tunnel
		tsManager := TailscaleManagerCtor(c.debugTunnel)
		if err := tsManager.Start(c.config); err != nil {
			return nil, err
		}
		return tsManager, nil
	} else if c.config.Type == config.ConfigTypeDirect {
		// Create and start direct connection
		directManager := DirectManagerCtor(c.debugTunnel)
		if err := directManager.Start(c.config); err != nil {
			return nil, err
		}
		return directManager, nil
	} else {
		return nil, fmt.Errorf("unsupported tunnel type: %T", c.config.Type)
	}
}

// loadIdentityFile loads the identity file and returns a signer
// Returns an error if the identity file is not found, cannot be read, or cannot be parsed.
// If the identity file requires a passphrase, it will prompt the user for the passphrase.
func (c *Client) loadIdentityFile() (ssh.Signer, error) {
	// Find identity file
	identityFile, err := expandHomeDir(c.config.SshConfig.IdentityFile)
	if err != nil {
		return nil, fmt.Errorf("failed to expand identity file path: %w", err)
	}
	if c.debug {
		log.Println("Using identity file:", identityFile)
	}
	// Read identity file
	key, err := readFile(identityFile)
	if err != nil {
		return nil, err
	}

	// Parse private key
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		var passphraseMissingError *ssh.PassphraseMissingError
		if errors.As(err, &passphraseMissingError) {
			if c.debug {
				log.Println("Private key requires passphrase")
			}
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return nil, fmt.Errorf("cannot prompt for passphrase: stdin is not a terminal (TTY)")
			}
			fmt.Print("Passphrase: ")
			input, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return nil, fmt.Errorf("failed to read passphrase from terminal: %w", err)
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(input))
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key with provided passphrase: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to parse private key from %s: %w", identityFile, err)
		}
	}
	return signer, nil
}

// getAgentSigners retrieves the list of available SSH signers from the SSH agent.
// If the SSH agent is not running or cannot be accessed, it returns nil without an error.
// Returns an error if there is an issue connecting to the agent.
func getAgentSigners() ([]ssh.Signer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil // No agent running
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	ag := agent.NewClient(conn)
	return ag.Signers()
}

// Connect establishes an SSH connection over the configured tunnel, sets up port forwarding and session recording if enabled.
// It handles authentication using identity files and SSH agents, verifies host keys, and manages terminal I/O.
// The function returns an error if the connection or session setup fails.
func (c *Client) Connect(outputWriter io.Writer) error {
	identitySigner, err := c.loadIdentityFile()
	if err != nil {
		if c.debug {
			log.Println("Failed to load identity file:", err)
		}
		// Only return an error if no agent signers are available
		agentSigners, agentErr := getAgentSigners()
		if agentErr != nil || len(agentSigners) == 0 {
			return fmt.Errorf("failed to load identity file and no SSH agent available: %w", err)
		}
	}

	if c.debug && identitySigner != nil {
		log.Println("Successfully loaded identity file")
	}

	agentSigners, err := getAgentSigners()
	if err != nil {
		return fmt.Errorf("failed to get agent signers: %w", err)
	}
	var signers []ssh.Signer
	if len(agentSigners) > 0 {
		signers = append(signers, agentSigners...)
	}
	if identitySigner != nil {
		signers = append(signers, identitySigner)
	}
	authMethod := ssh.PublicKeys(signers...)

	// Create SSH client config
	clientConfig := &ssh.ClientConfig{
		User: c.config.SshConfig.User,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if c.config.SshConfig.HostKey == nil {
				keyString := string(ssh.MarshalAuthorizedKey(key))
				keyFingerprint := ssh.FingerprintSHA256(key)

				fmt.Printf("\nWarning: No HostKey configured for %s\n", hostname)
				fmt.Printf("The authenticity of host '%s (%s)' can't be established.\n", hostname, remote.String())
				fmt.Printf("SSH key fingerprint is %s\n", keyFingerprint)
				fmt.Printf("SSH key: %s\n", strings.TrimSpace(keyString))
				fmt.Print("\nAre you sure you want to continue connecting (yes/no)? ")

				var response string
				fmt.Scanln(&response)
				response = strings.ToLower(strings.TrimSpace(response))

				if response == "yes" {
					fmt.Println("\nWarning: Accepting and trusting remote host key for this session only.")
					fmt.Println("To permanently trust this host, add the following to your wiressh_config file:")
					fmt.Printf("  HostKey %s\n", strings.TrimSpace(keyString))
					return nil
				}
				return fmt.Errorf("connection aborted by user (host key not accepted)")
			}

			err := ssh.FixedHostKey(c.config.SshConfig.HostKey)(hostname, remote, key)
			if err != nil {
				keyString := string(ssh.MarshalAuthorizedKey(key))
				keyFingerprint := ssh.FingerprintSHA256(key)
				configuredFingerprint := ssh.FingerprintSHA256(c.config.SshConfig.HostKey)

				fmt.Printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
				fmt.Printf("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n")
				fmt.Printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
				fmt.Printf("The host key for '%s' has changed!\n", hostname)
				fmt.Printf("Expected: %s\n", configuredFingerprint)
				fmt.Printf("Got:      %s\n", keyFingerprint)
				fmt.Printf("\nThis could indicate a man-in-the-middle attack, or the host key might have legitimately changed.\n")
				fmt.Printf("To update the host key, edit your wiressh_config file and replace the HostKey with:\n")
				fmt.Printf("  HostKey %s\n", strings.TrimSpace(keyString))

				return fmt.Errorf("connection aborted (host key mismatch)")
			}
			return nil
		},
		Timeout: c.config.SshConfig.Timeout,
	}

	// Start tunnel network
	tunnelNetwork, err := c.StartTunnelNetwork()
	if err != nil {
		return fmt.Errorf("failed to start tunnel network: %w", err)
	}

	// Variables for port forwarding cleanup
	var (
		listener net.Listener
		wg       *sync.WaitGroup
	)

	if c.debug {
		log.Printf("Connecting to SSH server %s:%s as user %s", c.config.SshConfig.HostName, c.config.SshConfig.Port, c.config.SshConfig.User)
	}

	addr := net.JoinHostPort(c.config.SshConfig.HostName, c.config.SshConfig.Port)
	// Dial the connection over the tunnel network
	conn, err := tunnelNetwork.DialTimeout(c.config.SshConfig.HostName, c.config.SshConfig.Port, c.config.SshConfig.Timeout)
	if err != nil {
		return fmt.Errorf("failed to dial SSH server: %w", err)
	}
	defer conn.Close()

	// Create SSH client connection
	sshConnection, chans, reqs, err := ssh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		return fmt.Errorf("failed to create SSH client connection: %w", err)
	}
	defer sshConnection.Close()

	// Create SSH client
	client := ssh.NewClient(sshConnection, chans, reqs)
	defer client.Close()

	if c.debug {
		log.Println("SSH connection established")
	}

	// Create session
	session, err := client.NewSession()
	if err != nil {
		// Session creation failed
		return fmt.Errorf("failed to create new SSH session: %w", err)
	}
	defer session.Close()

	// Create a context for managing the lifecycle of all goroutines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up port forwarding if specified
	if c.config.SshConfig.LocalForward != "" {
		pf, err := parsePortForward(c.config.SshConfig.LocalForward)
		if err != nil {
			return fmt.Errorf("invalid local port forwarding: %w", err)
		}
		if c.debug {
			log.Printf("Setting up local port forwarding: %s:%s -> %s:%s", pf.BindAddress, pf.Port, pf.Host, pf.HostPort)
		}
		listener, err = net.Listen("tcp", net.JoinHostPort(pf.BindAddress, pf.Port))
		if err != nil {
			return fmt.Errorf("failed to listen on local port: %w", err)
		}

		wg = &sync.WaitGroup{}

		// Start the forwarding goroutine
		go func() {
			defer listener.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
					localConn, err := listener.Accept()
					if err != nil {
						if err, ok := err.(net.Error); ok && err.Timeout() {
							continue
						}
						if c.debug && !errors.Is(err, net.ErrClosed) {
							log.Printf("Error accepting local connection: %v", err)
						}
						if !errors.Is(err, net.ErrClosed) {
							continue
						}
						return
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						c.handleLocalForward(localConn, client, pf)
					}()
				}
			}
		}()
	}

	// Set up unified signal handler for graceful shutdown
	signalHandler := signal.NewHandler(func() error {
		// Cancel context to stop accepting new connections (port forwarding)
		cancel()
		// Close the listener and wait for active connections if port forwarding is active
		if listener != nil {
			listener.Close()
			if wg != nil {
				wg.Wait()
			}
		}
		// Close the SSH session
		session.Close()
		// Stop the tunnel
		return tunnelNetwork.Stop()
	})
	signalHandler.Start()
	defer tunnelNetwork.Stop()

	// Set up terminal
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("failed to set terminal to raw mode: %w", err)
	}
	defer term.Restore(fd, oldState)

	// Get terminal size
	w, h, err := term.GetSize(fd)
	if err != nil {
		w, h = 80, 40
	}

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	// Request PTY
	if err := session.RequestPty("xterm", h, w, modes); err != nil {
		return fmt.Errorf("failed to request PTY for terminal session: %w", err)
	}

	// Set up I/O with recording/sharing if enabled
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe for session: %w", err)
	}

	go func() {
		_, _ = io.Copy(stdin, os.Stdin)
	}()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe for session: %w", err)
	}

	go func() {
		var output io.Reader = stdout
		if outputWriter != nil {
			output = io.TeeReader(output, outputWriter)
		}
		_, _ = io.Copy(os.Stdout, output)
	}()

	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe for session: %w", err)
	}

	go func() {
		var output io.Reader = stderr
		if outputWriter != nil {
			output = io.TeeReader(output, outputWriter)
		}
		_, _ = io.Copy(os.Stderr, output)
	}()

	// Handle terminal resizing
	go func() {
		resizeTicker := time.NewTicker(100 * time.Millisecond)
		defer resizeTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-resizeTicker.C:
				newW, newH, err := term.GetSize(fd)
				if err != nil {
					continue
				}
				if newW != w || newH != h {
					_ = session.WindowChange(newH, newW)
					w, h = newW, newH
				}
			}
		}
	}()

	// Start shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell session: %w", err)
	}

	// Wait for session to complete
	if err := session.Wait(); err != nil {
		return fmt.Errorf("session terminated with error: %w", err)
	}
	return nil
}
