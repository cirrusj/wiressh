package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cirrusj/wiressh/pkg/config"
	"github.com/cirrusj/wiressh/pkg/liveshare"
	"github.com/cirrusj/wiressh/pkg/recorder"
	"github.com/cirrusj/wiressh/pkg/ssh"
	"golang.org/x/term"
)

type colorFunc func(string) string

// getColorFuncs returns two functions that can be used to color strings
// red or yellow, depending on whether the stderr is a tty or not.
func getColorFuncs() (colorFunc, colorFunc) {
	isatty := term.IsTerminal(int(os.Stderr.Fd()))

	red := func(s string) string {
		if isatty {
			return "\033[31m" + s + "\033[0m"
		}
		return s
	}

	yellow := func(s string) string {
		if isatty {
			return "\033[33m" + s + "\033[0m"
		}
		return s
	}

	return red, yellow
}

// printUsage prints the usage message for wiressh.
//
// It takes a single argument, the name of the program (usually the result of
// filepath.Base(os.Args[0])), and prints a usage message to os.Stderr.
//
// The message includes the program name, a description of wiressh, usage
// information, available flags, examples, and a link to the wiressh GitHub
// page for more information.
func printUsage(progname string) {
	fmt.Fprintf(os.Stderr, `
wiressh - Simple SSH client with WireGuard and Tailscale tunnel support

Usage:
  %s [flags] host

Flags:
  -c string   Path to WireGuard configuration file (default "~/.ssh/wiressh_config")
  -d          Enable debug logging
  -l          Enable debug logging for the tunnel
  -t int      Connection timeout in seconds (default 15)
  -f          Print the configuration file format help
  -r string   Path to record file (asciicast v2 format)
  -s string   Enable live sharing on specified address (for example "127.0.0.1:9999")

Examples:
  wiressh myserver
  wiressh -r session.cast myserver
  wiressh -d -c ~/.ssh/custom_config myserver
  wiressh -s 127.0.0.1:9999 myserver

For more information, see: https://github.com/cirrusj/wiressh
`, progname)
}

func main() {
	progname := filepath.Base(os.Args[0])
	red, yellow := getColorFuncs()

	// Parse command line arguments
	wireSshConfigFile := flag.String("c", "~/.ssh/wiressh_config", "Path to WireGuard configuration file")
	recordFile := flag.String("r", "", "Path to record file (asciicast v2 format)")
	debug := flag.Bool("d", false, "Enable debug logging")
	debugTunnel := flag.Bool("l", false, "Enable debug logging for the tunnel")
	timeout := flag.Int("t", 15, "Connection timeout in seconds")
	printConfigHelp := flag.Bool("f", false, "Print the configuration file format help")
	liveShareAddr := flag.String("s", "", "Enable live sharing on specified address")
	flag.Usage = func() { printUsage(progname) }
	flag.Parse()

	if *debug {
		fmt.Fprintln(os.Stderr, red("WARNING: Debug mode enabled. This may expose sensitive information in logs."))
		fmt.Fprintln(os.Stderr, yellow("Do not share these logs with others as they may contain private keys and credentials."))
	}

	if *printConfigHelp {
		printConfigFormatHelp()
		os.Exit(0)
	}

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, red("Error: Missing host argument."))
		flag.Usage()
		os.Exit(1)
	}
	host := flag.Arg(0)

	if err := validateRecordingFile(*recordFile, *debug); err != nil {
		fmt.Fprintln(os.Stderr, red(err.Error()))
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(host, *wireSshConfigFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, red(fmt.Sprintf("Error loading configuration: %v", err)))
		os.Exit(1)
	}

	// Override the default timeout if specified via command line
	if *timeout != 15 { // Only override if different from default
		cfg.SshConfig.Timeout = time.Duration(*timeout) * time.Second
	}

	if *debug {
		logConfig(cfg)
	}

	// Initialize the SSH client
	client := ssh.NewClient(cfg, *debug, *debugTunnel)

	// Set up live sharing and recording writers
	var writers []io.Writer
	if *recordFile != "" {
		w, h := 80, 40
		if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
			if tw, th, err := term.GetSize(fd); err == nil {
				w, h = tw, th
			}
		}
		rec, err := recorder.NewRecorder(*recordFile, w, h, "xterm", fmt.Sprintf("wiressh session to %s", cfg.SshConfig.HostName))
		if err != nil {
			fmt.Fprintln(os.Stderr, red(fmt.Sprintf("Error initializing session recorder: %v", err)))
			os.Exit(1)
		}
		writers = append(writers, rec)
		defer rec.Close()
	}
	var liveShareWriter io.Writer
	if *liveShareAddr != "" {
		fmt.Printf("Live sharing enabled on http://%s\n", *liveShareAddr)
		var err error
		liveShareWriter, err = liveshare.Start(*liveShareAddr, *debug)
		if err != nil {
			fmt.Fprintln(os.Stderr, red(fmt.Sprintf("Error starting live sharing server: %v", err)))
			os.Exit(1)
		}
		writers = append(writers, liveShareWriter)
		defer liveshare.Stop()
	}

	var outputWriter io.Writer
	if len(writers) == 1 {
		outputWriter = writers[0]
	} else if len(writers) > 1 {
		outputWriter = io.MultiWriter(writers...)
	} else {
		outputWriter = nil
	}
	// Connect to the SSH server with optional recording/live sharing
	if err := client.Connect(outputWriter); err != nil {
		fmt.Fprintln(os.Stderr, red(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	if *debug {
		logSessionEnd(host, *recordFile, yellow)
	}
}

// printConfigFormatHelp prints the wiressh config file format to stdout.
func printConfigFormatHelp() {
	fmt.Println("wiressh config file format (similar to ssh_config):")
	fmt.Println("Host <pattern>")
	fmt.Println("  Type           wireguard | tailscale | direct (required)")
	fmt.Println("  Hostname       Hostname of the server (optional, overrides host argument)")
	fmt.Println("  User           Username to connect as (optional, defaults to current user)")
	fmt.Println("  Port           Port to connect to (optional, defaults to 22)")
	fmt.Println("  IdentityFile   Path to the private key file (optional, defaults to ~/.ssh/id_rsa)")
	fmt.Println("  HostKey        Remote server host key (optional, if not provided the remote server host key will be printed and the user will be asked if they want to continue)")
	fmt.Println("  LocalForward   Configure an SSH LocalForward (optional, see ssh_config for more details)")
	fmt.Println("\n# WireGuard-specific:")
	fmt.Println("  PrivateKey     WireGuard private key (required)")
	fmt.Println("  PublicKey      WireGuard public key (required)")
	fmt.Println("  PresharedKey   WireGuard preshared key (optional)")
	fmt.Println("  AllowedIP      WireGuard allowed IP (optional, defaults to 0.0.0.0/0)")
	fmt.Println("  WGServer       WireGuard server formatted as host:port (required)")
	fmt.Println("  IPAddress      IP address to bind the WireGuard tunnel to (required)")
	fmt.Println("  DNSServer      DNS server to use for the WireGuard tunnel (required)")
	fmt.Println("\n# Tailscale-specific:")
	fmt.Println("  AuthKey        Tailscale auth key (required)")
}

// validateRecordingFile validates the recording file, if specified, and returns an error if the file already exists.
// If debug is true, it will log the recording file name.
func validateRecordingFile(recordFile string, debug bool) error {
	if recordFile == "" {
		return nil
	}

	if _, err := os.Stat(recordFile); err == nil {
		return fmt.Errorf("the recording file '%s' already exists. Please choose a different file name or remove the existing file", recordFile)
	}

	if debug {
		log.Println("Recording to:", recordFile)
	}

	return nil
}

// logConfig logs the configuration, with private keys redacted for security.
func logConfig(cfg *config.WireSshConfig) {
	cfgForLog := *cfg
	if cfgForLog.WireguardConfig.PrivateKey != "" {
		cfgForLog.WireguardConfig.PrivateKey = "[REDACTED]"
	}
	if cfgForLog.WireguardConfig.PublicKey != "" {
		cfgForLog.WireguardConfig.PublicKey = "[REDACTED]"
	}
	if cfgForLog.WireguardConfig.PresharedKey != "" {
		cfgForLog.WireguardConfig.PresharedKey = "[REDACTED]"
	}
	if cfgForLog.TailscaleConfig.AuthKey != "" {
		cfgForLog.TailscaleConfig.AuthKey = "[REDACTED]"
	}
	log.Printf("Configuration (keys redacted): %+v\n", cfgForLog)
}

// logSessionEnd logs a message indicating the end of a session, including the host and recording file (if specified).
// The message is printed to stderr and colored yellow.
func logSessionEnd(host, recordFile string, yellow colorFunc) {
	msg := "Session ended. SSH connection to " + host + " closed."
	if recordFile != "" {
		msg += " Session recorded to " + recordFile + "."
	}
	fmt.Fprintln(os.Stderr, yellow(msg))
}
