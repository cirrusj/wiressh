package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/cirrusj/wiressh/recorder"
	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	debug      bool
	recordFile string
)

func main() {
	// Parse arguments
	progname := filepath.Base(os.Args[0])
	var wireConfigFile string
	var sshConfigFile string
	var sshKnownHosts string
	flag.StringVar(&wireConfigFile, "c", "~/.ssh/wiressh_config", "wiressh config")
	flag.StringVar(&sshConfigFile, "s", "~/.ssh/config", "SSH config")
	flag.StringVar(&sshKnownHosts, "k", "~/.ssh/known_hosts", "SSH known hosts")
	flag.StringVar(&recordFile, "r", "", "Record session to file (asciicast v2 format)")
	flag.BoolVar(&debug, "d", false, "Debug")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, `Usage of %s:
	%s [flags] host
Flags:
`, progname, progname)
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		// log.Fatalln("Missing host argument")
		fmt.Println("Missing host argument")
		flag.Usage()
		os.Exit(1)
	}
	host := flag.Arg(0)
	if debug {
		log.Println("Host:", host)
	}

	// Check if recording file exists
	if recordFile != "" {
		if _, err := os.Stat(recordFile); err == nil {
			log.Fatalf("Recording file %s already exists", recordFile)
		}
	}

	if debug {
		log.Println("Config:", wireConfigFile)
	}
	if strings.HasPrefix(wireConfigFile, "~/") {
		home, _ := os.UserHomeDir()
		wireConfigFile = filepath.Join(home, wireConfigFile[2:])
	}
	// Read wiressh config
	wireConfigRead, err := os.Open(wireConfigFile)
	if err != nil {
		log.Fatalf("Failed to load wireguard config: %s", err)
	}
	wireConfig, err := ssh_config.Decode(wireConfigRead)
	if err != nil {
		log.Fatalf("Failed to parse wireguard config: %s", err)
	}
	privateKey, err := wireConfig.Get(host, "PrivateKey")
	if err != nil {
		log.Fatalf("Failed to get PrivateKey for %s: %s", host, err)
	}
	if privateKey == "" {
		log.Fatalf("PrivateKey for host %s not found in %s", host, wireConfigFile)
	}
	privateKey, _ = EncodeBase64ToHex(privateKey)
	if debug {
		log.Println("PrivateKey:", privateKey)
	}
	publicKey, err := wireConfig.Get(host, "PublicKey")
	if err != nil {
		log.Fatalf("Failed to get PublicKey for %s: %s", host, err)
	}
	if publicKey == "" {
		log.Fatalf("PublicKey for host %s not found in %s", host, wireConfigFile)
	}
	publicKey, _ = EncodeBase64ToHex(publicKey)
	if debug {
		log.Println("PublicKey:", publicKey)
	}
	presharedKey, _ := wireConfig.Get(host, "PresharedKey")
	if presharedKey != "" {
		presharedKey, _ = EncodeBase64ToHex(presharedKey)
		if debug {
			log.Println("PresharedKey:", presharedKey)
		}
	}
	ipAddressString, err := wireConfig.Get(host, "IPAddress")
	if err != nil {
		log.Fatalf("Failed to get IPAddress for %s: %s", host, err)
	}
	if ipAddressString == "" {
		log.Fatalf("IPAddress for host %s not found in %s", host, wireConfigFile)
	}
	ipAddress, err := netip.ParseAddr(ipAddressString)
	if err != nil {
		log.Fatalf("Failed to parse IPAddress for %s: %v", host, err)
	}
	if debug {
		log.Println("IPAddress:", ipAddress)
	}
	dnsServerString, err := wireConfig.Get(host, "DNSServer")
	if err != nil {
		log.Fatalf("Failed to get DNSServer for %s: %s", host, err)
	}
	if dnsServerString == "" {
		log.Fatalf("DNSServer for host %s not found in %s", host, wireConfigFile)
	}
	dnsServer, err := netip.ParseAddr(dnsServerString)
	if err != nil {
		log.Fatalf("Failed to parse DNSServer for %s: %v", host, err)
	}
	if debug {
		log.Println("DNSServer:", dnsServer)
	}
	allowedIP, err := wireConfig.Get(host, "AllowedIP")
	if err != nil {
		log.Fatalf("Failed to get AllowedIP for %s: %s", host, err)
	}
	if allowedIP == "" {
		allowedIP = "0.0.0.0/0"
	}
	if debug {
		log.Println("AllowedIP:", allowedIP)
	}
	wgServerPort, err := wireConfig.Get(host, "WGServer")
	if err != nil {
		log.Fatalf("Failed to get WGServer for %s: %s", host, err)
	}
	if wgServerPort == "" {
		log.Fatalf("WGServer for host %s not found in %s", host, wireConfigFile)
	}
	if debug {
		log.Println("WGServer:", wgServerPort)
	}
	wgServerString, wgPort, err := net.SplitHostPort(wgServerPort)
	if err != nil {
		log.Fatalf("Failed to parse WGServer: %s", err)
	}
	wgServerIPs, err := net.LookupIP(wgServerString)
	if err != nil {
		log.Fatalf("Could not resolve host: %v\n", err)
	}
	var wgServer net.IP
	if len(wgServerIPs) == 1 {
		wgServer = wgServerIPs[0]
	} else {
		log.Fatalf("Host resolves to multiple IPs: %s\n", wgServerIPs)
	}
	if debug {
		log.Println("wgServer:", wgServer)
		log.Println("wgPort:", wgPort)
	}
	var wgConf string
	if privateKey != "" {
		wgConf = wgConf + fmt.Sprintf("private_key=%s\n", privateKey)
	}
	if publicKey != "" {
		wgConf = wgConf + fmt.Sprintf("public_key=%s\n", publicKey)
	}
	if presharedKey != "" {
		wgConf = wgConf + fmt.Sprintf("preshared_key=%s\n", presharedKey)
	}
	if wgServer != nil && wgPort != "" {
		wgConf = wgConf + fmt.Sprintf("endpoint=%s:%s\n", wgServer, wgPort)
	}
	wgConf = wgConf + fmt.Sprintf("allowed_ip=%s\n", allowedIP)
	if debug {
		log.Println(wgConf)
	}

	// Read SSH config
	if strings.HasPrefix(sshConfigFile, "~/") {
		home, _ := os.UserHomeDir()
		sshConfigFile = filepath.Join(home, sshConfigFile[2:])
	}
	sshConfigRead, err := os.Open(sshConfigFile)
	if err != nil {
		log.Fatalf("Failed to load SSH config: %s", err)
	}
	if debug {
		log.Println("SSH config:", sshConfigFile)
	}
	sshConfig, err := ssh_config.Decode(sshConfigRead)
	if err != nil {
		log.Fatalf("Failed to parse SSH config: %s", err)
	}
	sshUser, err := sshConfig.Get(host, "User")
	if err != nil {
		log.Fatalf("Failed to get ssh User from config: %s", err)
	}
	if sshUser == "" {
		if currentUser, err := user.Current(); err != nil {
			log.Fatalf("Failed to get username: %s", err)
		} else {
			sshUser = currentUser.Username
		}
	}
	if debug {
		log.Println("SSH User:", sshUser)
	}
	sshHostName, err := sshConfig.Get(host, "HostName")
	if err != nil {
		log.Fatalf("Failed to get ssh HostName from config: %s", err)
	}
	if sshHostName == "" {
		sshHostName = host
	}
	if debug {
		log.Println("SSH Host:", sshHostName)
	}
	sshPort, err := sshConfig.Get(host, "Port")
	if err != nil {
		log.Fatalf("Failed to get ssh Port from config: %s", err)
	}
	if sshPort == "" {
		sshPort = "22"
	}
	if debug {
		log.Println("SSH Port:", sshPort)
	}
	sshIdentityFile, err := sshConfig.Get(host, "IdentityFile")
	if err != nil {
		log.Fatalf("Failed to get ssh IdentityFile from config: %s", err)
	}
	if strings.HasPrefix(sshIdentityFile, "~/") {
		home, _ := os.UserHomeDir()
		sshIdentityFile = filepath.Join(home, sshIdentityFile[2:])
	}
	if debug {
		log.Println("SSH IdentityFile:", sshIdentityFile)
	}

	// Start the wg tunnel
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{ipAddress},
		[]netip.Addr{dnsServer},
		1420)
	if err != nil {
		log.Panic(err)
	}
	logLevel := device.LogLevelError
	if debug {
		logLevel = device.LogLevelVerbose
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	err = dev.IpcSet(wgConf)
	if err != nil {
		//		TODO: print an error
		return
	}
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	// Parse the SSH key
	sshKey, err := os.ReadFile(sshIdentityFile)
	if err != nil {
		log.Fatalf("Failed to read IdentityFile: %s", err)
	}
	if debug {
		log.Println("SSH IdentityFile:", sshIdentityFile)
	}
	sshSigner, err := ssh.ParsePrivateKey(sshKey)
	if err != nil {
		var passphraseMissingError *ssh.PassphraseMissingError
		if errors.As(err, &passphraseMissingError) {
			fmt.Print("Passphrase: ")
			input, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				log.Fatalf("Failed to read passphase: %s", err)
			}
			passphrase := strings.TrimSpace(strings.Trim(string(input), "\n"))
			sshSigner, err = ssh.ParsePrivateKeyWithPassphrase(sshKey, []byte(passphrase))
			if err != nil {
				log.Fatalf("Failed to decrypt private key: %s", err)
			}
		}
	}

	if strings.HasPrefix(sshKnownHosts, "~/") {
		home, _ := os.UserHomeDir()
		sshKnownHosts = filepath.Join(home, sshKnownHosts[2:])
	}
	hostKeyCallback, err := knownhosts.New(sshKnownHosts)
	if err != nil {
		log.Fatalf("Could not read known hosts: %s ", err)
	}
	// Configure the SSH client
	sshClientConfig := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(sshSigner),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         5 * time.Second,
	}

	// Connect
	sshConnect(tnet, sshHostName, sshPort, sshClientConfig)
}

func EncodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}

func DialWG(network, addr string, config *ssh.ClientConfig, tnet *netstack.Net) (*ssh.Client, error) {
	// Use wg tnet to dial the connection
	connection, err := tnet.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(connection, addr, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func sshConnect(tnet *netstack.Net, host string, port string, clientConfig *ssh.ClientConfig) {
	// SSH connect
	address := net.JoinHostPort(host, port)
	sshClient, err := DialWG("tcp", address, clientConfig, tnet)
	if err != nil {
		log.Fatal(err)
	}
	defer func(sshClient *ssh.Client) {
		err := sshClient.Close()
		if err != nil {
			log.Println("Error when closing ssh:", err)
		}
	}(sshClient)
	if debug {
		log.Printf("Connected to %s\n", host)
	}
	session, err := sshClient.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer func(session *ssh.Session) {
		err := session.Close()
		if err != nil {
			log.Println("Error when closing session:", err)
		}
	}(session)

	// Configure the pty
	var askTerm string
	switch t := os.Getenv("TERM"); t {
	case "", "xterm-256color":
		askTerm = "xterm-256color"
	case "xterm":
		askTerm = "xterm"
	default:
		askTerm = "xterm-256color"
	}
	if debug {
		log.Println("TERM:", askTerm)
	}

	var rec *recorder.Recorder
	if recordFile != "" {
		w, h, err := term.GetSize(int(os.Stdin.Fd()))
		if err != nil {
			log.Println("Could not get term size. Setting to 80, 40")
			w, h = 80, 40
		}
		rec, err = recorder.NewRecorder(recordFile, w, h, askTerm, fmt.Sprintf("wiressh session to %s", host))
		if err != nil {
			log.Fatalf("Failed to create recorder: %v", err)
		}
		defer rec.Close()
	}

	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		if originalState, err := term.MakeRaw(fd); err != nil {
			log.Println("Fallback")
		} else {
			defer func(fd int, oldState *term.State) {
				err := term.Restore(fd, oldState)
				if err != nil {
					log.Println("Error when restoring term:", err)
				}
			}(fd, originalState)
			w, h, err := term.GetSize(fd)
			if err != nil {
				log.Println("Could not get term size. Setting to 80, 40")
				w, h = 80, 40
			}
			if err := session.RequestPty(askTerm, h, w, ssh.TerminalModes{
				ssh.ECHO: 0,
			}); err != nil {
				log.Fatalf("Request for pseudo terminal failed: %s", err)
			}
			// Resize pty as required
			go func() {
				for {
					_, ok := <-time.After(100 * time.Millisecond)
					if !ok {
						break
					}
					newW, newH, _ := term.GetSize(fd)
					if newW != w || newH != h {
						err := session.WindowChange(h, w)
						if err != nil {
							log.Println("Error when informing remote host of a window size change:", err)
						}
						h = newH
						w = newW
					}
				}
			}()
		}
	}

	// Get data
	stdin, err := session.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if rec != nil {
			// Wrap stdin with recorder
			tee := io.TeeReader(os.Stdin, &recordingWriter{rec: rec, isInput: true})
			_, err := io.Copy(stdin, tee)
			if err != nil {
				log.Println("Error when doing an io.Copy:", err)
			}
		} else {
			_, err := io.Copy(stdin, os.Stdin)
			if err != nil {
				log.Println("Error when doing an io.Copy:", err)
			}
		}
	}()
	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if rec != nil {
			// Wrap stdout with recorder
			tee := io.TeeReader(stdout, &recordingWriter{rec: rec, isInput: false})
			_, err := io.Copy(os.Stdout, tee)
			if err != nil {
				log.Println("Error when doing an io.Copy:", err)
			}
		} else {
			_, err := io.Copy(os.Stdout, stdout)
			if err != nil {
				log.Println("Error when doing an io.Copy:", err)
			}
		}
	}()
	stderr, err := session.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if rec != nil {
			// Wrap stderr with recorder
			tee := io.TeeReader(stderr, &recordingWriter{rec: rec, isInput: false})
			_, err := io.Copy(os.Stderr, tee)
			if err != nil {
				log.Println("Error when doing an io.Copy:", err)
			}
		} else {
			_, err := io.Copy(os.Stderr, stderr)
			if err != nil {
				log.Println("Error when doing an io.Copy:", err)
			}
		}
	}()

	// Start the shell
	if err := session.Shell(); err != nil {
		log.Fatal(err)
	}

	// Wait to complete
	if err := session.Wait(); err != nil {
		log.Fatal(err)
	}
}

// recordingWriter implements io.Writer and writes to the recorder
type recordingWriter struct {
	rec     *recorder.Recorder
	isInput bool
}

func (w *recordingWriter) Write(p []byte) (n int, err error) {
	if w.isInput {
		err = w.rec.WriteInput(p)
	} else {
		err = w.rec.WriteOutput(p)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
