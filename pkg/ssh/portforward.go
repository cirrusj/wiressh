package ssh

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

// PortForward represents a port forwarding configuration
type PortForward struct {
	BindAddress string
	Port        string
	Host        string
	HostPort    string
}

// parsePortForward parses a port forwarding string into a PortForward struct
func parsePortForward(forward string) (*PortForward, error) {
	parts := strings.Split(forward, ":")
	if len(parts) < 3 || len(parts) > 4 {
		return nil, fmt.Errorf("invalid port forwarding format: %s", forward)
	}

	pf := &PortForward{}
	if len(parts) == 4 {
		pf.BindAddress = parts[0]
		pf.Port = parts[1]
		pf.Host = parts[2]
		pf.HostPort = parts[3]
	} else {
		pf.BindAddress = "127.0.0.1"
		pf.Port = parts[0]
		pf.Host = parts[1]
		pf.HostPort = parts[2]
	}

	return pf, nil
}

// dialer is an interface for types that can dial network connections (used for SSH client abstraction)
type dialer interface {
	Dial(network, addr string) (net.Conn, error)
}

// handleLocalForward handles a single local port forwarding connection
func (c *Client) handleLocalForward(localConn net.Conn, client dialer, pf *PortForward) {
	defer localConn.Close()

	remoteConn, err := client.Dial("tcp", net.JoinHostPort(pf.Host, pf.HostPort))
	if err != nil {
		if c.debug {
			log.Printf("Error dialing remote host: %v", err)
		}
		return
	}
	defer remoteConn.Close()

	// Copy data between connections
	done := make(chan struct{})
	go func() {
		io.Copy(remoteConn, localConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(localConn, remoteConn)
		done <- struct{}{}
	}()

	// Wait for both copy operations to complete
	<-done
	<-done
}
