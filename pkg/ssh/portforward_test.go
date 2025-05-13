package ssh

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// TestParsePortForward covers valid and invalid port forwarding strings
func TestParsePortForward(t *testing.T) {
	tests := []struct {
		input   string
		expect  *PortForward
		wantErr bool
	}{
		{"8080:remotehost:80", &PortForward{"127.0.0.1", "8080", "remotehost", "80"}, false},
		{"0.0.0.0:2222:host:22", &PortForward{"0.0.0.0", "2222", "host", "22"}, false},
		{"badformat", nil, true},
		{"1:2", nil, true},
		{"a:b:c:d:e", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pf, err := parsePortForward(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePortForward() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && pf != nil && tt.expect != nil {
				if *pf != *tt.expect {
					t.Errorf("ParsePortForward() = %+v, want %+v", pf, tt.expect)
				}
			}
		})
	}
}

// fakeSSHClient mocks ssh.Client for handleLocalForward testing
type fakeSSHClient struct {
	DialFunc func(network, addr string) (net.Conn, error)
}

func (f *fakeSSHClient) Dial(network, addr string) (net.Conn, error) {
	return f.DialFunc(network, addr)
}

// mockConn is a minimal net.Conn for testing close
type mockConn struct {
	closeFunc func() error
}

func (m *mockConn) Read(b []byte) (n int, err error)             { return 0, io.EOF }
func (m *mockConn) Write(b []byte) (n int, err error)            { return len(b), nil }
func (m *mockConn) Close() error                                 { return m.closeFunc() }
func (m *mockConn) LocalAddr() net.Addr                          { return nil }
func (m *mockConn) RemoteAddr() net.Addr                         { return nil }
func (m *mockConn) SetDeadline(t time.Time) error                { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error            { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error           { return nil }

func TestHandleLocalForward_DialError(t *testing.T) {
	client := &Client{debug: true}
	localConnClosed := false
	localConn := &mockConn{closeFunc: func() error { localConnClosed = true; return nil }}
	sshClient := &fakeSSHClient{
		DialFunc: func(network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("dial error")
		},
	}
	pf := &PortForward{Host: "host", HostPort: "22"}
	client.handleLocalForward(localConn, sshClient, pf)
	if !localConnClosed {
		t.Error("localConn should be closed on dial error")
	}
}

func TestHandleLocalForward_DataCopy(t *testing.T) {
	client := &Client{debug: true}
	localConnClosed := false
	remoteConnClosed := false

	// Create a pipe for local connection
	localReader, localWriter := io.Pipe()
	localConn := &mockConn{
		closeFunc: func() error {
			localConnClosed = true
			localReader.Close()
			localWriter.Close()
			return nil
		},
	}

	// Create a pipe for remote connection
	remoteReader, remoteWriter := io.Pipe()
	remoteConn := &mockConn{
		closeFunc: func() error {
			remoteConnClosed = true
			remoteReader.Close()
			remoteWriter.Close()
			return nil
		},
	}

	sshClient := &fakeSSHClient{
		DialFunc: func(network, addr string) (net.Conn, error) {
			return remoteConn, nil
		},
	}

	pf := &PortForward{Host: "host", HostPort: "22"}

	done := make(chan struct{})
	go func() {
		client.handleLocalForward(localConn, sshClient, pf)
		done <- struct{}{}
	}()

	// Close both ends to trigger cleanup
	localConn.Close()
	remoteConn.Close()

	<-done

	if !localConnClosed {
		t.Error("localConn should be closed")
	}
	if !remoteConnClosed {
		t.Error("remoteConn should be closed")
	}
}
