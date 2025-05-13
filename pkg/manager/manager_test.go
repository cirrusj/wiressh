package manager

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cirrusj/wiressh/pkg/config"
)

type mockManager struct {
	startCalled       bool
	stopCalled        bool
	dialCalled        bool
	dialTimeoutCalled bool
}

func (m *mockManager) Start(cfg *config.WireSshConfig) error {
	m.startCalled = true
	return nil
}
func (m *mockManager) Stop() error {
	m.stopCalled = true
	return nil
}
func (m *mockManager) Dial(addr string, port string) (net.Conn, error) {
	m.dialCalled = true
	return nil, errors.New("mock dial")
}
func (m *mockManager) DialTimeout(addr string, port string, timeout time.Duration) (net.Conn, error) {
	m.dialTimeoutCalled = true
	return nil, errors.New("mock dialtimeout")
}

func TestManagerInterface(t *testing.T) {
	var m Manager = &mockManager{}
	_ = m.Start(nil)
	_ = m.Stop()
	_, _ = m.Dial("host", "22")
	_, _ = m.DialTimeout("host", "22", time.Second)

	mm := m.(*mockManager)
	if !mm.startCalled {
		t.Error("Start was not called")
	}
	if !mm.stopCalled {
		t.Error("Stop was not called")
	}
	if !mm.dialCalled {
		t.Error("Dial was not called")
	}
	if !mm.dialTimeoutCalled {
		t.Error("DialTimeout was not called")
	}
}
