package direct

import (
	"testing"
	"time"
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

func TestManager_Start_Stop(t *testing.T) {
	mgr := NewManager(false)
	if err := mgr.Start(nil); err != nil {
		t.Errorf("Start failed: %v", err)
	}
	if err := mgr.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

func TestManager_Dial_DialTimeout(t *testing.T) {
	mgr := NewManager(false)
	// Use localhost and a closed port to ensure error but no panic
	_, err := mgr.Dial("127.0.0.1", "65000")
	if err == nil {
		t.Error("Dial should fail for closed port")
	}
	_, err = mgr.DialTimeout("127.0.0.1", "65000", 100*time.Millisecond)
	if err == nil {
		t.Error("DialTimeout should fail for closed port")
	}
}
