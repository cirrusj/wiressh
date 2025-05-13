package signal

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestHandler_CleanupCalledOnSIGINT(t *testing.T) {
	called := false
	h := NewHandler(func() error {
		called = true
		return nil
	})
	h.setExitFunc(func(int) {}) // prevent os.Exit in test
	h.Start()

	// Send SIGINT
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(syscall.SIGINT)

	time.Sleep(100 * time.Millisecond)
	if !called {
		t.Error("cleanup function was not called on SIGINT")
	}
}

func TestHandler_CleanupCalledOnSIGTERM(t *testing.T) {
	called := false
	h := NewHandler(func() error {
		called = true
		return nil
	})
	h.setExitFunc(func(int) {}) // prevent os.Exit in test
	h.Start()

	// Send SIGTERM
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(syscall.SIGTERM)

	time.Sleep(100 * time.Millisecond)
	if !called {
		t.Error("cleanup function was not called on SIGTERM")
	}
}
