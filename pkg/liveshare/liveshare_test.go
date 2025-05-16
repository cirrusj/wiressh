package liveshare

import (
	"io"
	"testing"
	"time"
)

func TestStartAndStop(t *testing.T) {
	// Use port 0 to let the OS pick an available port
	writer, err := Start("127.0.0.1:0", true)
	if err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	if writer == nil {
		t.Fatalf("Start() returned nil writer")
	}

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Test that writer implements io.Writer
	_, err = writer.Write([]byte("test data"))
	if err != nil && err != io.EOF {
		// Accept io.EOF as some writers may return it
		t.Errorf("Writer.Write returned unexpected error: %v", err)
	}

	// Stop the server
	err = Stop()
	if err != nil {
		t.Errorf("Stop() returned error: %v", err)
	}
}

func TestStartTwice(t *testing.T) {
	_, err := Start("127.0.0.1:0", false)
	if err != nil {
		t.Fatalf("First Start() returned error: %v", err)
	}
	_, err = Start("127.0.0.1:0", false)
	if err != nil {
		t.Errorf("Second Start() returned error: %v", err)
	}
	_ = Stop()
}

func TestStopWithoutStart(t *testing.T) {
	// Should not panic or error
	err := Stop()
	if err != nil {
		t.Errorf("Stop() without Start returned error: %v", err)
	}
}
