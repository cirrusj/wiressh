package recorder

import (
	"os"
	"testing"
)

func TestRecorder_NewRecorderAndClose(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "recorder_test_*.cast")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	filename := tmpfile.Name()
	tmpfile.Close()
	defer os.Remove(filename)

	r, err := NewRecorder(filename, 80, 24, "xterm", "test session")
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
	if _, err := os.Stat(filename); err != nil {
		t.Errorf("Recorder file not created: %v", err)
	}
}

func TestRecorder_WriteOutputAndInput(t *testing.T) {
	r, err := NewRecorder(os.DevNull, 80, 24, "xterm", "test session")
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}
	defer r.Close()

	if err := r.WriteOutput([]byte("output test")); err != nil {
		t.Errorf("WriteOutput failed: %v", err)
	}
	if err := r.WriteInput([]byte("input test")); err != nil {
		t.Errorf("WriteInput failed: %v", err)
	}
}
