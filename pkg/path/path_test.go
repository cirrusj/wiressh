package path

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home directory: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name:    "no tilde",
			path:    "/absolute/path",
			want:    "/absolute/path",
			wantErr: false,
		},
		{
			name:    "tilde expansion",
			path:    "~/test/path",
			want:    filepath.Join(home, "test/path"),
			wantErr: false,
		},
		{
			name:    "tilde only",
			path:    "~",
			want:    "~",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			want:    "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandHomeDir(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandHomeDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExpandHomeDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMustExpandHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home directory: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		want      string
		wantPanic bool
	}{
		{
			name:      "no tilde",
			path:      "/absolute/path",
			want:      "/absolute/path",
			wantPanic: false,
		},
		{
			name:      "tilde expansion",
			path:      "~/test/path",
			want:      filepath.Join(home, "test/path"),
			wantPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Error("MustExpandHomeDir() did not panic")
					}
				}()
			}

			got := MustExpandHomeDir(tt.path)
			if got != tt.want {
				t.Errorf("MustExpandHomeDir() = %v, want %v", got, tt.want)
			}
		})
	}
}
