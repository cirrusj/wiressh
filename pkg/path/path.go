package path

import (
	"os"
	"path/filepath"
	"strings"
)

// ExpandHomeDir expands paths that start with "~/" to the user's home directory
func ExpandHomeDir(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, path[2:]), nil
}

// MustExpandHomeDir is like ExpandHomeDir but panics if there is an error.
// Use with caution: this function will terminate the program if path expansion fails.
func MustExpandHomeDir(path string) string {
	expanded, err := ExpandHomeDir(path)
	if err != nil {
		panic(err)
	}
	return expanded
}
