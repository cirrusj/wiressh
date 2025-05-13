package path

import (
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// randomString generates a random string of a given length
func randomString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

// GetConfigDir returns the config directory based on the user's config directory
func GetConfigDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tsnet-wiressh", randomString(8)), nil
}

// CreateConfigDir creates the config directory
func CreateConfigDir(debug bool) (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	if debug {
		log.Println("Created config directory:", dir)
	}
	return dir, nil
}
