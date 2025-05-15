package liveshare

import (
	"crypto/rand"
	"encoding/base64"
)

// generateRandomPassword creates a secure random password
func generateRandomPassword() (string, error) {
	// Generate 16 random bytes (128 bits)
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	
	// Convert to base64 to make it URL-safe and readable
	return base64.URLEncoding.EncodeToString(b), nil
}
