package liveshare

import (
	"io"
	"log"
)

var (
	// Global server instance
	server *Server
)

// Start initializes and starts the live sharing server in a goroutine
func Start(addr string, debug bool) (io.Writer, string, error) {
	// Generate a secure random password
	password, err := generateRandomPassword()
	if err != nil {
		return nil, "", err
	}

	server = NewServer(addr, debug, password)
	
	// Start the server in a goroutine
	go func() {
		if err := server.Start(); err != nil {
			if debug {
				log.Printf("Live sharing server error: %v", err)
			}
		}
	}()
	
	return server, password, nil
}

// Stop shuts down the live sharing server
func Stop() error {
	if server != nil {
		return server.Stop()
	}
	return nil
}
