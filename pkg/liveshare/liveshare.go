package liveshare

import (
	"log"
	"net/http"
)

var (
	// Global server instance
	server *Server
)

// Start initializes and starts the live sharing server in a goroutine
func Start(addr string, debug bool) (*Server, error) {
	// Generate a secure random password
	password, err := generateRandomPassword()
	if err != nil {
		return nil, err
	}

	server = NewServer(addr, debug, password)

	// Start the server in a goroutine
	go func() {
		err := server.Start()
		if err != nil && err != http.ErrServerClosed {
			log.Printf("Error starting live sharing server: %v", err)
		}
	}()

	return server, nil
}

// Stop shuts down the live sharing server
func Stop() error {
	if server != nil {
		return server.Stop()
	}
	return nil
}
