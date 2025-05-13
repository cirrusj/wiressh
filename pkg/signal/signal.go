package signal

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// Handler handles OS signals and executes cleanup function
// exit is a function called to exit the process (defaults to os.Exit, can be overridden for testing)
type Handler struct {
	cleanup func() error
	exit    func(int)
}

// NewHandler creates a new signal handler
func NewHandler(cleanup func() error) *Handler {
	return &Handler{
		cleanup: cleanup,
		exit:    os.Exit,
	}
}

// setExitFunc allows tests to override the exit behavior
func (h *Handler) setExitFunc(f func(int)) {
	h.exit = f
}

// Start starts the signal handler
func (h *Handler) Start() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received shutdown signal, cleaning up...")
		if h.cleanup != nil {
			if err := h.cleanup(); err != nil {
				log.Printf("Warning: Cleanup failed: %v", err)
			}
		}
		h.exit(0)
	}()
}
