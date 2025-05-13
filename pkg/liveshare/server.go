package liveshare

import (
	"context"
	"embed"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed templates
var templateFS embed.FS

// Server represents a live sharing server for SSH sessions
type Server struct {
	addr       string
	clients    map[*websocket.Conn]bool
	broadcast  chan []byte
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mutex      sync.Mutex
	server     *http.Server
	debug      bool
}

// NewServer creates a new live sharing server
func NewServer(addr string, debug bool) *Server {
	if addr == "" {
		addr = "127.0.0.1:9999"
	}
	return &Server{
		addr:       addr,
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
		debug:      debug,
	}
}

// Start initializes and starts the web server
func (s *Server) Start() error {
	// Configure websocket upgrader
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for simplicity
		},
	}

	// Set up HTTP routes
	mux := http.NewServeMux()

	// Serve the main page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFS(templateFS, "templates/index.html")
		if err != nil {
			http.Error(w, "Failed to load template", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	})

	// Handle WebSocket connections
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			if s.debug {
				log.Printf("Failed to upgrade connection: %v", err)
			}
			return
		}

		// Register new client
		s.register <- conn

		// Handle client disconnection
		defer func() {
			s.unregister <- conn
			conn.Close()
		}()

		// Keep connection alive with ping/pong
		conn.SetPingHandler(func(data string) error {
			return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
		})

		// Read loop (we don't actually use messages from clients, but we need to handle them)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	})

	// Create HTTP server
	s.server = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	// Start client handler goroutine
	go s.handleClients()

	// Start server
	return s.server.ListenAndServe()
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

// Write sends data to all connected clients
func (s *Server) Write(p []byte) (n int, err error) {
	s.broadcast <- p
	return len(p), nil
}

// handleClients manages WebSocket client connections and broadcasts
func (s *Server) handleClients() {
	for {
		select {
		case client := <-s.register:
			s.mutex.Lock()
			s.clients[client] = true
			s.mutex.Unlock()
			if s.debug {
				log.Printf("New client connected, total: %d", len(s.clients))
			}

		case client := <-s.unregister:
			s.mutex.Lock()
			delete(s.clients, client)
			s.mutex.Unlock()
			if s.debug {
				log.Printf("Client disconnected, total: %d", len(s.clients))
			}

		case message := <-s.broadcast:
			s.mutex.Lock()
			for client := range s.clients {
				err := client.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					client.Close()
					delete(s.clients, client)
				}
			}
			s.mutex.Unlock()
		}
	}
}
