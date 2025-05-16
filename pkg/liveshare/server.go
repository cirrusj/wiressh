package liveshare

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed templates
var templateFS embed.FS

// Server represents a live sharing server for SSH sessions
type Server struct {
	addr            string
	clients         map[*websocket.Conn]bool
	broadcast       chan []byte
	register        chan *websocket.Conn
	unregister      chan *websocket.Conn
	mutex           sync.Mutex
	server          *http.Server
	debug           bool
	password        string
	certFingerprint string
}

// NewServer creates a new live sharing server
func NewServer(addr string, debug bool, password string) *Server {
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
		password:   password,
	}
}

// calculateFingerprint calculates the SHA-256 fingerprint of a certificate
// Returns the fingerprint in lowercase without colons (e.g., "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
func calculateFingerprint(certBytes []byte) string {
	hash := sha256.Sum256(certBytes)
	return fmt.Sprintf("%x", hash)
}

// generateSelfSignedCert generates a self-signed certificate for localhost
func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"WireSSH Live Share"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create tls.Certificate
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// Start initializes and starts the web server with HTTPS
func (s *Server) Start() error {
	// Generate self-signed certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		return err
	}

	// Calculate and store certificate fingerprint
	s.certFingerprint = calculateFingerprint(cert.Certificate[0])

	// Print connection information
	fmt.Printf("Live sharing enabled on https://%s\n", s.addr)
	fmt.Printf("Certificate fingerprint: %s\n", s.certFingerprint)
	fmt.Printf("Live sharing password: %s\n", s.password)

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1", "h2"},
		// Suppress TLS handshake errors when debug is not enabled
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"http/1.1", "h2"},
			}, nil
		},
	}

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
		// Check authentication
		providedPassword := r.URL.Query().Get("password")
		if providedPassword != s.password {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

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

	// Create HTTPS server with TLS config
	s.server = &http.Server{
		Addr:      s.addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// Configure error logging based on debug flag
	if !s.debug {
		s.server.ErrorLog = log.New(io.Discard, "", 0)
	}

	// Start client handler goroutine
	go s.handleClients()

	// Start HTTPS server
	httpsListener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	// Create a TLS listener for HTTPS
	tlsListener := tls.NewListener(httpsListener, tlsConfig)

	if s.debug {
		log.Printf("Starting HTTPS server on https://%s", s.addr)
	}

	// Start the HTTPS server (this is the main server)
	return s.server.Serve(tlsListener)
}

// GetCertFingerprint returns the SHA-256 fingerprint of the server's certificate
func (s *Server) GetCertFingerprint() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.certFingerprint
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Close all client connections with a normal closure code (1000)
	for client := range s.clients {
		client.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Session ended"),
			time.Now().Add(5*time.Second),
		)
		client.Close()
	}

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
