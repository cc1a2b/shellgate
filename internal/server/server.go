// Package server provides the HTTP server and WebSocket handler for ShellGate.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/cc1a2b/shellgate/internal/auth"
	"github.com/cc1a2b/shellgate/internal/session"
	"github.com/cc1a2b/shellgate/web"
	"golang.org/x/crypto/acme/autocert"
)

// Config holds the server configuration.
type Config struct {
	Host    string
	Port    int
	Shell   string
	Verbose bool

	// Auth
	AuthMode  string // none, token, password, otp
	Token     string
	Password  string
	OTPDir    string
	AllowIP   string
	RateLimit float64
	NoAuthAck bool // --i-know-what-im-doing

	// TLS
	TLSEnabled bool
	TLSConfig  *tls.Config
	AutoCert   *autocert.Manager

	// Session
	MaxSessions int
	Timeout     time.Duration
	IdleTimeout time.Duration

	// Recording
	RecordEnabled bool
	RecordDir     string

	// Sharing
	ShareEnabled    bool
	ShareTTL        time.Duration
	ShareMaxViewers int
}

// Server is the main ShellGate HTTP/WebSocket server.
type Server struct {
	cfg       Config
	mux       *http.ServeMux
	server    *http.Server
	auth      auth.Authenticator
	sessions  *session.Manager
	shares    *session.ShareManager
	startTime time.Time
}

// New creates a new Server with the given configuration.
func New(cfg Config) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		mux:       http.NewServeMux(),
		startTime: time.Now(),
	}

	// Setup session manager
	s.sessions = session.NewManager(session.ManagerConfig{
		MaxSessions: cfg.MaxSessions,
		Timeout:     cfg.Timeout,
		IdleTimeout: cfg.IdleTimeout,
	})

	// Setup share manager
	if cfg.ShareEnabled {
		s.shares = session.NewShareManager()
	}

	// Setup authenticator
	authenticator, err := s.setupAuth()
	if err != nil {
		return nil, fmt.Errorf("setup auth: %w", err)
	}
	s.auth = authenticator

	if err := s.registerRoutes(); err != nil {
		return nil, fmt.Errorf("register routes: %w", err)
	}

	// Build middleware chain
	var handler http.Handler = s.mux

	// Apply auth middleware
	if s.auth != nil {
		handler = s.auth.Middleware(handler)
	}

	// Apply security headers
	handler = securityHeaders(handler)

	// Apply IP whitelist
	if cfg.AllowIP != "" {
		wl, err := NewIPWhitelist(cfg.AllowIP)
		if err != nil {
			return nil, fmt.Errorf("parse IP whitelist: %w", err)
		}
		if wl != nil {
			handler = wl.Middleware(handler)
		}
	}

	// Apply rate limiter
	if cfg.RateLimit > 0 {
		rl := NewRateLimiter(cfg.RateLimit)
		handler = rl.Middleware(handler)
	}

	// Apply request logger
	handler = requestLogger(handler)

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	s.server = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}

	if cfg.TLSConfig != nil {
		s.server.TLSConfig = cfg.TLSConfig
	}

	return s, nil
}

// setupAuth configures the authenticator based on config.
func (s *Server) setupAuth() (auth.Authenticator, error) {
	switch s.cfg.AuthMode {
	case "none":
		if !s.cfg.NoAuthAck {
			return nil, fmt.Errorf("--auth none requires --i-know-what-im-doing flag")
		}
		slog.Warn("authentication disabled — server is open to anyone")
		return &auth.NoneAuth{}, nil

	case "password":
		if s.cfg.Password == "" {
			return nil, fmt.Errorf("--password is required when using --auth password")
		}
		loginPage, err := web.Assets.ReadFile("static/auth.html")
		if err != nil {
			return nil, fmt.Errorf("read login page: %w", err)
		}
		return auth.NewPasswordAuth(s.cfg.Password, loginPage)

	case "otp":
		loginPage, err := web.Assets.ReadFile("static/auth.html")
		if err != nil {
			return nil, fmt.Errorf("read login page: %w", err)
		}
		return auth.NewOTPAuth(s.cfg.OTPDir, loginPage)

	case "token", "":
		return auth.NewTokenAuth(s.cfg.Token)

	default:
		return nil, fmt.Errorf("unknown auth mode: %s", s.cfg.AuthMode)
	}
}

// registerRoutes sets up all HTTP routes.
func (s *Server) registerRoutes() error {
	staticFS, err := fs.Sub(web.Assets, "static")
	if err != nil {
		return fmt.Errorf("static fs: %w", err)
	}
	fileServer := http.FileServer(http.FS(staticFS))

	// WebSocket endpoint
	s.mux.HandleFunc("/ws", s.handleWebSocket)

	// Share WebSocket endpoint
	s.mux.HandleFunc("/ws/share/", s.handleShareWebSocket)

	// API endpoints
	s.mux.HandleFunc("/api/sessions", s.handleAPISessions)
	s.mux.HandleFunc("/healthz", s.handleHealthz)

	// Static files (fallback)
	s.mux.Handle("/", fileServer)

	return nil
}

// handleHealthz responds with a health check including uptime and session count.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	uptime := time.Since(s.startTime).Truncate(time.Second).String()
	sessions := s.sessions.Count()

	fmt.Fprintf(w, `{"status":"ok","uptime":"%s","sessions":%d}`, uptime, sessions)
}

// handleAPISessions returns a list of active sessions.
func (s *Server) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	list := s.sessions.List()
	if err := json.NewEncoder(w).Encode(list); err != nil {
		slog.Error("encode sessions", "error", err)
	}
}

// ListenAndServe starts the HTTP server (with TLS if configured).
func (s *Server) ListenAndServe() error {
	slog.Info("server starting", "addr", s.server.Addr, "tls", s.cfg.TLSEnabled)

	if s.cfg.TLSEnabled && s.server.TLSConfig != nil {
		return s.server.ListenAndServeTLS("", "")
	}

	return s.server.ListenAndServe()
}

// AutoCertManager returns the autocert manager for HTTP-01 challenge handler, if configured.
func (s *Server) AutoCertManager() *autocert.Manager {
	return s.cfg.AutoCert
}

// Shutdown gracefully shuts down the server and cleans up sessions.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("server shutting down")

	s.sessions.Close()
	if s.shares != nil {
		s.shares.Close()
	}

	return s.server.Shutdown(ctx)
}

// Addr returns the server's listen address.
func (s *Server) Addr() string {
	return s.server.Addr
}

// Auth returns the configured authenticator.
func (s *Server) Auth() auth.Authenticator {
	return s.auth
}
