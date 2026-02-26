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
	"sync"
	"time"

	"github.com/cc1a2b/shellgate/internal/acl"
	"github.com/cc1a2b/shellgate/internal/auth"
	"github.com/cc1a2b/shellgate/internal/audit"
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

	// Dynamic ACL (Phase 9)
	MaxFailedAttempts int
	BanDuration       time.Duration
	GeoIPEnabled      bool
	GeoIPDBPath       string
	AllowedCountries  string
	BlockedCountries  string
	AccessWindowStart string
	AccessWindowEnd   string
	AccessWindowTZ    string

	// Stealth Mode (Phase 10)
	StealthEnabled bool
	RandomPort     bool
	PortRangeMin   int
	PortRangeMax   int
	AutoCloseTTL   time.Duration

	// Telegram (Phase 8)
	TelegramEnabled bool
	TelegramToken   string
	TelegramUserIDs []int64
	ExternalHost    string

	// Audit (Phase 11)
	AuditLogPath  string
	WebhookURL    string
	WebhookEvents string
	MetricsEnabled bool
}

// ServerStatus holds server status information for the Telegram bot.
type ServerStatus struct {
	Listening    bool
	Port         int
	Uptime       time.Duration
	Sessions     int
	TLSEnabled   bool
	RecordingOn  bool
	BannedIPs    int
}

// SessionInfo is a serializable snapshot of session metadata (for bot commands).
type SessionInfo struct {
	ID        string
	ClientIP  string
	Duration  time.Duration
	UserAgent string
}

// Server is the main ShellGate HTTP/WebSocket server.
type Server struct {
	cfg       Config
	mux       *http.ServeMux
	server    *http.Server
	handler   http.Handler
	auth      auth.Authenticator
	sessions  *session.Manager
	shares    *session.ShareManager
	startTime time.Time

	// Dynamic ACL (Phase 9)
	acl *acl.DynamicACL

	// Controllable listener (Phase 10)
	listener   net.Listener
	listenerMu sync.Mutex
	listening  bool

	// One-time tokens (Phase 8)
	oneTimeTokens *auth.OneTimeTokenStore

	// Audit (Phase 11)
	audit   *audit.Logger
	metrics *audit.Metrics

	// Event notification callback (Phase 8 — used by Telegram bot)
	onEvent   func(event string, detail map[string]string)
	onEventMu sync.RWMutex
}

// New creates a new Server with the given configuration.
func New(cfg Config) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		mux:       http.NewServeMux(),
		startTime: time.Now(),
	}

	// Setup one-time token store
	s.oneTimeTokens = auth.NewOneTimeTokenStore()

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

	// Wire one-time tokens into token auth
	if ta, ok := s.auth.(*auth.TokenAuth); ok {
		ta.SetOneTimeStore(s.oneTimeTokens)
	}

	// Setup audit logger
	if cfg.AuditLogPath != "" {
		auditLogger, err := audit.NewLogger(cfg.AuditLogPath)
		if err != nil {
			return nil, fmt.Errorf("setup audit logger: %w", err)
		}
		s.audit = auditLogger

		// Setup webhook if configured
		if cfg.WebhookURL != "" {
			webhook := audit.NewWebhookNotifier(cfg.WebhookURL, cfg.WebhookEvents)
			auditLogger.SetWebhook(webhook)
		}
	}

	// Setup metrics
	if cfg.MetricsEnabled {
		s.metrics = audit.NewMetrics()
	}

	// Setup Dynamic ACL
	aclCfg := acl.Config{
		InitialCIDRs:     cfg.AllowIP,
		MaxFailedAttempts: cfg.MaxFailedAttempts,
		BanDuration:       cfg.BanDuration,
		AllowedCountries:  cfg.AllowedCountries,
		BlockedCountries:  cfg.BlockedCountries,
		WindowStart:       cfg.AccessWindowStart,
		WindowEnd:         cfg.AccessWindowEnd,
		WindowTZ:          cfg.AccessWindowTZ,
	}
	if cfg.GeoIPEnabled && cfg.GeoIPDBPath != "" {
		aclCfg.GeoIPDBPath = cfg.GeoIPDBPath
	}

	dynACL, err := acl.NewDynamicACL(aclCfg)
	if err != nil {
		return nil, fmt.Errorf("setup dynamic ACL: %w", err)
	}
	s.acl = dynACL

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

	// Apply Dynamic ACL middleware (replaces old static IPWhitelist)
	handler = s.acl.Middleware(handler)

	// Apply rate limiter
	if cfg.RateLimit > 0 {
		rl := NewRateLimiter(cfg.RateLimit)
		handler = rl.Middleware(handler)
	}

	// Apply request logger
	handler = requestLogger(handler)

	s.handler = handler

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

	// Metrics endpoint (Phase 11)
	if s.metrics != nil {
		s.mux.HandleFunc("/metrics", s.handleMetrics)
	}

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

	listening := s.IsListening()
	fmt.Fprintf(w, `{"status":"ok","uptime":"%s","sessions":%d,"listening":%t}`, uptime, sessions, listening)
}

// handleAPISessions returns a list of active sessions.
func (s *Server) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	list := s.sessions.List()
	if err := json.NewEncoder(w).Encode(list); err != nil {
		slog.Error("encode sessions", "error", err)
	}
}

// handleMetrics serves Prometheus-format metrics.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metrics == nil {
		http.Error(w, "Metrics not enabled", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.SetActiveSessions(s.sessions.Count())
	_, _ = w.Write([]byte(s.metrics.Render()))
}

// StartListener creates a net.Listener and starts serving. Non-blocking.
func (s *Server) StartListener() (string, error) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	if s.listening {
		return s.listener.Addr().String(), nil
	}

	addr := s.server.Addr
	var ln net.Listener
	var err error

	if s.cfg.TLSEnabled && s.server.TLSConfig != nil {
		ln, err = tls.Listen("tcp", addr, s.server.TLSConfig)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return "", fmt.Errorf("listen on %s: %w", addr, err)
	}

	s.listener = ln
	s.listening = true

	go func() {
		slog.Info("server listening", "addr", ln.Addr().String(), "tls", s.cfg.TLSEnabled)
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
		}
		s.listenerMu.Lock()
		s.listening = false
		s.listenerMu.Unlock()
	}()

	s.emitServerEvent("server_start", map[string]string{"addr": ln.Addr().String()})
	s.auditLog("server_start", "", "", fmt.Sprintf("listening on %s", ln.Addr().String()))

	return ln.Addr().String(), nil
}

// StopListener closes the listener and shuts down active sessions.
func (s *Server) StopListener() error {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	if !s.listening {
		return nil
	}

	// Kill all active sessions
	s.sessions.Close()
	// Re-create session manager for next open cycle
	s.sessions = session.NewManager(session.ManagerConfig{
		MaxSessions: s.cfg.MaxSessions,
		Timeout:     s.cfg.Timeout,
		IdleTimeout: s.cfg.IdleTimeout,
	})

	// Revoke all one-time tokens
	s.oneTimeTokens.RevokeAll()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.server.Shutdown(ctx)
	s.listening = false

	// Re-create the http.Server so it can be started again
	s.server = &http.Server{
		Addr:              s.server.Addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	if s.cfg.TLSConfig != nil {
		s.server.TLSConfig = s.cfg.TLSConfig
	}

	s.emitServerEvent("server_stop", nil)
	s.auditLog("server_stop", "", "", "listener stopped")

	slog.Info("server listener stopped")
	return err
}

// IsListening returns whether the server is currently accepting connections.
func (s *Server) IsListening() bool {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	return s.listening
}

// ListenAndServe starts the HTTP server (with TLS if configured).
// This is the traditional blocking method. For stealth mode, use StartListener()/StopListener().
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
	if s.acl != nil {
		s.acl.Close()
	}
	if s.audit != nil {
		s.audit.Close()
	}
	s.oneTimeTokens.Stop()

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

// ACL returns the dynamic ACL.
func (s *Server) ACL() *acl.DynamicACL {
	return s.acl
}

// SetPort updates the server's listening port.
func (s *Server) SetPort(port int) {
	s.cfg.Port = port
	s.server.Addr = net.JoinHostPort(s.cfg.Host, fmt.Sprintf("%d", port))
}

// GetPort returns the current configured port.
func (s *Server) GetPort() int {
	return s.cfg.Port
}

// --- ServerController interface methods (for Telegram bot) ---

// GenerateOneTimeToken creates a single-use token with the given TTL.
func (s *Server) GenerateOneTimeToken(ttl time.Duration) (string, error) {
	return s.oneTimeTokens.Generate(ttl)
}

// RevokeToken revokes a one-time token.
func (s *Server) RevokeToken(token string) error {
	s.oneTimeTokens.Revoke(token)
	return nil
}

// GetStatus returns the current server status.
func (s *Server) GetStatus() ServerStatus {
	return ServerStatus{
		Listening:   s.IsListening(),
		Port:        s.cfg.Port,
		Uptime:      time.Since(s.startTime),
		Sessions:    s.sessions.Count(),
		TLSEnabled:  s.cfg.TLSEnabled,
		RecordingOn: s.cfg.RecordEnabled,
		BannedIPs:   len(s.acl.ListBanned()),
	}
}

// ListSessions returns info about all active sessions.
func (s *Server) ListSessions() []SessionInfo {
	raw := s.sessions.List()
	result := make([]SessionInfo, len(raw))
	for i, si := range raw {
		result[i] = SessionInfo{
			ID:        si.ID,
			ClientIP:  si.ClientIP,
			Duration:  time.Since(si.StartedAt),
			UserAgent: si.UserAgent,
		}
	}
	return result
}

// KillSession terminates a session by ID.
func (s *Server) KillSession(id string) error {
	_, ok := s.sessions.Get(id)
	if !ok {
		return fmt.Errorf("session %s not found", id)
	}
	s.sessions.Remove(id)
	s.auditLog("session_kill", id, "", "killed via bot command")
	return nil
}

// AddWhitelistIP adds a CIDR to the dynamic whitelist.
func (s *Server) AddWhitelistIP(cidr string) error {
	return s.acl.AddNetwork(cidr)
}

// RemoveWhitelistIP removes a CIDR from the dynamic whitelist.
func (s *Server) RemoveWhitelistIP(cidr string) error {
	return s.acl.RemoveNetwork(cidr)
}

// ToggleRecording toggles session recording on/off.
func (s *Server) ToggleRecording() bool {
	s.cfg.RecordEnabled = !s.cfg.RecordEnabled
	return s.cfg.RecordEnabled
}

// CreateShareLink creates a share link for a session.
func (s *Server) CreateShareLink(sessionID string) (string, error) {
	if s.shares == nil {
		return "", fmt.Errorf("sharing not enabled")
	}
	link, err := s.shares.Create(sessionID, s.cfg.ShareTTL, s.cfg.ShareMaxViewers)
	if err != nil {
		return "", err
	}
	return link.Token, nil
}

// SetEventHandler sets the notification callback for server events.
func (s *Server) SetEventHandler(fn func(event string, detail map[string]string)) {
	s.onEventMu.Lock()
	s.onEvent = fn
	s.onEventMu.Unlock()
}

// emitServerEvent sends an event to the registered handler.
func (s *Server) emitServerEvent(event string, detail map[string]string) {
	s.onEventMu.RLock()
	fn := s.onEvent
	s.onEventMu.RUnlock()

	if fn != nil {
		go fn(event, detail)
	}
}

// auditLog writes an entry to the audit log if configured.
func (s *Server) auditLog(event, sessionID, clientIP, detail string) {
	if s.audit == nil {
		return
	}

	country := ""
	if clientIP != "" && s.acl != nil {
		if geo, err := s.acl.LookupGeo(clientIP); err == nil && geo != nil {
			country = geo.CountryCode
		}
	}

	s.audit.Log(audit.Entry{
		Event:     event,
		SessionID: sessionID,
		ClientIP:  clientIP,
		Country:   country,
		Detail:    detail,
	})
}

// RecordAuthFailure records an auth failure for fail2ban and metrics.
func (s *Server) RecordAuthFailure(ip string) {
	if s.acl != nil {
		s.acl.RecordFailure(ip)
	}
	if s.metrics != nil {
		s.metrics.IncAuthFailure()
	}
	s.auditLog("auth_failure", "", ip, "invalid credentials")
	s.emitServerEvent("auth_failure", map[string]string{"ip": ip})
}

// RecordAuthSuccess records a successful auth for metrics.
func (s *Server) RecordAuthSuccess(ip string) {
	if s.metrics != nil {
		s.metrics.IncAuthSuccess()
	}
	s.auditLog("auth", "", ip, "authenticated")
}
