package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// SessionCookieName is the name of the authentication cookie.
	SessionCookieName = "shellgate_session"

	// SessionMaxAge is the maximum age of a session cookie (24 hours).
	SessionMaxAge = 24 * time.Hour

	// MaxLoginAttempts is the maximum login attempts per IP per minute.
	MaxLoginAttempts = 5
)

// PasswordAuth implements password-based authentication with session cookies.
type PasswordAuth struct {
	passwordHash []byte
	hmacKey      []byte
	loginPage    []byte

	// Rate limiting
	attempts   map[string]*rateBucket
	attemptsMu sync.Mutex
}

type rateBucket struct {
	count    int
	resetAt  time.Time
}

// sessionData represents the signed session cookie payload.
type sessionData struct {
	Authenticated bool   `json:"a"`
	ExpiresAt     int64  `json:"e"`
	Nonce         string `json:"n"`
}

// NewPasswordAuth creates a new password authenticator.
func NewPasswordAuth(password string, loginPageHTML []byte) (*PasswordAuth, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt hash: %w", err)
	}

	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("generate hmac key: %w", err)
	}

	return &PasswordAuth{
		passwordHash: hash,
		hmacKey:      hmacKey,
		loginPage:    loginPageHTML,
		attempts:     make(map[string]*rateBucket),
	}, nil
}

// Name returns the authenticator name.
func (p *PasswordAuth) Name() string { return "password" }

// Middleware wraps the handler with password authentication.
func (p *PasswordAuth) Middleware(next http.Handler) http.Handler {
	mux := http.NewServeMux()

	// Login endpoint
	mux.HandleFunc("/auth/login", p.handleLogin)

	// Login page
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(p.loginPage)
	})

	// Everything else requires authentication
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		valid, err := p.Validate(r)
		if err != nil {
			slog.Error("session validation error", "error", err, "remote", r.RemoteAddr)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !valid {
			http.Redirect(w, r, "/auth", http.StatusTemporaryRedirect)
			return
		}

		next.ServeHTTP(w, r)
	})

	return mux
}

// Validate checks if the request has a valid session cookie.
func (p *PasswordAuth) Validate(r *http.Request) (bool, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return false, nil
	}

	data, err := p.verifySession(cookie.Value)
	if err != nil {
		return false, nil
	}

	if !data.Authenticated || time.Now().Unix() > data.ExpiresAt {
		return false, nil
	}

	return true, nil
}

// handleLogin processes login form submissions.
func (p *PasswordAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting
	clientIP := r.RemoteAddr
	if !p.checkRateLimit(clientIP) {
		slog.Warn("login rate limit exceeded", "remote", clientIP)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		http.Redirect(w, r, "/auth?error=missing", http.StatusSeeOther)
		return
	}

	if err := bcrypt.CompareHashAndPassword(p.passwordHash, []byte(password)); err != nil {
		slog.Warn("failed login attempt", "remote", clientIP)
		http.Redirect(w, r, "/auth?error=invalid", http.StatusSeeOther)
		return
	}

	// Generate session cookie
	sessionValue, err := p.createSession()
	if err != nil {
		slog.Error("session creation failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionValue,
		Path:     "/",
		MaxAge:   int(SessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	slog.Info("successful login", "remote", clientIP)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// createSession generates a signed session cookie value.
func (p *PasswordAuth) createSession() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	data := sessionData{
		Authenticated: true,
		ExpiresAt:     time.Now().Add(SessionMaxAge).Unix(),
		Nonce:         base64.RawURLEncoding.EncodeToString(nonce),
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sig := p.sign(payload)

	return encoded + "." + sig, nil
}

// verifySession validates and decodes a session cookie value.
func (p *PasswordAuth) verifySession(value string) (*sessionData, error) {
	// Split into payload.signature
	dotIdx := -1
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx < 0 {
		return nil, fmt.Errorf("invalid session format")
	}

	encodedPayload := value[:dotIdx]
	sig := value[dotIdx+1:]

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	expectedSig := p.sign(payload)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid signature")
	}

	var data sessionData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return &data, nil
}

// sign creates an HMAC-SHA256 signature for the given payload.
func (p *PasswordAuth) sign(payload []byte) string {
	mac := hmac.New(sha256.New, p.hmacKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// checkRateLimit returns true if the client is within rate limits.
func (p *PasswordAuth) checkRateLimit(clientIP string) bool {
	p.attemptsMu.Lock()
	defer p.attemptsMu.Unlock()

	now := time.Now()
	bucket, ok := p.attempts[clientIP]

	if !ok || now.After(bucket.resetAt) {
		p.attempts[clientIP] = &rateBucket{
			count:   1,
			resetAt: now.Add(time.Minute),
		}
		return true
	}

	bucket.count++
	return bucket.count <= MaxLoginAttempts
}
