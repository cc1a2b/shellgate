package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const (
	// TokenSessionCookie is the cookie name for token-based session persistence.
	TokenSessionCookie = "shellgate_token_session"
)

// TokenAuth implements bearer token authentication.
// On first valid auth (via header or query param), a session cookie is set
// so that subsequent requests (CSS, JS, WebSocket) pass through.
type TokenAuth struct {
	token   []byte
	hmacKey []byte
}

// NewTokenAuth creates a new token authenticator with the given token.
// If token is empty, a secure random token is generated.
func NewTokenAuth(token string) (*TokenAuth, error) {
	if token == "" {
		generated, err := GenerateToken(32)
		if err != nil {
			return nil, fmt.Errorf("generate token: %w", err)
		}
		token = generated
		fmt.Printf("Generated auth token: %s\n", token)
	}

	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("generate hmac key: %w", err)
	}

	return &TokenAuth{
		token:   []byte(token),
		hmacKey: hmacKey,
	}, nil
}

// Name returns the authenticator name.
func (t *TokenAuth) Name() string { return "token" }

// Middleware wraps the handler with token authentication.
func (t *TokenAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		// Check existing session cookie first (for sub-requests: CSS, JS, WS)
		if t.validateCookie(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Check token via header or query param
		valid, err := t.Validate(r)
		if err != nil {
			slog.Error("token validation error", "error", err, "remote", r.RemoteAddr)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !valid {
			slog.Warn("unauthorized access attempt", "remote", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Valid token — set session cookie
		t.setSessionCookie(w, r)

		// If token was in query param, redirect to strip it from URL
		// This ensures sub-resources (CSS, JS) load with the cookie
		if r.URL.Query().Get("token") != "" {
			cleanURL := *r.URL
			q := cleanURL.Query()
			q.Del("token")
			cleanURL.RawQuery = q.Encode()
			http.Redirect(w, r, cleanURL.String(), http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Validate checks the request for a valid bearer token.
// Tokens can be provided via:
//   - Authorization: Bearer <token> header
//   - ?token=<token> query parameter
func (t *TokenAuth) Validate(r *http.Request) (bool, error) {
	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		provided := []byte(authHeader[7:])
		if subtle.ConstantTimeCompare(provided, t.token) == 1 {
			return true, nil
		}
	}

	// Check query parameter
	queryToken := r.URL.Query().Get("token")
	if queryToken != "" {
		if subtle.ConstantTimeCompare([]byte(queryToken), t.token) == 1 {
			return true, nil
		}
	}

	return false, nil
}

// Token returns the current token string.
func (t *TokenAuth) Token() string {
	return string(t.token)
}

// setSessionCookie creates and sets an HMAC-signed session cookie.
func (t *TokenAuth) setSessionCookie(w http.ResponseWriter, r *http.Request) {
	data := sessionData{
		Authenticated: true,
		ExpiresAt:     time.Now().Add(SessionMaxAge).Unix(),
		Nonce:         fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sig := t.sign(payload)

	http.SetCookie(w, &http.Cookie{
		Name:     TokenSessionCookie,
		Value:    encoded + "." + sig,
		Path:     "/",
		MaxAge:   int(SessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// validateCookie checks if the request has a valid session cookie.
func (t *TokenAuth) validateCookie(r *http.Request) bool {
	cookie, err := r.Cookie(TokenSessionCookie)
	if err != nil {
		return false
	}

	// Split payload.signature
	dotIdx := -1
	for i := len(cookie.Value) - 1; i >= 0; i-- {
		if cookie.Value[i] == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx < 0 {
		return false
	}

	encodedPayload := cookie.Value[:dotIdx]
	sig := cookie.Value[dotIdx+1:]

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return false
	}

	expectedSig := t.sign(payload)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false
	}

	var data sessionData
	if err := json.Unmarshal(payload, &data); err != nil {
		return false
	}

	return data.Authenticated && time.Now().Unix() <= data.ExpiresAt
}

// sign creates an HMAC-SHA256 signature.
func (t *TokenAuth) sign(payload []byte) string {
	mac := hmac.New(sha256.New, t.hmacKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// GenerateToken generates a cryptographically secure random hex token.
func GenerateToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(b), nil
}
