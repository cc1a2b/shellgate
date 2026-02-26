package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"crypto/hmac"
	"crypto/sha256"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// OTPIssuer is the issuer name displayed in authenticator apps.
	OTPIssuer = "ShellGate"

	// OTPSecretFile is the filename for storing the TOTP secret.
	OTPSecretFile = "otp.key"
)

// OTPAuth implements TOTP-based two-factor authentication.
type OTPAuth struct {
	secret    string
	hmacKey   []byte
	loginPage []byte

	// Rate limiting
	attempts   map[string]*rateBucket
	attemptsMu sync.Mutex
}

// NewOTPAuth creates a new OTP authenticator with the secret loaded from the config directory.
func NewOTPAuth(configDir string, loginPageHTML []byte) (*OTPAuth, error) {
	secretPath := filepath.Join(configDir, OTPSecretFile)

	secret, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, fmt.Errorf("read OTP secret from %s: %w (run 'shellgate setup-otp' first)", secretPath, err)
	}

	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("generate hmac key: %w", err)
	}

	return &OTPAuth{
		secret:    string(secret),
		hmacKey:   hmacKey,
		loginPage: loginPageHTML,
		attempts:  make(map[string]*rateBucket),
	}, nil
}

// Name returns the authenticator name.
func (o *OTPAuth) Name() string { return "otp" }

// Middleware wraps the handler with OTP authentication.
func (o *OTPAuth) Middleware(next http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth/login", o.handleLogin)

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(o.loginPage)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		valid, err := o.Validate(r)
		if err != nil {
			slog.Error("OTP validation error", "error", err, "remote", r.RemoteAddr)
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

// Validate checks if the request has a valid OTP session cookie.
func (o *OTPAuth) Validate(r *http.Request) (bool, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return false, nil
	}

	data, err := o.verifySession(cookie.Value)
	if err != nil {
		return false, nil
	}

	if !data.Authenticated || time.Now().Unix() > data.ExpiresAt {
		return false, nil
	}

	return true, nil
}

// handleLogin processes OTP form submissions.
func (o *OTPAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := r.RemoteAddr
	if !o.checkRateLimit(clientIP) {
		slog.Warn("OTP login rate limit exceeded", "remote", clientIP)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Redirect(w, r, "/auth?error=missing", http.StatusSeeOther)
		return
	}

	valid := totp.Validate(code, o.secret)
	if !valid {
		slog.Warn("failed OTP attempt", "remote", clientIP)
		http.Redirect(w, r, "/auth?error=invalid", http.StatusSeeOther)
		return
	}

	sessionValue, err := o.createSession()
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

	slog.Info("successful OTP login", "remote", clientIP)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// createSession generates a signed session cookie value.
func (o *OTPAuth) createSession() (string, error) {
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
	sig := o.sign(payload)

	return encoded + "." + sig, nil
}

// verifySession validates and decodes a session cookie value.
func (o *OTPAuth) verifySession(value string) (*sessionData, error) {
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

	expectedSig := o.sign(payload)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid signature")
	}

	var data sessionData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return &data, nil
}

// sign creates an HMAC-SHA256 signature.
func (o *OTPAuth) sign(payload []byte) string {
	mac := hmac.New(sha256.New, o.hmacKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// checkRateLimit returns true if the client is within rate limits.
func (o *OTPAuth) checkRateLimit(clientIP string) bool {
	o.attemptsMu.Lock()
	defer o.attemptsMu.Unlock()

	now := time.Now()
	bucket, ok := o.attempts[clientIP]

	if !ok || now.After(bucket.resetAt) {
		o.attempts[clientIP] = &rateBucket{
			count:   1,
			resetAt: now.Add(time.Minute),
		}
		return true
	}

	bucket.count++
	return bucket.count <= MaxLoginAttempts
}

// SetupOTP generates a new TOTP secret and stores it in the config directory.
// Returns the OTP key for display (URI + secret).
func SetupOTP(configDir, accountName string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      OTPIssuer,
		AccountName: accountName,
	})
	if err != nil {
		return nil, fmt.Errorf("generate TOTP: %w", err)
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	secretPath := filepath.Join(configDir, OTPSecretFile)
	if err := os.WriteFile(secretPath, []byte(key.Secret()), 0600); err != nil {
		return nil, fmt.Errorf("write OTP secret: %w", err)
	}

	return key, nil
}
