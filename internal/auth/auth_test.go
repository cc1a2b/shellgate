package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoneAuth(t *testing.T) {
	a := &NoneAuth{}
	assert.Equal(t, "none", a.Name())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	valid, err := a.Validate(req)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestTokenAuth_ValidHeader(t *testing.T) {
	a, err := NewTokenAuth("test-secret-token")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer test-secret-token")

	valid, err := a.Validate(req)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestTokenAuth_ValidQuery(t *testing.T) {
	a, err := NewTokenAuth("test-secret-token")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/?token=test-secret-token", nil)

	valid, err := a.Validate(req)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestTokenAuth_Invalid(t *testing.T) {
	a, err := NewTokenAuth("test-secret-token")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")

	valid, err := a.Validate(req)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestTokenAuth_NoCredentials(t *testing.T) {
	a, err := NewTokenAuth("test-secret-token")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	valid, err := a.Validate(req)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestTokenAuth_AutoGenerate(t *testing.T) {
	a, err := NewTokenAuth("")
	require.NoError(t, err)
	assert.NotEmpty(t, a.Token())
	assert.Len(t, a.Token(), 64) // 32 bytes = 64 hex chars
}

func TestTokenAuth_MiddlewareBlocks(t *testing.T) {
	a, err := NewTokenAuth("secret")
	require.NoError(t, err)

	handler := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Without token
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// With valid token
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTokenAuth_HealthzBypass(t *testing.T) {
	a, err := NewTokenAuth("secret")
	require.NoError(t, err)

	handler := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPasswordAuth_LoginFlow(t *testing.T) {
	loginPage := []byte("<html>login</html>")
	a, err := NewPasswordAuth("test-pass-123", loginPage)
	require.NoError(t, err)

	handler := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("protected"))
	}))

	// Unauthenticated request → redirect to /auth
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)

	// GET /auth → login page
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "login")

	// POST /auth/login with correct password
	form := url.Values{"password": {"test-pass-123"}}
	req = httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusSeeOther, rec.Code)

	// Extract session cookie
	cookies := rec.Result().Cookies()
	require.NotEmpty(t, cookies)
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == SessionCookieName {
			sessionCookie = c
		}
	}
	require.NotNil(t, sessionCookie)

	// Authenticated request with cookie
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "protected", rec.Body.String())
}

func TestPasswordAuth_WrongPassword(t *testing.T) {
	loginPage := []byte("<html>login</html>")
	a, err := NewPasswordAuth("correct-password", loginPage)
	require.NoError(t, err)

	handler := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	form := url.Values{"password": {"wrong-password"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "error=invalid")
}

func TestPasswordAuth_RateLimit(t *testing.T) {
	loginPage := []byte("<html>login</html>")
	a, err := NewPasswordAuth("password", loginPage)
	require.NoError(t, err)

	handler := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust rate limit
	for i := 0; i < MaxLoginAttempts+1; i++ {
		form := url.Values{"password": {"wrong"}}
		req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if i >= MaxLoginAttempts {
			assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		}
	}
}

func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken(32)
	require.NoError(t, err)
	assert.Len(t, token1, 64)

	token2, err := GenerateToken(32)
	require.NoError(t, err)
	assert.NotEqual(t, token1, token2)
}

func TestSetupOTP(t *testing.T) {
	dir := t.TempDir()
	key, err := SetupOTP(dir, "test@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, key.Secret())
	assert.Contains(t, key.URL(), "otpauth://")

	// Verify file was created
	secretPath := filepath.Join(dir, OTPSecretFile)
	data, err := os.ReadFile(secretPath)
	require.NoError(t, err)
	assert.Equal(t, key.Secret(), string(data))
}
