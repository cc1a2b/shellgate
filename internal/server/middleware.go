package server

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// requestLogger is a basic logging middleware for HTTP requests.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		slog.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration", time.Since(start),
			"remote", r.RemoteAddr,
		)
	})
}

// securityHeaders adds security headers to all responses.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:")
		next.ServeHTTP(w, r)
	})
}

// IPWhitelist restricts access to the given CIDR ranges.
type IPWhitelist struct {
	networks []*net.IPNet
}

// NewIPWhitelist parses a comma-separated list of CIDR ranges.
func NewIPWhitelist(cidrs string) (*IPWhitelist, error) {
	if cidrs == "" {
		return nil, nil
	}

	wl := &IPWhitelist{}
	for _, cidr := range strings.Split(cidrs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		// Add /32 for bare IPs
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		wl.networks = append(wl.networks, network)
	}

	if len(wl.networks) == 0 {
		return nil, nil
	}

	return wl, nil
}

// Middleware returns an HTTP middleware that enforces the IP whitelist.
func (wl *IPWhitelist) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r.RemoteAddr)
		if ip == nil {
			slog.Warn("could not parse client IP", "remote", r.RemoteAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		for _, network := range wl.networks {
			if network.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}

		slog.Warn("IP not in whitelist", "remote", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

// RateLimiter provides per-IP rate limiting.
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.Mutex
	rps      float64
	burst    int
}

// NewRateLimiter creates a new per-IP rate limiter.
func NewRateLimiter(requestsPerSecond float64) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      requestsPerSecond,
		burst:    int(requestsPerSecond * 2),
	}
}

// Middleware returns an HTTP middleware that enforces rate limits.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r.RemoteAddr).String()

		limiter := rl.getLimiter(ip)
		if !limiter.Allow() {
			slog.Warn("rate limit exceeded", "remote", r.RemoteAddr)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if limiter, ok := rl.limiters[ip]; ok {
		return limiter
	}

	limiter := rate.NewLimiter(rate.Limit(rl.rps), rl.burst)
	rl.limiters[ip] = limiter

	// Garbage collect old entries periodically (simple approach)
	if len(rl.limiters) > 10000 {
		rl.limiters = make(map[string]*rate.Limiter)
		rl.limiters[ip] = limiter
	}

	return limiter
}

// extractIP parses the IP address from a remote address string.
func extractIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return net.ParseIP(remoteAddr)
	}
	return net.ParseIP(host)
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
