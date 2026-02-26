package server

import (
	"bufio"
	"fmt"
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

// rateLimiterEntry holds a limiter and its last access time for TTL eviction.
type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter provides per-IP rate limiting with TTL-based eviction.
type RateLimiter struct {
	entries map[string]*rateLimiterEntry
	mu      sync.Mutex
	rps     float64
	burst   int
	ttl     time.Duration
}

// NewRateLimiter creates a new per-IP rate limiter.
// Entries are evicted after 10 minutes of inactivity.
func NewRateLimiter(requestsPerSecond float64) *RateLimiter {
	rl := &RateLimiter{
		entries: make(map[string]*rateLimiterEntry),
		rps:     requestsPerSecond,
		burst:   int(requestsPerSecond * 2),
		ttl:     10 * time.Minute,
	}
	go rl.evictLoop()
	return rl
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

	now := time.Now()
	if entry, ok := rl.entries[ip]; ok {
		entry.lastSeen = now
		return entry.limiter
	}

	limiter := rate.NewLimiter(rate.Limit(rl.rps), rl.burst)
	rl.entries[ip] = &rateLimiterEntry{limiter: limiter, lastSeen: now}
	return limiter
}

// evictLoop removes stale rate limiter entries every 60 seconds.
func (rl *RateLimiter) evictLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.ttl)
		for ip, entry := range rl.entries {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.entries, ip)
			}
		}
		rl.mu.Unlock()
	}
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
// It preserves http.Hijacker and http.Flusher interfaces for WebSocket support.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
}

func (rw *responseWriter) Flush() {
	if fl, ok := rw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}
