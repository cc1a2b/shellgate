// Package acl provides runtime-mutable access control with fail2ban, GeoIP, and time windows.
package acl

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ACLEventType identifies the type of ACL event.
type ACLEventType string

const (
	EventIPBanned     ACLEventType = "ip_banned"
	EventIPUnbanned   ACLEventType = "ip_unbanned"
	EventIPWhitelisted ACLEventType = "ip_whitelisted"
	EventIPRemoved    ACLEventType = "ip_removed"
	EventIPBlocked    ACLEventType = "ip_blocked"
	EventGeoBlocked   ACLEventType = "geo_blocked"
	EventTimeBlocked  ACLEventType = "time_blocked"
)

// ACLEvent represents an event emitted by the ACL system.
type ACLEvent struct {
	Type      ACLEventType
	IP        string
	Detail    string
	Timestamp time.Time
}

// timeOfDay represents a time within a day (hours and minutes).
type timeOfDay struct {
	Hour   int
	Minute int
}

func parseTimeOfDay(s string) (*timeOfDay, error) {
	if s == "" {
		return nil, nil
	}
	var h, m int
	n, err := fmt.Sscanf(s, "%d:%d", &h, &m)
	if err != nil || n != 2 {
		return nil, fmt.Errorf("invalid time format %q, expected HH:MM", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return nil, fmt.Errorf("invalid time %q: hours must be 0-23, minutes 0-59", s)
	}
	return &timeOfDay{Hour: h, Minute: m}, nil
}

func (t *timeOfDay) toMinutes() int {
	return t.Hour*60 + t.Minute
}

// failRecord tracks authentication failures for a single IP.
type failRecord struct {
	count    int
	firstAt  time.Time
	lastAt   time.Time
}

// Config holds configuration for the DynamicACL.
type Config struct {
	InitialCIDRs     string        // comma-separated initial whitelist CIDRs
	MaxFailedAttempts int           // 0 = disable fail2ban
	BanDuration      time.Duration // how long bans last
	GeoIPDBPath      string        // path to MaxMind .mmdb file
	AllowedCountries string        // comma-separated allowed country codes
	BlockedCountries string        // comma-separated blocked country codes
	WindowStart      string        // HH:MM access window start
	WindowEnd        string        // HH:MM access window end
	WindowTZ         string        // timezone name (e.g. "Asia/Riyadh")
}

// DynamicACL provides runtime-mutable IP whitelisting, fail2ban, GeoIP filtering,
// and time-based access windows.
type DynamicACL struct {
	networks    []*net.IPNet
	netMu       sync.RWMutex

	failures    map[string]*failRecord
	banned      map[string]time.Time
	banMu       sync.RWMutex
	maxFails    int
	banDuration time.Duration

	geoIP       *GeoIPResolver
	allowCC     map[string]bool
	blockCC     map[string]bool

	windowStart *timeOfDay
	windowEnd   *timeOfDay
	windowTZ    *time.Location

	onEvent     func(ACLEvent)
	eventMu     sync.RWMutex

	done        chan struct{}
}

// NewDynamicACL creates a new DynamicACL from the given configuration.
func NewDynamicACL(cfg Config) (*DynamicACL, error) {
	acl := &DynamicACL{
		failures:    make(map[string]*failRecord),
		banned:      make(map[string]time.Time),
		maxFails:    cfg.MaxFailedAttempts,
		banDuration: cfg.BanDuration,
		done:        make(chan struct{}),
	}

	if acl.maxFails <= 0 {
		acl.maxFails = 10
	}
	if acl.banDuration <= 0 {
		acl.banDuration = 15 * time.Minute
	}

	// Parse initial CIDRs
	if cfg.InitialCIDRs != "" {
		for _, cidr := range strings.Split(cfg.InitialCIDRs, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			if err := acl.AddNetwork(cidr); err != nil {
				return nil, fmt.Errorf("parse initial CIDR %q: %w", cidr, err)
			}
		}
	}

	// Setup GeoIP
	if cfg.GeoIPDBPath != "" {
		resolver, err := NewGeoIPResolver(cfg.GeoIPDBPath)
		if err != nil {
			return nil, fmt.Errorf("load GeoIP database: %w", err)
		}
		acl.geoIP = resolver
	}

	// Parse country codes
	if cfg.AllowedCountries != "" {
		acl.allowCC = make(map[string]bool)
		for _, cc := range strings.Split(cfg.AllowedCountries, ",") {
			cc = strings.TrimSpace(strings.ToUpper(cc))
			if cc != "" {
				acl.allowCC[cc] = true
			}
		}
	}
	if cfg.BlockedCountries != "" {
		acl.blockCC = make(map[string]bool)
		for _, cc := range strings.Split(cfg.BlockedCountries, ",") {
			cc = strings.TrimSpace(strings.ToUpper(cc))
			if cc != "" {
				acl.blockCC[cc] = true
			}
		}
	}

	// Parse time window
	var err error
	acl.windowStart, err = parseTimeOfDay(cfg.WindowStart)
	if err != nil {
		return nil, fmt.Errorf("parse window start: %w", err)
	}
	acl.windowEnd, err = parseTimeOfDay(cfg.WindowEnd)
	if err != nil {
		return nil, fmt.Errorf("parse window end: %w", err)
	}

	if cfg.WindowTZ != "" {
		acl.windowTZ, err = time.LoadLocation(cfg.WindowTZ)
		if err != nil {
			return nil, fmt.Errorf("parse timezone: %w", err)
		}
	} else {
		acl.windowTZ = time.Local
	}

	// Only start cleanup goroutine if ban tracking is possible
	if cfg.BanDuration > 0 {
		go acl.cleanupLoop()
	}

	return acl, nil
}

// AddNetwork adds a CIDR range to the whitelist.
func (a *DynamicACL) AddNetwork(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	a.netMu.Lock()
	// Check for duplicates
	for _, existing := range a.networks {
		if existing.String() == network.String() {
			a.netMu.Unlock()
			return nil
		}
	}
	a.networks = append(a.networks, network)
	a.netMu.Unlock()

	a.emitEvent(ACLEvent{
		Type:      EventIPWhitelisted,
		IP:        network.String(),
		Detail:    "added to whitelist",
		Timestamp: time.Now(),
	})

	slog.Info("ACL: network added to whitelist", "cidr", network.String())
	return nil
}

// RemoveNetwork removes a CIDR range from the whitelist.
func (a *DynamicACL) RemoveNetwork(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	a.netMu.Lock()
	target := network.String()
	found := false
	for i, existing := range a.networks {
		if existing.String() == target {
			a.networks = append(a.networks[:i], a.networks[i+1:]...)
			found = true
			break
		}
	}
	a.netMu.Unlock()

	if !found {
		return fmt.Errorf("network %s not in whitelist", target)
	}

	a.emitEvent(ACLEvent{
		Type:      EventIPRemoved,
		IP:        target,
		Detail:    "removed from whitelist",
		Timestamp: time.Now(),
	})

	slog.Info("ACL: network removed from whitelist", "cidr", target)
	return nil
}

// ListNetworks returns all whitelisted CIDR ranges.
func (a *DynamicACL) ListNetworks() []string {
	a.netMu.RLock()
	defer a.netMu.RUnlock()

	result := make([]string, len(a.networks))
	for i, n := range a.networks {
		result[i] = n.String()
	}
	return result
}

// RecordFailure records an authentication failure for the given IP.
// Returns true if the IP is now banned.
func (a *DynamicACL) RecordFailure(ip string) bool {
	a.banMu.Lock()
	defer a.banMu.Unlock()

	now := time.Now()

	rec, ok := a.failures[ip]
	if !ok {
		a.failures[ip] = &failRecord{count: 1, firstAt: now, lastAt: now}
		return false
	}

	// Reset if last failure was more than banDuration ago
	if now.Sub(rec.lastAt) > a.banDuration {
		a.failures[ip] = &failRecord{count: 1, firstAt: now, lastAt: now}
		return false
	}

	rec.count++
	rec.lastAt = now

	if rec.count >= a.maxFails {
		a.banned[ip] = now.Add(a.banDuration)
		delete(a.failures, ip)

		a.emitEvent(ACLEvent{
			Type:      EventIPBanned,
			IP:        ip,
			Detail:    fmt.Sprintf("banned after %d failures, expires %s", rec.count, a.banned[ip].Format(time.RFC3339)),
			Timestamp: now,
		})

		slog.Warn("ACL: IP banned", "ip", ip, "failures", rec.count, "duration", a.banDuration)
		return true
	}

	return false
}

// IsBanned checks if an IP is currently banned.
func (a *DynamicACL) IsBanned(ip string) bool {
	a.banMu.RLock()
	defer a.banMu.RUnlock()

	expiry, banned := a.banned[ip]
	if !banned {
		return false
	}
	if time.Now().After(expiry) {
		return false
	}
	return true
}

// Ban manually bans an IP for the configured ban duration.
func (a *DynamicACL) Ban(ip string) {
	a.banMu.Lock()
	a.banned[ip] = time.Now().Add(a.banDuration)
	a.banMu.Unlock()

	a.emitEvent(ACLEvent{
		Type:      EventIPBanned,
		IP:        ip,
		Detail:    "manually banned",
		Timestamp: time.Now(),
	})

	slog.Info("ACL: IP manually banned", "ip", ip, "duration", a.banDuration)
}

// Unban removes an IP ban.
func (a *DynamicACL) Unban(ip string) {
	a.banMu.Lock()
	delete(a.banned, ip)
	delete(a.failures, ip)
	a.banMu.Unlock()

	a.emitEvent(ACLEvent{
		Type:      EventIPUnbanned,
		IP:        ip,
		Detail:    "unbanned",
		Timestamp: time.Now(),
	})

	slog.Info("ACL: IP unbanned", "ip", ip)
}

// ListBanned returns all currently banned IPs with their expiry times.
func (a *DynamicACL) ListBanned() map[string]time.Time {
	a.banMu.RLock()
	defer a.banMu.RUnlock()

	now := time.Now()
	result := make(map[string]time.Time)
	for ip, expiry := range a.banned {
		if now.Before(expiry) {
			result[ip] = expiry
		}
	}
	return result
}

// LookupGeo returns GeoIP information for the given IP. Returns nil if GeoIP is not configured.
func (a *DynamicACL) LookupGeo(ip string) (*GeoInfo, error) {
	if a.geoIP == nil {
		return nil, nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP: %s", ip)
	}
	return a.geoIP.Lookup(parsed)
}

// SetEventHandler sets the callback function for ACL events.
func (a *DynamicACL) SetEventHandler(fn func(ACLEvent)) {
	a.eventMu.Lock()
	a.onEvent = fn
	a.eventMu.Unlock()
}

// Middleware returns an HTTP middleware that enforces the ACL rules.
// Check order: banned → whitelist → GeoIP → time window.
func (a *DynamicACL) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip ACL for health check
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r.RemoteAddr)
		if ip == nil {
			slog.Warn("ACL: could not parse client IP", "remote", r.RemoteAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		ipStr := ip.String()

		// 1. Check ban list
		if a.IsBanned(ipStr) {
			slog.Debug("ACL: banned IP blocked", "ip", ipStr)
			a.emitEvent(ACLEvent{
				Type:      EventIPBlocked,
				IP:        ipStr,
				Detail:    "banned",
				Timestamp: time.Now(),
			})
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// 2. Check whitelist (if configured)
		a.netMu.RLock()
		hasWhitelist := len(a.networks) > 0
		allowed := false
		if hasWhitelist {
			for _, network := range a.networks {
				if network.Contains(ip) {
					allowed = true
					break
				}
			}
		}
		a.netMu.RUnlock()

		if hasWhitelist && !allowed {
			slog.Debug("ACL: IP not in whitelist", "ip", ipStr)
			a.emitEvent(ACLEvent{
				Type:      EventIPBlocked,
				IP:        ipStr,
				Detail:    "not in whitelist",
				Timestamp: time.Now(),
			})
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// 3. Check GeoIP
		if a.geoIP != nil && (len(a.allowCC) > 0 || len(a.blockCC) > 0) {
			geo, err := a.geoIP.Lookup(ip)
			if err == nil && geo != nil {
				if len(a.blockCC) > 0 && a.blockCC[geo.CountryCode] {
					slog.Debug("ACL: blocked country", "ip", ipStr, "country", geo.CountryCode)
					a.emitEvent(ACLEvent{
						Type:      EventGeoBlocked,
						IP:        ipStr,
						Detail:    fmt.Sprintf("blocked country: %s", geo.CountryCode),
						Timestamp: time.Now(),
					})
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				if len(a.allowCC) > 0 && !a.allowCC[geo.CountryCode] {
					slog.Debug("ACL: country not in allow list", "ip", ipStr, "country", geo.CountryCode)
					a.emitEvent(ACLEvent{
						Type:      EventGeoBlocked,
						IP:        ipStr,
						Detail:    fmt.Sprintf("country not allowed: %s", geo.CountryCode),
						Timestamp: time.Now(),
					})
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		// 4. Check time window
		if a.windowStart != nil && a.windowEnd != nil {
			if !a.isInTimeWindow() {
				slog.Debug("ACL: outside access window", "ip", ipStr)
				a.emitEvent(ACLEvent{
					Type:      EventTimeBlocked,
					IP:        ipStr,
					Detail:    "outside access window",
					Timestamp: time.Now(),
				})
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isInTimeWindow checks if the current time is within the configured access window.
func (a *DynamicACL) isInTimeWindow() bool {
	now := time.Now().In(a.windowTZ)
	current := (&timeOfDay{Hour: now.Hour(), Minute: now.Minute()}).toMinutes()
	start := a.windowStart.toMinutes()
	end := a.windowEnd.toMinutes()

	if start <= end {
		// Normal range (e.g., 09:00 - 17:00)
		return current >= start && current < end
	}
	// Overnight range (e.g., 22:00 - 06:00)
	return current >= start || current < end
}

// Close shuts down the DynamicACL and releases resources.
func (a *DynamicACL) Close() {
	select {
	case <-a.done:
	default:
		close(a.done)
	}
	if a.geoIP != nil {
		a.geoIP.Close()
	}
}

func (a *DynamicACL) emitEvent(evt ACLEvent) {
	a.eventMu.RLock()
	fn := a.onEvent
	a.eventMu.RUnlock()

	if fn != nil {
		go fn(evt)
	}
}

func (a *DynamicACL) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.done:
			return
		case <-ticker.C:
			a.cleanupExpired()
		}
	}
}

func (a *DynamicACL) cleanupExpired() {
	a.banMu.Lock()
	defer a.banMu.Unlock()

	now := time.Now()
	for ip, expiry := range a.banned {
		if now.After(expiry) {
			delete(a.banned, ip)
			slog.Debug("ACL: ban expired", "ip", ip)
		}
	}

	// Clean up old failure records
	for ip, rec := range a.failures {
		if now.Sub(rec.lastAt) > a.banDuration {
			delete(a.failures, ip)
		}
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
