// Package session provides session lifecycle management for ShellGate.
package session

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cc1a2b/shellgate/internal/pty"
)

// Session represents an active terminal session.
type Session struct {
	ID        string
	StartedAt time.Time
	ClientIP  string
	UserAgent string
	PTY       *pty.Session
	Recorder  *Recorder
	LastInput time.Time

	mu sync.Mutex
}

// UpdateLastInput records the timestamp of the last input.
func (s *Session) UpdateLastInput() {
	s.mu.Lock()
	s.LastInput = time.Now()
	s.mu.Unlock()
}

// Manager tracks active sessions with lifecycle controls.
type Manager struct {
	sessions    map[string]*Session
	mu          sync.RWMutex
	maxSessions int
	timeout     time.Duration
	idleTimeout time.Duration
	done        chan struct{}
}

// ManagerConfig holds configuration for the session manager.
type ManagerConfig struct {
	MaxSessions int
	Timeout     time.Duration
	IdleTimeout time.Duration
}

// NewManager creates a new session manager.
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 5
	}

	m := &Manager{
		sessions:    make(map[string]*Session),
		maxSessions: cfg.MaxSessions,
		timeout:     cfg.Timeout,
		idleTimeout: cfg.IdleTimeout,
		done:        make(chan struct{}),
	}

	// Start cleanup goroutine
	go m.cleanupLoop()

	return m
}

// Create registers a new session. Returns an error if max sessions exceeded.
func (m *Manager) Create(id, clientIP, userAgent string, ptySess *pty.Session, rec *Recorder) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.sessions) >= m.maxSessions {
		return nil, fmt.Errorf("max sessions (%d) reached", m.maxSessions)
	}

	now := time.Now()
	sess := &Session{
		ID:        id,
		StartedAt: now,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		PTY:       ptySess,
		Recorder:  rec,
		LastInput: now,
	}

	m.sessions[id] = sess
	slog.Info("session created", "id", id, "remote", clientIP, "active", len(m.sessions))
	return sess, nil
}

// Get retrieves a session by ID.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// Remove removes and cleans up a session.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()

	if ok {
		if sess.Recorder != nil {
			sess.Recorder.Close()
		}
		if sess.PTY != nil {
			sess.PTY.Close()
		}
		slog.Info("session removed", "id", id, "active", m.Count())
	}
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// SessionInfo is a serializable snapshot of session metadata.
type SessionInfo struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"started_at"`
	ClientIP  string    `json:"client_ip"`
	UserAgent string    `json:"user_agent"`
	Duration  string    `json:"duration"`
}

// List returns info about all active sessions.
func (m *Manager) List() []SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, SessionInfo{
			ID:        s.ID,
			StartedAt: s.StartedAt,
			ClientIP:  s.ClientIP,
			UserAgent: s.UserAgent,
			Duration:  time.Since(s.StartedAt).Truncate(time.Second).String(),
		})
	}
	return result
}

// Close shuts down the manager and all active sessions.
func (m *Manager) Close() {
	close(m.done)

	m.mu.Lock()
	defer m.mu.Unlock()

	for id, sess := range m.sessions {
		if sess.Recorder != nil {
			sess.Recorder.Close()
		}
		if sess.PTY != nil {
			sess.PTY.Close()
		}
		slog.Info("session closed on shutdown", "id", id)
	}
	m.sessions = make(map[string]*Session)
}

// cleanupLoop periodically checks for timed-out and idle sessions.
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *Manager) cleanup() {
	m.mu.RLock()
	var toRemove []string
	now := time.Now()

	for id, sess := range m.sessions {
		// Check absolute timeout
		if m.timeout > 0 && now.Sub(sess.StartedAt) > m.timeout {
			toRemove = append(toRemove, id)
			slog.Info("session timed out", "id", id, "duration", now.Sub(sess.StartedAt))
			continue
		}

		// Check idle timeout
		sess.mu.Lock()
		lastInput := sess.LastInput
		sess.mu.Unlock()

		if m.idleTimeout > 0 && now.Sub(lastInput) > m.idleTimeout {
			toRemove = append(toRemove, id)
			slog.Info("session idle timeout", "id", id, "idle", now.Sub(lastInput))
		}
	}
	m.mu.RUnlock()

	for _, id := range toRemove {
		m.Remove(id)
	}
}
