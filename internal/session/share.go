package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ShareLink represents a shareable read-only terminal link.
type ShareLink struct {
	Token      string
	SessionID  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	MaxViewers int
	Viewers    int

	// Broadcast channel for output to viewers
	broadcast chan []byte
	mu        sync.Mutex
	closed    bool
}

// ShareManager manages shareable read-only session links.
type ShareManager struct {
	links map[string]*ShareLink
	mu    sync.RWMutex
	done  chan struct{}
}

// NewShareManager creates a new share link manager.
func NewShareManager() *ShareManager {
	sm := &ShareManager{
		links: make(map[string]*ShareLink),
		done:  make(chan struct{}),
	}
	go sm.cleanupLoop()
	return sm
}

// Create generates a new share link for a session.
func (sm *ShareManager) Create(sessionID string, ttl time.Duration, maxViewers int) (*ShareLink, error) {
	if ttl == 0 {
		ttl = time.Hour
	}
	if maxViewers <= 0 {
		maxViewers = 10
	}

	token, err := generateShareToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	link := &ShareLink{
		Token:      token,
		SessionID:  sessionID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		MaxViewers: maxViewers,
		broadcast:  make(chan []byte, 256),
	}

	sm.mu.Lock()
	sm.links[token] = link
	sm.mu.Unlock()

	slog.Info("share link created", "token", token[:8]+"...", "session", sessionID, "ttl", ttl)
	return link, nil
}

// Get retrieves a share link by token.
func (sm *ShareManager) Get(token string) (*ShareLink, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	link, ok := sm.links[token]
	if !ok {
		return nil, false
	}

	if time.Now().After(link.ExpiresAt) {
		return nil, false
	}

	return link, true
}

// Remove deletes a share link.
func (sm *ShareManager) Remove(token string) {
	sm.mu.Lock()
	link, ok := sm.links[token]
	if ok {
		delete(sm.links, token)
		link.Close()
	}
	sm.mu.Unlock()
}

// AddViewer increments the viewer count. Returns false if max viewers reached.
func (sl *ShareLink) AddViewer() bool {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.Viewers >= sl.MaxViewers {
		return false
	}
	sl.Viewers++
	return true
}

// RemoveViewer decrements the viewer count.
func (sl *ShareLink) RemoveViewer() {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if sl.Viewers > 0 {
		sl.Viewers--
	}
}

// Broadcast sends output data to all viewers.
func (sl *ShareLink) Broadcast(data []byte) {
	sl.mu.Lock()
	if sl.closed {
		sl.mu.Unlock()
		return
	}
	sl.mu.Unlock()

	select {
	case sl.broadcast <- data:
	default:
		// Drop message if buffer full (viewers too slow)
	}
}

// Output returns the channel for receiving broadcast output.
func (sl *ShareLink) Output() <-chan []byte {
	return sl.broadcast
}

// ViewerCount returns the current viewer count.
func (sl *ShareLink) ViewerCount() int {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return sl.Viewers
}

// Close closes the share link broadcast channel.
func (sl *ShareLink) Close() {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if !sl.closed {
		sl.closed = true
		close(sl.broadcast)
	}
}

// BroadcastToSession sends output data to all share links associated with a session.
func (sm *ShareManager) BroadcastToSession(sessionID string, data []byte) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, link := range sm.links {
		if link.SessionID == sessionID && !link.closed {
			link.Broadcast(data)
		}
	}
}

// Close shuts down the share manager.
func (sm *ShareManager) Close() {
	close(sm.done)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, link := range sm.links {
		link.Close()
	}
	sm.links = make(map[string]*ShareLink)
}

func (sm *ShareManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.done:
			return
		case <-ticker.C:
			sm.cleanupExpired()
		}
	}
}

func (sm *ShareManager) cleanupExpired() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	for token, link := range sm.links {
		if now.After(link.ExpiresAt) {
			link.Close()
			delete(sm.links, token)
			slog.Info("share link expired", "token", token[:8]+"...")
		}
	}
}

func generateShareToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate share token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
