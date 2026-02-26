package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// OneTimeToken represents a single-use authentication token with expiry.
type OneTimeToken struct {
	Token     string
	ExpiresAt time.Time
	Used      bool
}

// OneTimeTokenStore manages single-use tokens for one-time access links.
type OneTimeTokenStore struct {
	tokens map[string]*OneTimeToken
	mu     sync.RWMutex
	done   chan struct{}
}

// NewOneTimeTokenStore creates a new one-time token store with periodic cleanup.
func NewOneTimeTokenStore() *OneTimeTokenStore {
	s := &OneTimeTokenStore{
		tokens: make(map[string]*OneTimeToken),
		done:   make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// cleanupLoop removes expired tokens every 5 minutes.
func (s *OneTimeTokenStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.Cleanup()
		}
	}
}

// Stop stops the cleanup goroutine.
func (s *OneTimeTokenStore) Stop() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

// Generate creates a new one-time token with the given TTL.
// Returns the token string (32-byte hex-encoded = 64 chars).
func (s *OneTimeTokenStore) Generate(ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate one-time token: %w", err)
	}

	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.tokens[token] = &OneTimeToken{
		Token:     token,
		ExpiresAt: time.Now().Add(ttl),
	}
	s.mu.Unlock()

	return token, nil
}

// Validate checks if a token is valid and consumes it on first use.
// Returns true only once per token.
func (s *OneTimeTokenStore) Validate(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	ot, ok := s.tokens[token]
	if !ok {
		return false
	}

	if ot.Used || time.Now().After(ot.ExpiresAt) {
		delete(s.tokens, token)
		return false
	}

	// Consume the token
	ot.Used = true
	delete(s.tokens, token)
	return true
}

// Revoke removes a specific token.
func (s *OneTimeTokenStore) Revoke(token string) {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
}

// RevokeAll removes all tokens.
func (s *OneTimeTokenStore) RevokeAll() {
	s.mu.Lock()
	s.tokens = make(map[string]*OneTimeToken)
	s.mu.Unlock()
}

// Cleanup removes expired tokens.
func (s *OneTimeTokenStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for token, ot := range s.tokens {
		if now.After(ot.ExpiresAt) || ot.Used {
			delete(s.tokens, token)
		}
	}
}

// Count returns the number of active (non-expired, non-used) tokens.
func (s *OneTimeTokenStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, ot := range s.tokens {
		if !ot.Used && now.Before(ot.ExpiresAt) {
			count++
		}
	}
	return count
}
