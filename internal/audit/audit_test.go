package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger_WriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path)
	require.NoError(t, err)
	defer logger.Close()

	// Write some entries
	logger.Log(Entry{
		Event:    "session_create",
		SessionID: "abc123",
		ClientIP: "1.2.3.4",
		Country:  "SA",
		Detail:   "new session",
	})

	logger.Log(Entry{
		Event:    "auth_failure",
		ClientIP: "5.6.7.8",
		Country:  "CN",
		Detail:   "invalid token",
	})

	logger.Close()

	// Read and verify
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry Entry
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &entry))
		entries = append(entries, entry)
	}

	require.Len(t, entries, 2)

	assert.Equal(t, "session_create", entries[0].Event)
	assert.Equal(t, "abc123", entries[0].SessionID)
	assert.Equal(t, "1.2.3.4", entries[0].ClientIP)
	assert.Equal(t, "SA", entries[0].Country)
	assert.False(t, entries[0].Timestamp.IsZero())

	assert.Equal(t, "auth_failure", entries[1].Event)
	assert.Equal(t, "5.6.7.8", entries[1].ClientIP)
}

func TestLogger_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "deep", "audit.jsonl")

	logger, err := NewLogger(path)
	require.NoError(t, err)
	defer logger.Close()

	logger.Log(Entry{Event: "test"})
	logger.Close()

	_, err = os.Stat(path)
	assert.NoError(t, err)
}

func TestMetrics_Render(t *testing.T) {
	m := NewMetrics()

	m.IncConnection()
	m.IncConnection()
	m.IncAuthSuccess()
	m.IncAuthFailure()
	m.IncSessionCreated()
	m.SetActiveSessions(3)

	output := m.Render()

	assert.Contains(t, output, "shellgate_connections_total 2")
	assert.Contains(t, output, "shellgate_auth_success_total 1")
	assert.Contains(t, output, "shellgate_auth_failure_total 1")
	assert.Contains(t, output, "shellgate_sessions_active 3")
	assert.Contains(t, output, "shellgate_sessions_created_total 1")
	assert.Contains(t, output, "# TYPE shellgate_connections_total counter")
	assert.Contains(t, output, "# TYPE shellgate_sessions_active gauge")
}

func TestWebhookNotifier_EventFilter(t *testing.T) {
	w := NewWebhookNotifier("http://localhost:9999/webhook", "auth_failure,session_create")
	defer w.Close()

	assert.True(t, w.eventFilter["auth_failure"])
	assert.True(t, w.eventFilter["session_create"])
	assert.False(t, w.eventFilter["connect"])
}

func TestWebhookNotifier_NoFilter(t *testing.T) {
	w := NewWebhookNotifier("http://localhost:9999/webhook", "")
	defer w.Close()

	assert.Nil(t, w.eventFilter)
}

func TestWebhookNotifier_QueueDrop(t *testing.T) {
	w := NewWebhookNotifier("http://localhost:1/unreachable", "")
	defer w.Close()

	// Fill the queue (1000 capacity)
	for i := 0; i < 1001; i++ {
		w.Send(Entry{Event: "test"})
	}

	// Should not panic or block
	time.Sleep(10 * time.Millisecond)
}

func TestMetrics_Concurrent(t *testing.T) {
	m := NewMetrics()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			m.IncConnection()
			m.IncAuthSuccess()
			m.IncAuthFailure()
			m.IncSessionCreated()
			m.IncWSMessagesIn()
			m.IncWSMessagesOut()
		}
		close(done)
	}()

	// Concurrent reads
	for i := 0; i < 100; i++ {
		_ = m.Render()
	}

	<-done

	output := m.Render()
	assert.Contains(t, output, "shellgate_connections_total 1000")
}

func TestMetrics_PrometheusFormat(t *testing.T) {
	m := NewMetrics()
	m.IncConnection()

	output := m.Render()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Each metric should have HELP, TYPE, and value lines
	helpCount := 0
	typeCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "# HELP") {
			helpCount++
		}
		if strings.HasPrefix(line, "# TYPE") {
			typeCount++
		}
	}

	assert.Equal(t, 9, helpCount)
	assert.Equal(t, 9, typeCount)
}
