// Package audit provides structured JSON audit logging, webhook notifications,
// and Prometheus-format metrics for ShellGate.
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry represents a single audit log entry.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	SessionID string    `json:"session_id,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	Country   string    `json:"country,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

// Logger writes structured JSON audit log entries to a file.
type Logger struct {
	file    *os.File
	encoder *json.Encoder
	mu      sync.Mutex
	webhook *WebhookNotifier
}

// NewLogger creates a new audit logger that writes to the given file path.
// Creates parent directories if needed.
func NewLogger(path string) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create audit log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	return &Logger{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// SetWebhook configures a webhook notifier for forwarding audit events.
func (l *Logger) SetWebhook(w *WebhookNotifier) {
	l.mu.Lock()
	l.webhook = w
	l.mu.Unlock()
}

// Log writes an audit entry to the log file and optionally forwards it to webhooks.
func (l *Logger) Log(entry Entry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	l.mu.Lock()
	if err := l.encoder.Encode(entry); err != nil {
		slog.Error("audit log write failed", "error", err)
	}
	webhook := l.webhook
	l.mu.Unlock()

	// Forward to webhook asynchronously
	if webhook != nil {
		webhook.Send(entry)
	}
}

// Close flushes and closes the audit log file.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		_ = l.file.Sync()
		l.file.Close()
	}
	if l.webhook != nil {
		l.webhook.Close()
	}
}
