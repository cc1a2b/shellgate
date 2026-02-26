package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebhookNotifier sends audit entries as HTTP POST requests to a configured URL.
type WebhookNotifier struct {
	url         string
	eventFilter map[string]bool
	client      *http.Client
	queue       chan Entry
	done        chan struct{}
	wg          sync.WaitGroup
}

// NewWebhookNotifier creates a new webhook notifier.
// eventFilter is a comma-separated list of event types to forward (empty = all events).
func NewWebhookNotifier(url, eventFilter string) *WebhookNotifier {
	w := &WebhookNotifier{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
		queue:  make(chan Entry, 1000),
		done:   make(chan struct{}),
	}

	if eventFilter != "" {
		w.eventFilter = make(map[string]bool)
		for _, evt := range strings.Split(eventFilter, ",") {
			evt = strings.TrimSpace(evt)
			if evt != "" {
				w.eventFilter[evt] = true
			}
		}
	}

	w.wg.Add(1)
	go w.worker()

	return w
}

// Send queues an entry for async delivery.
func (w *WebhookNotifier) Send(entry Entry) {
	if w.eventFilter != nil && !w.eventFilter[entry.Event] {
		return
	}

	select {
	case w.queue <- entry:
	default:
		slog.Warn("webhook queue full, dropping event", "event", entry.Event)
	}
}

// Close stops the webhook worker and waits for it to drain.
func (w *WebhookNotifier) Close() {
	close(w.done)
	w.wg.Wait()
}

func (w *WebhookNotifier) worker() {
	defer w.wg.Done()
	for {
		select {
		case <-w.done:
			// Drain remaining entries (bounded — only what's in the buffer)
			for {
				select {
				case entry := <-w.queue:
					w.deliver(entry)
				default:
					return
				}
			}
		case entry := <-w.queue:
			w.deliver(entry)
		}
	}
}

func (w *WebhookNotifier) deliver(entry Entry) {
	body, err := json.Marshal(entry)
	if err != nil {
		slog.Error("webhook marshal failed", "error", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		slog.Error("webhook request creation failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ShellGate-Webhook/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		slog.Debug("webhook delivery failed", "error", err, "url", w.url)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Debug("webhook returned error", "status", resp.StatusCode, "url", w.url)
	}
}
