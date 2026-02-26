package audit

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Metrics provides hand-written Prometheus-format metrics without heavy dependencies.
type Metrics struct {
	connectionsTotal   atomic.Int64
	authSuccessTotal   atomic.Int64
	authFailureTotal   atomic.Int64
	sessionsActive     atomic.Int64
	sessionsCreated    atomic.Int64
	sessionsClosed     atomic.Int64
	bannedIPs          atomic.Int64
	wsMessagesIn       atomic.Int64
	wsMessagesOut      atomic.Int64
}

// NewMetrics creates a new metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// IncConnection increments the total connections counter.
func (m *Metrics) IncConnection() {
	m.connectionsTotal.Add(1)
}

// IncAuthSuccess increments the successful auth counter.
func (m *Metrics) IncAuthSuccess() {
	m.authSuccessTotal.Add(1)
}

// IncAuthFailure increments the failed auth counter.
func (m *Metrics) IncAuthFailure() {
	m.authFailureTotal.Add(1)
}

// IncSessionCreated increments the sessions created counter.
func (m *Metrics) IncSessionCreated() {
	m.sessionsCreated.Add(1)
}

// IncSessionClosed increments the sessions closed counter.
func (m *Metrics) IncSessionClosed() {
	m.sessionsClosed.Add(1)
}

// SetActiveSessions sets the current active sessions gauge.
func (m *Metrics) SetActiveSessions(n int) {
	m.sessionsActive.Store(int64(n))
}

// IncBannedIPs increments the banned IP counter.
func (m *Metrics) IncBannedIPs() {
	m.bannedIPs.Add(1)
}

// DecBannedIPs decrements the banned IP counter.
func (m *Metrics) DecBannedIPs() {
	m.bannedIPs.Add(-1)
}

// IncWSMessagesIn increments the inbound WebSocket message counter.
func (m *Metrics) IncWSMessagesIn() {
	m.wsMessagesIn.Add(1)
}

// IncWSMessagesOut increments the outbound WebSocket message counter.
func (m *Metrics) IncWSMessagesOut() {
	m.wsMessagesOut.Add(1)
}

// Render returns all metrics in Prometheus exposition format.
func (m *Metrics) Render() string {
	var sb strings.Builder

	writeMetric := func(name, help, mtype string, value int64) {
		sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, help))
		sb.WriteString(fmt.Sprintf("# TYPE %s %s\n", name, mtype))
		sb.WriteString(fmt.Sprintf("%s %d\n", name, value))
	}

	writeMetric("shellgate_connections_total", "Total WebSocket connections", "counter", m.connectionsTotal.Load())
	writeMetric("shellgate_auth_success_total", "Total successful authentications", "counter", m.authSuccessTotal.Load())
	writeMetric("shellgate_auth_failure_total", "Total failed authentications", "counter", m.authFailureTotal.Load())
	writeMetric("shellgate_sessions_active", "Currently active sessions", "gauge", m.sessionsActive.Load())
	writeMetric("shellgate_sessions_created_total", "Total sessions created", "counter", m.sessionsCreated.Load())
	writeMetric("shellgate_sessions_closed_total", "Total sessions closed", "counter", m.sessionsClosed.Load())
	writeMetric("shellgate_banned_ips", "Currently banned IPs", "gauge", m.bannedIPs.Load())
	writeMetric("shellgate_ws_messages_in_total", "Total inbound WebSocket messages", "counter", m.wsMessagesIn.Load())
	writeMetric("shellgate_ws_messages_out_total", "Total outbound WebSocket messages", "counter", m.wsMessagesOut.Load())

	return sb.String()
}
