package telegram

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockController implements ServerController for testing.
type mockController struct {
	listening  bool
	port       int
	recording  bool
	sessions   []SessionInfo
	lastToken  string
	killCalled string
}

func (m *mockController) StartListener() (string, error)    { m.listening = true; return "0.0.0.0:8080", nil }
func (m *mockController) StopListener() error               { m.listening = false; return nil }
func (m *mockController) IsListening() bool                  { return m.listening }
func (m *mockController) GenerateOneTimeToken(ttl time.Duration) (string, error) {
	m.lastToken = "test-token-abc123"
	return m.lastToken, nil
}
func (m *mockController) RevokeToken(token string) error     { return nil }
func (m *mockController) GetStatus() ServerStatus {
	return ServerStatus{
		Listening:   m.listening,
		Port:        m.port,
		Uptime:      5 * time.Minute,
		Sessions:    len(m.sessions),
		TLSEnabled:  false,
		RecordingOn: m.recording,
		BannedIPs:   0,
	}
}
func (m *mockController) ListSessions() []SessionInfo        { return m.sessions }
func (m *mockController) KillSession(id string) error        { m.killCalled = id; return nil }
func (m *mockController) AddWhitelistIP(cidr string) error   { return nil }
func (m *mockController) RemoveWhitelistIP(cidr string) error { return nil }
func (m *mockController) ToggleRecording() bool              { m.recording = !m.recording; return m.recording }
func (m *mockController) CreateShareLink(sessionID string) (string, error) {
	return "share-token-xyz", nil
}
func (m *mockController) GetPort() int                       { return m.port }
func (m *mockController) SetPort(port int)                   { m.port = port }

func TestBuildURL(t *testing.T) {
	bot := &Bot{
		cfg: BotConfig{
			ExternalHost: "myserver.com",
			TLSEnabled:   true,
		},
	}

	url := bot.buildURL(8443, "abc123token")
	assert.Equal(t, "https://myserver.com:8443/?token=abc123token", url)

	bot.cfg.TLSEnabled = false
	url = bot.buildURL(8080, "token123")
	assert.Equal(t, "http://myserver.com:8080/?token=token123", url)
}

func TestBuildURLDefaultHost(t *testing.T) {
	bot := &Bot{
		cfg: BotConfig{},
	}

	url := bot.buildURL(8080, "tok")
	assert.Equal(t, "http://localhost:8080/?token=tok", url)
}

func TestRateLimiting(t *testing.T) {
	bot := &Bot{}

	// First call should not be rate limited
	assert.False(t, bot.isRateLimited())

	// Second call within 10s should be rate limited
	assert.True(t, bot.isRateLimited())
}

func TestCommandHandlersExist(t *testing.T) {
	expectedCommands := []string{
		"start", "help", "open", "close", "status",
		"whitelist", "unwhitelist", "sessions", "kill",
		"record", "share", "ban", "unban", "port",
	}

	for _, cmd := range expectedCommands {
		_, ok := commandHandlers[cmd]
		assert.True(t, ok, "command handler missing: %s", cmd)
	}
}

func TestNotifierFormatEvent(t *testing.T) {
	notifier := &Notifier{bot: &Bot{}}

	tests := []struct {
		event  string
		detail map[string]string
		want   string
	}{
		{
			"connect",
			map[string]string{"ip": "1.2.3.4", "user_agent": "Mozilla"},
			"New Connection",
		},
		{
			"disconnect",
			map[string]string{"session_id": "abc", "ip": "1.2.3.4", "duration": "5m"},
			"Disconnected",
		},
		{
			"auth_failure",
			map[string]string{"ip": "5.6.7.8"},
			"Auth Failure",
		},
		{
			"server_start",
			map[string]string{"addr": "0.0.0.0:8080"},
			"Server Started",
		},
		{
			"server_stop",
			nil,
			"Server Stopped",
		},
	}

	for _, tt := range tests {
		t.Run(tt.event, func(t *testing.T) {
			msg := notifier.formatEvent(tt.event, tt.detail)
			assert.Contains(t, msg, tt.want)
		})
	}
}
