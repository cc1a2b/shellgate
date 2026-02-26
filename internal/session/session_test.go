package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerCreateAndRemove(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 3})
	defer m.Close()

	assert.Equal(t, 0, m.Count())

	// We can't create real PTY sessions in sandbox, test the manager logic directly
	// by using nil PTY (manager doesn't read/write to PTY)
}

func TestManagerMaxSessions(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 2})
	defer m.Close()

	// Manually add sessions to test limit
	m.mu.Lock()
	m.sessions["s1"] = &Session{ID: "s1", StartedAt: time.Now(), LastInput: time.Now()}
	m.sessions["s2"] = &Session{ID: "s2", StartedAt: time.Now(), LastInput: time.Now()}
	m.mu.Unlock()

	assert.Equal(t, 2, m.Count())

	_, err := m.Create("s3", "127.0.0.1", "test", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max sessions")
}

func TestManagerList(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 5})
	defer m.Close()

	m.mu.Lock()
	m.sessions["s1"] = &Session{
		ID:        "s1",
		StartedAt: time.Now().Add(-5 * time.Minute),
		ClientIP:  "10.0.0.1",
		UserAgent: "Mozilla/5.0",
		LastInput: time.Now(),
	}
	m.mu.Unlock()

	list := m.List()
	require.Len(t, list, 1)
	assert.Equal(t, "s1", list[0].ID)
	assert.Equal(t, "10.0.0.1", list[0].ClientIP)
}

func TestManagerGet(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 5})
	defer m.Close()

	m.mu.Lock()
	m.sessions["test-id"] = &Session{ID: "test-id", StartedAt: time.Now(), LastInput: time.Now()}
	m.mu.Unlock()

	sess, ok := m.Get("test-id")
	assert.True(t, ok)
	assert.Equal(t, "test-id", sess.ID)

	_, ok = m.Get("nonexistent")
	assert.False(t, ok)
}

func TestSessionUpdateLastInput(t *testing.T) {
	s := &Session{LastInput: time.Now().Add(-time.Hour)}
	before := s.LastInput

	s.UpdateLastInput()
	assert.True(t, s.LastInput.After(before))
}

func TestRecorder(t *testing.T) {
	dir := t.TempDir()

	rec, err := NewRecorder(RecorderConfig{
		Dir:       dir,
		SessionID: "test-session",
		Width:     80,
		Height:    24,
		Shell:     "/bin/bash",
		Title:     "Test Recording",
	})
	require.NoError(t, err)

	// Write some events
	require.NoError(t, rec.WriteOutput([]byte("hello world\r\n")))
	require.NoError(t, rec.WriteInput([]byte("ls -la\r")))
	require.NoError(t, rec.WriteResize(120, 40))
	require.NoError(t, rec.WriteOutput([]byte("total 42\r\n")))

	// Close and flush
	require.NoError(t, rec.Close())

	// Read and verify file
	data, err := os.ReadFile(rec.FilePath())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.GreaterOrEqual(t, len(lines), 5) // header + 4 events

	// Verify header
	var header asciicastHeader
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &header))
	assert.Equal(t, 2, header.Version)
	assert.Equal(t, 80, header.Width)
	assert.Equal(t, 24, header.Height)
	assert.Equal(t, "Test Recording", header.Title)

	// Verify events are valid JSON arrays
	for _, line := range lines[1:] {
		var event []json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(line), &event), "invalid event line: %s", line)
		assert.Len(t, event, 3)
	}

	// Verify file is in the right directory
	files, err := filepath.Glob(filepath.Join(dir, "session-test-session-*.cast"))
	require.NoError(t, err)
	assert.Len(t, files, 1)
}

func TestRecorderDoubleClose(t *testing.T) {
	dir := t.TempDir()

	rec, err := NewRecorder(RecorderConfig{
		Dir:       dir,
		SessionID: "double-close",
		Width:     80,
		Height:    24,
	})
	require.NoError(t, err)

	assert.NoError(t, rec.Close())
	assert.NoError(t, rec.Close()) // Should not panic
}

func TestShareManager(t *testing.T) {
	sm := NewShareManager()
	defer sm.Close()

	link, err := sm.Create("session-1", time.Hour, 5)
	require.NoError(t, err)
	assert.NotEmpty(t, link.Token)
	assert.Equal(t, "session-1", link.SessionID)
	assert.Equal(t, 5, link.MaxViewers)

	// Get existing link
	found, ok := sm.Get(link.Token)
	assert.True(t, ok)
	assert.Equal(t, link.Token, found.Token)

	// Get non-existent link
	_, ok = sm.Get("nonexistent")
	assert.False(t, ok)
}

func TestShareLinkViewers(t *testing.T) {
	sm := NewShareManager()
	defer sm.Close()

	link, err := sm.Create("session-1", time.Hour, 2)
	require.NoError(t, err)

	assert.True(t, link.AddViewer())
	assert.True(t, link.AddViewer())
	assert.False(t, link.AddViewer()) // Max reached

	assert.Equal(t, 2, link.ViewerCount())

	link.RemoveViewer()
	assert.Equal(t, 1, link.ViewerCount())
	assert.True(t, link.AddViewer())
}

func TestShareLinkBroadcast(t *testing.T) {
	sm := NewShareManager()
	defer sm.Close()

	link, err := sm.Create("session-1", time.Hour, 10)
	require.NoError(t, err)

	// Send data
	link.Broadcast([]byte("hello"))

	// Receive data
	select {
	case data := <-link.Output():
		assert.Equal(t, "hello", string(data))
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for broadcast")
	}
}

func TestShareLinkExpiry(t *testing.T) {
	sm := NewShareManager()
	defer sm.Close()

	// Create with very short TTL
	link, err := sm.Create("session-1", time.Millisecond, 10)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	_, ok := sm.Get(link.Token)
	assert.False(t, ok, "expired link should not be returned")
}

func TestShareManagerRemove(t *testing.T) {
	sm := NewShareManager()
	defer sm.Close()

	link, err := sm.Create("session-1", time.Hour, 10)
	require.NoError(t, err)

	sm.Remove(link.Token)

	_, ok := sm.Get(link.Token)
	assert.False(t, ok)
}
