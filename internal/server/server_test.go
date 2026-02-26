package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ptyPkg "github.com/cc1a2b/shellgate/internal/pty"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	cfg := Config{
		Host:  "127.0.0.1",
		Port:  0,
		Shell: "/bin/sh",
	}

	srv, err := New(cfg)
	require.NoError(t, err)

	ts := httptest.NewServer(srv.mux)
	return srv, ts
}

// requirePTY skips the test if PTY allocation is not available.
func requirePTY(t *testing.T) {
	t.Helper()
	sess, err := ptyPkg.New("/bin/sh", nil)
	if err != nil {
		t.Skipf("PTY not available in this environment: %v", err)
	}
	sess.Close()
}

func TestHealthEndpoint(t *testing.T) {
	_, ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
}

func TestStaticFileServing(t *testing.T) {
	_, ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

func TestWebSocketHandshake(t *testing.T) {
	_, ts := newTestServer(t)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
}

func TestWebSocketMessageExchange(t *testing.T) {
	requirePTY(t)

	_, ts := newTestServer(t)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send resize
	resizeMsg := WSMessage{Type: "resize", Cols: 80, Rows: 24}
	err = conn.WriteJSON(resizeMsg)
	require.NoError(t, err)

	// Send a command
	inputMsg := WSMessage{Type: "input", Data: "echo ws_test_ok\n"}
	err = conn.WriteJSON(inputMsg)
	require.NoError(t, err)

	// Read output messages until we find our marker
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	found := false
	for i := 0; i < 50; i++ {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg WSMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		if msg.Type == "output" && strings.Contains(msg.Data, "ws_test_ok") {
			found = true
			break
		}
	}

	assert.True(t, found, "expected to find ws_test_ok in output")
}

func TestWebSocketPingPong(t *testing.T) {
	requirePTY(t)

	_, ts := newTestServer(t)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send ping message (application-level)
	err = conn.WriteJSON(WSMessage{Type: "ping"})
	require.NoError(t, err)

	// Read until we get a pong
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	found := false
	for i := 0; i < 20; i++ {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg WSMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		if msg.Type == "pong" {
			found = true
			break
		}
	}

	assert.True(t, found, "expected pong response")
}

func TestWebSocketInvalidMessage(t *testing.T) {
	requirePTY(t)

	_, ts := newTestServer(t)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send invalid JSON — server should not crash
	err = conn.WriteMessage(websocket.TextMessage, []byte("not json"))
	require.NoError(t, err)

	// Server should still be alive — send a valid message
	err = conn.WriteJSON(WSMessage{Type: "ping"})
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 20; i++ {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg WSMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		if msg.Type == "pong" {
			return // Success
		}
	}

	t.Fatal("server did not respond after invalid message")
}
