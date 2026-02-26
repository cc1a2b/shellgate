package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cc1a2b/shellgate/internal/auth"
	"github.com/cc1a2b/shellgate/internal/pty"
	"github.com/cc1a2b/shellgate/internal/session"
	"github.com/gorilla/websocket"
)

const (
	// MaxMessageSize is the maximum allowed WebSocket message size (64KB).
	MaxMessageSize = 64 * 1024

	// WriteWait is the time allowed to write a message to the peer.
	WriteWait = 10 * time.Second

	// PongWait is the time allowed to read the next pong message from the peer.
	PongWait = 60 * time.Second

	// PingInterval is the interval at which pings are sent. Must be less than PongWait.
	PingInterval = (PongWait * 9) / 10

	// PTYReadBufferSize is the buffer size for reading from PTY.
	PTYReadBufferSize = 4096

	// FlushInterval is the interval for flushing buffered PTY output to WebSocket.
	FlushInterval = 10 * time.Millisecond
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
	CheckOrigin: func(r *http.Request) bool {
		return true // Auth is handled at middleware level
	},
}

// WSMessage represents a WebSocket message exchanged between client and server.
type WSMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

// handleWebSocket upgrades the HTTP connection to a WebSocket and bridges it to a PTY.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("websocket upgrade failed", "error", err, "remote", r.RemoteAddr)
		return
	}

	clientIP := extractIP(r.RemoteAddr).String()
	slog.Info("websocket connected", "remote", r.RemoteAddr)

	// Emit connection event
	if s.metrics != nil {
		s.metrics.IncConnection()
	}
	s.emitServerEvent("connect", map[string]string{
		"ip":         clientIP,
		"user_agent": r.UserAgent(),
	})
	s.auditLog("connect", "", clientIP, "websocket connected")

	// Create PTY session
	ptySess, err := pty.New(s.cfg.Shell, nil)
	if err != nil {
		slog.Error("pty allocation failed", "error", err)
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "failed to allocate terminal"))
		conn.Close()
		return
	}

	// Generate session ID
	sessionID, err := auth.GenerateToken(8)
	if err != nil {
		slog.Error("generate session id failed", "error", err)
		ptySess.Close()
		conn.Close()
		return
	}

	// Setup recorder if enabled
	var rec *session.Recorder
	if s.cfg.RecordEnabled {
		rec, err = session.NewRecorder(session.RecorderConfig{
			Dir:       s.cfg.RecordDir,
			SessionID: sessionID,
			Width:     80,
			Height:    24,
			Shell:     s.cfg.Shell,
		})
		if err != nil {
			slog.Error("recorder creation failed", "error", err)
			// Continue without recording
			rec = nil
		} else {
			slog.Info("recording session", "file", rec.FilePath())
		}
	}

	// Register session
	sess, err := s.sessions.Create(sessionID, r.RemoteAddr, r.UserAgent(), ptySess, rec)
	if err != nil {
		slog.Error("session creation failed", "error", err)
		ptySess.Close()
		if rec != nil {
			rec.Close()
		}
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, err.Error()))
		conn.Close()
		return
	}

	// Emit session creation event
	if s.metrics != nil {
		s.metrics.IncSessionCreated()
	}
	s.auditLog("session_create", sessionID, clientIP, "new session")

	ctx, cancel := context.WithCancel(r.Context())
	wsDone := make(chan struct{})

	var wsMu sync.Mutex

	// Write pump: PTY → WebSocket
	go s.writePump(ctx, conn, ptySess, &wsMu, wsDone, rec, sess)

	// Read pump: WebSocket → PTY (blocks until connection closes)
	s.readPump(ctx, conn, ptySess, &wsMu, rec, sess)

	// Cleanup
	cancel()
	<-wsDone
	s.sessions.Remove(sessionID)
	slog.Info("websocket disconnected", "remote", r.RemoteAddr, "session", sessionID)

	// Emit disconnect event
	if s.metrics != nil {
		s.metrics.IncSessionClosed()
	}
	duration := time.Since(sess.StartedAt).Truncate(time.Second).String()
	s.emitServerEvent("disconnect", map[string]string{
		"session_id": sessionID,
		"ip":         clientIP,
		"duration":   duration,
	})
	s.auditLog("session_close", sessionID, clientIP, "disconnected after "+duration)
}

// readPump reads messages from the WebSocket and forwards input to the PTY.
func (s *Server) readPump(ctx context.Context, conn *websocket.Conn, ptySess *pty.Session, wsMu *sync.Mutex, rec *session.Recorder, sess *session.Session) {
	defer conn.Close()

	conn.SetReadLimit(MaxMessageSize)
	conn.SetReadDeadline(time.Now().Add(PongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, raw, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				slog.Debug("websocket read error", "error", err)
			}
			return
		}

		var msg WSMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			slog.Debug("invalid websocket message", "error", err)
			continue
		}

		switch msg.Type {
		case "input":
			if len(msg.Data) > 0 {
				if _, err := ptySess.Write([]byte(msg.Data)); err != nil {
					slog.Debug("pty write error", "error", err)
					return
				}
				if sess != nil {
					sess.UpdateLastInput()
				}
				if rec != nil {
					_ = rec.WriteInput([]byte(msg.Data))
				}
			}
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 {
				if err := ptySess.Resize(msg.Cols, msg.Rows); err != nil {
					slog.Debug("pty resize error", "error", err)
				}
				if rec != nil {
					_ = rec.WriteResize(int(msg.Cols), int(msg.Rows))
				}
			}
		case "ping":
			wsMu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
			err := conn.WriteJSON(WSMessage{Type: "pong"})
			wsMu.Unlock()
			if err != nil {
				slog.Debug("pong write error", "error", err)
				return
			}
		default:
			slog.Debug("unknown message type", "type", msg.Type)
		}
	}
}

// writePump reads output from the PTY and sends it to the WebSocket client.
func (s *Server) writePump(ctx context.Context, conn *websocket.Conn, ptySess *pty.Session, wsMu *sync.Mutex, done chan<- struct{}, rec *session.Recorder, sess *session.Session) {
	defer close(done)

	ticker := time.NewTicker(PingInterval)
	defer ticker.Stop()

	flushTicker := time.NewTicker(FlushInterval)
	defer flushTicker.Stop()

	buf := make([]byte, PTYReadBufferSize)
	var outputBuf []byte
	var bufMu sync.Mutex

	// PTY read goroutine
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := ptySess.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])

				bufMu.Lock()
				outputBuf = append(outputBuf, data...)
				bufMu.Unlock()

				// Record output
				if rec != nil {
					_ = rec.WriteOutput(data)
				}

				// Broadcast to share viewers
				if s.shares != nil {
					s.broadcastToShares(sess.ID, data)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	flush := func() error {
		bufMu.Lock()
		if len(outputBuf) == 0 {
			bufMu.Unlock()
			return nil
		}
		data := make([]byte, len(outputBuf))
		copy(data, outputBuf)
		outputBuf = outputBuf[:0]
		bufMu.Unlock()

		msg := WSMessage{
			Type: "output",
			Data: string(data),
		}

		payload, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("marshal output: %w", err)
		}

		wsMu.Lock()
		_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
		err = conn.WriteMessage(websocket.TextMessage, payload)
		wsMu.Unlock()

		return err
	}

	for {
		select {
		case <-ctx.Done():
			_ = flush()
			return

		case <-ptySess.Done():
			_ = flush()
			wsMu.Lock()
			_ = conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "shell exited"))
			wsMu.Unlock()
			return

		case <-readDone:
			_ = flush()
			return

		case <-flushTicker.C:
			if err := flush(); err != nil {
				slog.Debug("flush error", "error", err)
				return
			}

		case <-ticker.C:
			wsMu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
			err := conn.WriteMessage(websocket.PingMessage, nil)
			wsMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// broadcastToShares sends output to all active share links for a session.
func (s *Server) broadcastToShares(sessionID string, data []byte) {
	if s.shares == nil {
		return
	}
	s.shares.BroadcastToSession(sessionID, data)
}

// handleShareWebSocket handles read-only WebSocket connections for shared sessions.
func (s *Server) handleShareWebSocket(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil {
		http.Error(w, "Sharing not enabled", http.StatusNotFound)
		return
	}

	// Extract token from URL: /ws/share/{token}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid share URL", http.StatusBadRequest)
		return
	}
	token := parts[3]

	link, ok := s.shares.Get(token)
	if !ok {
		http.Error(w, "Share link not found or expired", http.StatusNotFound)
		return
	}

	if !link.AddViewer() {
		http.Error(w, "Maximum viewers reached", http.StatusTooManyRequests)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		link.RemoveViewer()
		slog.Error("share websocket upgrade failed", "error", err)
		return
	}

	slog.Info("share viewer connected", "token", token[:8]+"...", "viewers", link.ViewerCount())

	// Write-only: send output to viewer
	go func() {
		defer func() {
			conn.Close()
			link.RemoveViewer()
			slog.Info("share viewer disconnected", "token", token[:8]+"...")
		}()

		for data := range link.Output() {
			msg := WSMessage{Type: "output", Data: string(data)}
			payload, err := json.Marshal(msg)
			if err != nil {
				return
			}

			conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}
		}
	}()

	// Read pump: discard all input from viewer (read-only)
	conn.SetReadLimit(512)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}
