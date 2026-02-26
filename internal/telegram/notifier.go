package telegram

import (
	"fmt"
	"log/slog"
	"time"
)

// Notifier wraps the Bot to provide event-driven notifications.
type Notifier struct {
	bot *Bot
}

// NewNotifier creates a new notifier attached to the given bot.
func NewNotifier(bot *Bot) *Notifier {
	return &Notifier{bot: bot}
}

// EventHandler returns a function suitable for Server.SetEventHandler().
func (n *Notifier) EventHandler() func(event string, detail map[string]string) {
	return func(event string, detail map[string]string) {
		msg := n.formatEvent(event, detail)
		if msg != "" {
			n.bot.SendNotification(msg)
		}
	}
}

// formatEvent converts a server event into a human-readable Telegram message.
func (n *Notifier) formatEvent(event string, detail map[string]string) string {
	ip := detail["ip"]
	sessionID := detail["session_id"]
	ua := detail["user_agent"]

	switch event {
	case "connect":
		geo := ""
		if country := detail["country"]; country != "" {
			geo = fmt.Sprintf(" (%s)", country)
		}
		return fmt.Sprintf("🔗 *New Connection*\nIP: `%s`%s\nUA: %s", ip, geo, ua)

	case "disconnect":
		dur := detail["duration"]
		return fmt.Sprintf("🔌 *Disconnected*\nSession: `%s`\nIP: `%s`\nDuration: %s", sessionID, ip, dur)

	case "auth_failure":
		return fmt.Sprintf("⚠️ *Auth Failure*\nIP: `%s`", ip)

	case "ip_banned":
		return fmt.Sprintf("🚫 *IP Banned*\nIP: `%s`\nReason: %s", ip, detail["detail"])

	case "session_timeout":
		return fmt.Sprintf("⏰ *Session Timeout*\nSession: `%s`", sessionID)

	case "server_start":
		addr := detail["addr"]
		return fmt.Sprintf("🟢 *Server Started*\nAddr: %s", addr)

	case "server_stop":
		return "🔴 *Server Stopped*"

	case "session_kill":
		return fmt.Sprintf("💀 *Session Killed*\nSession: `%s`", sessionID)

	case "bot_command":
		user := detail["user"]
		cmd := detail["command"]
		return fmt.Sprintf("🤖 Bot command: /%s by %s", cmd, user)

	default:
		slog.Debug("telegram: unhandled event", "event", event)
		return ""
	}
}

// ACLEventHandler returns a function suitable for DynamicACL.SetEventHandler().
func (n *Notifier) ACLEventHandler() func(event string, detail map[string]string) {
	return func(event string, detail map[string]string) {
		ip := detail["ip"]
		d := detail["detail"]
		var msg string
		switch event {
		case "ip_banned":
			msg = fmt.Sprintf("🚫 *IP Banned (fail2ban)*\nIP: `%s`\n%s", ip, d)
		case "ip_unbanned":
			msg = fmt.Sprintf("✅ *IP Unbanned*\nIP: `%s`", ip)
		default:
			return
		}
		n.bot.SendNotification(msg)
	}
}

// NotifyAutoClose sends a notification that the server auto-closed.
func (n *Notifier) NotifyAutoClose(ttl time.Duration) {
	n.bot.SendNotification(fmt.Sprintf("🔒 *Auto-Closed*\nServer closed after %s TTL expired.", ttl))
}
