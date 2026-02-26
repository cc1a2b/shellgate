package telegram

import (
	"fmt"
	"strings"
	"time"
)

// commandHandler is a function that handles a bot command.
type commandHandler func(b *Bot, chatID int64, args string)

// commandHandlers maps command names to their handlers.
var commandHandlers = map[string]commandHandler{
	"start":       cmdStart,
	"help":        cmdHelp,
	"open":        cmdOpen,
	"close":       cmdClose,
	"status":      cmdStatus,
	"whitelist":   cmdWhitelist,
	"unwhitelist": cmdUnwhitelist,
	"sessions":    cmdSessions,
	"kill":        cmdKill,
	"record":      cmdRecord,
	"share":       cmdShare,
	"ban":         cmdBan,
	"unban":       cmdUnban,
	"port":        cmdPort,
}

func cmdStart(b *Bot, chatID int64, args string) {
	b.reply(chatID, `*ShellGate Bot* 🛡️

You are now registered for notifications.

Use /help to see all available commands.`)
}

func cmdHelp(b *Bot, chatID int64, args string) {
	b.reply(chatID, `*ShellGate Commands:*

*Server Control:*
/open \[duration] — Start listener & generate access link
/close — Stop listener & kill all sessions
/status — Show server status
/port \[number] — Show or set listening port

*Access Control:*
/whitelist <ip/cidr> — Add IP to whitelist
/unwhitelist <ip/cidr> — Remove IP from whitelist
/ban <ip> — Ban an IP
/unban <ip> — Unban an IP

*Sessions:*
/sessions — List active sessions
/kill <id> — Kill a session
/share <id> — Generate share link
/record — Toggle recording on/off

/help — Show this message`)
}

func cmdOpen(b *Bot, chatID int64, args string) {
	if b.isRateLimited() {
		b.reply(chatID, "Rate limited. Wait 10 seconds between /open commands.")
		return
	}

	// Parse TTL
	ttl := 2 * time.Hour
	if args != "" {
		parsed, err := time.ParseDuration(args)
		if err != nil {
			b.reply(chatID, fmt.Sprintf("Invalid duration: %s\nExamples: 30m, 1h, 2h30m", args))
			return
		}
		if parsed < time.Minute {
			b.reply(chatID, "Minimum duration is 1 minute.")
			return
		}
		if parsed > 24*time.Hour {
			b.reply(chatID, "Maximum duration is 24 hours.")
			return
		}
		ttl = parsed
	}

	var port int
	var err error

	// Use stealth controller if available (stealth mode)
	if b.stealth != nil && b.cfg.Stealth {
		port, err = b.stealth.Open(ttl)
		if err != nil {
			b.reply(chatID, fmt.Sprintf("Failed to open: %s", err))
			return
		}
	} else {
		// Non-stealth: just ensure listener is running
		if !b.controller.IsListening() {
			if _, err := b.controller.StartListener(); err != nil {
				b.reply(chatID, fmt.Sprintf("Failed to start listener: %s", err))
				return
			}
		}
		port = b.controller.GetPort()
	}

	// Generate one-time token
	token, err := b.controller.GenerateOneTimeToken(ttl)
	if err != nil {
		b.reply(chatID, fmt.Sprintf("Failed to generate token: %s", err))
		return
	}

	url := b.buildURL(port, token)

	scheme := "HTTP"
	if b.cfg.TLSEnabled {
		scheme = "HTTPS"
	} else {
		scheme += " ⚠️ (no TLS)"
	}

	b.reply(chatID, fmt.Sprintf(`*ShellGate Open* ✅

Port: %d
Protocol: %s
Auto-closes in: %s

*Access Link (one-time use):*
%s`, port, scheme, ttl, url))
}

func cmdClose(b *Bot, chatID int64, args string) {
	if b.stealth != nil && b.cfg.Stealth {
		if err := b.stealth.Close(); err != nil {
			b.reply(chatID, fmt.Sprintf("Close error: %s", err))
			return
		}
	} else {
		if err := b.controller.StopListener(); err != nil {
			b.reply(chatID, fmt.Sprintf("Stop error: %s", err))
			return
		}
	}

	b.reply(chatID, "*ShellGate Closed* 🔒\n\nAll sessions killed. All tokens revoked.")
}

func cmdStatus(b *Bot, chatID int64, args string) {
	status := b.controller.GetStatus()

	state := "Stopped 🔴"
	if status.Listening {
		state = "Listening 🟢"
	}

	tls := "disabled"
	if status.TLSEnabled {
		tls = "enabled"
	}

	recording := "off"
	if status.RecordingOn {
		recording = "on"
	}

	b.reply(chatID, fmt.Sprintf(`*ShellGate Status*

State: %s
Port: %d
Uptime: %s
Sessions: %d
TLS: %s
Recording: %s
Banned IPs: %d`,
		state,
		status.Port,
		status.Uptime.Truncate(time.Second),
		status.Sessions,
		tls,
		recording,
		status.BannedIPs,
	))
}

func cmdWhitelist(b *Bot, chatID int64, args string) {
	if args == "" {
		// List current whitelist
		if b.acl == nil {
			b.reply(chatID, "ACL not available.")
			return
		}
		networks := b.acl.ListNetworks()
		if len(networks) == 0 {
			b.reply(chatID, "Whitelist is empty (all IPs allowed).")
			return
		}
		b.reply(chatID, fmt.Sprintf("*Whitelisted Networks:*\n```\n%s\n```", strings.Join(networks, "\n")))
		return
	}

	if err := b.controller.AddWhitelistIP(args); err != nil {
		b.reply(chatID, fmt.Sprintf("Error: %s", err))
		return
	}
	b.reply(chatID, fmt.Sprintf("Added `%s` to whitelist.", args))
}

func cmdUnwhitelist(b *Bot, chatID int64, args string) {
	if args == "" {
		b.reply(chatID, "Usage: /unwhitelist <ip/cidr>")
		return
	}
	if err := b.controller.RemoveWhitelistIP(args); err != nil {
		b.reply(chatID, fmt.Sprintf("Error: %s", err))
		return
	}
	b.reply(chatID, fmt.Sprintf("Removed `%s` from whitelist.", args))
}

func cmdSessions(b *Bot, chatID int64, args string) {
	sessions := b.controller.ListSessions()
	if len(sessions) == 0 {
		b.reply(chatID, "No active sessions.")
		return
	}

	var sb strings.Builder
	sb.WriteString("*Active Sessions:*\n\n")
	for _, s := range sessions {
		ua := s.UserAgent
		if len(ua) > 30 {
			ua = ua[:27] + "..."
		}
		sb.WriteString(fmt.Sprintf("ID: `%s`\nIP: %s\nDuration: %s\nUA: %s\n\n",
			s.ID, s.ClientIP, s.Duration.Truncate(time.Second), ua))
	}
	b.reply(chatID, sb.String())
}

func cmdKill(b *Bot, chatID int64, args string) {
	if args == "" {
		b.reply(chatID, "Usage: /kill <session-id>")
		return
	}
	if err := b.controller.KillSession(args); err != nil {
		b.reply(chatID, fmt.Sprintf("Error: %s", err))
		return
	}
	b.reply(chatID, fmt.Sprintf("Session `%s` killed.", args))
}

func cmdRecord(b *Bot, chatID int64, args string) {
	state := b.controller.ToggleRecording()
	if state {
		b.reply(chatID, "Recording: *ON*")
	} else {
		b.reply(chatID, "Recording: *OFF*")
	}
}

func cmdShare(b *Bot, chatID int64, args string) {
	if args == "" {
		b.reply(chatID, "Usage: /share <session-id>")
		return
	}
	token, err := b.controller.CreateShareLink(args)
	if err != nil {
		b.reply(chatID, fmt.Sprintf("Error: %s", err))
		return
	}

	port := b.controller.GetPort()
	scheme := "http"
	if b.cfg.TLSEnabled {
		scheme = "https"
	}
	host := b.cfg.ExternalHost
	if host == "" {
		host = "localhost"
	}

	url := fmt.Sprintf("%s://%s:%d/ws/share/%s", scheme, host, port, token)
	b.reply(chatID, fmt.Sprintf("*Share Link (read-only):*\n%s", url))
}

func cmdBan(b *Bot, chatID int64, args string) {
	if args == "" {
		// List banned IPs
		if b.acl == nil {
			b.reply(chatID, "ACL not available.")
			return
		}
		banned := b.acl.ListBanned()
		if len(banned) == 0 {
			b.reply(chatID, "No banned IPs.")
			return
		}
		var sb strings.Builder
		sb.WriteString("*Banned IPs:*\n```\n")
		for ip, expiry := range banned {
			sb.WriteString(fmt.Sprintf("%s  (expires %s)\n", ip, expiry.Format("15:04:05")))
		}
		sb.WriteString("```")
		b.reply(chatID, sb.String())
		return
	}

	if b.acl == nil {
		b.reply(chatID, "ACL not available.")
		return
	}
	b.acl.Ban(args)
	b.reply(chatID, fmt.Sprintf("Banned `%s`.", args))
}

func cmdUnban(b *Bot, chatID int64, args string) {
	if args == "" {
		b.reply(chatID, "Usage: /unban <ip>")
		return
	}
	if b.acl == nil {
		b.reply(chatID, "ACL not available.")
		return
	}
	b.acl.Unban(args)
	b.reply(chatID, fmt.Sprintf("Unbanned `%s`.", args))
}

func cmdPort(b *Bot, chatID int64, args string) {
	if args == "" {
		b.reply(chatID, fmt.Sprintf("Current port: %d", b.controller.GetPort()))
		return
	}

	var port int
	if _, err := fmt.Sscanf(args, "%d", &port); err != nil || port < 1 || port > 65535 {
		b.reply(chatID, "Invalid port number. Must be 1-65535.")
		return
	}

	b.controller.SetPort(port)
	b.reply(chatID, fmt.Sprintf("Port set to %d. Takes effect on next /open.", port))
}
