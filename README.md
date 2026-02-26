# ShellGate

**Your server is one click away.**

Instant web-based terminal access to any server from a single binary. Install with one command, get a secure browser terminal in seconds.

[![CI](https://github.com/cc1a2b/shellgate/actions/workflows/ci.yml/badge.svg)](https://github.com/cc1a2b/shellgate/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cc1a2b/shellgate)](https://goreportcard.com/report/github.com/cc1a2b/shellgate)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why ShellGate?

- **Zero dependencies** — Single binary, embedded web assets. No Node.js, no Python, no runtime.
- **Secure by default** — Auto-generated auth token, TLS support, fail2ban, GeoIP filtering. Never runs open.
- **Telegram control plane** — Open/close your server, generate one-time access links, get real-time alerts — all from Telegram.
- **Stealth mode** — Server starts silent. One Telegram command opens it on a random port with a one-time token, auto-closes after a TTL.
- **Production-ready** — Session recording, sharing, audit logging, Prometheus metrics, webhook notifications.

## Quick Start

```bash
# Install
curl -sL https://raw.githubusercontent.com/cc1a2b/shellgate/main/scripts/install.sh | bash

# Run (auto-generates auth token)
shellgate

# Or with Go
go install github.com/cc1a2b/shellgate/cmd/shellgate@latest
shellgate
```

Open `http://your-server:8080?token=<printed-token>` in your browser.

## Usage

```bash
# Basic (auto token auth)
shellgate

# Password auth with TLS
shellgate --auth password --password mysecret --tls

# With Let's Encrypt
shellgate --tls --domain myserver.example.com

# Record sessions + enable sharing
shellgate --record --share

# Stealth mode with Telegram bot
shellgate --stealth --telegram \
  --telegram-token "$SHELLGATE_TELEGRAM_TOKEN" \
  --telegram-users "123456789" \
  --external-host myserver.com --tls

# GeoIP filtering (allow only specific countries)
shellgate --geoip --geoip-db /path/to/GeoLite2-Country.mmdb \
  --allowed-countries "US,GB,SA"

# Time-restricted access window
shellgate --access-window-start 09:00 --access-window-end 17:00 \
  --access-window-tz "Asia/Riyadh"

# Audit logging + Prometheus metrics
shellgate --audit-log /var/log/shellgate.jsonl --metrics

# Full hardened setup
shellgate --tls --stealth --telegram \
  --telegram-token "$SHELLGATE_TELEGRAM_TOKEN" \
  --telegram-users "123456789" \
  --external-host myserver.com \
  --max-failed-attempts 5 --ban-duration 1h \
  --geoip --geoip-db /path/to/GeoLite2-Country.mmdb \
  --allowed-countries "SA" \
  --access-window-start 08:00 --access-window-end 22:00 \
  --access-window-tz "Asia/Riyadh" \
  --audit-log /var/log/shellgate.jsonl --metrics \
  --auto-close 2h --random-port
```

## Telegram Bot

The killer feature. Control ShellGate entirely from Telegram — no SSH, no open ports, no exposed surface.

### Setup

1. Create a bot via [@BotFather](https://t.me/BotFather) and get the token.
2. Get your Telegram user ID (send `/start` to [@userinfobot](https://t.me/userinfobot)).
3. Set the token as an environment variable:
   ```bash
   export SHELLGATE_TELEGRAM_TOKEN="your-bot-token"
   ```
4. Start ShellGate with Telegram enabled:
   ```bash
   shellgate --telegram --telegram-users "YOUR_USER_ID" --external-host your-server.com --tls --stealth
   ```

### Commands

| Command | Description |
|---------|-------------|
| `/open [duration]` | Start listener, generate one-time access link (e.g. `/open 2h`) |
| `/close` | Stop listener, kill all sessions, revoke all tokens |
| `/status` | Show server status, uptime, sessions, TLS, banned IPs |
| `/sessions` | List active sessions with ID, IP, duration |
| `/kill <id>` | Kill a specific session |
| `/whitelist [ip]` | Add IP/CIDR to whitelist or list current |
| `/unwhitelist <ip>` | Remove IP/CIDR from whitelist |
| `/ban [ip]` | Ban an IP or list banned IPs |
| `/unban <ip>` | Remove ban |
| `/record` | Toggle session recording on/off |
| `/share <id>` | Generate read-only share link for a session |
| `/port [num]` | Show or change listening port |
| `/help` | Show all commands |

### `/open` Flow

```
You send: /open 2h

ShellGate responds:
  Server open on port 34821
  https://myserver.com:34821/?token=a3f8c9...
  Auto-closes in 2h

→ Click the link from any device
→ Full terminal in your browser
→ Auto-closes and cleans up after 2h
```

### Real-Time Notifications

The bot sends alerts for:
- New connections (IP, user-agent)
- Disconnections (session duration)
- Failed auth attempts
- IP bans (fail2ban triggers)
- Server start/stop

## Stealth Mode

Start the server without opening any ports. The listener only activates when you send `/open` via Telegram.

```bash
shellgate --stealth --random-port --auto-close 1h --telegram ...
```

- `--stealth` — Don't listen on startup. Wait for Telegram `/open`.
- `--random-port` — Pick a random port (10000-65000) on each `/open`.
- `--auto-close 1h` — Automatically close after the TTL expires.
- `--port-range-min` / `--port-range-max` — Custom port range.

## Security

ShellGate is designed with security as a first-class concern:

- **Never runs without auth** unless you explicitly pass `--auth none --i-know-what-im-doing`
- **Token auth**: 256-bit random token, constant-time comparison
- **Password auth**: bcrypt hashing, rate-limited login (5 attempts/min/IP)
- **TOTP 2FA**: RFC 6238 compatible, works with Google Authenticator/Authy
- **One-time tokens**: 32-byte crypto random, single use, short TTL (via Telegram `/open`)
- **TLS**: Self-signed (ED25519), Let's Encrypt auto-TLS, or custom certificates
- **Session cookies**: HttpOnly, Secure, SameSite=Strict, HMAC-SHA256 signed
- **Security headers**: CSP, X-Frame-Options, X-Content-Type-Options
- **Fail2ban**: Auto-ban IPs after N failed auth attempts (configurable threshold and duration)
- **GeoIP filtering**: Allow/block by country code using MaxMind GeoLite2
- **Time-window access**: Restrict access to specific hours and timezone
- **Dynamic IP whitelist**: Add/remove CIDRs at runtime via Telegram
- **Stealth mode**: Zero attack surface when not in use

See [SECURITY.md](SECURITY.md) for the full security policy.

## Audit & Monitoring

### Audit Log

JSON-lines structured audit log:

```bash
shellgate --audit-log /var/log/shellgate.jsonl
```

```json
{"timestamp":"2026-02-26T20:00:00Z","event":"session_create","session_id":"abc123","client_ip":"1.2.3.4","country":"SA","detail":"new session"}
{"timestamp":"2026-02-26T20:05:00Z","event":"auth_failure","client_ip":"5.6.7.8","country":"CN","detail":"invalid credentials"}
```

Events: `auth`, `auth_failure`, `session_create`, `session_close`, `session_kill`, `connect`, `disconnect`, `ip_banned`, `server_start`, `server_stop`

### Prometheus Metrics

```bash
shellgate --metrics
# GET /metrics
```

```
shellgate_connections_total 42
shellgate_auth_success_total 38
shellgate_auth_failure_total 4
shellgate_sessions_active 2
shellgate_sessions_created_total 15
shellgate_sessions_closed_total 13
shellgate_banned_ips 1
shellgate_ws_messages_in_total 1024
shellgate_ws_messages_out_total 8192
```

### Webhook Notifications

Forward audit events to Slack, Discord, or any HTTP endpoint:

```bash
shellgate --webhook-url "https://hooks.slack.com/services/..." \
  --webhook-events "auth_failure,ip_banned,connect,disconnect"
```

## All Flags

### Server

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `8080` | Listen port |
| `--shell` | `$SHELL` | Shell to spawn |
| `--verbose` | `false` | Debug logging |

### Authentication

| Flag | Default | Description |
|------|---------|-------------|
| `--auth` | `token` | Auth mode: `none\|token\|password\|otp` |
| `--token` | auto | Static auth token (env: `SHELLGATE_TOKEN`) |
| `--password` | | Password for web login |
| `--allow-ip` | | Initial CIDR whitelist (comma-separated) |
| `--rate-limit` | `10` | Requests/sec per IP (0=disable) |
| `--i-know-what-im-doing` | `false` | Acknowledge running without auth |

### TLS

| Flag | Default | Description |
|------|---------|-------------|
| `--tls` | `false` | Enable TLS |
| `--domain` | | Domain for Let's Encrypt auto-TLS |
| `--cert` | | Custom TLS cert path |
| `--key` | | Custom TLS key path |

### Sessions

| Flag | Default | Description |
|------|---------|-------------|
| `--max-sessions` | `5` | Max concurrent sessions |
| `--timeout` | `30m` | Session timeout (0=no timeout) |
| `--idle-timeout` | `10m` | Idle timeout (0=no timeout) |
| `--record` | `false` | Enable asciicast v2 recording |
| `--record-dir` | `~/.shellgate/recordings` | Recording directory |
| `--share` | `false` | Enable session sharing |
| `--share-ttl` | `1h` | Share link TTL |
| `--share-max-viewers` | `10` | Max viewers per share |

### Access Control

| Flag | Default | Description |
|------|---------|-------------|
| `--max-failed-attempts` | `10` | Auth failures before IP ban (0=disable) |
| `--ban-duration` | `15m` | Duration of IP bans |
| `--geoip` | `false` | Enable GeoIP filtering |
| `--geoip-db` | | Path to MaxMind GeoLite2 `.mmdb` file |
| `--allowed-countries` | | Allowed country codes (comma-separated) |
| `--blocked-countries` | | Blocked country codes (comma-separated) |
| `--access-window-start` | | Access window start time (`HH:MM`) |
| `--access-window-end` | | Access window end time (`HH:MM`) |
| `--access-window-tz` | | Access window timezone (e.g. `Asia/Riyadh`) |

### Stealth Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--stealth` | `false` | Don't listen on startup (wait for `/open`) |
| `--random-port` | `false` | Random port on each `/open` |
| `--port-range-min` | `10000` | Min port for random selection |
| `--port-range-max` | `65000` | Max port for random selection |
| `--auto-close` | | Auto-close listener after duration (e.g. `1h`) |

### Telegram

| Flag | Default | Description |
|------|---------|-------------|
| `--telegram` | `false` | Enable Telegram bot |
| `--telegram-token` | | Bot token (env: `SHELLGATE_TELEGRAM_TOKEN`) |
| `--telegram-users` | | Allowed user IDs (comma-separated) |
| `--external-host` | | External hostname for access links |

### Audit & Monitoring

| Flag | Default | Description |
|------|---------|-------------|
| `--audit-log` | | Path to audit log file (JSON lines) |
| `--webhook-url` | | Webhook URL for event notifications |
| `--webhook-events` | | Event types to forward (comma-separated) |
| `--metrics` | `false` | Enable `/metrics` endpoint (Prometheus) |

## Subcommands

```bash
shellgate                    # Start server (default)
shellgate serve              # Explicit start
shellgate setup-otp          # Configure TOTP 2FA
shellgate sessions           # List active sessions
shellgate version            # Version info
shellgate completion bash    # Shell completions
```

## Configuration

Config file at `~/.shellgate/config.yaml`:

```yaml
host: 0.0.0.0
port: 8080
shell: /bin/bash
auth: token
rate-limit: 10
max-sessions: 5
timeout: 30m
idle-timeout: 10m
```

Environment variables: `SHELLGATE_PORT`, `SHELLGATE_TOKEN`, `SHELLGATE_TELEGRAM_TOKEN`, etc.

Priority: CLI flags > environment > config file > defaults.

## Comparison

| Feature | ShellGate | ttyd | gotty | wetty |
|---------|-----------|------|-------|-------|
| Single binary | Yes | Yes | Yes | No |
| Telegram control | Yes | No | No | No |
| Stealth mode | Yes | No | No | No |
| Fail2ban / GeoIP | Yes | No | No | No |
| Session sharing | Yes | No | Read-only | No |
| Session recording | Yes | No | No | No |
| Auto TLS | Yes | No | No | No |
| 2FA/OTP | Yes | No | No | No |
| Audit log | Yes | No | No | No |
| Prometheus metrics | Yes | No | No | No |
| Auth built-in | Token/Password/OTP | Basic | Basic | SSH |
| Config file | Yes | No | No | Yes |

## Architecture

```
                          Telegram Bot (out-of-band)
                               |
                          Bot Commands
                               |
Browser (xterm.js) <--WS--> ShellGate Binary <---> Audit Logger
                               |                      |
                  +------------+------------+    Webhook / Metrics
                  |            |            |
               HTTP Srv    PTY Mgr    Session Ctrl
                  |            |            |
               Auth + TLS + ACL + Rate Limit + Recording
                  |
         Fail2ban + GeoIP + Time Windows
```

All frontend assets are embedded in the binary via `embed.FS`.

## Building from Source

```bash
git clone https://github.com/cc1a2b/shellgate.git
cd shellgate
make build
./shellgate
```

## License

[MIT](LICENSE)
