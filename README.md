# ShellGate

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/release/cc1a2b/shellgate.svg)](https://github.com/cc1a2b/shellgate/releases)
[![GitHub stars](https://img.shields.io/github/stars/cc1a2b/shellgate)](https://github.com/cc1a2b/shellgate/stargazers)
[![CI](https://github.com/cc1a2b/shellgate/actions/workflows/ci.yml/badge.svg)](https://github.com/cc1a2b/shellgate/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cc1a2b/shellgate)](https://goreportcard.com/report/github.com/cc1a2b/shellgate)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/cc1a2b/shellgate/releases)

**🚪 Instant Web-Based Terminal Access from a Single Binary**

*Your server is one click away — secure browser terminal in seconds, with Telegram control plane, fail2ban, GeoIP filtering, and stealth mode.*

</div>

## 📖 About

**ShellGate** is a single-binary, web-based terminal access platform. Drop one binary on a server, run it, and get a secure browser terminal in seconds — with auto-generated auth tokens, TLS, fail2ban-style IP banning, GeoIP filtering, time-restricted access windows, session recording, and a Telegram control plane that lets you open and close access remotely without ever exposing SSH.

<div align="center">
<img alt="ShellGate Screenshot" src="https://github.com/user-attachments/assets/5d43a45b-16ec-4174-b5d6-3289d7a0c0d0" width="100%">

*ShellGate — secure browser terminal access, controlled from Telegram.*
</div>

---

## 📑 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Telegram Bot](#-telegram-bot)
- [Command Reference](#-command-reference)
- [Advanced Usage](#-advanced-usage)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

---

## ✨ Features

### 🎯 Core Capabilities
- **🚪 Single Static Binary**: Embedded web assets — no Node.js, no Python, no runtime to install
- **🔐 Secure by Default**: Auto-generated auth token, TLS support, fail2ban, GeoIP filtering
- **🤖 Telegram Control Plane**: Open/close server, generate one-time access links, get real-time alerts — all from Telegram
- **🥷 Stealth Mode**: Server starts silent; one Telegram command opens it on a random port with a one-time token, auto-closes after a TTL
- **📼 Production-Ready**: Session recording, sharing, audit logging, Prometheus metrics, webhook notifications

### 🧠 Defense-in-Depth
> **Open ports are temporary by design.**

- **🎯 Fail2Ban-Style IP Banning**: Auto-ban after configurable failed attempts
- **🏢 GeoIP Filtering**: Allow/block by country (MaxMind GeoLite2)
- **🧠 Time-Restricted Windows**: Only accept connections during business hours, in a configured timezone
- **📊 Audit Logging**: Every command, every session, every ban — JSONL for downstream SIEM ingestion
- **📡 Prometheus Metrics**: Sessions, latencies, bans, geographic distribution

### 🌐 Networking & Security
<details>
<summary><strong>TLS, ACME, proxy, and stealth — production-grade defaults</strong></summary>

- **🔒 TLS Support**: Bring your own cert, or auto-issue via Let's Encrypt with `--domain`
- **🎭 Auth Modes**: Token (default), password, or OIDC
- **🥷 Stealth Mode**: Listener silent until `/open` command; auto-close after TTL
- **🔧 Random Port**: Generate a random port per `/open` to defeat scanners
- **🛡️ One-Time Tokens**: Tokens expire after first use or TTL, whichever comes first
- **📋 IP Whitelist / Blacklist**: Manual control over allowed IPs and CIDRs

</details>

### 🔐 Telegram Operations
<details>
<summary><strong>Killer feature — control your server from Telegram, no SSH required</strong></summary>

| Command | Description |
|---|---|
| **🚪 `/open [duration]`** | Start listener, generate one-time access link (e.g. `/open 2h`) |
| **🔒 `/close`** | Stop listener, kill all sessions, revoke all tokens |
| **📊 `/status`** | Show server status, uptime, sessions, TLS, banned IPs |
| **📋 `/sessions`** | List active sessions with ID, IP, duration |
| **💀 `/kill <id>`** | Kill a specific session |
| **✅ `/whitelist [ip]`** | Add IP/CIDR to whitelist or list current |
| **🚫 `/ban [ip]`** | Ban an IP or list banned IPs |
| **🔓 `/unban <ip>`** | Remove ban |
| **📼 `/record`** | Toggle session recording on/off |
| **🔗 `/share <id>`** | Generate read-only share link for a session |
| **🔌 `/port [num]`** | Show or change listening port |
| **❓ `/help`** | Show all commands |

> **🎯 Setup**: Create a bot via [@BotFather](https://t.me/BotFather), get your user ID from [@userinfobot](https://t.me/userinfobot), then start with `--telegram --telegram-users "YOUR_ID"`.

</details>

### 📤 Observability & Reporting
<details>
<summary><strong>Audit, metrics, and webhooks for production deployments</strong></summary>

- **📄 Audit Log**: JSONL of every command, session, and ban event
- **📊 Prometheus Metrics**: Scrape `/metrics` for Grafana dashboards
- **🔴 Webhook Notifications**: Push session opens and closes to Slack, Discord, or any HTTP endpoint
- **📼 Session Recording**: Replay full terminal sessions with asciinema-compatible format

</details>

---

## 📦 Installation

### One-Line Installer
```bash
curl -sL https://raw.githubusercontent.com/cc1a2b/shellgate/main/scripts/install.sh | bash
```

### Go Install
```bash
go install github.com/cc1a2b/shellgate/cmd/shellgate@latest
```

### Build from Source
```bash
git clone https://github.com/cc1a2b/shellgate.git
cd shellgate
make build
```

### System Requirements
- **Linux, macOS, or Windows** (64-bit)
- **Optional GeoIP DB**: MaxMind GeoLite2-Country for `--geoip`
- **Optional Telegram bot** for the control-plane commands

---

## 🚀 Quick Start

### Run with auto-generated token
```bash
shellgate
# prints: http://your-server:8080?token=<auto-generated>
```

### Hardened start with TLS + Telegram + stealth
```bash
shellgate --tls --stealth --telegram \
  --telegram-token "$SHELLGATE_TELEGRAM_TOKEN" \
  --telegram-users "123456789" \
  --external-host myserver.com
```

---

## 💡 Usage Examples

```bash
# Basic (auto token auth)
shellgate

# Password auth with TLS
shellgate --auth password --password mysecret --tls

# Let's Encrypt
shellgate --tls --domain myserver.example.com

# Record sessions + enable sharing
shellgate --record --share

# Stealth mode with Telegram control plane
shellgate --stealth --telegram \
  --telegram-token "$SHELLGATE_TELEGRAM_TOKEN" \
  --telegram-users "123456789" \
  --external-host myserver.com --tls

# GeoIP filtering — Saudi-only
shellgate --geoip --geoip-db /path/to/GeoLite2-Country.mmdb \
  --allowed-countries "SA"

# Time-restricted access window
shellgate --access-window-start 09:00 --access-window-end 17:00 \
  --access-window-tz "Asia/Riyadh"

# Audit logging + Prometheus metrics
shellgate --audit-log /var/log/shellgate.jsonl --metrics
```

---

## 🤖 Telegram Bot

Control ShellGate entirely from Telegram — no SSH, no open ports, no exposed surface.

### Setup
1. Create a bot via [@BotFather](https://t.me/BotFather) and get the token.
2. Get your Telegram user ID (send `/start` to [@userinfobot](https://t.me/userinfobot)).
3. Set the token as an environment variable:
   ```bash
   export SHELLGATE_TELEGRAM_TOKEN="your-bot-token"
   ```
4. Start ShellGate with Telegram enabled:
   ```bash
   shellgate --telegram --telegram-users "YOUR_USER_ID" \
     --external-host your-server.com --tls --stealth
   ```

### `/open` Flow
1. Send `/open 2h` to the bot.
2. ShellGate starts the listener on a random port with a one-time token.
3. Bot replies with a secure URL.
4. Open the URL in any browser → terminal.
5. After 2 hours (or `/close`), listener stops, token revoked, server invisible again.

---

## 📋 Command Reference

```
Usage:
  shellgate [flags]

Auth & TLS:
  --auth MODE                      token (default) | password | oidc
  --password STR                   Password for password auth
  --tls                            Enable TLS
  --domain HOST                    Auto-issue Let's Encrypt cert for HOST

Telegram Control Plane:
  --telegram                       Enable Telegram bot
  --telegram-token STR             Bot token (or env SHELLGATE_TELEGRAM_TOKEN)
  --telegram-users LIST            Comma-separated allowed user IDs
  --external-host HOST             External hostname (for share links)

Stealth & Hardening:
  --stealth                        Listener silent until /open
  --random-port                    Random port on each /open
  --auto-close DURATION            Auto-close listener after DURATION
  --max-failed-attempts INT        Fail2ban threshold
  --ban-duration DURATION          Ban TTL
  --geoip                          Enable GeoIP filtering
  --geoip-db PATH                  MaxMind GeoLite2-Country DB path
  --allowed-countries LIST         ISO country codes (comma-separated)
  --access-window-start HH:MM      Allow connections only after
  --access-window-end HH:MM        Allow connections only before
  --access-window-tz TZ            Timezone for the window

Recording & Sharing:
  --record                         Record all sessions
  --share                          Allow read-only session sharing

Observability:
  --audit-log PATH                 JSONL audit log
  --metrics                        Expose /metrics for Prometheus
  --webhook URL                    Push session events to URL

Utility:
  -h, --help                       Show help
  -V, --version                    Show version
```

---

## 🔧 Advanced Usage

### Full hardened production setup
```bash
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

### Systemd unit
```ini
[Unit]
Description=ShellGate
After=network.target

[Service]
ExecStart=/usr/local/bin/shellgate --tls --stealth --telegram \
  --telegram-users "123456789" --external-host myserver.com
Restart=on-failure
Environment=SHELLGATE_TELEGRAM_TOKEN=xxx

[Install]
WantedBy=multi-user.target
```

---

## 🤝 Contributing

Contributions welcome.

- **🐛 Report bugs** via [GitHub Issues](https://github.com/cc1a2b/shellgate/issues)
- **💡 Suggest features** that strengthen the security posture
- **📝 Improve documentation**
- **🔧 Submit pull requests** for new auth modes, integrations, or hardening features

### Development Setup
```bash
git clone https://github.com/cc1a2b/shellgate.git
cd shellgate
go mod tidy
make build
```

---

## 📄 License

ShellGate is released under the **MIT License**. See [LICENSE](https://github.com/cc1a2b/shellgate/blob/main/LICENSE) for details.

```
Copyright (c) 2024-2026 Hussain Alsharman
Licensed under MIT License — free for commercial and personal use
```

---

## ☕ Support

If ShellGate makes your life easier:

<div align="center">

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/default-orange.png)](https://www.buymeacoffee.com/cc1a2b)

**⭐ Star this repo** • **🐦 Follow [@cc1a2b](https://twitter.com/cc1a2b)** • **📢 Share with sysadmins**

</div>

---

<div align="center">

**🚪 ShellGate — Instant Web-Based Terminal Access from a Single Binary**

*Built with ❤️ by [cc1a2b](https://github.com/cc1a2b) for sysadmins and power users*

</div>
