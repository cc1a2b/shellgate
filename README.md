# ShellGate

**Your server is one click away.**

Instant web-based terminal access to any server from a single binary. Install with one command, get a secure browser terminal in seconds.

[![CI](https://github.com/cc1a2b/shellgate/actions/workflows/ci.yml/badge.svg)](https://github.com/cc1a2b/shellgate/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cc1a2b/shellgate)](https://goreportcard.com/report/github.com/cc1a2b/shellgate)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why ShellGate?

- **Zero dependencies** — Single binary, embedded web assets. No Node.js, no Python, no runtime.
- **Secure by default** — Auto-generated auth token, TLS support, rate limiting, IP whitelisting. Never runs open.
- **Production-ready features** — Session recording, read-only sharing, TOTP 2FA, Let's Encrypt auto-TLS.

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

# Password auth
shellgate --auth password --password mysecret

# With TLS (self-signed)
shellgate --tls

# With Let's Encrypt
shellgate --tls --domain myserver.example.com

# Record sessions
shellgate --record

# Enable session sharing
shellgate --share

# Custom shell and port
shellgate --shell /bin/zsh --port 9090

# IP whitelist
shellgate --allow-ip 192.168.1.0/24,10.0.0.5

# No auth (requires explicit acknowledgment)
shellgate --auth none --i-know-what-im-doing
```

## All Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `8080` | Listen port |
| `--shell` | `$SHELL` | Shell to spawn |
| `--verbose` | `false` | Debug logging |
| `--auth` | `token` | Auth mode: `none\|token\|password\|otp` |
| `--token` | auto | Static auth token |
| `--password` | | Password for web login |
| `--allow-ip` | | CIDR whitelist (comma-separated) |
| `--rate-limit` | `10` | Requests/sec per IP |
| `--tls` | `false` | Enable TLS |
| `--domain` | | Domain for Let's Encrypt |
| `--cert` | | Custom TLS cert path |
| `--key` | | Custom TLS key path |
| `--max-sessions` | `5` | Max concurrent sessions |
| `--timeout` | `30m` | Session timeout |
| `--idle-timeout` | `10m` | Idle timeout |
| `--record` | `false` | Enable asciicast recording |
| `--record-dir` | `~/.shellgate/recordings` | Recording directory |
| `--share` | `false` | Enable session sharing |
| `--share-ttl` | `1h` | Share link TTL |
| `--share-max-viewers` | `10` | Max viewers per share |

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

Environment variables: `SHELLGATE_PORT`, `SHELLGATE_TOKEN`, etc.

Priority: CLI flags > environment > config file > defaults.

## Security

ShellGate is designed with security as a first-class concern:

- **Never runs without auth** unless you explicitly pass `--auth none --i-know-what-im-doing`
- **Token auth**: 256-bit random token, constant-time comparison
- **Password auth**: bcrypt hashing, rate-limited login (5 attempts/min/IP)
- **TOTP 2FA**: RFC 6238 compatible, works with Google Authenticator/Authy
- **TLS**: Self-signed (ED25519), Let's Encrypt, or custom certificates
- **Session cookies**: HttpOnly, Secure, SameSite=Strict, HMAC-SHA256 signed
- **Security headers**: CSP, X-Frame-Options, X-Content-Type-Options
- **IP whitelisting**: Restrict by CIDR ranges

See [SECURITY.md](SECURITY.md) for the full security policy.

## Comparison

| Feature | ShellGate | ttyd | gotty | wetty |
|---------|-----------|------|-------|-------|
| Single binary | Yes | Yes | Yes | No |
| Session sharing | Yes | No | Read-only | No |
| Session recording | Yes | No | No | No |
| Auto TLS | Yes | No | No | No |
| 2FA/OTP | Yes | No | No | No |
| Mobile optimized | Yes | Partial | Partial | Partial |
| Auth built-in | Token/Password/OTP | Basic | Basic | SSH |
| Config file | Yes | No | No | Yes |

## Architecture

```
Browser (xterm.js) <--WebSocket--> ShellGate Binary
                                     |
                        +------------+------------+
                        |            |            |
                     HTTP Srv    PTY Mgr    Session Ctrl
                        |            |            |
                     Auth + TLS + Rate Limit + Recording
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
