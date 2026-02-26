# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in ShellGate, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email: security@example.com (replace with your actual contact)
3. Include: description, reproduction steps, impact assessment

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

## Security Design

### Authentication
- Default: auto-generated 256-bit token (never runs without auth unless explicitly acknowledged)
- Password auth: bcrypt-hashed, rate-limited (5 attempts/minute/IP)
- TOTP 2FA: RFC 6238 compliant, secrets stored with 0600 permissions

### Transport Security
- TLS 1.2+ enforced when enabled
- Self-signed certificates use ED25519
- Let's Encrypt integration for production deployments

### Session Security
- Configurable session timeouts and idle timeouts
- Maximum concurrent session limits
- Session cookies: HttpOnly, Secure, SameSite=Strict, HMAC-signed

### Input Validation
- WebSocket message size limited to 64KB
- JSON message format strictly validated
- Rate limiting per IP address

### Headers
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Content-Security-Policy enforced
- Referrer-Policy: strict-origin-when-cross-origin

### Best Practices
- Never expose ShellGate on the public internet without TLS and strong authentication
- Use IP whitelisting (`--allow-ip`) to restrict access
- Enable session recording (`--record`) for audit trails
- Rotate tokens regularly
- Run behind a reverse proxy (nginx/caddy) for additional protection
