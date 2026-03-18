# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (latest) | Yes |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private vulnerability reporting:
1. Go to the [Security tab](https://github.com/stv3/warden/security) of this repository
2. Click **"Report a vulnerability"**
3. Fill in the details — include steps to reproduce, impact, and any suggested fix

You can expect an acknowledgment within 48 hours and a resolution timeline within 7 days for confirmed issues.

## Scope

In scope:
- Authentication bypass or credential exposure
- Injection vulnerabilities (SQL, command, SSRF)
- Privilege escalation
- Sensitive data leakage from the API
- Insecure defaults that ship in the Docker image

Out of scope:
- Vulnerabilities in third-party scanner products that Warden connects to
- Denial of service against self-hosted instances
- Issues requiring physical access to the host

## Security Design Notes

- Warden enforces strong credential requirements at startup (`WARDEN_ENV=production`)
- All API endpoints require a signed JWT
- Rate limiting is applied to authentication and password change endpoints
- CORS is restricted to an explicit origin allowlist (no wildcards)
- The Docker image runs as a non-root user
- Self-signed cert support is included for air-gapped / private network deployments
