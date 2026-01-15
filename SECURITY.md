# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously at FLIT. If you discover a security vulnerability, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email us at: **security@flit.io**

Include the following in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt within 48 hours
2. **Assessment**: We will assess the vulnerability within 7 days
3. **Resolution**: Critical issues will be patched within 30 days
4. **Disclosure**: We will coordinate public disclosure with you

### Scope

The following are in scope:
- Authentication bypass
- Authorization flaws
- Data exposure
- Injection vulnerabilities
- Cryptographic weaknesses
- Rate limiting bypass

The following are out of scope:
- Social engineering attacks
- Physical attacks
- Denial of service (unless it reveals a deeper issue)
- Issues in dependencies (report to the dependency maintainers)

## Security Best Practices

When deploying FLIT:

1. **Use strong secrets**
   - `SECRET_KEY`: Minimum 50 characters, randomly generated
   - `MCRYPT_KEY`: Exactly 32 characters, randomly generated

2. **Enable HTTPS**
   - Always use TLS in production
   - Set `SECURE_SSL_REDIRECT=True`

3. **Configure ALLOWED_HOSTS**
   - Never use `*` in production
   - List only your actual domains

4. **Secure your database**
   - Use SSL connections
   - Restrict network access
   - Use strong passwords

5. **Monitor and audit**
   - Enable structured logging
   - Set up alerting for suspicious activity
   - Review audit logs regularly

## Security Features

FLIT includes several built-in security features:

- **HMAC Authentication**: Cryptographically signed API requests
- **JWT with Expiration**: Short-lived tokens for user sessions
- **Replay Protection**: Prevents request replay attacks
- **Rate Limiting**: Protects against brute force
- **Audit Logging**: Cryptographically chained, tamper-evident logs
- **Input Validation**: Strict validation on all inputs

## Acknowledgments

We thank the security researchers who have helped improve FLIT:

*No vulnerabilities reported yet - be the first!*

---

<p align="center">
  <strong>Security is at the core of FLIT's mission.</strong><br>
  <em>Protecting Money in Motion</em>
</p>
