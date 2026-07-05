# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: [security@example.com](mailto:security@example.com)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✓ Current |

## Security Design

This project implements multiple layers of security:

### Authentication & Authorization

- **JWT validation** with issuer, audience, signature, and expiration checks
- **Mutual TLS** between all agent runtimes (X.509 from internal CA)
- **OAuth 2.0** with proper PKCE/state parameters for CSRF protection
- **Scope enforcement** — agents can only access resources within their authorized scopes
- **Identity propagation** with HMAC-SHA256 tamper detection

### Secrets Management

- All sensitive credentials stored in AWS Secrets Manager
- No secrets in source code, environment variables, or Terraform state
- Secrets referenced via ARN/data source only
- Automated rotation support with configurable intervals
- Private keys encrypted at rest in Secrets Manager

### Infrastructure Security

- Terraform state encrypted with S3 SSE-KMS
- State access restricted to deployment role via IAM policies
- DynamoDB state locking prevents concurrent modifications
- VPC security groups enforce mTLS port access between agents only
- CloudWatch audit logs retained for 90 days minimum

### Data Protection

- Sensitive data masked in all log output and CLI verbose mode
- JWT signatures never logged in plaintext
- Authorization header values masked after scheme prefix
- Client secrets and refresh tokens masked in OAuth exchange logs
- Correlation IDs used for tracing (no PII in trace data)

### Dependency Security

- Dependencies pinned with minimum versions in `pyproject.toml`
- Dependabot alerts monitored via the platform itself
- CycloneDX SBOM generated for full supply chain visibility

## Security Considerations for Deployment

1. **Rotate secrets regularly** — Use Secrets Manager rotation with appropriate intervals
2. **Restrict state access** — Only the deployment role should access Terraform state
3. **Monitor the auth failure alarm** — Spikes may indicate credential stuffing or token theft
4. **Review certificate expiration** — mTLS certificates should be rotated before expiry
5. **Limit OAuth scopes** — Only grant the minimum scopes needed per agent
6. **Network isolation** — Deploy agents in private subnets with security group enforcement
