# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the AIR v1 specification or reference tooling, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use one of these channels:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/cyntrisec/air-v1/security/advisories/new)
2. **Email**: security@cyntrisec.com

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix**: Depends on severity; critical issues prioritized

## Scope

- **COSE/CWT receipt structure** (signature bypass, claim parsing, malformed vectors)
- **Golden vector correctness** (test vectors that incorrectly pass or fail)
- **Verification algorithm** (logic errors in the normative verification steps)
- **Interop tooling** (Python/JS reference verifiers)

## Supported Versions

| Version | Supported |
|---------|-----------|
| v1.0.x  | Yes       |