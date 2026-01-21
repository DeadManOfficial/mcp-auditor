# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities by emailing:

1. **GitHub Security Advisories** (Preferred): Use [GitHub's private vulnerability reporting](https://github.com/DeadManOfficial/mcp-auditor/security/advisories/new)

2. **Direct Contact**: If you cannot use GitHub Security Advisories, open a private discussion or contact the maintainers directly.

### What to Include

Please include the following information in your report:

- **Description**: A clear description of the vulnerability
- **Impact**: What an attacker could achieve by exploiting this
- **Reproduction Steps**: Step-by-step instructions to reproduce
- **Affected Versions**: Which versions are affected
- **Suggested Fix**: If you have a suggested remediation

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability and determine severity
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical issues within 7 days
- **Credit**: We will credit you in the release notes (unless you prefer anonymity)

### Severity Levels

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Remote code execution, data breach | 24-48 hours |
| High | Privilege escalation, significant data exposure | 3-5 days |
| Medium | Limited impact vulnerabilities | 7-14 days |
| Low | Minor issues, hardening recommendations | Next release |

## Security Best Practices

When using MCP Auditor:

1. **Keep Updated**: Always use the latest version
2. **Review Permissions**: MCP Auditor runs with the permissions of your Node.js process
3. **Sensitive Data**: Be cautious when auditing code containing real credentials or PII
4. **Network Access**: MCP Auditor does not make external network requests by default

## Scope

This security policy covers:

- The `mcp-auditor` npm package
- The source code in this repository
- The MCP server implementation

This policy does NOT cover:

- Claude Desktop application (report to Anthropic)
- The MCP protocol itself (report to Anthropic)
- Third-party integrations

## Acknowledgments

We thank the following security researchers for responsibly disclosing vulnerabilities:

*No vulnerabilities reported yet.*

---

Thank you for helping keep MCP Auditor secure! 🛡️
