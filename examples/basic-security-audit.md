# Example: Basic Security Audit

This example demonstrates how to perform a security audit on a web application using MCP Auditor.

## Scenario

You have a Node.js/Express application and want to:
1. Audit the code for vulnerabilities
2. Check OWASP Top 10 compliance
3. Review cloud security posture

## Step 1: Start an Audit Session

```
User: Start a security audit for our e-commerce platform.
      The scope is the Node.js backend API.
      Objectives: identify vulnerabilities, assess OWASP compliance, review AWS configuration
```

Claude will use `start_audit` to initialize the session.

## Step 2: Audit the Code

```
User: Here's our authentication middleware, please audit it:

const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send('No token');

  try {
    const decoded = jwt.verify(token, 'secret123');
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).send('Invalid token');
  }
}
```

Claude will use `audit_code` and find:
- ⚠️ **CRITICAL**: Hardcoded secret ('secret123')
- ⚠️ **HIGH**: Token not properly extracted (should split 'Bearer ')
- ⚠️ **MEDIUM**: Generic error message (information disclosure)

## Step 3: OWASP Assessment

```
User: Assess our application against OWASP Top 10.
      We use JWT authentication, PostgreSQL database,
      and deploy on AWS ECS.
```

Claude will use `assess_owasp` and provide findings for each category.

## Step 4: Cloud Security Review

```
User: Review our AWS security configuration.
      We're using ECS, RDS PostgreSQL, S3 for uploads,
      and CloudFront for CDN.
```

Claude will use `assess_cloud_security` with provider 'AWS'.

## Step 5: Generate Report

```
User: Generate the full audit report in markdown format.
```

Claude will use `generate_report` with format 'markdown'.

## Sample Output

The report will include:
- Executive summary
- All findings with severity ratings
- Evidence collected
- Prioritized recommendations
- Risk score calculation

---

**Next Steps**: See [compliance-audit.md](compliance-audit.md) for compliance framework assessment.
