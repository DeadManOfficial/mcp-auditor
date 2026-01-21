# Example: SOC 2 Compliance Audit

This example demonstrates preparing for a SOC 2 Type II audit.

## Scenario

Your SaaS company is preparing for SOC 2 Type II certification and needs to:
1. Generate a compliance checklist
2. Assess current state
3. Identify gaps
4. Map controls to other frameworks

## Step 1: Generate Checklist

```
User: Generate a SOC 2 compliance checklist for our cloud-based
      project management SaaS platform.
```

Claude will use `generate_compliance_checklist` with framework 'SOC2'.

**Output**: Complete checklist organized by Trust Service Criteria:
- Security (CC1-CC9)
- Availability (A1)
- Processing Integrity (PI1)
- Confidentiality (C1)
- Privacy (P1-P8)

## Step 2: Assess Current State

```
User: Assess our SOC 2 compliance. Current state:

Security Controls:
- MFA enabled for all employees (Okta)
- AWS with security groups, WAF
- Quarterly access reviews
- No formal vulnerability management program

Availability:
- 99.9% SLA
- Multi-AZ RDS
- No documented DR plan

Change Management:
- GitHub PRs required
- No formal CAB process
- Production deployments via CI/CD
```

Claude will use `assess_compliance` and identify gaps:
- ⚠️ Missing vulnerability management program
- ⚠️ No documented DR/BCP
- ⚠️ No Change Advisory Board
- ✅ MFA implementation
- ✅ Access review process

## Step 3: Map to Other Frameworks

```
User: We also need ISO 27001. Map our SOC 2 controls to ISO 27001.
```

Claude will use `map_compliance_controls` to show overlapping requirements.

## Step 4: Prioritize Remediation

```
User: Perform a risk assessment on these compliance gaps.
```

Claude will use `risk_assessment` to prioritize:
1. **HIGH**: No DR plan (Impact: 5, Likelihood: 3)
2. **HIGH**: No vuln management (Impact: 4, Likelihood: 4)
3. **MEDIUM**: No CAB process (Impact: 3, Likelihood: 3)

## Output Summary

| Gap | Risk Score | Priority | Effort |
|-----|------------|----------|--------|
| DR Plan | 15 | HIGH | 2-4 weeks |
| Vuln Mgmt | 16 | HIGH | 4-6 weeks |
| CAB Process | 9 | MEDIUM | 1-2 weeks |

---

**Next Steps**: See [forensic-investigation.md](forensic-investigation.md) for fraud investigation techniques.
