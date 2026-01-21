# Example: Forensic Financial Investigation

This example demonstrates using forensic tools to investigate potential financial fraud.

## Scenario

The internal audit team has flagged suspicious expense reports. You need to:
1. Analyze transaction amounts for manipulation
2. Assess fraud risk indicators
3. Prepare interview questions
4. Document evidence

## Step 1: Benford's Law Analysis

```
User: Analyze these expense report amounts for anomalies:

[1250, 2340, 1890, 4500, 4999, 4998, 4997, 4995, 3200,
 4990, 4985, 4980, 1100, 2500, 4975, 4970, 4965, 4960,
 3800, 4955, 4950, 4945, 4940, 2100, 4935, 4930, 4920]
```

Claude will use `analyze_benford` and detect:
- ⚠️ **Anomaly Detected**: First digit distribution deviates significantly from Benford's Law
- Chi-square statistic indicates manipulation (p < 0.01)
- Unusual clustering around $4,900-$5,000 (just under approval threshold)

## Step 2: Red Flag Scan

```
User: Scan these expense descriptions for red flags:

"Client dinner at Prime Steakhouse - Project Alpha"
"Uber rides for client meetings (cash reimbursement)"
"Office supplies from vendor ABC Corp"
"Consulting services - urgent payment needed"
"Gift cards for team building event"
"Travel expenses - personal card used"
```

Claude will use `scan_red_flags` with category 'EXPENSES' and find:
- ⚠️ **HIGH**: Cash reimbursement requests
- ⚠️ **HIGH**: Gift card purchases
- ⚠️ **MEDIUM**: Urgency language ("urgent payment needed")
- ⚠️ **MEDIUM**: Personal card usage pattern

## Step 3: Fraud Risk Assessment

```
User: Assess fraud risk for this scenario:

Employee: Senior Project Manager, 8 years tenure
Patterns observed:
- Expenses cluster just below $5,000 approval limit
- Multiple vendors with similar names
- Frequent "urgent" payment requests
- Approving own direct reports' expenses
- No vacation taken in 2 years
```

Claude will use `assess_fraud_risk` and identify:
- **Structuring** (splitting to avoid thresholds)
- **Shell company indicators** (similar vendor names)
- **Segregation of duties violation**
- **Behavioral red flag** (no vacation - concealment)

## Step 4: Generate Interview Guide

```
User: Generate an interview guide for the suspect.
      This is a suspected expense fraud case involving
      fictitious vendors and structured transactions.
```

Claude will use `generate_interview_guide` with type 'suspect':
- Rapport building techniques
- Non-accusatory question framework
- Specific questions about vendors
- Deception indicators to watch for
- Documentation requirements

## Step 5: Collect Evidence

```
User: Document this evidence for the investigation file:

Source: Expense Management System
Type: Transaction Log
Content: Export of all expenses by employee ID 12345
         from 2023-01-01 to 2024-01-01
```

Claude will use `collect_evidence` to:
- Create SHA-256 hash for integrity
- Record chain of custody
- Timestamp the collection

## Investigation Summary

| Finding | Severity | Evidence |
|---------|----------|----------|
| Benford deviation | CRITICAL | Statistical analysis |
| Structuring pattern | HIGH | Transaction clustering |
| Fictitious vendors | HIGH | Vendor analysis |
| SOD violation | MEDIUM | Approval logs |
| Behavioral indicators | MEDIUM | HR records |

**Recommended Actions**:
1. Preserve all electronic evidence
2. Conduct forensic interview
3. Review vendor master file
4. Engage legal counsel
5. Consider law enforcement referral

---

**Related**: See [basic-security-audit.md](basic-security-audit.md) for security assessment.
