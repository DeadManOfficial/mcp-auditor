<div align="center">

<br>

# MCP Auditor

**Forensic-Grade Security & Compliance Analysis for Claude**

35 tools · 8 domains · Zero external API dependencies

<br>

<a href="https://www.npmjs.com/package/@officialdeadman/mcp-auditor">
  <img src="https://img.shields.io/badge/npm-@officialdeadman/mcp--auditor-CB3837?style=for-the-badge&logo=npm&logoColor=white" alt="npm" />
</a>
<a href="https://github.com/DeadManOfficial/mcp-auditor">
  <img src="https://img.shields.io/badge/GitHub-Source-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub" />
</a>
<a href="https://modelcontextprotocol.io">
  <img src="https://img.shields.io/badge/MCP-Compatible-00D4AA?style=for-the-badge" alt="MCP" />
</a>

<br><br>

</div>

---

## Install

```bash
npm install -g @officialdeadman/mcp-auditor
```

Add to Claude config:

```json
{
  "mcpServers": {
    "mcp-auditor": {
      "command": "npx",
      "args": ["-y", "@officialdeadman/mcp-auditor"]
    }
  }
}
```

<details>
<summary>Config locations</summary>

- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

</details>

---

## Tools

### Audit Engine

| Tool | Description |
|------|-------------|
| `start_audit` | Initialize audit with scope & objectives |
| `add_finding` | Record findings with severity & evidence |
| `collect_evidence` | Hash evidence for chain of custody |
| `generate_report` | Generate reports (JSON/Markdown) |

### Security

| Tool | Description |
|------|-------------|
| `assess_owasp` | OWASP Top 10 assessment |
| `assess_cloud_security` | AWS / Azure / GCP evaluation |
| `assess_zero_trust` | Zero Trust architecture review |
| `get_mitre_techniques` | MITRE ATT&CK lookup |

### Compliance

| Tool | Description |
|------|-------------|
| `generate_compliance_checklist` | SOC 2, HIPAA, PCI-DSS, GDPR, ISO 27001 |
| `assess_compliance` | Gap analysis & recommendations |
| `map_compliance_controls` | Cross-framework mapping |

### Forensic

| Tool | Description |
|------|-------------|
| `analyze_benford` | Benford's Law analysis |
| `assess_fraud_risk` | Fraud scheme indicators |
| `assess_aml_risk` | Anti-money laundering evaluation |
| `generate_interview_guide` | PEACE/FAINT methodology |

### Code

| Tool | Description |
|------|-------------|
| `audit_code` | Security & quality audit |
| `calculate_code_metrics` | LOC, complexity, functions |
| `analyze_dependencies` | Package vulnerabilities |
| `scan_red_flags` | 100+ forensic red flags |

### Operational

| Tool | Description |
|------|-------------|
| `assess_waste` | TIMWOOD identification |
| `generate_dmaic_plan` | Six Sigma planning |
| `analyze_value_stream` | Process efficiency |
| `get_efficiency_metrics` | OEE, PCE, Takt definitions |

### IT Systems

| Tool | Description |
|------|-------------|
| `assess_cobit` | COBIT 5 governance |
| `assess_change_management` | Change control evaluation |
| `assess_backup_recovery` | DR/BCP assessment |
| `assess_ad_security` | Active Directory review |

### AI/ML

| Tool | Description |
|------|-------------|
| `assess_ai_risks` | 14-category risk assessment |
| `assess_fairness` | Fairness metrics |
| `generate_model_card` | Model documentation |

### Multi-Domain

| Tool | Description |
|------|-------------|
| `comprehensive_audit` | Cross-domain audit |
| `risk_assessment` | Likelihood × Impact scoring |

---

## Frameworks

`OWASP` `MITRE ATT&CK` `NIST CSF` `ISO 27001` `PCI-DSS` `SOC 2` `HIPAA` `GDPR` `COBIT` `CMMC` `FedRAMP`

---

## Examples

**Security audit:**
```
Audit this code for vulnerabilities: [code]
```

**Compliance check:**
```
Assess our SOC 2 compliance. Current state: [description]
```

**Fraud detection:**
```
Analyze these amounts with Benford's Law: [numbers]
```

---

## Architecture

```
src/
├── index.ts           # MCP server
├── core/              # Engine, types, red flags
├── domains/           # 7 audit domain modules
└── handlers/          # Tool handlers
```

---

## Contributing

```bash
git clone https://github.com/DeadManOfficial/mcp-auditor.git
cd mcp-auditor
npm install
npm run build
```

See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## License

MIT

---

<div align="center">

<br>

<a href="https://github.com/DeadManOfficial">
  <img src="https://img.shields.io/badge/Built_by-DeadMan-100000?style=flat&logo=github" alt="DeadMan" />
</a>

<br><br>

<sub>BUILD > BUY</sub>

</div>
