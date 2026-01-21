<div align="center">

# 🔍 MCP Auditor

### *The Omniscient Auditor* — Forensic-Grade Security & Compliance Analysis

[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-00D4AA?style=for-the-badge&logo=anthropic&logoColor=white)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)

<br />

**35 Professional Auditing Tools** | **8 Audit Domains** | **Zero Dependencies on External APIs**

[Getting Started](#-quick-start) • [Tools Reference](#-tools-reference) • [Examples](#-examples) • [Contributing](#-contributing)

<br />

<img src="https://raw.githubusercontent.com/anthropics/anthropic-cookbook/main/misc/mcp-logo.png" alt="MCP Logo" width="120" />

</div>

---

## 🌟 What is MCP Auditor?

**MCP Auditor** is a comprehensive Model Context Protocol (MCP) server that brings **enterprise-grade auditing capabilities** directly into Claude. It transforms Claude into a forensic auditor, security analyst, compliance officer, and code reviewer — all in one.

> *"Like having an entire audit team available 24/7, powered by AI."*

### Why MCP Auditor?

| Traditional Auditing | With MCP Auditor |
|---------------------|------------------|
| Manual checklist reviews | Automated framework assessments |
| Expensive external consultants | Instant, on-demand analysis |
| Siloed audit domains | Unified cross-domain auditing |
| Static reports | Interactive, contextual findings |
| Weeks of preparation | Real-time insights |

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🛡️ Security Auditing
- **OWASP Top 10** vulnerability assessment
- **MITRE ATT&CK** threat modeling
- **Zero Trust** architecture evaluation
- **Cloud Security** (AWS, Azure, GCP)
- Real-time vulnerability detection

</td>
<td width="50%">

### 📋 Compliance Frameworks
- **SOC 2** Type I & II
- **HIPAA** / **HITECH**
- **PCI-DSS v4.0**
- **GDPR** / **CCPA**
- **ISO 27001** / **NIST CSF**
- **FedRAMP** / **CMMC**

</td>
</tr>
<tr>
<td width="50%">

### 🔬 Forensic Analysis
- **Benford's Law** statistical analysis
- **Fraud risk** indicators (8 schemes)
- **AML** transaction monitoring
- **Interview guide** generation (PEACE/FAINT)
- Chain of custody evidence tracking

</td>
<td width="50%">

### 💻 Code Quality
- **50+ vulnerability patterns**
- **SQL injection**, **XSS**, **Command injection**
- **Hardcoded secrets** detection
- **Code smell** identification
- **Dependency** analysis

</td>
</tr>
<tr>
<td width="50%">

### ⚙️ Operational Excellence
- **TIMWOOD** waste assessment
- **DMAIC** improvement planning
- **Value Stream** mapping
- **11 efficiency metrics** (OEE, PCE, Takt)
- Process optimization

</td>
<td width="50%">

### 🤖 AI/ML Governance
- **14 AI risk categories**
- **Fairness metrics** (5 standard measures)
- **Model Card** generation
- Bias detection guidance
- Explainability assessment

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ ([Download](https://nodejs.org/))
- **Claude Desktop** ([Download](https://claude.ai/download))

### Installation

#### Option 1: NPM (Recommended)

```bash
npm install -g @officialdeadman/mcp-auditor
```

#### Option 2: From Source

```bash
git clone https://github.com/anthropics/mcp-auditor.git
cd mcp-auditor
npm install
npm run build
```

### Configure Claude Desktop

Add to your Claude Desktop configuration:

<details>
<summary><b>📍 Windows</b> — <code>%APPDATA%\Claude\claude_desktop_config.json</code></summary>

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

</details>

<details>
<summary><b>📍 macOS</b> — <code>~/Library/Application Support/Claude/claude_desktop_config.json</code></summary>

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

</details>

<details>
<summary><b>📍 Linux</b> — <code>~/.config/Claude/claude_desktop_config.json</code></summary>

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

</details>

### Verify Installation

1. **Restart Claude Desktop** completely
2. Look for the **🔨 hammer icon** in the chat input
3. You should see **35 tools** from `mcp-auditor`

---

## 🛠️ Tools Reference

### 🎯 Audit Engine (4 tools)

| Tool | Description |
|------|-------------|
| `start_audit` | Initialize audit engagement with scope & objectives |
| `add_finding` | Record findings with severity, evidence, recommendations |
| `collect_evidence` | Collect & hash evidence for chain of custody |
| `generate_report` | Generate comprehensive audit reports (JSON/Markdown) |

### 🚨 Red Flag Detection (1 tool)

| Tool | Description |
|------|-------------|
| `scan_red_flags` | Scan for 100+ forensic red flags across 10 categories |

**Categories:** Journal Entries, Expenses, Vendor Payments, Communication, Timing, Revenue, Assets, Code Security, Compliance, Behavioral

### 💻 Code Audit (3 tools)

| Tool | Description |
|------|-------------|
| `audit_code` | Comprehensive security & quality audit |
| `calculate_code_metrics` | LOC, complexity, function counts |
| `analyze_dependencies` | Package vulnerability analysis |

### 🛡️ Security Audit (4 tools)

| Tool | Description |
|------|-------------|
| `assess_owasp` | OWASP Top 10 (2021) assessment |
| `assess_cloud_security` | AWS/Azure/GCP security evaluation |
| `assess_zero_trust` | Zero Trust architecture review |
| `get_mitre_techniques` | MITRE ATT&CK technique lookup |

### 🔬 Forensic Audit (4 tools)

| Tool | Description |
|------|-------------|
| `analyze_benford` | Benford's Law statistical analysis |
| `assess_fraud_risk` | Fraud scheme indicator assessment |
| `assess_aml_risk` | Anti-money laundering risk evaluation |
| `generate_interview_guide` | PEACE/FAINT methodology guides |

### 📋 Compliance Audit (3 tools)

| Tool | Description |
|------|-------------|
| `generate_compliance_checklist` | Framework-specific checklists |
| `assess_compliance` | Gap analysis & recommendations |
| `map_compliance_controls` | Cross-framework control mapping |

### ⚙️ Operational Audit (4 tools)

| Tool | Description |
|------|-------------|
| `assess_waste` | TIMWOOD waste identification |
| `generate_dmaic_plan` | Six Sigma improvement planning |
| `analyze_value_stream` | Process cycle efficiency analysis |
| `get_efficiency_metrics` | Operational metric definitions |

### 🖥️ IT Systems Audit (4 tools)

| Tool | Description |
|------|-------------|
| `assess_cobit` | COBIT 5 governance assessment |
| `assess_change_management` | Change control evaluation |
| `assess_backup_recovery` | DR/BCP assessment |
| `assess_ad_security` | Active Directory security review |

### 🤖 AI/ML Audit (3 tools)

| Tool | Description |
|------|-------------|
| `assess_ai_risks` | 14-category AI risk assessment |
| `assess_fairness` | Fairness metric evaluation |
| `generate_model_card` | Model documentation template |

### 🌐 Multi-Domain (2 tools)

| Tool | Description |
|------|-------------|
| `comprehensive_audit` | Cross-domain automated audit |
| `risk_assessment` | Likelihood × Impact scoring |

---

## 📚 Examples

### Example 1: Security Code Review

```
You: Please audit this code for security vulnerabilities:
     [paste your code]

Claude: I'll use the audit_code tool to analyze this...
        [Returns detailed findings with CWE references]
```

### Example 2: Compliance Gap Analysis

```
You: We're preparing for SOC 2 Type II. Our current state:
     - We use AWS with MFA enabled
     - No formal change management process
     - Weekly backups to S3

Claude: I'll assess your compliance posture...
        [Returns gap analysis with prioritized recommendations]
```

### Example 3: Fraud Investigation

```
You: Analyze these transaction amounts for anomalies:
     [list of numbers]

Claude: I'll run Benford's Law analysis...
        [Returns chi-square statistics and flags suspicious patterns]
```

### Example 4: Full Audit Engagement

```
You: Start a security audit for our e-commerce platform

Claude: I'll initialize the audit engagement...
        [Creates audit session, runs assessments, collects evidence,
         generates comprehensive report]
```

---

## 🏗️ Architecture

```
mcp-auditor/
├── src/
│   ├── index.ts              # MCP server entry point
│   ├── core/
│   │   ├── engine.ts         # Audit engine & reporting
│   │   ├── red-flags.ts      # 100+ red flag patterns
│   │   ├── types.ts          # TypeScript definitions
│   │   └── constants.ts      # Configuration constants
│   ├── domains/
│   │   ├── code-audit.ts     # Code security analysis
│   │   ├── security-audit.ts # OWASP, cloud, zero-trust
│   │   ├── forensic-audit.ts # Benford, fraud, AML
│   │   ├── compliance-audit.ts
│   │   ├── operational-audit.ts
│   │   ├── it-systems-audit.ts
│   │   └── ai-ml-audit.ts
│   └── handlers/             # Tool request handlers
└── dist/                     # Compiled JavaScript
```

---

## 🔗 Related Projects

Explore the **MCP Ecosystem**:

| Project | Description |
|---------|-------------|
| [MCP Specification](https://spec.modelcontextprotocol.io) | Official MCP protocol specification |
| [MCP Servers](https://github.com/modelcontextprotocol/servers) | Official MCP server implementations |
| [Claude Desktop](https://claude.ai/download) | Claude AI desktop application |
| [Anthropic Cookbook](https://github.com/anthropics/anthropic-cookbook) | Recipes for building with Claude |

### Complementary MCPs

- **[mcp-filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)** — File system access for auditing local codebases
- **[mcp-github](https://github.com/modelcontextprotocol/servers/tree/main/src/github)** — GitHub integration for repository audits
- **[mcp-postgres](https://github.com/modelcontextprotocol/servers/tree/main/src/postgres)** — Database access for data audits

---

## 📖 Audit Frameworks & Standards

MCP Auditor implements guidance from industry-recognized frameworks:

| Framework | Version | Coverage |
|-----------|---------|----------|
| [OWASP Top 10](https://owasp.org/Top10/) | 2021 | Full |
| [MITRE ATT&CK](https://attack.mitre.org/) | v14 | 6 tactics |
| [NIST CSF](https://www.nist.gov/cyberframework) | 2.0 | Full |
| [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html) | 2022 | Full |
| [PCI-DSS](https://www.pcisecuritystandards.org/) | v4.0 | Full |
| [SOC 2](https://www.aicpa.org/soc2) | 2017 | Full |
| [COBIT](https://www.isaca.org/resources/cobit) | 5 | Full |
| [HIPAA](https://www.hhs.gov/hipaa/) | Current | Full |
| [GDPR](https://gdpr.eu/) | Current | Full |

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Clone the repository
git clone https://github.com/anthropics/mcp-auditor.git
cd mcp-auditor

# Install dependencies
npm install

# Run in development mode
npm run dev

# Build for production
npm run build

# Run self-audit (dogfooding!)
npx tsx self-audit.ts
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **[Anthropic](https://anthropic.com)** for Claude and the MCP protocol
- **[OWASP Foundation](https://owasp.org)** for security guidance
- **[MITRE Corporation](https://attack.mitre.org)** for ATT&CK framework
- **[ISACA](https://isaca.org)** for COBIT and audit standards

---

<div align="center">

**Built with ❤️ for the security community**

[⬆ Back to Top](#-mcp-auditor)

</div>
