# Changelog

All notable changes to MCP Auditor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-21

### 🎉 Initial Release

**MCP Auditor** — The Omniscient Auditor for Claude Desktop

#### Added

**Core Engine**
- Audit session management with `start_audit`
- Finding tracking with severity levels and evidence
- Chain of custody evidence collection with SHA-256 hashing
- Comprehensive report generation (JSON & Markdown)

**Security Auditing (4 tools)**
- OWASP Top 10 (2021) vulnerability assessment
- Cloud security evaluation (AWS, Azure, GCP)
- Zero Trust architecture analysis
- MITRE ATT&CK technique lookup

**Code Auditing (3 tools)**
- 50+ vulnerability pattern detection
- Code smell identification
- Dependency analysis

**Forensic Auditing (4 tools)**
- Benford's Law statistical analysis
- Fraud risk assessment (8 schemes)
- AML risk evaluation
- Interview guide generation (PEACE/FAINT)

**Compliance Auditing (3 tools)**
- 8 framework checklists (SOC 2, HIPAA, PCI-DSS, GDPR, ISO 27001, FedRAMP, CMMC, NIST CSF)
- Gap analysis and recommendations
- Cross-framework control mapping

**Operational Auditing (4 tools)**
- TIMWOOD waste assessment
- DMAIC improvement planning
- Value Stream Mapping analysis
- 11 efficiency metric definitions

**IT Systems Auditing (4 tools)**
- COBIT 5 governance assessment
- Change management evaluation
- Backup/DR assessment
- Active Directory security review

**AI/ML Auditing (3 tools)**
- 14-category AI risk assessment
- Fairness metric evaluation (5 metrics)
- Model Card template generation

**Red Flag Detection**
- 100+ forensic red flag patterns
- 10 detection categories

**Multi-Domain**
- Comprehensive cross-domain auditing
- Risk scoring (Likelihood × Impact)

---

## [Unreleased]

### Planned Features
- [ ] SARBANES-OXLEY (SOX) compliance framework
- [ ] NIST 800-53 control mapping
- [ ] Supply chain security assessment (SLSA)
- [ ] Container security scanning
- [ ] Infrastructure as Code (IaC) auditing
- [ ] API security assessment
- [ ] Kubernetes security posture
