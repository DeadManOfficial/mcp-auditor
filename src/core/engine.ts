// Core Audit Engine - The Brain of the Omniscient Auditor

import {
  Finding,
  Evidence,
  AuditReport,
  AuditConfig,
  AuditContext,
  AuditStatistics,
  Severity,
  AuditStatus,
  AuditDomain,
} from './types.js';
import { createHash, randomUUID } from 'crypto';
import {
  SEVERITY_WEIGHTS,
  SEVERITY_ORDER,
  MAX_RISK_SCORE,
  RATING_THRESHOLDS,
  EVIDENCE_LIMITS,
  UUID_SLICE_LENGTH,
  ID_PREFIXES,
  REPORT_STRINGS,
} from './constants.js';

export class AuditEngine {
  private findings: Finding[] = [];
  private evidence: Evidence[] = [];
  private startTime: string = '';

  constructor(private config: AuditConfig) {}

  // Start an audit session
  startAudit(): string {
    this.startTime = new Date().toISOString();
    this.findings = [];
    this.evidence = [];
    return `Audit session started at ${this.startTime}`;
  }

  // Add a finding with automatic ID and timestamp
  addFinding(finding: Omit<Finding, 'id' | 'timestamp'>): Finding {
    const fullFinding: Finding = {
      ...finding,
      id: `${ID_PREFIXES.FINDING}-${randomUUID().slice(0, UUID_SLICE_LENGTH).toUpperCase()}`,
      timestamp: new Date().toISOString(),
    };
    this.findings.push(fullFinding);
    return fullFinding;
  }

  // Collect evidence with hash for chain of custody
  collectEvidence(
    type: Evidence['type'],
    description: string,
    content: string,
    source: string
  ): Evidence {
    const maxLen = EVIDENCE_LIMITS.MAX_CONTENT_LENGTH;
    const evidence: Evidence = {
      type,
      description,
      content: content.length > maxLen ? content.slice(0, maxLen) + '...[truncated]' : content,
      hash: this.hashContent(content),
      source,
      collectedAt: new Date().toISOString(),
    };
    this.evidence.push(evidence);
    return evidence;
  }

  // SHA-256 hash for evidence integrity
  private hashContent(content: string): string {
    return createHash('sha256').update(content).digest('hex');
  }

  // Calculate risk score (0-100)
  calculateRiskScore(): number {
    if (this.findings.length === 0) return 0;

    let totalWeight = 0;
    let maxPossible = 0;

    for (const finding of this.findings) {
      totalWeight += SEVERITY_WEIGHTS[finding.severity];
      maxPossible += SEVERITY_WEIGHTS.CRITICAL;
    }

    return Math.min(MAX_RISK_SCORE, Math.round((totalWeight / Math.max(maxPossible, 1)) * MAX_RISK_SCORE));
  }

  // Get statistics
  getStatistics(): AuditStatistics {
    return {
      totalFindings: this.findings.length,
      critical: this.findings.filter(f => f.severity === 'CRITICAL').length,
      high: this.findings.filter(f => f.severity === 'HIGH').length,
      medium: this.findings.filter(f => f.severity === 'MEDIUM').length,
      low: this.findings.filter(f => f.severity === 'LOW').length,
      info: this.findings.filter(f => f.severity === 'INFO').length,
      passed: this.findings.filter(f => f.status === 'PASS').length,
      failed: this.findings.filter(f => f.status === 'FAIL').length,
    };
  }

  // Determine overall rating
  getOverallRating(): AuditStatus {
    const stats = this.getStatistics();
    if (stats.critical > 0) return 'FAIL';
    if (stats.high > RATING_THRESHOLDS.HIGH_COUNT_FAIL) return 'FAIL';
    if (stats.high > 0 || stats.medium > RATING_THRESHOLDS.MEDIUM_COUNT_WARNING) return 'WARNING';
    if (stats.medium > 0) return 'REVIEW_REQUIRED';
    return 'PASS';
  }

  // Generate executive summary
  generateExecutiveSummary(): string {
    const stats = this.getStatistics();
    const rating = this.getOverallRating();
    const riskScore = this.calculateRiskScore();

    let summary = `## Executive Summary\n\n`;
    summary += `**Overall Rating:** ${rating}\n`;
    summary += `**Risk Score:** ${riskScore}/100\n\n`;
    summary += `### Findings Overview\n`;
    summary += `- **Critical:** ${stats.critical}\n`;
    summary += `- **High:** ${stats.high}\n`;
    summary += `- **Medium:** ${stats.medium}\n`;
    summary += `- **Low:** ${stats.low}\n`;
    summary += `- **Informational:** ${stats.info}\n\n`;

    if (stats.critical > 0) {
      summary += `**${REPORT_STRINGS.IMMEDIATE_ACTION}:** ${stats.critical} critical finding(s) detected that require immediate remediation.\n\n`;
    }

    if (stats.high > 0) {
      summary += `**${REPORT_STRINGS.HIGH_PRIORITY}:** ${stats.high} high-severity finding(s) should be addressed within 7 days.\n\n`;
    }

    return summary;
  }

  // Generate full report
  generateReport(title: string, scope: string, auditor: string = REPORT_STRINGS.AUDITOR_NAME): AuditReport {
    const endTime = new Date().toISOString();

    return {
      id: `${ID_PREFIXES.AUDIT}-${randomUUID().slice(0, UUID_SLICE_LENGTH).toUpperCase()}`,
      title,
      scope,
      domain: this.config.domains,
      auditor,
      startTime: this.startTime,
      endTime,
      executiveSummary: this.generateExecutiveSummary(),
      overallRating: this.getOverallRating(),
      riskScore: this.calculateRiskScore(),
      findings: this.findings,
      statistics: this.getStatistics(),
      methodology: [
        'Evidence-based verification',
        'Pattern analysis and red flag detection',
        'Compliance framework mapping',
        'Risk-weighted scoring',
      ],
      recommendations: this.generateRecommendations(),
    };
  }

  // Generate recommendations based on findings
  private generateRecommendations(): string[] {
    const recommendations: string[] = [];
    const stats = this.getStatistics();

    if (stats.critical > 0) {
      recommendations.push('IMMEDIATE: Address all critical findings before any further development or deployment');
    }

    if (stats.high > 0) {
      recommendations.push('SHORT-TERM: Schedule remediation of high-severity findings within the next sprint');
    }

    if (stats.medium > 3) {
      recommendations.push('MEDIUM-TERM: Create a backlog item to address medium-severity findings systematically');
    }

    // Domain-specific recommendations
    const domainFindings = new Map<AuditDomain, number>();
    for (const finding of this.findings) {
      domainFindings.set(finding.domain, (domainFindings.get(finding.domain) || 0) + 1);
    }

    if ((domainFindings.get('SECURITY') || 0) > 2) {
      recommendations.push('Conduct a comprehensive security review and consider penetration testing');
    }

    if ((domainFindings.get('COMPLIANCE') || 0) > 2) {
      recommendations.push('Engage compliance officer to review and update policies');
    }

    if ((domainFindings.get('CODE') || 0) > 5) {
      recommendations.push('Implement automated code quality gates in CI/CD pipeline');
    }

    return recommendations;
  }

  // Get all findings
  getFindings(): Finding[] {
    return [...this.findings];
  }

  // Get findings by severity
  getFindingsBySeverity(severity: Severity): Finding[] {
    return this.findings.filter(f => f.severity === severity);
  }

  // Get findings by domain
  getFindingsByDomain(domain: AuditDomain): Finding[] {
    return this.findings.filter(f => f.domain === domain);
  }

  // Export report as Markdown
  exportMarkdown(report: AuditReport): string {
    let md = `# ${report.title}\n\n`;
    md += `**Report ID:** ${report.id}\n`;
    md += `**Auditor:** ${report.auditor}\n`;
    md += `**Scope:** ${report.scope}\n`;
    md += `**Date:** ${report.startTime} - ${report.endTime}\n\n`;
    md += `---\n\n`;
    md += report.executiveSummary;
    md += `\n---\n\n`;
    md += `## Detailed Findings\n\n`;

    for (const severity of SEVERITY_ORDER) {
      const severityFindings = report.findings.filter(f => f.severity === severity);
      if (severityFindings.length === 0) continue;

      md += `### ${severity} Severity (${severityFindings.length})\n\n`;

      for (const finding of severityFindings) {
        md += `#### ${finding.id}: ${finding.title}\n\n`;
        md += `- **Domain:** ${finding.domain}\n`;
        md += `- **Status:** ${finding.status}\n`;
        if (finding.location?.file) {
          md += `- **Location:** ${finding.location.file}`;
          if (finding.location.line) md += `:${finding.location.line}`;
          md += `\n`;
        }
        if (finding.cwe) md += `- **CWE:** ${finding.cwe}\n`;
        if (finding.cvss) md += `- **CVSS:** ${finding.cvss}\n`;
        md += `\n**Description:**\n${finding.description}\n\n`;
        md += `**Recommendation:**\n${finding.recommendation}\n\n`;

        if (finding.evidence.length > 0) {
          md += `**Evidence:**\n`;
          for (const ev of finding.evidence) {
            md += `- ${ev.type}: ${ev.description} (Hash: ${ev.hash?.slice(0, 16)}...)\n`;
          }
          md += `\n`;
        }
        md += `---\n\n`;
      }
    }

    md += `## Recommendations\n\n`;
    for (const rec of report.recommendations) {
      md += `- ${rec}\n`;
    }

    md += `\n---\n\n`;
    md += `*Report generated by ${report.auditor} - ${REPORT_STRINGS.TAGLINE}*\n`;

    return md;
  }
}
