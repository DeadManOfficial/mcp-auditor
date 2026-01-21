/**
 * Multi-Domain Audit Handlers
 */

import { RedFlagScanner } from '../core/red-flags.js';
import { Finding } from '../core/types.js';
import { CodeAuditor } from '../domains/code-audit.js';
import { SecurityAuditor } from '../domains/security-audit.js';
import { ForensicAuditor } from '../domains/forensic-audit.js';
import { ToolResult, ToolArgs } from './types.js';
import { RISK_THRESHOLDS } from '../core/constants.js';

const redFlagScanner = new RedFlagScanner();
const codeAuditor = new CodeAuditor();
const securityAuditor = new SecurityAuditor();
const forensicAuditor = new ForensicAuditor();

export async function handleComprehensiveAudit(args: ToolArgs): Promise<ToolResult> {
  const content = args.content as string;
  const domains = args.domains as string[] || ['CODE', 'SECURITY', 'COMPLIANCE', 'FORENSIC'];
  const depth = args.depth as string || 'standard';

  const allFindings: Finding[] = [];
  const results: Record<string, unknown> = {
    auditDepth: depth,
    domains: domains
  };

  // Red flag scan for all
  const redFlags = redFlagScanner.scan(content);
  if (redFlags.length > 0) {
    const rfFindings = redFlagScanner.matchesToFindings(redFlags);
    results.redFlags = rfFindings.map(f => ({
      title: f.title,
      severity: f.severity,
      domain: f.domain
    }));
    allFindings.push(...rfFindings);
  }

  // Domain-specific analysis
  if (domains.includes('CODE')) {
    const codeFindings = await codeAuditor.auditCode(content, 'comprehensive-audit.txt');
    results.codeAnalysis = {
      vulnerabilities: codeFindings.filter(f => f.domain === 'SECURITY').length,
      codeSmells: codeFindings.filter(f => f.domain === 'CODE').length
    };
    allFindings.push(...codeFindings);
  }

  if (domains.includes('SECURITY')) {
    const owaspFindings = await securityAuditor.assessOwasp(content);
    allFindings.push(...owaspFindings);
    securityAuditor.clearFindings();
  }

  if (domains.includes('FORENSIC')) {
    const fraudFindings = forensicAuditor.assessFraudRisk(content);
    allFindings.push(...fraudFindings);
    forensicAuditor.clearFindings();
  }

  results.findings = allFindings.map(f => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    domain: f.domain,
    status: f.status
  }));

  results.summary = {
    totalFindings: allFindings.length,
    bySeverity: {
      CRITICAL: allFindings.filter(f => f.severity === 'CRITICAL').length,
      HIGH: allFindings.filter(f => f.severity === 'HIGH').length,
      MEDIUM: allFindings.filter(f => f.severity === 'MEDIUM').length,
      LOW: allFindings.filter(f => f.severity === 'LOW').length
    }
  };

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(results, null, 2)
    }]
  };
}

export async function handleRiskAssessment(args: ToolArgs): Promise<ToolResult> {
  const findings = args.findings as Array<{
    title: string;
    description: string;
    likelihood: number;
    impact: number;
  }>;

  const assessed = findings.map(f => {
    const riskScore = f.likelihood * f.impact;
    let riskLevel: string;
    if (riskScore >= RISK_THRESHOLDS.CRITICAL) riskLevel = 'CRITICAL';
    else if (riskScore >= RISK_THRESHOLDS.HIGH) riskLevel = 'HIGH';
    else if (riskScore >= RISK_THRESHOLDS.MEDIUM) riskLevel = 'MEDIUM';
    else if (riskScore >= RISK_THRESHOLDS.LOW) riskLevel = 'LOW';
    else riskLevel = 'MINIMAL';

    return {
      ...f,
      riskScore,
      riskLevel,
      priority: riskScore
    };
  }).sort((a, b) => b.riskScore - a.riskScore);

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        assessedFindings: assessed,
        summary: {
          total: assessed.length,
          criticalRisks: assessed.filter(f => f.riskLevel === 'CRITICAL').length,
          highRisks: assessed.filter(f => f.riskLevel === 'HIGH').length,
          averageRiskScore: assessed.length > 0
            ? assessed.reduce((sum, f) => sum + f.riskScore, 0) / assessed.length
            : 0
        }
      }, null, 2)
    }]
  };
}
