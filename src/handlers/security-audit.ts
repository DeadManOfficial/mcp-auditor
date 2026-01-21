/**
 * Security Audit Handlers
 */

import { SecurityAuditor, MITRE_TECHNIQUES } from '../domains/security-audit.js';
import { ToolResult, ToolArgs } from './types.js';

const securityAuditor = new SecurityAuditor();

export async function handleAssessOwasp(args: ToolArgs): Promise<ToolResult> {
  const targetInfo = args.evidenceNotes
    ? `${args.applicationContext}\n\nEvidence Notes:\n${args.evidenceNotes}`
    : args.applicationContext as string;

  const owaspFindings = await securityAuditor.assessOwasp(targetInfo);
  securityAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        owaspTop10Categories: owaspFindings.length,
        findings: owaspFindings.map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          status: f.status,
          description: f.description,
          recommendation: f.recommendation
        }))
      }, null, 2)
    }]
  };
}

export async function handleAssessCloudSecurity(args: ToolArgs): Promise<ToolResult> {
  const cloudFindings = securityAuditor.assessCloudSecurity(
    args.provider as 'AWS' | 'AZURE' | 'GCP'
  );
  securityAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        provider: args.provider,
        configurationContext: args.configurationData,
        totalChecks: cloudFindings.length,
        findings: cloudFindings.map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          status: f.status,
          description: f.description,
          recommendation: f.recommendation
        }))
      }, null, 2)
    }]
  };
}

export async function handleAssessZeroTrust(args: ToolArgs): Promise<ToolResult> {
  const zeroTrustFindings = securityAuditor.assessZeroTrust();
  securityAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        architectureContext: args.architectureDescription,
        totalChecks: zeroTrustFindings.length,
        findings: zeroTrustFindings.map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          status: f.status,
          description: f.description,
          recommendation: f.recommendation
        }))
      }, null, 2)
    }]
  };
}

export async function handleGetMitreTechniques(args: ToolArgs): Promise<ToolResult> {
  const category = args.category as string | undefined;
  const techniques = category
    ? MITRE_TECHNIQUES.filter(t => t.tactic.toLowerCase().includes(category.toLowerCase()))
    : MITRE_TECHNIQUES;

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        category: category || 'ALL',
        count: techniques.length,
        techniques: techniques.map(t => ({
          tactic: t.tactic,
          techniqueId: t.techniqueId,
          techniqueName: t.techniqueName,
          description: t.description,
          detection: t.detection,
          mitigation: t.mitigation
        }))
      }, null, 2)
    }]
  };
}

export { securityAuditor };
