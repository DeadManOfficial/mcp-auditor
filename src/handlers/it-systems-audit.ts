/**
 * IT Systems Audit Handlers
 */

import { ITSystemsAuditor } from '../domains/it-systems-audit.js';
import { ToolResult, ToolArgs } from './types.js';

const itSystemsAuditor = new ITSystemsAuditor();

export async function handleAssessCOBIT(args: ToolArgs): Promise<ToolResult> {
  const contextData = `Domain: ${args.domain}\n\nCurrent State:\n${args.currentState}`;
  const cobitFindings = itSystemsAuditor.assessCOBIT(contextData);
  itSystemsAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        cobitDomain: args.domain,
        totalFindings: cobitFindings.length,
        findings: cobitFindings.map(f => ({
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

export async function handleAssessChangeManagement(args: ToolArgs): Promise<ToolResult> {
  const changeFindings = itSystemsAuditor.assessChangeManagement(args.processDescription as string);
  itSystemsAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        totalFindings: changeFindings.length,
        findings: changeFindings.map(f => ({
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

export async function handleAssessBackupRecovery(args: ToolArgs): Promise<ToolResult> {
  const backupFindings = itSystemsAuditor.assessBackupRecovery(args.currentPractices as string);
  itSystemsAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        totalFindings: backupFindings.length,
        findings: backupFindings.map(f => ({
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

export async function handleAssessADSecurity(args: ToolArgs): Promise<ToolResult> {
  const adFindings = itSystemsAuditor.assessADSecurity(args.adConfiguration as string);
  itSystemsAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        totalFindings: adFindings.length,
        findings: adFindings.map(f => ({
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

export { itSystemsAuditor };
