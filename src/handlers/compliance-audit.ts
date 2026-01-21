/**
 * Compliance Audit Handlers
 */

import { ComplianceAuditor } from '../domains/compliance-audit.js';
import { ComplianceFramework } from '../core/types.js';
import { ToolResult, ToolArgs } from './types.js';

const complianceAuditor = new ComplianceAuditor();

export async function handleGenerateComplianceChecklist(args: ToolArgs): Promise<ToolResult> {
  const checklist = complianceAuditor.generateChecklist(
    args.framework as ComplianceFramework
  );

  return {
    content: [{
      type: 'text',
      text: `# ${args.framework} Compliance Checklist\n\n**Scope:** ${args.scope || 'Full Assessment'}\n\n${checklist}`
    }]
  };
}

export async function handleAssessCompliance(args: ToolArgs): Promise<ToolResult> {
  const complianceFindings = complianceAuditor.assessCompliance(
    args.framework as ComplianceFramework,
    args.currentState as string
  );
  complianceAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        framework: args.framework,
        totalFindings: complianceFindings.length,
        findings: complianceFindings.map(f => ({
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

export async function handleMapComplianceControls(args: ToolArgs): Promise<ToolResult> {
  const mapping = complianceAuditor.mapControls(
    args.sourceFramework as ComplianceFramework,
    args.targetFramework as ComplianceFramework
  );

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        sourceFramework: args.sourceFramework,
        targetFramework: args.targetFramework,
        mappings: mapping
      }, null, 2)
    }]
  };
}

export { complianceAuditor };
