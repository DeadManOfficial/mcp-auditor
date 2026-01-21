/**
 * Audit Engine Handlers
 */

import { AuditEngine } from '../core/engine.js';
import { AuditDomain, Severity } from '../core/types.js';
import { ToolResult, ToolArgs } from './types.js';

// Audit state management
let currentAuditConfig: {
  name: string;
  domain: AuditDomain;
  scope: string;
  objectives: string[];
  startDate: string;
  id: string;
} | null = null;

let auditEngine: AuditEngine | null = null;

export function getAuditEngine(): AuditEngine | null {
  return auditEngine;
}

export function getCurrentConfig() {
  return currentAuditConfig;
}

export async function handleStartAudit(args: ToolArgs): Promise<ToolResult> {
  const domain = args.domain as AuditDomain;
  currentAuditConfig = {
    name: args.name as string,
    domain,
    scope: args.scope as string,
    objectives: args.objectives as string[],
    startDate: new Date().toISOString(),
    id: `AUDIT-${Date.now()}`
  };

  auditEngine = new AuditEngine({
    domains: [domain],
    severity_threshold: 'LOW'
  });
  auditEngine.startAudit();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        message: `Audit "${args.name}" started`,
        auditId: currentAuditConfig.id,
        domain: currentAuditConfig.domain,
        scope: currentAuditConfig.scope,
        objectives: currentAuditConfig.objectives,
        startDate: currentAuditConfig.startDate
      }, null, 2)
    }]
  };
}

export async function handleAddFinding(args: ToolArgs): Promise<ToolResult> {
  if (!auditEngine) {
    return {
      content: [{
        type: 'text',
        text: 'Error: No audit session started. Use start_audit first.'
      }],
      isError: true
    };
  }

  const finding = auditEngine.addFinding({
    domain: currentAuditConfig?.domain || 'GENERAL',
    severity: args.severity as Severity,
    status: 'REVIEW_REQUIRED',
    title: args.title as string,
    description: args.description as string,
    evidence: (args.evidence as string[] || []).map(e => ({
      type: 'DATA' as const,
      description: e,
      source: 'Manual input',
      collectedAt: new Date().toISOString()
    })),
    recommendation: (args.recommendations as string[] || []).join('\n'),
  });

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        message: 'Finding added',
        finding: {
          id: finding.id,
          title: finding.title,
          severity: finding.severity,
          domain: finding.domain
        }
      }, null, 2)
    }]
  };
}

export async function handleCollectEvidence(args: ToolArgs): Promise<ToolResult> {
  if (!auditEngine) {
    return {
      content: [{
        type: 'text',
        text: 'Error: No audit session started. Use start_audit first.'
      }],
      isError: true
    };
  }

  const evidenceType = args.type as 'FILE' | 'LOG' | 'SCREENSHOT' | 'DATA' | 'TESTIMONY' | 'CONFIGURATION';
  const evidence = auditEngine.collectEvidence(
    evidenceType,
    args.source as string,
    args.content as string,
    args.source as string
  );

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        message: 'Evidence collected with chain of custody hash',
        evidence: {
          type: evidence.type,
          source: evidence.source,
          hash: evidence.hash,
          collectedAt: evidence.collectedAt
        }
      }, null, 2)
    }]
  };
}

export async function handleGenerateReport(args: ToolArgs): Promise<ToolResult> {
  if (!auditEngine || !currentAuditConfig) {
    return {
      content: [{
        type: 'text',
        text: 'Error: No audit session started. Use start_audit first.'
      }],
      isError: true
    };
  }

  const format = args.format as string || 'json';
  const report = auditEngine.generateReport(
    currentAuditConfig.name,
    currentAuditConfig.scope,
    'Omniscient Auditor'
  );

  if (format === 'markdown') {
    return {
      content: [{
        type: 'text',
        text: auditEngine.exportMarkdown(report)
      }]
    };
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(report, null, 2)
    }]
  };
}
