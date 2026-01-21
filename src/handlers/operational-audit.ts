/**
 * Operational Audit Handlers
 */

import { OperationalAuditor, ValueStreamAnalyzer } from '../domains/operational-audit.js';
import { ToolResult, ToolArgs } from './types.js';

const operationalAuditor = new OperationalAuditor();

export async function handleAssessWaste(args: ToolArgs): Promise<ToolResult> {
  const contextData = args.metrics
    ? `${args.processDescription}\n\nMetrics:\n${args.metrics}`
    : args.processDescription as string;
  const wasteFindings = operationalAuditor.assessWaste(contextData);
  operationalAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        timwoodAnalysis: {
          processContext: args.processDescription,
          metrics: args.metrics
        },
        totalFindings: wasteFindings.length,
        findings: wasteFindings.map(f => ({
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

export async function handleGenerateDMAICPlan(args: ToolArgs): Promise<ToolResult> {
  const projectName = `${args.problemStatement} - ${args.scope}`;
  const plan = operationalAuditor.generateDMAICPlan(projectName);

  return {
    content: [{
      type: 'text',
      text: `# DMAIC Plan\n\n**Problem:** ${args.problemStatement}\n**Scope:** ${args.scope}\n**Current Metrics:** ${args.currentMetrics || 'To be measured'}\n\n${plan}`
    }]
  };
}

export async function handleAnalyzeValueStream(args: ToolArgs): Promise<ToolResult> {
  const steps = args.steps as Array<{
    name: string;
    cycleTime: number;
    waitTime: number;
    valueAdded: boolean;
  }>;

  const elements = steps.map(s => ({
    name: s.name,
    type: 'PROCESS' as const,
    cycleTime: s.cycleTime,
    waitTime: s.waitTime,
    valueAdded: s.valueAdded
  }));

  const analyzer = new ValueStreamAnalyzer();
  const analysis = analyzer.analyze(elements);

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(analysis, null, 2)
    }]
  };
}

export async function handleGetEfficiencyMetrics(args: ToolArgs): Promise<ToolResult> {
  const allMetrics = operationalAuditor.getMetricsReference();
  const requestedNames = args.metricNames as string[] | undefined;

  const metrics = requestedNames && requestedNames.length > 0
    ? allMetrics.filter(m => requestedNames.some(n =>
        m.name.toLowerCase().includes(n.toLowerCase()) ||
        m.id.toLowerCase() === n.toLowerCase()
      ))
    : allMetrics;

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        count: metrics.length,
        metrics: metrics.map(m => ({
          id: m.id,
          name: m.name,
          category: m.category,
          description: m.description,
          formula: m.formula,
          target: m.target,
          interpretation: m.interpretation
        }))
      }, null, 2)
    }]
  };
}

export { operationalAuditor };
