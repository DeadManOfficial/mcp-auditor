/**
 * Forensic Audit Handlers
 */

import { ForensicAuditor, BenfordAnalyzer } from '../domains/forensic-audit.js';
import { ToolResult, ToolArgs } from './types.js';

const forensicAuditor = new ForensicAuditor();

export async function handleAnalyzeBenford(args: ToolArgs): Promise<ToolResult> {
  const numbers = args.numbers as number[];
  const analysisType = args.analysisType as string || 'both';
  const analyzer = new BenfordAnalyzer();

  const result: Record<string, unknown> = {};
  if (analysisType === 'first_digit' || analysisType === 'both') {
    result.firstDigit = analyzer.analyze(numbers);
  }
  if (analysisType === 'second_digit' || analysisType === 'both') {
    result.secondDigit = analyzer.analyzeSecondDigit(numbers);
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2)
    }]
  };
}

export async function handleAssessFraudRisk(args: ToolArgs): Promise<ToolResult> {
  const contextData = args.financialData
    ? `${args.context}\n\nFinancial Data:\n${args.financialData}`
    : args.context as string;
  const assessment = forensicAuditor.assessFraudRisk(contextData);
  const findings = forensicAuditor.getFindings();
  forensicAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        fraudIndicators: assessment.map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          domain: f.domain
        })),
        findings: findings.map(f => ({
          title: f.title,
          severity: f.severity,
          description: f.description,
          recommendation: f.recommendation
        }))
      }, null, 2)
    }]
  };
}

export async function handleAssessAMLRisk(args: ToolArgs): Promise<ToolResult> {
  const contextData = args.customerInfo
    ? `${args.transactionData}\n\nCustomer Info:\n${args.customerInfo}`
    : args.transactionData as string;
  const assessment = forensicAuditor.assessAMLRisk(contextData);
  const findings = forensicAuditor.getFindings();
  forensicAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        amlIndicators: assessment.map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          domain: f.domain
        })),
        findings: findings.map(f => ({
          title: f.title,
          severity: f.severity,
          description: f.description,
          recommendation: f.recommendation
        }))
      }, null, 2)
    }]
  };
}

export async function handleGenerateInterviewGuide(args: ToolArgs): Promise<ToolResult> {
  const role = `${args.interviewType} - ${args.caseContext}`;
  const guide = forensicAuditor.generateInterviewGuide(role);

  let output = guide;
  if (args.topicsTocover && (args.topicsTocover as string[]).length > 0) {
    output += `\n\n## Custom Topics to Cover\n\n`;
    for (const topic of args.topicsTocover as string[]) {
      output += `- [ ] ${topic}\n`;
    }
  }

  return {
    content: [{
      type: 'text',
      text: output
    }]
  };
}

export { forensicAuditor };
