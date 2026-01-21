/**
 * AI/ML Audit Handlers
 */

import { AIMLAuditor } from '../domains/ai-ml-audit.js';
import { ToolResult, ToolArgs } from './types.js';

const aimlAuditor = new AIMLAuditor();

export async function handleAssessAIRisks(args: ToolArgs): Promise<ToolResult> {
  const contextData = args.deploymentContext
    ? `${args.modelDescription}\n\nDeployment Context:\n${args.deploymentContext}`
    : args.modelDescription as string;
  const aiFindings = aimlAuditor.assessAIRisks(contextData);
  aimlAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        modelDescription: args.modelDescription,
        deploymentContext: args.deploymentContext,
        totalFindings: aiFindings.length,
        findings: aiFindings.map(f => ({
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

export async function handleAssessFairness(args: ToolArgs): Promise<ToolResult> {
  const metricsContext = {
    protectedAttribute: args.protectedAttribute as string,
    predictions: args.modelPredictions as string
  };
  const fairnessFindings = aimlAuditor.assessFairness(
    metricsContext as unknown as Record<string, number>,
    `Protected Attribute: ${args.protectedAttribute}\nPredictions: ${args.modelPredictions}`
  );
  aimlAuditor.clearFindings();

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        protectedAttribute: args.protectedAttribute,
        totalFindings: fairnessFindings.length,
        findings: fairnessFindings.map(f => ({
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

export async function handleGenerateModelCard(args: ToolArgs): Promise<ToolResult> {
  const modelCard = aimlAuditor.generateModelCardTemplate(args.modelName as string);

  return {
    content: [{
      type: 'text',
      text: `# Model Card: ${args.modelName}\n\n**Type:** ${args.modelType}\n**Intended Use:** ${args.intendedUse}\n\n${modelCard}`
    }]
  };
}

export { aimlAuditor };
