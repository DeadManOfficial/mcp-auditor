/**
 * Code Audit Handlers
 */

import { CodeAuditor } from '../domains/code-audit.js';
import { DEPENDENCY_THRESHOLDS, SENSITIVE_PACKAGES } from '../core/constants.js';
import { ToolResult, ToolArgs } from './types.js';

const codeAuditor = new CodeAuditor();

export async function handleAuditCode(args: ToolArgs): Promise<ToolResult> {
  const findings = await codeAuditor.auditCode(
    args.code as string,
    args.filename as string || 'unknown.js',
    args.language as string
  );

  const vulnerabilities = findings.filter(f => f.domain === 'SECURITY');
  const codeSmells = findings.filter(f => f.domain === 'CODE');

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        summary: {
          totalFindings: findings.length,
          vulnerabilities: vulnerabilities.length,
          codeSmells: codeSmells.length
        },
        findings: findings.map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          domain: f.domain,
          description: f.description,
          recommendation: f.recommendation,
          location: f.location,
          cwe: f.cwe
        }))
      }, null, 2)
    }]
  };
}

export async function handleCalculateCodeMetrics(args: ToolArgs): Promise<ToolResult> {
  const code = args.code as string;
  const lines = code.split('\n');

  const metrics = {
    linesOfCode: lines.filter(l => l.trim().length > 0).length,
    linesOfComments: lines.filter(l =>
      l.trim().startsWith('//') ||
      l.trim().startsWith('/*') ||
      l.trim().startsWith('*')
    ).length,
    blankLines: lines.filter(l => l.trim().length === 0).length,
    functions: (code.match(/function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\(|=>\s*\{/g) || []).length,
    classes: (code.match(/class\s+\w+/g) || []).length,
    imports: (code.match(/import\s+|require\s*\(/g) || []).length,
    todoCount: (code.match(/TODO|FIXME|XXX/gi) || []).length,
    estimatedComplexity: Math.round(
      (code.match(/if\s*\(|else\s*\{|for\s*\(|while\s*\(|switch\s*\(|case\s+|catch\s*\(|\?\?|\|\||&&/g) || []).length * 1.5
    )
  };

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(metrics, null, 2)
    }]
  };
}

export async function handleAnalyzeDependencies(args: ToolArgs): Promise<ToolResult> {
  try {
    const pkg = JSON.parse(args.packageJson as string);
    const deps = pkg.dependencies || {};
    const devDeps = pkg.devDependencies || {};

    const analysis = {
      projectName: pkg.name,
      version: pkg.version,
      totalDependencies: Object.keys(deps).length + Object.keys(devDeps).length,
      production: Object.entries(deps).map(([name, version]) => ({ name, version, type: 'production' })),
      development: Object.entries(devDeps).map(([name, version]) => ({ name, version, type: 'development' })),
      recommendations: [] as string[]
    };

    // Check dependency count
    if (Object.keys(deps).length > DEPENDENCY_THRESHOLDS.HIGH_DEPENDENCY_COUNT) {
      analysis.recommendations.push(
        'Consider reducing production dependencies to improve bundle size and security surface.'
      );
    }

    // Check for security-sensitive packages
    const foundSensitive = Object.keys(deps).filter(d =>
      SENSITIVE_PACKAGES.some(s => d.includes(s))
    );
    if (foundSensitive.length > 0) {
      analysis.recommendations.push(
        `Security-sensitive packages found: ${foundSensitive.join(', ')}. Ensure these are kept updated.`
      );
    }

    return {
      content: [{
        type: 'text',
        text: JSON.stringify(analysis, null, 2)
      }]
    };
  } catch (e) {
    return {
      content: [{
        type: 'text',
        text: `Error parsing package.json: ${e instanceof Error ? e.message : 'Invalid JSON'}`
      }],
      isError: true
    };
  }
}

export { codeAuditor };
