/**
 * Red Flag Detection Handlers
 */

import { RedFlagScanner } from '../core/red-flags.js';
import { ToolResult, ToolArgs } from './types.js';

const redFlagScanner = new RedFlagScanner();

export async function handleScanRedFlags(args: ToolArgs): Promise<ToolResult> {
  let matches = redFlagScanner.scan(args.content as string, 'user-provided');

  // Filter by categories if specified
  const requestedCategories = args.categories as string[] | undefined;
  if (requestedCategories && requestedCategories.length > 0) {
    matches = matches.filter(m => requestedCategories.includes(m.pattern.category));
  }

  const findings = redFlagScanner.matchesToFindings(matches);

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        totalMatches: matches.length,
        bySeverity: {
          CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
          HIGH: findings.filter(f => f.severity === 'HIGH').length,
          MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
          LOW: findings.filter(f => f.severity === 'LOW').length
        },
        findings: findings.map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          domain: f.domain,
          description: f.description,
          recommendation: f.recommendation
        }))
      }, null, 2)
    }]
  };
}

export { redFlagScanner };
