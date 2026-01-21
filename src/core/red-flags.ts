// Red Flag Detection System - Forensic Pattern Recognition
// Based on comprehensive forensic audit research

import { Severity, RedFlagPattern, Finding, AuditDomain, Evidence } from './types.js';
import { randomUUID } from 'crypto';
import {
  SEVERITY_WEIGHTS,
  EVIDENCE_LIMITS,
  UUID_SLICE_LENGTH,
  ID_PREFIXES,
} from './constants.js';

// Forensic Keyword Red Flag Tables
export const RED_FLAG_PATTERNS: RedFlagPattern[] = [
  // ============================================
  // JOURNAL ENTRY RED FLAGS
  // ============================================
  {
    category: 'JOURNAL_ENTRIES',
    keywords: ['plug', 'net to zero', 'force balance', 'make it work', 'override', 'per [name]', 'per boss', 'per cfo', 'per ceo', 'adjust to budget', 'true up'],
    severity: 'HIGH',
    interpretation: 'Indicators of manual manipulation to force financial statements to balance or meet targets. May indicate earnings management or fraud.',
  },
  {
    category: 'JOURNAL_ENTRIES',
    keywords: ['round', 'estimate', 'approximately', 'roughly', 'about', 'ballpark'],
    severity: 'MEDIUM',
    interpretation: 'Vague quantification in journal entries may indicate lack of documentation or invented figures.',
  },
  {
    category: 'JOURNAL_ENTRIES',
    keywords: ['reverse later', 'will fix', 'temporary', 'placeholder', 'tbd', 'to be determined'],
    severity: 'MEDIUM',
    interpretation: 'Entries intended for later reversal or correction may be used to manipulate period-end results.',
  },

  // ============================================
  // EXPENSE AND PAYMENT RED FLAGS
  // ============================================
  {
    category: 'EXPENSES',
    keywords: ['gift', 'facilitation', 'grease', 'expedite', 'speed money', 'tea money', 'consulting fee', 'advisory fee', 'referral fee'],
    severity: 'HIGH',
    interpretation: 'Vague descriptions often hide bribery, kickbacks, FCPA violations, or personal expenses disguised as business costs.',
  },
  {
    category: 'EXPENSES',
    keywords: ['miscellaneous', 'sundry', 'other', 'various', 'general', 'admin fee', 'service charge'],
    severity: 'MEDIUM',
    interpretation: 'Catch-all categories that obscure the true nature of expenses. Common vehicle for hiding improper payments.',
  },
  {
    category: 'EXPENSES',
    keywords: ['cash', 'petty cash', 'reimbursement', 'out of pocket', 'personal funds'],
    severity: 'MEDIUM',
    interpretation: 'Cash transactions lack the audit trail of electronic payments. Higher risk of fictitious expenses.',
  },

  // ============================================
  // VENDOR AND PROCUREMENT RED FLAGS
  // ============================================
  {
    category: 'VENDOR_PAYMENTS',
    keywords: ['urgent', 'rush', 'asap', 'immediately', 'wire', 'same day', 'priority', 'expedited'],
    severity: 'HIGH',
    interpretation: 'Attempts to bypass procurement controls, rush approvals, or expedite payments to fraudulent entities.',
  },
  {
    category: 'VENDOR_PAYMENTS',
    keywords: ['one-time', 'special', 'exception', 'override approval', 'bypass', 'waive'],
    severity: 'HIGH',
    interpretation: 'Circumvention of normal controls. One-time vendors with no history are common fraud vehicles.',
  },
  {
    category: 'VENDOR_PAYMENTS',
    keywords: ['sole source', 'no bid', 'single vendor', 'preferred supplier', 'exclusive'],
    severity: 'MEDIUM',
    interpretation: 'Lack of competitive bidding may indicate kickback arrangements or favoritism.',
  },
  {
    category: 'VENDOR_PAYMENTS',
    keywords: ['retainer', 'advance', 'deposit', 'prepayment', 'upfront'],
    severity: 'MEDIUM',
    interpretation: 'Advance payments before services rendered create opportunity for payment to shell companies.',
  },

  // ============================================
  // COMMUNICATION RED FLAGS
  // ============================================
  {
    category: 'COMMUNICATION',
    keywords: ['delete this', 'destroy', 'shred', 'get rid of', 'burn', 'dispose'],
    severity: 'CRITICAL',
    interpretation: 'HIGH CONFIDENCE indicator of evidence destruction and concealment of wrongdoing.',
  },
  {
    category: 'COMMUNICATION',
    keywords: ['off the record', 'between us', 'keep quiet', 'don\'t tell', 'confidential', 'secret', 'private'],
    severity: 'HIGH',
    interpretation: 'Attempts to hide information from oversight or audit. May indicate collusion.',
  },
  {
    category: 'COMMUNICATION',
    keywords: ['burner', 'separate phone', 'personal email', 'private email', 'text me', 'call me', 'don\'t email'],
    severity: 'CRITICAL',
    interpretation: 'Use of unofficial communication channels to evade monitoring and create deniability.',
  },
  {
    category: 'COMMUNICATION',
    keywords: ['don\'t copy', 'no cc', 'keep this between', 'need to know', 'eyes only'],
    severity: 'HIGH',
    interpretation: 'Limiting distribution of information may indicate attempt to hide improper activity.',
  },
  {
    category: 'COMMUNICATION',
    keywords: ['cover', 'bury', 'hide', 'conceal', 'disguise', 'mask', 'obscure'],
    severity: 'CRITICAL',
    interpretation: 'Direct indicators of intentional concealment of information or transactions.',
  },

  // ============================================
  // TIMING RED FLAGS
  // ============================================
  {
    category: 'TIMING',
    keywords: ['weekend', 'saturday', 'sunday', 'holiday', 'after hours', 'late night', '2am', '3am', '4am'],
    severity: 'HIGH',
    interpretation: 'Out-of-band activity often suggests a fraudster working when oversight is minimal.',
  },
  {
    category: 'TIMING',
    keywords: ['month end', 'quarter end', 'year end', 'close', 'deadline', 'last minute', 'cutoff'],
    severity: 'MEDIUM',
    interpretation: 'Period-end transactions receive heightened scrutiny for earnings manipulation.',
  },
  {
    category: 'TIMING',
    keywords: ['backdate', 'back-date', 'pre-date', 'antedate', 'change date', 'adjust date'],
    severity: 'CRITICAL',
    interpretation: 'Document dating manipulation is a strong indicator of fraud or records falsification.',
  },

  // ============================================
  // REVENUE RECOGNITION RED FLAGS
  // ============================================
  {
    category: 'REVENUE',
    keywords: ['side letter', 'side agreement', 'verbal agreement', 'handshake deal', 'off-book', 'unwritten'],
    severity: 'CRITICAL',
    interpretation: 'Side agreements often contain terms that negate revenue recognition but are hidden from auditors.',
  },
  {
    category: 'REVENUE',
    keywords: ['channel stuffing', 'push sales', 'pull forward', 'accelerate', 'early shipment', 'bill and hold'],
    severity: 'HIGH',
    interpretation: 'Techniques to artificially inflate current period revenue at expense of future periods.',
  },
  {
    category: 'REVENUE',
    keywords: ['round trip', 'swap', 'barter', 'exchange', 'reciprocal'],
    severity: 'HIGH',
    interpretation: 'Round-trip transactions create artificial revenue with no economic substance.',
  },

  // ============================================
  // ASSET MANIPULATION RED FLAGS
  // ============================================
  {
    category: 'ASSETS',
    keywords: ['capitalize', 'defer', 'amortize', 'extend life', 'change estimate', 'revise useful life'],
    severity: 'MEDIUM',
    interpretation: 'Changes in accounting estimates can be used to manipulate earnings.',
  },
  {
    category: 'ASSETS',
    keywords: ['write off', 'write-off', 'impairment', 'obsolete', 'scrap', 'dispose'],
    severity: 'MEDIUM',
    interpretation: 'Asset write-offs can hide theft or be timed for earnings management.',
  },
  {
    category: 'ASSETS',
    keywords: ['inventory adjustment', 'shrinkage', 'variance', 'count difference', 'physical vs book'],
    severity: 'MEDIUM',
    interpretation: 'Inventory discrepancies may indicate theft, fictitious inventory, or poor controls.',
  },

  // ============================================
  // CODE AND SECURITY RED FLAGS
  // ============================================
  {
    category: 'CODE_SECURITY',
    keywords: ['password', 'passwd', 'secret', 'api_key', 'apikey', 'api-key', 'token', 'credential', 'private_key'],
    severity: 'CRITICAL',
    interpretation: 'Hardcoded credentials in source code. Immediate security vulnerability.',
  },
  {
    category: 'CODE_SECURITY',
    keywords: ['todo', 'fixme', 'hack', 'workaround', 'temporary fix', 'remove this', 'don\'t commit'],
    severity: 'MEDIUM',
    interpretation: 'Technical debt indicators. Code may contain known issues or insecure workarounds.',
  },
  {
    category: 'CODE_SECURITY',
    keywords: ['disable auth', 'skip validation', 'bypass', 'override security', 'trust all', 'insecure'],
    severity: 'CRITICAL',
    interpretation: 'Security controls being deliberately bypassed. Major vulnerability.',
  },
  {
    category: 'CODE_SECURITY',
    keywords: ['eval(', 'exec(', 'system(', 'shell_exec', 'subprocess', 'os.system', 'child_process'],
    severity: 'HIGH',
    interpretation: 'Dynamic code execution. Potential for command injection if user input reaches these functions.',
  },
  {
    category: 'CODE_SECURITY',
    keywords: ['sql', 'query', 'select * from', 'insert into', 'delete from', 'drop table'],
    severity: 'MEDIUM',
    interpretation: 'SQL operations. Verify parameterized queries are used to prevent SQL injection.',
  },

  // ============================================
  // COMPLIANCE RED FLAGS
  // ============================================
  {
    category: 'COMPLIANCE',
    keywords: ['ignore compliance', 'skip audit', 'avoid detection', 'workaround policy', 'exception'],
    severity: 'HIGH',
    interpretation: 'Deliberate circumvention of compliance controls.',
  },
  {
    category: 'COMPLIANCE',
    keywords: ['pii', 'ssn', 'social security', 'credit card', 'phi', 'health record', 'hipaa', 'gdpr'],
    severity: 'HIGH',
    interpretation: 'Sensitive data handling. Ensure proper controls and encryption are in place.',
  },

  // ============================================
  // BEHAVIORAL RED FLAGS (Interview/Investigation)
  // ============================================
  {
    category: 'BEHAVIORAL',
    keywords: ['never takes vacation', 'always first in', 'won\'t delegate', 'only one who knows', 'irreplaceable'],
    severity: 'HIGH',
    interpretation: 'Classic fraud perpetrator behavior. Maintaining exclusive control prevents detection.',
  },
  {
    category: 'BEHAVIORAL',
    keywords: ['lifestyle change', 'new car', 'expensive', 'luxury', 'gambling', 'financial problems', 'debt'],
    severity: 'MEDIUM',
    interpretation: 'Lifestyle indicators that may suggest motivation for fraud (pressure/opportunity/rationalization).',
  },
];

// Red Flag Scanner Class
export class RedFlagScanner {
  private patterns: RedFlagPattern[];

  constructor(customPatterns?: RedFlagPattern[]) {
    this.patterns = customPatterns || RED_FLAG_PATTERNS;
  }

  // Scan content for red flags
  scan(content: string, context?: string): RedFlagMatch[] {
    const matches: RedFlagMatch[] = [];
    const contentLower = content.toLowerCase();
    const lines = content.split('\n');

    for (const pattern of this.patterns) {
      for (const keyword of pattern.keywords) {
        const keywordLower = keyword.toLowerCase();
        let index = 0;

        while ((index = contentLower.indexOf(keywordLower, index)) !== -1) {
          // Find the line number
          let lineNumber = 1;
          let charCount = 0;
          for (let i = 0; i < lines.length; i++) {
            charCount += lines[i].length + 1; // +1 for newline
            if (charCount > index) {
              lineNumber = i + 1;
              break;
            }
          }

          // Get surrounding context
          const contextStart = Math.max(0, index - EVIDENCE_LIMITS.CONTEXT_CHARS_BEFORE);
          const contextEnd = Math.min(content.length, index + keyword.length + EVIDENCE_LIMITS.CONTEXT_CHARS_AFTER);
          const matchContext = content.slice(contextStart, contextEnd);

          matches.push({
            pattern,
            keyword,
            line: lineNumber,
            column: index - (charCount - lines[lineNumber - 1].length - 1),
            context: matchContext.replace(/\n/g, ' ').trim(),
            source: context || 'unknown',
          });

          index += keyword.length;
        }
      }
    }

    // Sort by severity (lower weight = higher priority, so we reverse the weights)
    const severityPriority: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
      INFO: 4,
    };

    return matches.sort((a, b) => severityPriority[a.pattern.severity] - severityPriority[b.pattern.severity]);
  }

  // Convert matches to findings
  matchesToFindings(matches: RedFlagMatch[], domain: AuditDomain = 'GENERAL'): Finding[] {
    const findings: Finding[] = [];

    // Group matches by pattern category
    const grouped = new Map<string, RedFlagMatch[]>();
    for (const match of matches) {
      const key = `${match.pattern.category}-${match.pattern.severity}`;
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key)!.push(match);
    }

    for (const [key, groupMatches] of grouped) {
      const pattern = groupMatches[0].pattern;
      const evidence: Evidence[] = groupMatches.slice(0, EVIDENCE_LIMITS.MAX_EVIDENCE_PER_FINDING).map(m => ({
        type: 'DATA',
        description: `Keyword "${m.keyword}" found at line ${m.line}`,
        content: m.context,
        source: m.source,
        collectedAt: new Date().toISOString(),
      }));

      findings.push({
        id: `${ID_PREFIXES.RED_FLAG}-${randomUUID().slice(0, UUID_SLICE_LENGTH).toUpperCase()}`,
        domain,
        severity: pattern.severity,
        status: pattern.severity === 'CRITICAL' ? 'FAIL' : 'WARNING',
        title: `Red Flag: ${pattern.category.replace(/_/g, ' ')} Pattern Detected`,
        description: `${groupMatches.length} instance(s) of ${pattern.category} red flag patterns detected.\n\n**Interpretation:** ${pattern.interpretation}\n\n**Keywords matched:** ${[...new Set(groupMatches.map(m => m.keyword))].join(', ')}`,
        evidence,
        recommendation: this.getRecommendation(pattern),
        timestamp: new Date().toISOString(),
      });
    }

    return findings;
  }

  // Get specific recommendation based on pattern
  private getRecommendation(pattern: RedFlagPattern): string {
    const recommendations: Record<string, string> = {
      JOURNAL_ENTRIES: 'Review all flagged journal entries with supporting documentation. Verify authorization and business purpose. Consider forensic examination of related transactions.',
      EXPENSES: 'Obtain detailed receipts and business justification for flagged expenses. Verify vendor legitimacy and cross-reference with expense policy.',
      VENDOR_PAYMENTS: 'Validate vendor existence and legitimacy. Check for PO box addresses, newly formed entities, or connections to employees. Review bid documentation.',
      COMMUNICATION: 'Preserve all flagged communications immediately. Consider legal hold. Interview relevant parties using forensic interview techniques.',
      TIMING: 'Analyze the business justification for out-of-band transactions. Cross-reference with system access logs and badge records.',
      REVENUE: 'Examine revenue transactions for proper documentation, customer acknowledgment, and compliance with revenue recognition standards (ASC 606).',
      ASSETS: 'Perform physical verification of assets. Review write-off authorization and compare to industry benchmarks.',
      CODE_SECURITY: 'Immediately remediate any hardcoded credentials. Rotate compromised secrets. Implement secrets management solution.',
      COMPLIANCE: 'Review data handling procedures. Verify encryption at rest and in transit. Assess access controls and audit logging.',
      BEHAVIORAL: 'Implement mandatory vacation policy. Ensure segregation of duties. Consider anonymous hotline for reporting.',
    };

    return recommendations[pattern.category] || 'Investigate the flagged items and document findings with supporting evidence.';
  }

  // Scan file specifically
  async scanFile(filePath: string, content: string): Promise<RedFlagMatch[]> {
    return this.scan(content, filePath);
  }

  // Get patterns by category
  getPatternsByCategory(category: string): RedFlagPattern[] {
    return this.patterns.filter(p => p.category === category);
  }

  // Add custom pattern
  addPattern(pattern: RedFlagPattern): void {
    this.patterns.push(pattern);
  }

  // Get all categories
  getCategories(): string[] {
    return [...new Set(this.patterns.map(p => p.category))];
  }
}

export interface RedFlagMatch {
  pattern: RedFlagPattern;
  keyword: string;
  line: number;
  column: number;
  context: string;
  source: string;
}

// Singleton instance
export const redFlagScanner = new RedFlagScanner();
