// Financial/Forensic Audit Module
// Covers: Benford's Law, fraud detection, AML, transaction analysis, interviews, deception detection

import { Finding, Evidence, Severity, AuditDomain, BenfordAnalysis, InterviewQuestion } from '../core/types.js';
import { randomUUID } from 'crypto';

// ============================================
// BENFORD'S LAW ANALYSIS
// ============================================

// Expected first digit frequencies per Benford's Law
export const BENFORD_EXPECTED: Record<number, number> = {
  1: 0.301,
  2: 0.176,
  3: 0.125,
  4: 0.097,
  5: 0.079,
  6: 0.067,
  7: 0.058,
  8: 0.051,
  9: 0.046,
};

// Second digit expected frequencies
export const BENFORD_SECOND_DIGIT: Record<number, number> = {
  0: 0.120,
  1: 0.114,
  2: 0.109,
  3: 0.104,
  4: 0.100,
  5: 0.097,
  6: 0.093,
  7: 0.090,
  8: 0.088,
  9: 0.085,
};

export interface BenfordResult {
  digit: number;
  expected: number;
  actual: number;
  count: number;
  deviation: number;
  deviationPercent: number;
  suspicious: boolean;
  zScore: number;
}

export interface BenfordSummary {
  totalNumbers: number;
  validNumbers: number;
  chiSquare: number;
  pValue: number;
  meanAbsoluteDeviation: number;
  suspicious: boolean;
  suspiciousDigits: number[];
  results: BenfordResult[];
  interpretation: string;
}

export class BenfordAnalyzer {
  // Analyze numbers against Benford's Law
  analyze(numbers: number[]): BenfordSummary {
    // Filter valid numbers (>= 10 to have meaningful first digits)
    const validNumbers = numbers.filter(n => Math.abs(n) >= 10);

    if (validNumbers.length < 100) {
      return {
        totalNumbers: numbers.length,
        validNumbers: validNumbers.length,
        chiSquare: 0,
        pValue: 1,
        meanAbsoluteDeviation: 0,
        suspicious: false,
        suspiciousDigits: [],
        results: [],
        interpretation: 'Insufficient sample size. Benford\'s Law requires at least 100 data points for meaningful analysis.',
      };
    }

    // Count first digits
    const digitCounts: Record<number, number> = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0 };

    for (const num of validNumbers) {
      const firstDigit = parseInt(Math.abs(num).toString()[0]);
      if (firstDigit >= 1 && firstDigit <= 9) {
        digitCounts[firstDigit]++;
      }
    }

    // Calculate results
    const results: BenfordResult[] = [];
    let chiSquare = 0;
    let totalDeviation = 0;
    const suspiciousDigits: number[] = [];

    for (let digit = 1; digit <= 9; digit++) {
      const count = digitCounts[digit];
      const actual = count / validNumbers.length;
      const expected = BENFORD_EXPECTED[digit];
      const deviation = actual - expected;
      const deviationPercent = (deviation / expected) * 100;

      // Z-score calculation
      const variance = (expected * (1 - expected)) / validNumbers.length;
      const stdDev = Math.sqrt(variance);
      const zScore = deviation / stdDev;

      // Chi-square contribution
      const chiContribution = Math.pow(count - (expected * validNumbers.length), 2) / (expected * validNumbers.length);
      chiSquare += chiContribution;

      totalDeviation += Math.abs(deviation);

      // Flag suspicious if deviation > 20% or z-score > 2
      const suspicious = Math.abs(deviationPercent) > 20 || Math.abs(zScore) > 2;
      if (suspicious) {
        suspiciousDigits.push(digit);
      }

      results.push({
        digit,
        expected,
        actual,
        count,
        deviation,
        deviationPercent,
        suspicious,
        zScore,
      });
    }

    // Calculate p-value (chi-square with 8 degrees of freedom)
    const pValue = this.chiSquarePValue(chiSquare, 8);
    const meanAbsoluteDeviation = totalDeviation / 9;

    // Determine if overall data is suspicious
    const suspicious = pValue < 0.05 || suspiciousDigits.length >= 3;

    // Generate interpretation
    let interpretation = '';
    if (suspicious) {
      interpretation = `**SUSPICIOUS DATA PATTERN DETECTED**\n\n`;
      interpretation += `The data does not conform to Benford's Law (p-value: ${pValue.toFixed(4)}).\n\n`;
      interpretation += `This may indicate:\n`;
      interpretation += `- Fabricated or manipulated numbers\n`;
      interpretation += `- Data entry errors\n`;
      interpretation += `- Rounding or truncation of values\n`;
      interpretation += `- Natural deviation due to data constraints (e.g., price ceilings)\n\n`;
      interpretation += `Suspicious digits: ${suspiciousDigits.join(', ')}\n\n`;
      interpretation += `**Recommendation:** Perform detailed examination of transactions involving these leading digits.`;
    } else {
      interpretation = `Data conforms to Benford's Law (p-value: ${pValue.toFixed(4)}).\n\n`;
      interpretation += `No significant anomalies detected in digit distribution. `;
      interpretation += `This does not rule out fraud but indicates the data has natural variance patterns.`;
    }

    return {
      totalNumbers: numbers.length,
      validNumbers: validNumbers.length,
      chiSquare,
      pValue,
      meanAbsoluteDeviation,
      suspicious,
      suspiciousDigits,
      results,
      interpretation,
    };
  }

  // Second digit analysis (more sensitive to fraud)
  analyzeSecondDigit(numbers: number[]): BenfordSummary {
    const validNumbers = numbers.filter(n => Math.abs(n) >= 10);

    if (validNumbers.length < 100) {
      return {
        totalNumbers: numbers.length,
        validNumbers: validNumbers.length,
        chiSquare: 0,
        pValue: 1,
        meanAbsoluteDeviation: 0,
        suspicious: false,
        suspiciousDigits: [],
        results: [],
        interpretation: 'Insufficient sample size for second digit analysis.',
      };
    }

    const digitCounts: Record<number, number> = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0 };

    for (const num of validNumbers) {
      const numStr = Math.abs(num).toString().replace('.', '');
      if (numStr.length >= 2) {
        const secondDigit = parseInt(numStr[1]);
        digitCounts[secondDigit]++;
      }
    }

    const results: BenfordResult[] = [];
    let chiSquare = 0;
    const suspiciousDigits: number[] = [];

    for (let digit = 0; digit <= 9; digit++) {
      const count = digitCounts[digit];
      const actual = count / validNumbers.length;
      const expected = BENFORD_SECOND_DIGIT[digit];
      const deviation = actual - expected;
      const deviationPercent = (deviation / expected) * 100;

      const variance = (expected * (1 - expected)) / validNumbers.length;
      const zScore = deviation / Math.sqrt(variance);

      chiSquare += Math.pow(count - (expected * validNumbers.length), 2) / (expected * validNumbers.length);

      const suspicious = Math.abs(deviationPercent) > 25 || Math.abs(zScore) > 2.5;
      if (suspicious) suspiciousDigits.push(digit);

      results.push({
        digit,
        expected,
        actual,
        count,
        deviation,
        deviationPercent,
        suspicious,
        zScore,
      });
    }

    const pValue = this.chiSquarePValue(chiSquare, 9);
    const suspicious = pValue < 0.05 || suspiciousDigits.length >= 2;

    return {
      totalNumbers: numbers.length,
      validNumbers: validNumbers.length,
      chiSquare,
      pValue,
      meanAbsoluteDeviation: 0,
      suspicious,
      suspiciousDigits,
      results,
      interpretation: suspicious
        ? `Second digit analysis reveals suspicious patterns. Digits ${suspiciousDigits.join(', ')} show significant deviation.`
        : 'Second digit distribution appears normal.',
    };
  }

  // Approximation of chi-square p-value
  private chiSquarePValue(chiSquare: number, degreesOfFreedom: number): number {
    // Using Wilson-Hilferty approximation
    const k = degreesOfFreedom;
    const x = chiSquare;

    if (x <= 0) return 1;

    const z = Math.pow(x / k, 1 / 3) - (1 - 2 / (9 * k));
    const zNorm = z / Math.sqrt(2 / (9 * k));

    // Standard normal CDF approximation
    return 1 - this.normalCDF(zNorm);
  }

  private normalCDF(x: number): number {
    const a1 = 0.254829592;
    const a2 = -0.284496736;
    const a3 = 1.421413741;
    const a4 = -1.453152027;
    const a5 = 1.061405429;
    const p = 0.3275911;

    const sign = x < 0 ? -1 : 1;
    x = Math.abs(x) / Math.sqrt(2);

    const t = 1.0 / (1.0 + p * x);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);

    return 0.5 * (1.0 + sign * y);
  }

  // Generate finding from analysis
  toFinding(summary: BenfordSummary, source: string): Finding {
    return {
      id: `BENFORD-${randomUUID().slice(0, 8)}`,
      domain: 'FINANCIAL',
      severity: summary.suspicious ? 'HIGH' : 'INFO',
      status: summary.suspicious ? 'WARNING' : 'PASS',
      title: 'Benford\'s Law Analysis',
      description: summary.interpretation,
      evidence: [{
        type: 'DATA',
        description: 'Digit frequency analysis',
        content: JSON.stringify(summary.results, null, 2),
        source,
        collectedAt: new Date().toISOString(),
      }],
      recommendation: summary.suspicious
        ? 'Investigate transactions with suspicious leading digits. Cross-reference with supporting documentation. Consider expanding sample or forensic examination.'
        : 'Continue routine monitoring. Consider periodic re-analysis.',
      timestamp: new Date().toISOString(),
    };
  }
}

// ============================================
// FRAUD DETECTION PATTERNS
// ============================================

export interface FraudIndicator {
  id: string;
  name: string;
  category: 'ASSET_MISAPPROPRIATION' | 'FINANCIAL_STATEMENT' | 'CORRUPTION' | 'VENDOR_FRAUD' | 'PAYROLL_FRAUD';
  severity: Severity;
  description: string;
  redFlags: string[];
  testProcedures: string[];
  dataAnalytics: string[];
}

export const FRAUD_INDICATORS: FraudIndicator[] = [
  // Asset Misappropriation
  {
    id: 'FRAUD-001',
    name: 'Cash Skimming',
    category: 'ASSET_MISAPPROPRIATION',
    severity: 'HIGH',
    description: 'Cash receipts stolen before recording in the accounting system.',
    redFlags: [
      'Revenue growth inconsistent with industry/competitors',
      'Unexplained cash shortages',
      'Customer complaints about unpaid invoices',
      'Irregular deposit patterns',
      'Missing or altered cash register tapes',
    ],
    testProcedures: [
      'Compare cash register totals to deposits',
      'Reconcile customer accounts receivable',
      'Analyze revenue trends vs. comparable companies',
      'Test cash handling procedures',
    ],
    dataAnalytics: [
      'Gap analysis in receipt numbers',
      'Deposit timing analysis',
      'Revenue per employee trends',
    ],
  },
  {
    id: 'FRAUD-002',
    name: 'Billing Scheme - Shell Company',
    category: 'ASSET_MISAPPROPRIATION',
    severity: 'CRITICAL',
    description: 'Employee creates fictitious vendor to bill company for goods/services not received.',
    redFlags: [
      'Vendor address matches employee address',
      'Vendor uses PO Box',
      'Vendor has no online presence',
      'Vendor incorporated recently',
      'Payments always just below approval threshold',
      'Single employee handles entire vendor cycle',
    ],
    testProcedures: [
      'Match vendor addresses to employee addresses',
      'Verify vendor existence (state filings, D&B)',
      'Review vendors with no historical purchases',
      'Analyze payments by dollar threshold',
      'Test segregation of duties',
    ],
    dataAnalytics: [
      'Vendor master file duplicate address detection',
      'Payment clustering below thresholds',
      'Vendor age vs. payment volume',
    ],
  },
  {
    id: 'FRAUD-003',
    name: 'Ghost Employee',
    category: 'PAYROLL_FRAUD',
    severity: 'HIGH',
    description: 'Fictitious employees added to payroll; payments diverted to perpetrator.',
    redFlags: [
      'Multiple employees with same bank account',
      'Employees with same address',
      'Missing tax/benefit enrollments',
      'No badge swipes or time entries',
      'Payroll manager never takes vacation',
    ],
    testProcedures: [
      'Match payroll to HR records',
      'Compare badge access to payroll',
      'Analyze duplicate bank accounts',
      'Review new hire documentation',
      'Test direct deposit changes',
    ],
    dataAnalytics: [
      'Duplicate bank account detection',
      'Duplicate address detection',
      'Time/attendance vs. payroll comparison',
    ],
  },
  {
    id: 'FRAUD-004',
    name: 'Expense Reimbursement Fraud',
    category: 'ASSET_MISAPPROPRIATION',
    severity: 'MEDIUM',
    description: 'Employees submit fictitious or inflated expense claims.',
    redFlags: [
      'Round dollar amounts',
      'Sequential receipt numbers',
      'Expenses just below approval limits',
      'Weekend/holiday expenses',
      'Duplicate submissions',
      'Personal items disguised as business',
    ],
    testProcedures: [
      'Match receipts to credit card statements',
      'Verify vendor existence for cash expenses',
      'Analyze expense patterns by employee',
      'Review expenses near policy limits',
    ],
    dataAnalytics: [
      'Benford\'s Law on expense amounts',
      'Duplicate expense detection',
      'Weekend/holiday expense analysis',
      'Per diem vs. actual expense comparison',
    ],
  },

  // Financial Statement Fraud
  {
    id: 'FRAUD-005',
    name: 'Revenue Recognition Fraud',
    category: 'FINANCIAL_STATEMENT',
    severity: 'CRITICAL',
    description: 'Recording revenue before it is earned or recording fictitious revenue.',
    redFlags: [
      'Revenue spikes at period end',
      'High volume of credit memos after period close',
      'Bill and hold arrangements',
      'Side letters with customers',
      'Channel stuffing patterns',
      'Unusual related party transactions',
    ],
    testProcedures: [
      'Cut-off testing at period end',
      'Review credit memos post-close',
      'Confirm large transactions with customers',
      'Analyze revenue recognition timing',
      'Review contracts for non-standard terms',
    ],
    dataAnalytics: [
      'Revenue concentration by date',
      'Credit memo timing analysis',
      'Quarter-over-quarter revenue volatility',
    ],
  },
  {
    id: 'FRAUD-006',
    name: 'Inventory Fraud',
    category: 'FINANCIAL_STATEMENT',
    severity: 'HIGH',
    description: 'Overstating inventory to inflate assets and reduce COGS.',
    redFlags: [
      'Inventory growth exceeds sales growth',
      'Declining inventory turnover',
      'Adjustments to inventory counts',
      'Obsolete inventory not written off',
      'Count discrepancies',
    ],
    testProcedures: [
      'Observe physical inventory counts',
      'Test inventory costing',
      'Review obsolescence reserves',
      'Analyze inventory aging',
      'Compare inventory turnover to industry',
    ],
    dataAnalytics: [
      'Inventory to sales ratio trends',
      'Inventory adjustment analysis',
      'Negative inventory balances',
    ],
  },

  // Corruption
  {
    id: 'FRAUD-007',
    name: 'Kickback Scheme',
    category: 'CORRUPTION',
    severity: 'CRITICAL',
    description: 'Employee receives payment from vendor in exchange for favorable treatment.',
    redFlags: [
      'Vendor consistently wins bids without lowest price',
      'Sole-source justifications',
      'Employee lifestyle exceeds income',
      'Vendor complaints about unfair bidding',
      'Employee resistance to vendor audits',
    ],
    testProcedures: [
      'Analyze bid win rates by vendor',
      'Review sole-source justifications',
      'Compare prices to market rates',
      'Test vendor selection process',
      'Review employee conflicts of interest',
    ],
    dataAnalytics: [
      'Vendor win rate analysis',
      'Price variance to market analysis',
      'Purchase order splitting detection',
    ],
  },
  {
    id: 'FRAUD-008',
    name: 'FCPA/Bribery Violation',
    category: 'CORRUPTION',
    severity: 'CRITICAL',
    description: 'Improper payments to foreign officials to obtain business advantage.',
    redFlags: [
      'Payments through third-party agents',
      'Unusual consulting fees',
      'Cash payments in high-risk countries',
      'Gifts to government officials',
      'Lack of due diligence on intermediaries',
    ],
    testProcedures: [
      'Review third-party agent contracts',
      'Analyze payments in high-risk countries',
      'Test due diligence on intermediaries',
      'Review gift and entertainment logs',
      'Verify legitimate business purpose',
    ],
    dataAnalytics: [
      'Payment analysis by country risk',
      'Agent commission rate analysis',
      'Keyword search for red flag terms',
    ],
  },
];

// ============================================
// ANTI-MONEY LAUNDERING (AML) PATTERNS
// ============================================

export interface AMLIndicator {
  id: string;
  name: string;
  category: 'STRUCTURING' | 'LAYERING' | 'INTEGRATION' | 'BEHAVIORAL';
  severity: Severity;
  description: string;
  indicators: string[];
  reportingThreshold?: string;
}

export const AML_INDICATORS: AMLIndicator[] = [
  {
    id: 'AML-001',
    name: 'Structuring (Smurfing)',
    category: 'STRUCTURING',
    severity: 'CRITICAL',
    description: 'Breaking large transactions into smaller amounts to avoid reporting thresholds.',
    indicators: [
      'Multiple cash deposits just under $10,000',
      'Deposits made on consecutive days',
      'Multiple accounts used for deposits',
      'Customer awareness of reporting thresholds',
      'Reluctance to file CTR',
    ],
    reportingThreshold: '$10,000 CTR threshold',
  },
  {
    id: 'AML-002',
    name: 'Rapid Movement of Funds',
    category: 'LAYERING',
    severity: 'HIGH',
    description: 'Quick transfer of funds through multiple accounts or jurisdictions.',
    indicators: [
      'Funds deposited and immediately wired out',
      'Transfers to high-risk jurisdictions',
      'No apparent business reason for transfers',
      'Circular transactions returning to origin',
      'Use of multiple intermediary accounts',
    ],
  },
  {
    id: 'AML-003',
    name: 'Shell Company Activity',
    category: 'INTEGRATION',
    severity: 'CRITICAL',
    description: 'Use of corporate structures to obscure beneficial ownership.',
    indicators: [
      'Bearer share ownership',
      'Nominee directors',
      'Registered in secrecy jurisdictions',
      'No apparent business operations',
      'Complex ownership structures',
    ],
  },
  {
    id: 'AML-004',
    name: 'Unusual Customer Behavior',
    category: 'BEHAVIORAL',
    severity: 'MEDIUM',
    description: 'Customer behavior inconsistent with known profile.',
    indicators: [
      'Transaction activity inconsistent with business type',
      'Reluctance to provide information',
      'Unexplained changes in transaction patterns',
      'Use of multiple or foreign identification',
      'Involvement of third parties without clear purpose',
    ],
  },
  {
    id: 'AML-005',
    name: 'Trade-Based Money Laundering',
    category: 'INTEGRATION',
    severity: 'HIGH',
    description: 'Using trade transactions to transfer value and disguise origins.',
    indicators: [
      'Over or under-invoicing of goods',
      'Phantom shipments',
      'Multiple invoicing for same goods',
      'Misrepresentation of goods or services',
      'Unusual trade routes',
    ],
  },
  {
    id: 'AML-006',
    name: 'Cryptocurrency Red Flags',
    category: 'LAYERING',
    severity: 'HIGH',
    description: 'Suspicious cryptocurrency transaction patterns.',
    indicators: [
      'Structuring crypto transactions below reporting limits',
      'Use of mixing services or tumblers',
      'Transactions with darknet marketplaces',
      'Multiple wallet addresses with no apparent purpose',
      'Conversion through multiple exchanges',
    ],
  },
];

// ============================================
// FORENSIC INTERVIEW FRAMEWORK
// ============================================

// FAINT - Forensic Assessment Interview Technique
export const FAINT_QUESTIONS: InterviewQuestion[] = [
  // Baseline Questions (establish normal behavior)
  {
    category: 'BASELINE',
    question: 'Can you walk me through a typical day in your role?',
    purpose: 'Establish baseline verbal and non-verbal behavior.',
    redFlagResponses: ['Excessive detail on unrelated topics', 'Immediate defensiveness'],
  },
  {
    category: 'BASELINE',
    question: 'How long have you been in this position?',
    purpose: 'Simple factual question to calibrate normal response.',
  },
  {
    category: 'BASELINE',
    question: 'What do you enjoy most about your work?',
    purpose: 'Positive question to establish comfortable baseline.',
  },

  // Projective Questions (assess attitude toward issue)
  {
    category: 'PROJECTIVE',
    question: 'What do you think should happen to someone who commits fraud against the company?',
    purpose: 'Guilty individuals often recommend leniency; innocent recommend harsh punishment.',
    redFlagResponses: [
      'Suggests leniency or understanding',
      'Deflects or refuses to answer',
      'Excessive qualification of response',
    ],
  },
  {
    category: 'PROJECTIVE',
    question: 'Why do you think someone might do something like this?',
    purpose: 'May reveal personal rationalizations if guilty.',
    redFlagResponses: [
      'Detailed justifications',
      'Personal financial pressure narratives',
      'Criticism of company treatment of employees',
    ],
  },
  {
    category: 'PROJECTIVE',
    question: 'If you were investigating this, where would you look?',
    purpose: 'Guilty parties may direct away from evidence; innocent may offer helpful insights.',
    redFlagResponses: [
      'Misdirection to unlikely areas',
      'Implication of others without basis',
      'Claims investigation is unnecessary',
    ],
  },

  // Direct Questions
  {
    category: 'DIRECT',
    question: 'Did you take any money from the company?',
    purpose: 'Direct confrontation after projective questions.',
    redFlagResponses: [
      'Non-denial denial ("I would never do that")',
      'Qualified denial ("Not that I recall")',
      'Attack on questioner or investigation',
    ],
  },
  {
    category: 'DIRECT',
    question: 'Is there any reason your fingerprints/login would be on this document/system?',
    purpose: 'Present evidence and request explanation.',
    redFlagResponses: [
      'Immediate alibi without hearing specifics',
      'Blaming others',
      'Memory gaps only for relevant period',
    ],
  },

  // Control Questions
  {
    category: 'CONTROL',
    question: 'Have you ever taken anything from a previous employer?',
    purpose: 'Control question - everyone has minor transgressions; denial indicates deception.',
    redFlagResponses: [
      'Absolute denial of ever taking anything (even pens)',
      'Excessive defensiveness',
    ],
  },
];

// Behavioral Deception Indicators
export const DECEPTION_INDICATORS = {
  verbal: [
    { indicator: 'Non-denial denial', description: '"I would never do something like that" instead of "I didn\'t do it"', weight: 0.8 },
    { indicator: 'Qualified response', description: '"To the best of my knowledge", "As far as I recall"', weight: 0.6 },
    { indicator: 'Repetition of question', description: 'Buying time to formulate response', weight: 0.4 },
    { indicator: 'Attack on questioner', description: 'Deflecting by questioning the investigation', weight: 0.7 },
    { indicator: 'Selective memory', description: 'Perfect recall except for relevant events', weight: 0.8 },
    { indicator: 'Overly specific alibi', description: 'Rehearsed-sounding detailed account', weight: 0.5 },
    { indicator: 'Third-person references', description: 'Distancing from the act', weight: 0.5 },
    { indicator: 'Present tense denial', description: '"I don\'t lie" vs "I didn\'t lie"', weight: 0.4 },
    { indicator: 'Minimization', description: '"Just" or "only" when describing actions', weight: 0.5 },
  ],
  nonVerbal: [
    { indicator: 'Grooming behaviors', description: 'Touching face, adjusting clothing', weight: 0.3 },
    { indicator: 'Gaze aversion', description: 'Looking away during direct questions', weight: 0.3 },
    { indicator: 'Microexpressions', description: 'Brief flash of fear, contempt, or disgust', weight: 0.7 },
    { indicator: 'Timing mismatch', description: 'Verbal and non-verbal out of sync', weight: 0.6 },
    { indicator: 'Shoulder shrug', description: 'One-shoulder shrug indicates uncertainty in statement', weight: 0.5 },
    { indicator: 'Defensive posture', description: 'Crossed arms, leaning back, creating distance', weight: 0.3 },
    { indicator: 'Hand-to-face contact', description: 'Covering mouth, touching nose during response', weight: 0.4 },
    { indicator: 'Anchor point movement', description: 'Shifting feet or rocking when asked direct questions', weight: 0.4 },
  ],
  contextual: [
    { indicator: 'Never takes vacation', description: 'Maintaining control to prevent detection', weight: 0.9 },
    { indicator: 'First in, last out', description: 'Working when no one can observe', weight: 0.6 },
    { indicator: 'Refuses to delegate', description: 'Maintaining exclusive control over process', weight: 0.8 },
    { indicator: 'Lives beyond means', description: 'Lifestyle inconsistent with salary', weight: 0.7 },
    { indicator: 'Financial difficulties', description: 'Known debts or gambling issues', weight: 0.5 },
    { indicator: 'Close vendor relationships', description: 'Unusual personal ties to suppliers', weight: 0.6 },
    { indicator: 'Unusually defensive about area', description: 'Overreaction to audit inquiries', weight: 0.7 },
  ],
};

// ============================================
// FORENSIC AUDITOR CLASS
// ============================================

export class ForensicAuditor {
  private findings: Finding[] = [];
  private benfordAnalyzer: BenfordAnalyzer;

  constructor() {
    this.benfordAnalyzer = new BenfordAnalyzer();
  }

  // Analyze numbers with Benford's Law
  analyzeBenford(numbers: number[], source: string): Finding {
    const summary = this.benfordAnalyzer.analyze(numbers);
    const finding = this.benfordAnalyzer.toFinding(summary, source);
    this.findings.push(finding);
    return finding;
  }

  // Run fraud risk assessment
  assessFraudRisk(context: string): Finding[] {
    const findings: Finding[] = [];

    for (const indicator of FRAUD_INDICATORS) {
      findings.push({
        id: `${indicator.id}-${randomUUID().slice(0, 4)}`,
        domain: 'FINANCIAL',
        severity: indicator.severity,
        status: 'REVIEW_REQUIRED',
        title: `Fraud Risk: ${indicator.name}`,
        description: `**Category:** ${indicator.category}\n\n${indicator.description}\n\n**Red Flags to Look For:**\n${indicator.redFlags.map(r => `- ${r}`).join('\n')}\n\n**Test Procedures:**\n${indicator.testProcedures.map(t => `- ${t}`).join('\n')}\n\n**Data Analytics:**\n${indicator.dataAnalytics.map(d => `- ${d}`).join('\n')}`,
        evidence: [{
          type: 'DATA',
          description: 'Fraud risk assessment framework',
          source: context,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: `Execute test procedures for ${indicator.name}. Document evidence of controls or findings.`,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // AML risk assessment
  assessAMLRisk(context: string): Finding[] {
    const findings: Finding[] = [];

    for (const indicator of AML_INDICATORS) {
      findings.push({
        id: `${indicator.id}-${randomUUID().slice(0, 4)}`,
        domain: 'FINANCIAL',
        severity: indicator.severity,
        status: 'REVIEW_REQUIRED',
        title: `AML Risk: ${indicator.name}`,
        description: `**Category:** ${indicator.category}\n\n${indicator.description}\n\n**Indicators:**\n${indicator.indicators.map(i => `- ${i}`).join('\n')}${indicator.reportingThreshold ? `\n\n**Reporting Threshold:** ${indicator.reportingThreshold}` : ''}`,
        evidence: [{
          type: 'DATA',
          description: 'AML risk assessment',
          source: context,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: 'Implement transaction monitoring for these patterns. File SAR if suspicious activity confirmed.',
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Generate interview guide
  generateInterviewGuide(suspectRole: string): string {
    let guide = `# Forensic Interview Guide\n`;
    guide += `**Subject Role:** ${suspectRole}\n`;
    guide += `**Date:** ${new Date().toISOString().split('T')[0]}\n\n`;
    guide += `---\n\n`;

    guide += `## Pre-Interview Preparation\n`;
    guide += `- [ ] Review all documentary evidence\n`;
    guide += `- [ ] Prepare timeline of events\n`;
    guide += `- [ ] Identify specific questions based on evidence\n`;
    guide += `- [ ] Arrange interview room (neutral, private)\n`;
    guide += `- [ ] Plan witness order (peripheral witnesses first)\n\n`;

    guide += `## FAINT Interview Structure\n\n`;

    const categories = ['BASELINE', 'PROJECTIVE', 'DIRECT', 'CONTROL'] as const;

    for (const category of categories) {
      guide += `### ${category} Questions\n\n`;
      const questions = FAINT_QUESTIONS.filter(q => q.category === category);

      for (const q of questions) {
        guide += `**Q:** ${q.question}\n`;
        guide += `*Purpose:* ${q.purpose}\n`;
        if (q.redFlagResponses) {
          guide += `*Red Flags:* ${q.redFlagResponses.join('; ')}\n`;
        }
        guide += `\n`;
      }
    }

    guide += `## Deception Indicators to Monitor\n\n`;
    guide += `### Verbal\n`;
    for (const ind of DECEPTION_INDICATORS.verbal) {
      guide += `- **${ind.indicator}**: ${ind.description}\n`;
    }
    guide += `\n### Non-Verbal\n`;
    for (const ind of DECEPTION_INDICATORS.nonVerbal) {
      guide += `- **${ind.indicator}**: ${ind.description}\n`;
    }
    guide += `\n### Contextual\n`;
    for (const ind of DECEPTION_INDICATORS.contextual) {
      guide += `- **${ind.indicator}**: ${ind.description}\n`;
    }

    guide += `\n---\n`;
    guide += `*Interview conducted using FAINT methodology. Document all responses and observed behaviors.*\n`;

    return guide;
  }

  // Analyze transaction timing
  analyzeTransactionTiming(timestamps: Date[]): Finding {
    const offHours: Date[] = [];
    const weekends: Date[] = [];
    const periodEnd: Date[] = [];

    for (const ts of timestamps) {
      const hour = ts.getHours();
      const day = ts.getDay();
      const date = ts.getDate();

      // Off hours (before 7am or after 7pm)
      if (hour < 7 || hour >= 19) {
        offHours.push(ts);
      }

      // Weekends
      if (day === 0 || day === 6) {
        weekends.push(ts);
      }

      // Period end (last 3 days of month)
      if (date >= 28) {
        periodEnd.push(ts);
      }
    }

    const total = timestamps.length;
    const offHoursPercent = (offHours.length / total) * 100;
    const weekendsPercent = (weekends.length / total) * 100;
    const periodEndPercent = (periodEnd.length / total) * 100;

    const suspicious = offHoursPercent > 10 || weekendsPercent > 15 || periodEndPercent > 30;

    const finding: Finding = {
      id: `TIMING-${randomUUID().slice(0, 8)}`,
      domain: 'FINANCIAL',
      severity: suspicious ? 'HIGH' : 'INFO',
      status: suspicious ? 'WARNING' : 'PASS',
      title: 'Transaction Timing Analysis',
      description: `**Analysis of ${total} transactions:**\n\n` +
        `- Off-hours (before 7am/after 7pm): ${offHours.length} (${offHoursPercent.toFixed(1)}%)\n` +
        `- Weekends: ${weekends.length} (${weekendsPercent.toFixed(1)}%)\n` +
        `- Period-end (last 3 days): ${periodEnd.length} (${periodEndPercent.toFixed(1)}%)\n\n` +
        (suspicious ? '**SUSPICIOUS PATTERN DETECTED**: Unusual concentration of off-hours or period-end activity.' : 'Timing distribution appears normal.'),
      evidence: [{
        type: 'DATA',
        description: 'Transaction timing statistics',
        content: JSON.stringify({ offHoursPercent, weekendsPercent, periodEndPercent }),
        source: 'Transaction log analysis',
        collectedAt: new Date().toISOString(),
      }],
      recommendation: suspicious
        ? 'Investigate off-hours and period-end transactions. Review authorization and business justification.'
        : 'Continue routine monitoring.',
      timestamp: new Date().toISOString(),
    };

    this.findings.push(finding);
    return finding;
  }

  // Get all findings
  getFindings(): Finding[] {
    return this.findings;
  }

  // Clear findings
  clearFindings(): void {
    this.findings = [];
  }
}

// Export singleton
export const forensicAuditor = new ForensicAuditor();
export const benfordAnalyzer = new BenfordAnalyzer();
