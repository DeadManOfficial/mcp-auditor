/**
 * MCP Auditor Constants
 * Centralized configuration values to eliminate magic numbers
 */

// ============================================
// SEVERITY WEIGHTS FOR RISK CALCULATION
// ============================================

export const SEVERITY_WEIGHTS = {
  CRITICAL: 40,
  HIGH: 25,
  MEDIUM: 15,
  LOW: 5,
  INFO: 1,
} as const;

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

// ============================================
// RISK SCORE THRESHOLDS
// ============================================

export const RISK_THRESHOLDS = {
  CRITICAL: 20,  // Risk score >= 20 is CRITICAL
  HIGH: 15,      // Risk score >= 15 is HIGH
  MEDIUM: 10,    // Risk score >= 10 is MEDIUM
  LOW: 5,        // Risk score >= 5 is LOW
  MINIMAL: 0,    // Risk score < 5 is MINIMAL
} as const;

export const MAX_RISK_SCORE = 100;

// ============================================
// AUDIT RATING THRESHOLDS
// ============================================

export const RATING_THRESHOLDS = {
  HIGH_COUNT_FAIL: 2,      // More than 2 HIGH findings = FAIL
  MEDIUM_COUNT_WARNING: 5, // More than 5 MEDIUM findings = WARNING
} as const;

// ============================================
// EVIDENCE LIMITS
// ============================================

export const EVIDENCE_LIMITS = {
  MAX_CONTENT_LENGTH: 10000,     // Truncate evidence content at 10K chars
  MAX_EVIDENCE_PER_FINDING: 10,  // Max evidence items per finding
  CONTEXT_CHARS_BEFORE: 50,      // Context chars before match
  CONTEXT_CHARS_AFTER: 50,       // Context chars after match
} as const;

// ============================================
// CODE METRICS THRESHOLDS
// ============================================

export const CODE_THRESHOLDS = {
  MAX_FUNCTION_LINES: 50,         // Functions longer than this are flagged
  MAX_NESTING_DEPTH: 4,           // Nesting deeper than this is flagged
  MAX_CYCLOMATIC_COMPLEXITY: 10,  // Complexity higher than this is flagged
  MAX_FILE_LINES: 500,            // Files longer than this may need splitting
  MIN_COMMENT_RATIO: 0.1,         // Less than 10% comments is flagged
} as const;

// ============================================
// BENFORD'S LAW THRESHOLDS
// ============================================

export const BENFORD_THRESHOLDS = {
  MIN_SAMPLE_SIZE: 100,           // Minimum numbers for valid analysis
  DEVIATION_PERCENT_SUSPICIOUS: 20, // Deviation > 20% is suspicious
  Z_SCORE_SUSPICIOUS: 2,          // Z-score > 2 is suspicious
  P_VALUE_SUSPICIOUS: 0.05,       // P-value < 0.05 is suspicious
  SUSPICIOUS_DIGIT_COUNT: 3,      // 3+ suspicious digits = suspicious overall
} as const;

// ============================================
// TIMING ANALYSIS THRESHOLDS
// ============================================

export const TIMING_THRESHOLDS = {
  OFF_HOURS_START: 7,            // Before 7am is off-hours
  OFF_HOURS_END: 19,             // After 7pm is off-hours
  OFF_HOURS_PERCENT_SUSPICIOUS: 10,   // >10% off-hours is suspicious
  WEEKEND_PERCENT_SUSPICIOUS: 15,      // >15% weekend is suspicious
  PERIOD_END_PERCENT_SUSPICIOUS: 30,   // >30% period-end is suspicious
  PERIOD_END_DAYS: 3,            // Last 3 days of month = period end
} as const;

// ============================================
// VALUE STREAM ANALYSIS
// ============================================

export const VALUE_STREAM_THRESHOLDS = {
  LOW_PCE_THRESHOLD: 25,         // PCE < 25% is very low
  HIGH_DEFECT_RATE: 5,           // Defect rate > 5% is high
} as const;

// ============================================
// DEPENDENCY ANALYSIS
// ============================================

export const DEPENDENCY_THRESHOLDS = {
  HIGH_DEPENDENCY_COUNT: 50,     // More than 50 prod deps is concerning
} as const;

// ============================================
// SENSITIVE PACKAGES TO MONITOR
// ============================================

export const SENSITIVE_PACKAGES = [
  'bcrypt',
  'crypto',
  'jsonwebtoken',
  'passport',
  'helmet',
  'oauth',
  'session',
] as const;

// ============================================
// COMPLIANCE FRAMEWORKS
// ============================================

export const COMPLIANCE_FRAMEWORKS = [
  'SOC2',
  'ISO27001',
  'HIPAA',
  'PCI_DSS',
  'GDPR',
  'NIST',
  'OWASP',
  'CIS',
  'FEDRAMP',
  'CMMC',
] as const;

// ============================================
// AUDIT DOMAINS
// ============================================

export const AUDIT_DOMAINS = [
  'CODE',
  'SECURITY',
  'FINANCIAL',
  'COMPLIANCE',
  'OPERATIONAL',
  'IT_SYSTEMS',
  'AI_ML',
  'INFRASTRUCTURE',
  'GENERAL',
] as const;

// ============================================
// ID PREFIXES
// ============================================

export const ID_PREFIXES = {
  AUDIT: 'AUDIT',
  FINDING: 'FIND',
  RED_FLAG: 'RF',
  OWASP: 'OWASP',
  CLOUD: 'CLOUD',
  NETWORK: 'NET',
  ZERO_TRUST: 'ZT',
  BENFORD: 'BENFORD',
  FRAUD: 'FRAUD',
  AML: 'AML',
  TIMING: 'TIMING',
  COMPLIANCE: 'COMP',
  TIMWOOD: 'TIMWOOD',
  COBIT: 'COBIT',
  CHANGE: 'CHANGE',
  BACKUP: 'BACKUP',
  AD: 'AD',
  AI: 'AI',
  FAIRNESS: 'FAIR',
} as const;

// ============================================
// UUID SLICE LENGTH
// ============================================

export const UUID_SLICE_LENGTH = 8;

// ============================================
// REPORT STRINGS
// ============================================

export const REPORT_STRINGS = {
  AUDITOR_NAME: 'Omniscient Auditor',
  TAGLINE: 'Hostile to bullshit, loyal only to the evidence.',
  IMMEDIATE_ACTION: 'IMMEDIATE ACTION REQUIRED',
  HIGH_PRIORITY: 'HIGH PRIORITY',
} as const;
