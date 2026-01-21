// Core Types for Omniscient Auditor

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type AuditStatus = 'PASS' | 'FAIL' | 'WARNING' | 'REVIEW_REQUIRED';
export type AuditDomain =
  | 'CODE'
  | 'SECURITY'
  | 'FINANCIAL'
  | 'COMPLIANCE'
  | 'OPERATIONAL'
  | 'IT_SYSTEMS'
  | 'AI_ML'
  | 'INFRASTRUCTURE'
  | 'GENERAL';

export interface Finding {
  id: string;
  domain: AuditDomain;
  severity: Severity;
  status: AuditStatus;
  title: string;
  description: string;
  evidence: Evidence[];
  location?: Location;
  recommendation: string;
  references?: string[];
  cwe?: string;  // Common Weakness Enumeration
  cvss?: number; // Common Vulnerability Scoring System
  timestamp: string;
}

export interface Evidence {
  type: 'FILE' | 'LOG' | 'SCREENSHOT' | 'DATA' | 'TESTIMONY' | 'CONFIGURATION';
  description: string;
  content?: string;
  hash?: string;  // SHA-256 for chain of custody
  source: string;
  collectedAt: string;
}

export interface Location {
  file?: string;
  line?: number;
  column?: number;
  function?: string;
  component?: string;
  url?: string;
}

export interface AuditReport {
  id: string;
  title: string;
  scope: string;
  domain: AuditDomain[];
  auditor: string;
  startTime: string;
  endTime: string;
  executiveSummary: string;
  overallRating: AuditStatus;
  riskScore: number;  // 0-100
  findings: Finding[];
  statistics: AuditStatistics;
  methodology: string[];
  limitations?: string[];
  recommendations: string[];
}

export interface AuditStatistics {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  passed: number;
  failed: number;
}

export interface AuditConfig {
  domains: AuditDomain[];
  severity_threshold: Severity;
  include_patterns?: string[];
  exclude_patterns?: string[];
  frameworks?: ComplianceFramework[];
  custom_rules?: AuditRule[];
}

export type ComplianceFramework =
  | 'SOC2'
  | 'ISO27001'
  | 'HIPAA'
  | 'PCI_DSS'
  | 'GDPR'
  | 'NIST'
  | 'OWASP'
  | 'CIS'
  | 'FEDRAMP'
  | 'CMMC';

export interface AuditRule {
  id: string;
  name: string;
  description: string;
  domain: AuditDomain;
  severity: Severity;
  pattern?: RegExp | string;
  check: (context: AuditContext) => Promise<Finding | null>;
}

export interface AuditContext {
  target: string;
  content?: string;
  metadata?: Record<string, unknown>;
  config: AuditConfig;
}

// Red Flag Patterns from Forensic Research
export interface RedFlagPattern {
  category: string;
  keywords: string[];
  severity: Severity;
  interpretation: string;
}

// Benford's Law Analysis
export interface BenfordAnalysis {
  digit: number;
  expected: number;
  actual: number;
  deviation: number;
  suspicious: boolean;
}

// Interview/Investigation Types
export interface InterviewQuestion {
  category: 'BASELINE' | 'PROJECTIVE' | 'DIRECT' | 'CONTROL';
  question: string;
  purpose: string;
  redFlagResponses?: string[];
}
