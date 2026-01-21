/**
 * Handler Exports
 */

// Types
export * from './types.js';

// Audit Engine handlers
export {
  handleStartAudit,
  handleAddFinding,
  handleCollectEvidence,
  handleGenerateReport,
  getAuditEngine,
  getCurrentConfig
} from './audit-engine.js';

// Red Flag handlers
export { handleScanRedFlags } from './red-flags.js';

// Code Audit handlers
export {
  handleAuditCode,
  handleCalculateCodeMetrics,
  handleAnalyzeDependencies
} from './code-audit.js';

// Security Audit handlers
export {
  handleAssessOwasp,
  handleAssessCloudSecurity,
  handleAssessZeroTrust,
  handleGetMitreTechniques
} from './security-audit.js';

// Forensic Audit handlers
export {
  handleAnalyzeBenford,
  handleAssessFraudRisk,
  handleAssessAMLRisk,
  handleGenerateInterviewGuide
} from './forensic-audit.js';

// Compliance Audit handlers
export {
  handleGenerateComplianceChecklist,
  handleAssessCompliance,
  handleMapComplianceControls
} from './compliance-audit.js';

// Operational Audit handlers
export {
  handleAssessWaste,
  handleGenerateDMAICPlan,
  handleAnalyzeValueStream,
  handleGetEfficiencyMetrics
} from './operational-audit.js';

// IT Systems Audit handlers
export {
  handleAssessCOBIT,
  handleAssessChangeManagement,
  handleAssessBackupRecovery,
  handleAssessADSecurity
} from './it-systems-audit.js';

// AI/ML Audit handlers
export {
  handleAssessAIRisks,
  handleAssessFairness,
  handleGenerateModelCard
} from './ai-ml-audit.js';

// Multi-Domain handlers
export {
  handleComprehensiveAudit,
  handleRiskAssessment
} from './multi-domain.js';
