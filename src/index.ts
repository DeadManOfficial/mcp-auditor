#!/usr/bin/env node
/**
 * MCP Auditor - Omniscient Auditor MCP Server
 * Forensic-grade auditing across all domains with military-honed precision
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';

// Import all handlers
import {
  // Audit Engine
  handleStartAudit,
  handleAddFinding,
  handleCollectEvidence,
  handleGenerateReport,
  // Red Flags
  handleScanRedFlags,
  // Code Audit
  handleAuditCode,
  handleCalculateCodeMetrics,
  handleAnalyzeDependencies,
  // Security Audit
  handleAssessOwasp,
  handleAssessCloudSecurity,
  handleAssessZeroTrust,
  handleGetMitreTechniques,
  // Forensic Audit
  handleAnalyzeBenford,
  handleAssessFraudRisk,
  handleAssessAMLRisk,
  handleGenerateInterviewGuide,
  // Compliance Audit
  handleGenerateComplianceChecklist,
  handleAssessCompliance,
  handleMapComplianceControls,
  // Operational Audit
  handleAssessWaste,
  handleGenerateDMAICPlan,
  handleAnalyzeValueStream,
  handleGetEfficiencyMetrics,
  // IT Systems Audit
  handleAssessCOBIT,
  handleAssessChangeManagement,
  handleAssessBackupRecovery,
  handleAssessADSecurity,
  // AI/ML Audit
  handleAssessAIRisks,
  handleAssessFairness,
  handleGenerateModelCard,
  // Multi-Domain
  handleComprehensiveAudit,
  handleRiskAssessment,
  // Types
  ToolArgs
} from './handlers/index.js';

// Tool name to handler mapping
const TOOL_HANDLERS: Record<string, (args: ToolArgs) => Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }>> = {
  // Audit Engine
  'start_audit': handleStartAudit,
  'add_finding': handleAddFinding,
  'collect_evidence': handleCollectEvidence,
  'generate_report': handleGenerateReport,
  // Red Flags
  'scan_red_flags': handleScanRedFlags,
  // Code Audit
  'audit_code': handleAuditCode,
  'calculate_code_metrics': handleCalculateCodeMetrics,
  'analyze_dependencies': handleAnalyzeDependencies,
  // Security Audit
  'assess_owasp': handleAssessOwasp,
  'assess_cloud_security': handleAssessCloudSecurity,
  'assess_zero_trust': handleAssessZeroTrust,
  'get_mitre_techniques': handleGetMitreTechniques,
  // Forensic Audit
  'analyze_benford': handleAnalyzeBenford,
  'assess_fraud_risk': handleAssessFraudRisk,
  'assess_aml_risk': handleAssessAMLRisk,
  'generate_interview_guide': handleGenerateInterviewGuide,
  // Compliance Audit
  'generate_compliance_checklist': handleGenerateComplianceChecklist,
  'assess_compliance': handleAssessCompliance,
  'map_compliance_controls': handleMapComplianceControls,
  // Operational Audit
  'assess_waste': handleAssessWaste,
  'generate_dmaic_plan': handleGenerateDMAICPlan,
  'analyze_value_stream': handleAnalyzeValueStream,
  'get_efficiency_metrics': handleGetEfficiencyMetrics,
  // IT Systems Audit
  'assess_cobit': handleAssessCOBIT,
  'assess_change_management': handleAssessChangeManagement,
  'assess_backup_recovery': handleAssessBackupRecovery,
  'assess_ad_security': handleAssessADSecurity,
  // AI/ML Audit
  'assess_ai_risks': handleAssessAIRisks,
  'assess_fairness': handleAssessFairness,
  'generate_model_card': handleGenerateModelCard,
  // Multi-Domain
  'comprehensive_audit': handleComprehensiveAudit,
  'risk_assessment': handleRiskAssessment
};

// Define all available tools
const TOOLS: Tool[] = [
  // ==================== AUDIT ENGINE TOOLS ====================
  {
    name: 'start_audit',
    description: 'Initialize a new audit engagement with scope and objectives. This creates a new audit session that tracks all findings, evidence, and generates comprehensive reports.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Name of the audit engagement' },
        domain: {
          type: 'string',
          enum: ['FINANCIAL', 'COMPLIANCE', 'OPERATIONAL', 'IT_SYSTEMS', 'SECURITY', 'FORENSIC', 'CODE', 'AI_ML'],
          description: 'Primary audit domain'
        },
        scope: { type: 'string', description: 'Scope of the audit' },
        objectives: {
          type: 'array',
          items: { type: 'string' },
          description: 'List of audit objectives'
        }
      },
      required: ['name', 'domain', 'scope', 'objectives']
    }
  },
  {
    name: 'add_finding',
    description: 'Record an audit finding with severity, evidence, and recommendations. Findings are categorized and tracked for reporting.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string', description: 'Title of the finding' },
        description: { type: 'string', description: 'Detailed description' },
        severity: {
          type: 'string',
          enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
          description: 'Severity level'
        },
        category: { type: 'string', description: 'Finding category' },
        evidence: {
          type: 'array',
          items: { type: 'string' },
          description: 'Supporting evidence references'
        },
        recommendations: {
          type: 'array',
          items: { type: 'string' },
          description: 'Recommended remediation actions'
        },
        affectedAssets: {
          type: 'array',
          items: { type: 'string' },
          description: 'Assets affected by this finding'
        }
      },
      required: ['title', 'description', 'severity', 'category']
    }
  },
  {
    name: 'collect_evidence',
    description: 'Collect and hash evidence for chain of custody. Evidence is SHA-256 hashed with timestamps for forensic integrity.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', description: 'Type of evidence (document, screenshot, log, etc.)' },
        source: { type: 'string', description: 'Source of the evidence' },
        content: { type: 'string', description: 'Evidence content or description' },
        metadata: {
          type: 'object',
          description: 'Additional metadata about the evidence'
        }
      },
      required: ['type', 'source', 'content']
    }
  },
  {
    name: 'generate_report',
    description: 'Generate comprehensive audit report with all findings, evidence, and risk assessment.',
    inputSchema: {
      type: 'object',
      properties: {
        format: {
          type: 'string',
          enum: ['json', 'markdown'],
          description: 'Output format'
        }
      }
    }
  },

  // ==================== RED FLAG DETECTION TOOLS ====================
  {
    name: 'scan_red_flags',
    description: 'Scan text or data for forensic red flags across all categories: journal entries, expenses, vendor payments, communication patterns, timing anomalies, revenue recognition, asset misappropriation, code security, compliance violations, and behavioral indicators.',
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'Content to scan for red flags' },
        categories: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['JOURNAL_ENTRIES', 'EXPENSES', 'VENDOR_PAYMENTS', 'COMMUNICATION', 'TIMING', 'REVENUE', 'ASSETS', 'CODE_SECURITY', 'COMPLIANCE', 'BEHAVIORAL']
          },
          description: 'Specific categories to scan (omit for all)'
        }
      },
      required: ['content']
    }
  },

  // ==================== CODE AUDIT TOOLS ====================
  {
    name: 'audit_code',
    description: 'Perform comprehensive code security and quality audit. Detects vulnerabilities (SQL injection, XSS, command injection, hardcoded secrets, etc.) and code smells (god classes, long methods, deep nesting, etc.).',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Source code to audit' },
        language: { type: 'string', description: 'Programming language (auto-detected if not specified)' },
        filename: { type: 'string', description: 'Filename for context' }
      },
      required: ['code']
    }
  },
  {
    name: 'calculate_code_metrics',
    description: 'Calculate code complexity and quality metrics including lines of code, cyclomatic complexity estimates, function counts, and comment ratios.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Source code to analyze' }
      },
      required: ['code']
    }
  },
  {
    name: 'analyze_dependencies',
    description: 'Analyze package dependencies for known vulnerabilities, outdated versions, and license compliance issues.',
    inputSchema: {
      type: 'object',
      properties: {
        packageJson: { type: 'string', description: 'Contents of package.json or similar manifest' },
        lockFile: { type: 'string', description: 'Contents of lock file (optional)' }
      },
      required: ['packageJson']
    }
  },

  // ==================== SECURITY AUDIT TOOLS ====================
  {
    name: 'assess_owasp',
    description: 'Assess application against OWASP Top 10 (2021) vulnerabilities: Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable Components, Auth Failures, Integrity Failures, Logging Failures, SSRF.',
    inputSchema: {
      type: 'object',
      properties: {
        applicationContext: { type: 'string', description: 'Description of the application architecture and security controls' },
        evidenceNotes: { type: 'string', description: 'Notes from security testing or review' }
      },
      required: ['applicationContext']
    }
  },
  {
    name: 'assess_cloud_security',
    description: 'Assess cloud infrastructure security for AWS, Azure, or GCP. Checks IAM, network security, encryption, logging, and compliance.',
    inputSchema: {
      type: 'object',
      properties: {
        provider: {
          type: 'string',
          enum: ['AWS', 'AZURE', 'GCP'],
          description: 'Cloud provider'
        },
        configurationData: { type: 'string', description: 'Cloud configuration data or description' }
      },
      required: ['provider', 'configurationData']
    }
  },
  {
    name: 'assess_zero_trust',
    description: 'Evaluate Zero Trust Architecture implementation. Assesses identity verification, device trust, network segmentation, least privilege, and continuous monitoring.',
    inputSchema: {
      type: 'object',
      properties: {
        architectureDescription: { type: 'string', description: 'Description of current security architecture' }
      },
      required: ['architectureDescription']
    }
  },
  {
    name: 'get_mitre_techniques',
    description: 'Get MITRE ATT&CK techniques for threat modeling. Returns technique IDs, descriptions, and detection strategies.',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          enum: ['credential_access', 'lateral_movement', 'persistence', 'privilege_escalation', 'defense_evasion', 'exfiltration'],
          description: 'ATT&CK category'
        }
      }
    }
  },

  // ==================== FORENSIC AUDIT TOOLS ====================
  {
    name: 'analyze_benford',
    description: "Analyze numerical data using Benford's Law to detect potential manipulation or fraud. Returns chi-square statistics, p-values, and flags anomalous digit distributions.",
    inputSchema: {
      type: 'object',
      properties: {
        numbers: {
          type: 'array',
          items: { type: 'number' },
          description: 'Array of numbers to analyze'
        },
        analysisType: {
          type: 'string',
          enum: ['first_digit', 'second_digit', 'both'],
          description: 'Type of digit analysis'
        }
      },
      required: ['numbers']
    }
  },
  {
    name: 'assess_fraud_risk',
    description: 'Assess fraud risk using comprehensive fraud indicators: cash skimming, shell companies, ghost employees, bid rigging, fictitious revenue, round-tripping, channel stuffing, and cookie jar reserves.',
    inputSchema: {
      type: 'object',
      properties: {
        context: { type: 'string', description: 'Business context and observations' },
        financialData: { type: 'string', description: 'Relevant financial information' }
      },
      required: ['context']
    }
  },
  {
    name: 'assess_aml_risk',
    description: 'Assess Anti-Money Laundering (AML) risk. Checks for structuring, layering, shell companies, trade-based laundering, smurfing, and high-risk jurisdictions.',
    inputSchema: {
      type: 'object',
      properties: {
        transactionData: { type: 'string', description: 'Transaction patterns and data' },
        customerInfo: { type: 'string', description: 'Customer/entity information' }
      },
      required: ['transactionData']
    }
  },
  {
    name: 'generate_interview_guide',
    description: 'Generate forensic interview guide using FAINT (Forensic Assessment Interview Technique) and PEACE methodologies. Includes rapport building, cognitive interview techniques, and deception indicators.',
    inputSchema: {
      type: 'object',
      properties: {
        interviewType: {
          type: 'string',
          enum: ['witness', 'suspect', 'subject_matter_expert', 'whistleblower'],
          description: 'Type of interview'
        },
        caseContext: { type: 'string', description: 'Context of the investigation' },
        topicsTocover: {
          type: 'array',
          items: { type: 'string' },
          description: 'Key topics to address'
        }
      },
      required: ['interviewType', 'caseContext']
    }
  },

  // ==================== COMPLIANCE AUDIT TOOLS ====================
  {
    name: 'generate_compliance_checklist',
    description: 'Generate compliance checklist for major frameworks: SOC 2, HIPAA, PCI-DSS v4.0, GDPR, ISO 27001, FedRAMP, CMMC, NIST CSF.',
    inputSchema: {
      type: 'object',
      properties: {
        framework: {
          type: 'string',
          enum: ['SOC2', 'HIPAA', 'PCI_DSS', 'GDPR', 'ISO27001', 'FEDRAMP', 'CMMC', 'NIST_CSF'],
          description: 'Compliance framework'
        },
        scope: { type: 'string', description: 'Scope of compliance assessment' }
      },
      required: ['framework']
    }
  },
  {
    name: 'assess_compliance',
    description: 'Assess current compliance status against a specific framework. Returns gap analysis with findings and recommendations.',
    inputSchema: {
      type: 'object',
      properties: {
        framework: {
          type: 'string',
          enum: ['SOC2', 'HIPAA', 'PCI_DSS', 'GDPR', 'ISO27001', 'FEDRAMP', 'CMMC', 'NIST_CSF'],
          description: 'Compliance framework'
        },
        currentState: { type: 'string', description: 'Description of current controls and practices' }
      },
      required: ['framework', 'currentState']
    }
  },
  {
    name: 'map_compliance_controls',
    description: 'Map controls between different compliance frameworks. Shows overlapping requirements to reduce duplicate efforts.',
    inputSchema: {
      type: 'object',
      properties: {
        sourceFramework: {
          type: 'string',
          enum: ['SOC2', 'HIPAA', 'PCI_DSS', 'GDPR', 'ISO27001'],
          description: 'Source framework'
        },
        targetFramework: {
          type: 'string',
          enum: ['SOC2', 'HIPAA', 'PCI_DSS', 'GDPR', 'ISO27001'],
          description: 'Target framework to map to'
        }
      },
      required: ['sourceFramework', 'targetFramework']
    }
  },

  // ==================== OPERATIONAL AUDIT TOOLS ====================
  {
    name: 'assess_waste',
    description: 'Assess operational waste using TIMWOOD framework (Transport, Inventory, Motion, Waiting, Overproduction, Overprocessing, Defects). Returns waste indicators, metrics, and improvement recommendations.',
    inputSchema: {
      type: 'object',
      properties: {
        processDescription: { type: 'string', description: 'Description of the process to analyze' },
        metrics: { type: 'string', description: 'Available process metrics' }
      },
      required: ['processDescription']
    }
  },
  {
    name: 'generate_dmaic_plan',
    description: 'Generate DMAIC (Define, Measure, Analyze, Improve, Control) improvement plan for a process. Includes tools, deliverables, and key questions for each phase.',
    inputSchema: {
      type: 'object',
      properties: {
        problemStatement: { type: 'string', description: 'Problem statement or improvement opportunity' },
        scope: { type: 'string', description: 'Process scope' },
        currentMetrics: { type: 'string', description: 'Current performance metrics' }
      },
      required: ['problemStatement', 'scope']
    }
  },
  {
    name: 'analyze_value_stream',
    description: 'Perform Value Stream Mapping analysis. Calculates process cycle efficiency, identifies bottlenecks, and recommends improvements.',
    inputSchema: {
      type: 'object',
      properties: {
        steps: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              cycleTime: { type: 'number', description: 'Cycle time in minutes' },
              waitTime: { type: 'number', description: 'Wait time in minutes' },
              valueAdded: { type: 'boolean' }
            }
          },
          description: 'Process steps with timing data'
        }
      },
      required: ['steps']
    }
  },
  {
    name: 'get_efficiency_metrics',
    description: 'Get definitions and formulas for operational efficiency metrics: PCE, FPY, OEE, Takt Time, Lead Time, Throughput, WIP, Utilization, Availability, DPMO, Sigma Level.',
    inputSchema: {
      type: 'object',
      properties: {
        metricNames: {
          type: 'array',
          items: { type: 'string' },
          description: 'Specific metrics to retrieve (omit for all)'
        }
      }
    }
  },

  // ==================== IT SYSTEMS AUDIT TOOLS ====================
  {
    name: 'assess_cobit',
    description: 'Assess IT governance using COBIT 5 framework. Evaluates domains: EDM (Evaluate, Direct, Monitor), APO (Align, Plan, Organize), BAI (Build, Acquire, Implement), DSS (Deliver, Service, Support), MEA (Monitor, Evaluate, Assess).',
    inputSchema: {
      type: 'object',
      properties: {
        domain: {
          type: 'string',
          enum: ['EDM', 'APO', 'BAI', 'DSS', 'MEA', 'ALL'],
          description: 'COBIT domain to assess'
        },
        currentState: { type: 'string', description: 'Description of current IT governance practices' }
      },
      required: ['domain', 'currentState']
    }
  },
  {
    name: 'assess_change_management',
    description: 'Assess IT change management practices. Checks CAB process, testing, rollback procedures, documentation, emergency changes, and segregation of duties.',
    inputSchema: {
      type: 'object',
      properties: {
        processDescription: { type: 'string', description: 'Description of current change management process' }
      },
      required: ['processDescription']
    }
  },
  {
    name: 'assess_backup_recovery',
    description: 'Assess backup and disaster recovery practices. Evaluates backup frequency, offsite storage, encryption, testing, RTO/RPO, and documentation.',
    inputSchema: {
      type: 'object',
      properties: {
        currentPractices: { type: 'string', description: 'Description of current backup and DR practices' }
      },
      required: ['currentPractices']
    }
  },
  {
    name: 'assess_ad_security',
    description: 'Assess Active Directory security. Checks privileged accounts, group policy, password policy, service accounts, stale objects, AdminSDHolder, Kerberos settings, trusts, replication, and audit logging.',
    inputSchema: {
      type: 'object',
      properties: {
        adConfiguration: { type: 'string', description: 'AD configuration details and observations' }
      },
      required: ['adConfiguration']
    }
  },

  // ==================== AI/ML AUDIT TOOLS ====================
  {
    name: 'assess_ai_risks',
    description: 'Assess AI/ML system risks across 14 categories: Bias/Fairness, Explainability, Data Quality, Model Drift, Security, Privacy, Governance, Performance, Reliability, Compliance, Ethics, Documentation, Testing, and Monitoring.',
    inputSchema: {
      type: 'object',
      properties: {
        modelDescription: { type: 'string', description: 'Description of the AI/ML model and its use case' },
        deploymentContext: { type: 'string', description: 'How and where the model is deployed' }
      },
      required: ['modelDescription']
    }
  },
  {
    name: 'assess_fairness',
    description: 'Assess AI model fairness using standard metrics: Disparate Impact, Statistical Parity Difference, Equal Opportunity Difference, Predictive Equality, and Treatment Equality.',
    inputSchema: {
      type: 'object',
      properties: {
        protectedAttribute: { type: 'string', description: 'Protected attribute being evaluated (e.g., gender, race, age)' },
        modelPredictions: { type: 'string', description: 'Description of model predictions and outcomes by group' }
      },
      required: ['protectedAttribute', 'modelPredictions']
    }
  },
  {
    name: 'generate_model_card',
    description: 'Generate Model Card template following Google\'s Model Cards for Model Reporting framework. Includes sections for model details, intended use, factors, metrics, evaluation data, training data, ethical considerations, and caveats.',
    inputSchema: {
      type: 'object',
      properties: {
        modelName: { type: 'string', description: 'Name of the model' },
        modelType: { type: 'string', description: 'Type of model (classification, regression, etc.)' },
        intendedUse: { type: 'string', description: 'Intended use cases' }
      },
      required: ['modelName', 'modelType', 'intendedUse']
    }
  },

  // ==================== MULTI-DOMAIN TOOLS ====================
  {
    name: 'comprehensive_audit',
    description: 'Perform comprehensive audit across multiple domains. Analyzes content/context and applies relevant auditing frameworks automatically.',
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'Content or context to audit' },
        domains: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['CODE', 'SECURITY', 'COMPLIANCE', 'OPERATIONAL', 'IT_SYSTEMS', 'FORENSIC', 'AI_ML']
          },
          description: 'Domains to include (omit for auto-detection)'
        },
        depth: {
          type: 'string',
          enum: ['quick', 'standard', 'deep'],
          description: 'Audit depth level'
        }
      },
      required: ['content']
    }
  },
  {
    name: 'risk_assessment',
    description: 'Perform risk assessment with likelihood and impact scoring. Calculates risk scores and prioritizes findings.',
    inputSchema: {
      type: 'object',
      properties: {
        findings: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              title: { type: 'string' },
              description: { type: 'string' },
              likelihood: { type: 'number', description: '1-5 scale' },
              impact: { type: 'number', description: '1-5 scale' }
            }
          },
          description: 'Findings to assess'
        }
      },
      required: ['findings']
    }
  }
];

// Create MCP Server
const server = new Server(
  {
    name: 'mcp-auditor',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle list tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: TOOLS };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const toolArgs = args || {};

  try {
    const handler = TOOL_HANDLERS[name];
    if (handler) {
      return handler(toolArgs);
    }
    return {
      content: [{
        type: 'text',
        text: `Unknown tool: ${name}`
      }],
      isError: true
    };
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: `Error executing ${name}: ${error instanceof Error ? error.message : String(error)}`
      }],
      isError: true
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('MCP Auditor server started');
}

main().catch(console.error);
