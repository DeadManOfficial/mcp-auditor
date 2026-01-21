// IT/Systems Audit Module
// Covers: COBIT, ITIL, Change Management, Backup/Recovery, Access Control, Active Directory

import { Finding, Evidence, Severity, AuditDomain } from '../core/types.js';
import { randomUUID } from 'crypto';

// ============================================
// COBIT FRAMEWORK DOMAINS
// ============================================

export interface COBITDomain {
  id: string;
  name: string;
  description: string;
  objectives: COBITObjective[];
}

export interface COBITObjective {
  id: string;
  name: string;
  description: string;
  practices: string[];
  metrics: string[];
}

export const COBIT_DOMAINS: COBITDomain[] = [
  {
    id: 'EDM',
    name: 'Evaluate, Direct and Monitor',
    description: 'Governance processes to ensure stakeholder value delivery.',
    objectives: [
      {
        id: 'EDM01',
        name: 'Ensure Governance Framework',
        description: 'Analyze and articulate governance requirements.',
        practices: [
          'Define governance system',
          'Align governance with enterprise objectives',
          'Monitor governance system',
        ],
        metrics: [
          'Stakeholder satisfaction with governance',
          'Number of governance issues',
          'Time to resolve governance issues',
        ],
      },
      {
        id: 'EDM02',
        name: 'Ensure Benefits Delivery',
        description: 'Optimize value contribution from IT-enabled investments.',
        practices: [
          'Evaluate value optimization',
          'Direct value optimization',
          'Monitor value optimization',
        ],
        metrics: [
          'Percentage of IT investments delivering expected value',
          'Business case ROI achievement',
        ],
      },
      {
        id: 'EDM03',
        name: 'Ensure Risk Optimization',
        description: 'Ensure IT-related risk does not exceed appetite.',
        practices: [
          'Evaluate risk management',
          'Direct risk management',
          'Monitor risk management',
        ],
        metrics: [
          'Number of risk events',
          'Risk appetite breaches',
          'Risk treatment effectiveness',
        ],
      },
    ],
  },
  {
    id: 'APO',
    name: 'Align, Plan and Organize',
    description: 'Overall organization, strategy and supporting activities.',
    objectives: [
      {
        id: 'APO01',
        name: 'Manage IT Management Framework',
        description: 'Define and maintain IT organizational structure.',
        practices: [
          'Define organizational structure',
          'Establish roles and responsibilities',
          'Maintain management system',
        ],
        metrics: [
          'Employee satisfaction with IT organization',
          'Time to fill IT positions',
          'Role coverage percentage',
        ],
      },
      {
        id: 'APO12',
        name: 'Manage Risk',
        description: 'Identify, assess and reduce IT-related risks.',
        practices: [
          'Collect risk data',
          'Analyze risk',
          'Maintain risk profile',
          'Articulate risk',
          'Define risk management action portfolio',
          'Respond to risk',
        ],
        metrics: [
          'Risk register completeness',
          'Risk assessment frequency',
          'Risk mitigation effectiveness',
        ],
      },
      {
        id: 'APO13',
        name: 'Manage Security',
        description: 'Define, operate and monitor an ISMS.',
        practices: [
          'Establish ISMS',
          'Define security risk treatment plan',
          'Monitor and review ISMS',
        ],
        metrics: [
          'Security incidents',
          'Security awareness training completion',
          'Vulnerability remediation time',
        ],
      },
    ],
  },
  {
    id: 'BAI',
    name: 'Build, Acquire and Implement',
    description: 'Solution identification, development, acquisition, and implementation.',
    objectives: [
      {
        id: 'BAI06',
        name: 'Manage Changes',
        description: 'Manage all changes in a controlled manner.',
        practices: [
          'Evaluate and prioritize change requests',
          'Manage emergency changes',
          'Track and report change status',
          'Close and document changes',
        ],
        metrics: [
          'Change success rate',
          'Emergency change percentage',
          'Change-related incidents',
          'Change backlog',
        ],
      },
      {
        id: 'BAI09',
        name: 'Manage Assets',
        description: 'Manage IT assets throughout their lifecycle.',
        practices: [
          'Identify and record assets',
          'Manage asset lifecycle',
          'Manage licenses',
        ],
        metrics: [
          'Asset inventory accuracy',
          'License compliance percentage',
          'Asset utilization',
        ],
      },
      {
        id: 'BAI10',
        name: 'Manage Configuration',
        description: 'Define and maintain configuration items.',
        practices: [
          'Establish configuration model',
          'Establish configuration repository',
          'Maintain configuration items',
          'Produce status and configuration reports',
        ],
        metrics: [
          'CMDB accuracy',
          'Configuration item coverage',
          'Unauthorized changes detected',
        ],
      },
    ],
  },
  {
    id: 'DSS',
    name: 'Deliver, Service and Support',
    description: 'Operational delivery and support of IT services.',
    objectives: [
      {
        id: 'DSS01',
        name: 'Manage Operations',
        description: 'Coordinate and execute IT operational activities.',
        practices: [
          'Perform operational procedures',
          'Manage outsourced services',
          'Monitor IT infrastructure',
          'Manage the environment',
        ],
        metrics: [
          'Service availability',
          'Operational incidents',
          'SLA achievement',
        ],
      },
      {
        id: 'DSS02',
        name: 'Manage Service Requests and Incidents',
        description: 'Provide timely response to requests and incidents.',
        practices: [
          'Define classification schemes',
          'Record, classify and prioritize requests/incidents',
          'Verify, approve and fulfill requests',
          'Investigate and diagnose incidents',
          'Resolve and recover from incidents',
          'Track status and produce reports',
        ],
        metrics: [
          'Mean time to resolve (MTTR)',
          'First contact resolution rate',
          'Incident backlog',
          'Customer satisfaction',
        ],
      },
      {
        id: 'DSS04',
        name: 'Manage Continuity',
        description: 'Establish and maintain a business continuity capability.',
        practices: [
          'Define business continuity policy',
          'Maintain continuity strategy',
          'Develop BCP',
          'Exercise and test BCP',
          'Review and update BCP',
          'Conduct continuity training',
          'Manage backup arrangements',
          'Conduct post-resumption review',
        ],
        metrics: [
          'BCP test frequency',
          'RTO/RPO achievement',
          'Backup success rate',
          'DR exercise results',
        ],
      },
      {
        id: 'DSS05',
        name: 'Manage Security Services',
        description: 'Protect enterprise information assets.',
        practices: [
          'Protect against malware',
          'Manage network and connectivity security',
          'Manage endpoint security',
          'Manage user identity and access',
          'Manage physical access',
          'Manage sensitive documents',
          'Monitor infrastructure for security events',
        ],
        metrics: [
          'Malware incidents',
          'Security event detection rate',
          'Access review completion',
          'Physical security incidents',
        ],
      },
    ],
  },
  {
    id: 'MEA',
    name: 'Monitor, Evaluate and Assess',
    description: 'Performance monitoring, conformance, and assurance.',
    objectives: [
      {
        id: 'MEA01',
        name: 'Monitor, Evaluate and Assess Performance and Conformance',
        description: 'Collect and analyze performance and conformance data.',
        practices: [
          'Establish monitoring approach',
          'Set performance and conformance targets',
          'Collect and process performance data',
          'Analyze and report performance',
          'Ensure implementation of corrective actions',
        ],
        metrics: [
          'KPI achievement rate',
          'Audit finding closure rate',
          'Conformance score',
        ],
      },
      {
        id: 'MEA02',
        name: 'Monitor, Evaluate and Assess Internal Controls',
        description: 'Monitor and evaluate internal control effectiveness.',
        practices: [
          'Monitor internal controls',
          'Review business process controls effectiveness',
          'Perform control self-assessments',
          'Identify and report control deficiencies',
          'Ensure corrective actions are addressed',
        ],
        metrics: [
          'Control effectiveness ratings',
          'Control deficiencies identified',
          'Remediation completion rate',
        ],
      },
    ],
  },
];

// ============================================
// CHANGE MANAGEMENT AUDIT CHECKLIST
// ============================================

export interface ChangeManagementCheck {
  id: string;
  category: string;
  name: string;
  severity: Severity;
  description: string;
  evidence: string[];
  testProcedures: string[];
}

export const CHANGE_MANAGEMENT_CHECKS: ChangeManagementCheck[] = [
  // Policy and Process
  {
    id: 'CHG-001',
    category: 'POLICY',
    name: 'Change Management Policy',
    severity: 'HIGH',
    description: 'Formal change management policy exists and is approved.',
    evidence: [
      'Change management policy document',
      'Policy approval records',
      'Policy review dates',
    ],
    testProcedures: [
      'Obtain and review change management policy',
      'Verify policy is current (reviewed within 12 months)',
      'Confirm policy is approved by appropriate authority',
    ],
  },
  {
    id: 'CHG-002',
    category: 'PROCESS',
    name: 'Change Request Documentation',
    severity: 'HIGH',
    description: 'All changes are documented with required information.',
    evidence: [
      'Sample of change requests',
      'Change request form/template',
    ],
    testProcedures: [
      'Select sample of changes',
      'Verify each has: description, justification, impact analysis, rollback plan',
      'Verify requester and date are documented',
    ],
  },
  {
    id: 'CHG-003',
    category: 'APPROVAL',
    name: 'Change Approval Process',
    severity: 'HIGH',
    description: 'Changes are approved by appropriate authority before implementation.',
    evidence: [
      'Change approval records',
      'CAB meeting minutes',
      'Approval workflow configuration',
    ],
    testProcedures: [
      'Review approval workflow',
      'Verify sample of changes have documented approval',
      'Confirm approver has appropriate authority',
    ],
  },
  {
    id: 'CHG-004',
    category: 'TESTING',
    name: 'Change Testing',
    severity: 'HIGH',
    description: 'Changes are tested before production deployment.',
    evidence: [
      'Test plans and results',
      'UAT sign-off',
      'Testing environment documentation',
    ],
    testProcedures: [
      'Review testing requirements',
      'Verify test evidence for sample of changes',
      'Confirm testing environment exists separate from production',
    ],
  },
  {
    id: 'CHG-005',
    category: 'EMERGENCY',
    name: 'Emergency Change Process',
    severity: 'MEDIUM',
    description: 'Emergency changes follow defined expedited process.',
    evidence: [
      'Emergency change procedure',
      'Sample emergency changes',
      'Post-implementation reviews',
    ],
    testProcedures: [
      'Review emergency change procedure',
      'Verify emergency changes were appropriately classified',
      'Confirm post-implementation review completed',
    ],
  },
  {
    id: 'CHG-006',
    category: 'ROLLBACK',
    name: 'Rollback Capability',
    severity: 'HIGH',
    description: 'Rollback/backout plans exist for all changes.',
    evidence: [
      'Rollback plans in change requests',
      'Evidence of rollback testing',
    ],
    testProcedures: [
      'Verify rollback plan documented for each change',
      'Review rollback execution for any failed changes',
    ],
  },
  {
    id: 'CHG-007',
    category: 'SEGREGATION',
    name: 'Segregation of Duties',
    severity: 'HIGH',
    description: 'Developer cannot approve or deploy their own changes.',
    evidence: [
      'Approval workflow showing different approver',
      'Deployment access controls',
    ],
    testProcedures: [
      'Verify developer is not approver for sample of changes',
      'Review production deployment access',
      'Confirm separation of dev, test, and prod environments',
    ],
  },
  {
    id: 'CHG-008',
    category: 'AUDIT_TRAIL',
    name: 'Change Audit Trail',
    severity: 'MEDIUM',
    description: 'Complete audit trail maintained for all changes.',
    evidence: [
      'Change management system logs',
      'Version control history',
      'Deployment logs',
    ],
    testProcedures: [
      'Verify all changes are logged with timestamps',
      'Confirm logs are protected from modification',
      'Review retention of change records',
    ],
  },
];

// ============================================
// BACKUP AND RECOVERY AUDIT
// ============================================

export interface BackupCheck {
  id: string;
  category: string;
  name: string;
  severity: Severity;
  description: string;
  evidence: string[];
  testProcedures: string[];
}

export const BACKUP_RECOVERY_CHECKS: BackupCheck[] = [
  {
    id: 'BKP-001',
    category: 'POLICY',
    name: 'Backup Policy',
    severity: 'HIGH',
    description: 'Formal backup policy defines requirements and schedules.',
    evidence: [
      'Backup policy document',
      'Backup schedule',
      'Data classification for backup',
    ],
    testProcedures: [
      'Review backup policy completeness',
      'Verify policy covers all critical systems',
      'Confirm RTO/RPO defined for each system tier',
    ],
  },
  {
    id: 'BKP-002',
    category: 'EXECUTION',
    name: 'Backup Completion',
    severity: 'CRITICAL',
    description: 'Backups complete successfully per schedule.',
    evidence: [
      'Backup completion logs',
      'Backup monitoring alerts',
      'Failure investigation records',
    ],
    testProcedures: [
      'Review backup logs for sample period',
      'Calculate backup success rate',
      'Verify failures are investigated and resolved',
    ],
  },
  {
    id: 'BKP-003',
    category: 'ENCRYPTION',
    name: 'Backup Encryption',
    severity: 'HIGH',
    description: 'Backups are encrypted at rest and in transit.',
    evidence: [
      'Encryption configuration',
      'Key management procedures',
    ],
    testProcedures: [
      'Verify encryption is enabled',
      'Confirm encryption algorithm strength',
      'Review key management process',
    ],
  },
  {
    id: 'BKP-004',
    category: 'OFFSITE',
    name: 'Offsite Storage',
    severity: 'HIGH',
    description: 'Backups stored offsite or in geographically separate location.',
    evidence: [
      'Offsite storage contracts',
      'Geographic separation documentation',
      '3-2-1 rule compliance',
    ],
    testProcedures: [
      'Verify offsite storage location',
      'Confirm geographic separation from primary site',
      'Review 3-2-1 rule compliance (3 copies, 2 media types, 1 offsite)',
    ],
  },
  {
    id: 'BKP-005',
    category: 'TESTING',
    name: 'Recovery Testing',
    severity: 'CRITICAL',
    description: 'Regular recovery testing validates backup integrity.',
    evidence: [
      'Recovery test schedule',
      'Recovery test results',
      'RTO/RPO achievement documentation',
    ],
    testProcedures: [
      'Review recovery test frequency',
      'Verify recovery tests are successful',
      'Confirm RTO/RPO can be achieved',
    ],
  },
  {
    id: 'BKP-006',
    category: 'RETENTION',
    name: 'Backup Retention',
    severity: 'MEDIUM',
    description: 'Backup retention meets regulatory and business requirements.',
    evidence: [
      'Retention policy',
      'Retention compliance reports',
    ],
    testProcedures: [
      'Review retention requirements',
      'Verify backups are retained per policy',
      'Confirm secure destruction of expired backups',
    ],
  },
  {
    id: 'BKP-007',
    category: 'ACCESS',
    name: 'Backup Access Control',
    severity: 'HIGH',
    description: 'Access to backup systems and media is restricted.',
    evidence: [
      'Backup system access lists',
      'Physical media access controls',
    ],
    testProcedures: [
      'Review backup system access',
      'Verify least privilege applied',
      'Confirm physical security of backup media',
    ],
  },
  {
    id: 'BKP-008',
    category: 'IMMUTABILITY',
    name: 'Backup Immutability',
    severity: 'HIGH',
    description: 'Backups are protected from modification or deletion.',
    evidence: [
      'Immutable backup configuration',
      'WORM storage evidence',
    ],
    testProcedures: [
      'Verify immutability settings',
      'Test that backups cannot be deleted within retention period',
      'Review ransomware protection for backups',
    ],
  },
];

// ============================================
// ACTIVE DIRECTORY / ACCESS CONTROL AUDIT
// ============================================

export interface ADSecurityCheck {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  detection: string;
  mitigation: string;
}

export const AD_SECURITY_CHECKS: ADSecurityCheck[] = [
  {
    id: 'AD-001',
    name: 'Privileged Account Inventory',
    severity: 'CRITICAL',
    description: 'All privileged accounts (Domain Admins, Enterprise Admins, Schema Admins) are documented.',
    detection: 'Query AD for members of privileged groups. Compare to authorized list.',
    mitigation: 'Remove unauthorized accounts. Implement regular access reviews.',
  },
  {
    id: 'AD-002',
    name: 'Service Account Management',
    severity: 'HIGH',
    description: 'Service accounts are documented, have strong passwords, and follow least privilege.',
    detection: 'Enumerate service accounts. Check password age and last set date.',
    mitigation: 'Implement gMSA where possible. Set long, complex passwords. Regular rotation.',
  },
  {
    id: 'AD-003',
    name: 'Stale Account Detection',
    severity: 'MEDIUM',
    description: 'Inactive user and computer accounts are disabled or removed.',
    detection: 'Query for accounts not logged in within 90 days.',
    mitigation: 'Disable inactive accounts. Remove after extended period. Automate process.',
  },
  {
    id: 'AD-004',
    name: 'Password Policy',
    severity: 'HIGH',
    description: 'Strong password policy is enforced (length, complexity, history, expiration).',
    detection: 'Review Default Domain Policy and Fine-Grained Password Policies.',
    mitigation: 'Enforce 14+ character minimum. Require complexity. Implement password history.',
  },
  {
    id: 'AD-005',
    name: 'KRBTGT Password',
    severity: 'CRITICAL',
    description: 'KRBTGT account password is changed regularly to prevent Golden Ticket attacks.',
    detection: 'Check KRBTGT password last set date. Should be within 180 days.',
    mitigation: 'Change KRBTGT password twice (with replication between). Schedule regular rotation.',
  },
  {
    id: 'AD-006',
    name: 'Protected Users Group',
    severity: 'HIGH',
    description: 'Privileged accounts are members of Protected Users security group.',
    detection: 'Check membership of Protected Users group.',
    mitigation: 'Add all admin accounts to Protected Users. Test for compatibility issues.',
  },
  {
    id: 'AD-007',
    name: 'AdminSDHolder Permissions',
    severity: 'HIGH',
    description: 'AdminSDHolder ACL is not modified from default.',
    detection: 'Review AdminSDHolder ACL for unexpected permissions.',
    mitigation: 'Remove unauthorized permissions. Monitor for changes.',
  },
  {
    id: 'AD-008',
    name: 'SPN Configuration',
    severity: 'MEDIUM',
    description: 'Service Principal Names (SPNs) are properly configured and no user accounts have SPNs.',
    detection: 'Query for user accounts with SPNs (Kerberoastable accounts).',
    mitigation: 'Remove SPNs from user accounts. Use gMSA for services.',
  },
  {
    id: 'AD-009',
    name: 'Delegation Configuration',
    severity: 'HIGH',
    description: 'Unconstrained delegation is not enabled inappropriately.',
    detection: 'Query for accounts with unconstrained delegation.',
    mitigation: 'Use constrained delegation or resource-based delegation where needed.',
  },
  {
    id: 'AD-010',
    name: 'DC Security',
    severity: 'CRITICAL',
    description: 'Domain Controllers are hardened and access is restricted.',
    detection: 'Review DC local admin group membership. Check firewall rules.',
    mitigation: 'Restrict DC logon rights. Implement tiered admin model. Use PAW.',
  },
];

// ============================================
// IT SYSTEMS AUDITOR CLASS
// ============================================

export class ITSystemsAuditor {
  private findings: Finding[] = [];

  // Generate COBIT assessment
  assessCOBIT(context: string): Finding[] {
    const findings: Finding[] = [];

    for (const domain of COBIT_DOMAINS) {
      for (const objective of domain.objectives) {
        findings.push({
          id: `COBIT-${objective.id}-${randomUUID().slice(0, 4)}`,
          domain: 'IT_SYSTEMS',
          severity: 'INFO',
          status: 'REVIEW_REQUIRED',
          title: `COBIT ${objective.id}: ${objective.name}`,
          description: `**Domain:** ${domain.name}\n\n${objective.description}\n\n**Key Practices:**\n${objective.practices.map(p => `- ${p}`).join('\n')}\n\n**Metrics:**\n${objective.metrics.map(m => `- ${m}`).join('\n')}`,
          evidence: [{
            type: 'DATA',
            description: 'COBIT assessment checklist',
            source: context,
            collectedAt: new Date().toISOString(),
          }],
          recommendation: `Evaluate maturity level for ${objective.id}. Document current state and improvement opportunities.`,
          timestamp: new Date().toISOString(),
        });
      }
    }

    this.findings.push(...findings);
    return findings;
  }

  // Assess change management
  assessChangeManagement(context: string): Finding[] {
    const findings: Finding[] = [];

    for (const check of CHANGE_MANAGEMENT_CHECKS) {
      findings.push({
        id: `${check.id}-${randomUUID().slice(0, 4)}`,
        domain: 'IT_SYSTEMS',
        severity: check.severity,
        status: 'REVIEW_REQUIRED',
        title: `Change Management: ${check.name}`,
        description: `**Category:** ${check.category}\n\n${check.description}\n\n**Evidence Required:**\n${check.evidence.map(e => `- ${e}`).join('\n')}\n\n**Test Procedures:**\n${check.testProcedures.map(t => `- ${t}`).join('\n')}`,
        evidence: [{
          type: 'DATA',
          description: 'Change management audit checklist',
          source: context,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: 'Complete test procedures and document evidence.',
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Assess backup and recovery
  assessBackupRecovery(context: string): Finding[] {
    const findings: Finding[] = [];

    for (const check of BACKUP_RECOVERY_CHECKS) {
      findings.push({
        id: `${check.id}-${randomUUID().slice(0, 4)}`,
        domain: 'IT_SYSTEMS',
        severity: check.severity,
        status: 'REVIEW_REQUIRED',
        title: `Backup/Recovery: ${check.name}`,
        description: `**Category:** ${check.category}\n\n${check.description}\n\n**Evidence Required:**\n${check.evidence.map(e => `- ${e}`).join('\n')}\n\n**Test Procedures:**\n${check.testProcedures.map(t => `- ${t}`).join('\n')}`,
        evidence: [{
          type: 'DATA',
          description: 'Backup and recovery audit checklist',
          source: context,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: 'Complete test procedures and document evidence.',
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Assess Active Directory security
  assessADSecurity(context: string): Finding[] {
    const findings: Finding[] = [];

    for (const check of AD_SECURITY_CHECKS) {
      findings.push({
        id: `${check.id}-${randomUUID().slice(0, 4)}`,
        domain: 'SECURITY',
        severity: check.severity,
        status: 'REVIEW_REQUIRED',
        title: `AD Security: ${check.name}`,
        description: `${check.description}\n\n**Detection Method:**\n${check.detection}`,
        evidence: [{
          type: 'DATA',
          description: 'Active Directory security assessment',
          source: context,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: check.mitigation,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
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
export const itSystemsAuditor = new ITSystemsAuditor();
