// Compliance Audit Module
// Covers: SOC 2, ISO 27001, HIPAA, PCI-DSS, GDPR, NIST, FedRAMP, CMMC

import { Finding, Evidence, Severity, AuditDomain, ComplianceFramework } from '../core/types.js';
import { randomUUID } from 'crypto';

// ============================================
// COMPLIANCE CONTROL STRUCTURE
// ============================================

export interface ComplianceControl {
  id: string;
  framework: ComplianceFramework;
  category: string;
  name: string;
  description: string;
  requirements: string[];
  evidence: string[];
  testProcedures: string[];
  mappings?: Record<string, string>; // Maps to other frameworks
}

// ============================================
// SOC 2 TRUST SERVICE CRITERIA
// ============================================

export const SOC2_CONTROLS: ComplianceControl[] = [
  // SECURITY (Common Criteria - CC)
  {
    id: 'CC1.1',
    framework: 'SOC2',
    category: 'Control Environment',
    name: 'COSO Principle 1: Integrity and Ethical Values',
    description: 'The entity demonstrates a commitment to integrity and ethical values.',
    requirements: [
      'Code of conduct established and communicated',
      'Background checks performed on employees',
      'Annual ethics training required',
      'Whistleblower policy in place',
    ],
    evidence: [
      'Code of conduct document',
      'Background check policy and sample records',
      'Training completion records',
      'Whistleblower policy',
    ],
    testProcedures: [
      'Review code of conduct for completeness',
      'Verify background checks for sample of new hires',
      'Confirm training completion rates',
    ],
    mappings: { 'ISO27001': 'A.7.1.1', 'NIST': 'AT-2' },
  },
  {
    id: 'CC2.1',
    framework: 'SOC2',
    category: 'Communication and Information',
    name: 'Information Quality',
    description: 'The entity obtains and uses relevant quality information.',
    requirements: [
      'Information security policies documented',
      'Policies communicated to all employees',
      'Regular policy review process',
    ],
    evidence: [
      'Information security policy',
      'Policy distribution records',
      'Policy review documentation',
    ],
    testProcedures: [
      'Review policy completeness',
      'Verify policy distribution',
      'Confirm policy review dates',
    ],
    mappings: { 'ISO27001': 'A.5.1.1', 'NIST': 'PL-1' },
  },
  {
    id: 'CC3.1',
    framework: 'SOC2',
    category: 'Risk Assessment',
    name: 'Risk Identification and Analysis',
    description: 'The entity identifies and analyzes risks to achieving its objectives.',
    requirements: [
      'Risk assessment process documented',
      'Risk assessment performed annually',
      'Risk register maintained',
      'Risk treatment plans documented',
    ],
    evidence: [
      'Risk assessment methodology',
      'Risk assessment report',
      'Risk register',
      'Risk treatment plans',
    ],
    testProcedures: [
      'Review risk assessment methodology',
      'Verify annual risk assessment completion',
      'Review risk register for completeness',
    ],
    mappings: { 'ISO27001': 'A.8.2', 'NIST': 'RA-3', 'HIPAA': '164.308(a)(1)(ii)(A)' },
  },
  {
    id: 'CC5.1',
    framework: 'SOC2',
    category: 'Control Activities',
    name: 'Logical Access Controls',
    description: 'The entity implements logical access security controls.',
    requirements: [
      'User access provisioning process',
      'Role-based access control implemented',
      'Access reviews performed quarterly',
      'Privileged access restricted and monitored',
      'MFA required for remote access',
    ],
    evidence: [
      'Access provisioning procedures',
      'RBAC matrix',
      'Access review records',
      'Privileged account inventory',
      'MFA configuration evidence',
    ],
    testProcedures: [
      'Test user provisioning process',
      'Verify RBAC implementation',
      'Review access review completion',
      'Test privileged access controls',
      'Verify MFA enforcement',
    ],
    mappings: { 'ISO27001': 'A.9.2.1', 'NIST': 'AC-2', 'PCI_DSS': '7.1', 'HIPAA': '164.312(a)(1)' },
  },
  {
    id: 'CC6.1',
    framework: 'SOC2',
    category: 'Logical and Physical Access',
    name: 'Security Software Configuration',
    description: 'The entity implements security software to identify threats.',
    requirements: [
      'Anti-malware deployed on all endpoints',
      'Intrusion detection/prevention systems',
      'SIEM implemented for log aggregation',
      'Vulnerability scanning performed',
      'Penetration testing performed annually',
    ],
    evidence: [
      'AV/EDR deployment records',
      'IDS/IPS configuration',
      'SIEM architecture and logs',
      'Vulnerability scan reports',
      'Penetration test reports',
    ],
    testProcedures: [
      'Verify AV deployment coverage',
      'Review IDS/IPS alerts',
      'Review SIEM coverage',
      'Verify scan frequency and remediation',
      'Review pentest findings and remediation',
    ],
    mappings: { 'ISO27001': 'A.12.2.1', 'NIST': 'SI-3', 'PCI_DSS': '5.1' },
  },
  {
    id: 'CC6.6',
    framework: 'SOC2',
    category: 'Logical and Physical Access',
    name: 'Network Security',
    description: 'The entity implements controls to protect network security.',
    requirements: [
      'Firewall implemented at network boundary',
      'Network segmentation in place',
      'Encryption for data in transit',
      'Wireless security controls',
      'VPN for remote access',
    ],
    evidence: [
      'Firewall rule documentation',
      'Network diagram with segmentation',
      'TLS/encryption configuration',
      'Wireless security configuration',
      'VPN configuration',
    ],
    testProcedures: [
      'Review firewall rules',
      'Verify network segmentation',
      'Test encryption implementation',
      'Verify wireless security',
      'Test VPN configuration',
    ],
    mappings: { 'ISO27001': 'A.13.1.1', 'NIST': 'SC-7', 'PCI_DSS': '1.1' },
  },
  {
    id: 'CC7.1',
    framework: 'SOC2',
    category: 'System Operations',
    name: 'Security Incident Management',
    description: 'The entity detects, responds to, and resolves security incidents.',
    requirements: [
      'Incident response plan documented',
      'Incident response team identified',
      'Incident classification criteria defined',
      'Incident response tested annually',
      'Post-incident reviews conducted',
    ],
    evidence: [
      'Incident response plan',
      'IR team roster',
      'Incident classification matrix',
      'Tabletop exercise records',
      'Post-incident review documentation',
    ],
    testProcedures: [
      'Review IR plan completeness',
      'Verify team member training',
      'Test incident detection capability',
      'Review tabletop exercise results',
    ],
    mappings: { 'ISO27001': 'A.16.1.1', 'NIST': 'IR-1', 'HIPAA': '164.308(a)(6)' },
  },
  {
    id: 'CC8.1',
    framework: 'SOC2',
    category: 'Change Management',
    name: 'Change Management Process',
    description: 'The entity authorizes, tests, and documents changes.',
    requirements: [
      'Change management policy documented',
      'Change approval process defined',
      'Testing required before production',
      'Emergency change procedures defined',
      'Change audit trail maintained',
    ],
    evidence: [
      'Change management policy',
      'Change approval records',
      'Testing documentation',
      'Emergency change records',
      'Change log',
    ],
    testProcedures: [
      'Review change policy',
      'Test change approval workflow',
      'Verify testing evidence',
      'Review emergency changes',
    ],
    mappings: { 'ISO27001': 'A.12.1.2', 'NIST': 'CM-3', 'PCI_DSS': '6.4' },
  },
  {
    id: 'CC9.1',
    framework: 'SOC2',
    category: 'Risk Mitigation',
    name: 'Vendor Risk Management',
    description: 'The entity identifies and addresses risks from vendors.',
    requirements: [
      'Vendor risk assessment process',
      'Security requirements in contracts',
      'Vendor due diligence performed',
      'Ongoing vendor monitoring',
      'Vendor incident notification requirements',
    ],
    evidence: [
      'Vendor risk assessment records',
      'Sample contracts with security terms',
      'Due diligence documentation',
      'Vendor monitoring records',
    ],
    testProcedures: [
      'Review vendor risk process',
      'Verify contract terms',
      'Review due diligence samples',
      'Verify ongoing monitoring',
    ],
    mappings: { 'ISO27001': 'A.15.1.1', 'NIST': 'SA-9', 'HIPAA': '164.308(b)(1)' },
  },

  // AVAILABILITY
  {
    id: 'A1.1',
    framework: 'SOC2',
    category: 'Availability',
    name: 'Capacity Management',
    description: 'The entity maintains capacity to meet availability commitments.',
    requirements: [
      'Capacity planning process',
      'Performance monitoring',
      'Scalability mechanisms',
      'SLA definitions',
    ],
    evidence: [
      'Capacity planning documentation',
      'Monitoring dashboards',
      'Auto-scaling configuration',
      'SLA documentation',
    ],
    testProcedures: [
      'Review capacity planning',
      'Verify monitoring coverage',
      'Test auto-scaling',
      'Review SLA performance',
    ],
  },
  {
    id: 'A1.2',
    framework: 'SOC2',
    category: 'Availability',
    name: 'Backup and Recovery',
    description: 'The entity maintains backup and recovery capabilities.',
    requirements: [
      'Backup policy and schedule',
      'Backup encryption',
      'Recovery testing performed',
      'RTO/RPO defined and met',
      'Offsite backup storage',
    ],
    evidence: [
      'Backup policy',
      'Backup logs',
      'Recovery test records',
      'RTO/RPO documentation',
      'Offsite storage contracts',
    ],
    testProcedures: [
      'Review backup policy',
      'Verify backup completion',
      'Review recovery test results',
      'Verify RTO/RPO metrics',
    ],
    mappings: { 'ISO27001': 'A.12.3.1', 'NIST': 'CP-9', 'HIPAA': '164.308(a)(7)(ii)(A)' },
  },

  // CONFIDENTIALITY
  {
    id: 'C1.1',
    framework: 'SOC2',
    category: 'Confidentiality',
    name: 'Data Classification',
    description: 'The entity identifies and classifies confidential information.',
    requirements: [
      'Data classification policy',
      'Classification labels defined',
      'Data inventory maintained',
      'Handling procedures by classification',
    ],
    evidence: [
      'Classification policy',
      'Data inventory',
      'Sample classified data',
      'Handling procedures',
    ],
    testProcedures: [
      'Review classification policy',
      'Verify data inventory',
      'Test classification implementation',
    ],
    mappings: { 'ISO27001': 'A.8.2.1', 'NIST': 'AC-4', 'GDPR': 'Article 5' },
  },
  {
    id: 'C1.2',
    framework: 'SOC2',
    category: 'Confidentiality',
    name: 'Data Encryption',
    description: 'The entity protects confidential information through encryption.',
    requirements: [
      'Encryption at rest for sensitive data',
      'Encryption in transit (TLS 1.2+)',
      'Key management procedures',
      'Encryption algorithms approved',
    ],
    evidence: [
      'Encryption configuration',
      'TLS configuration',
      'Key management documentation',
      'Approved algorithm list',
    ],
    testProcedures: [
      'Verify encryption at rest',
      'Test TLS configuration',
      'Review key management',
      'Verify algorithm compliance',
    ],
    mappings: { 'ISO27001': 'A.10.1.1', 'NIST': 'SC-13', 'PCI_DSS': '3.4', 'HIPAA': '164.312(a)(2)(iv)' },
  },

  // PRIVACY
  {
    id: 'P1.1',
    framework: 'SOC2',
    category: 'Privacy',
    name: 'Privacy Notice',
    description: 'The entity provides notice about its privacy practices.',
    requirements: [
      'Privacy policy published',
      'Data collection purposes disclosed',
      'Third-party sharing disclosed',
      'User rights documented',
    ],
    evidence: [
      'Privacy policy',
      'Website privacy notice',
      'Data collection disclosures',
    ],
    testProcedures: [
      'Review privacy policy completeness',
      'Verify disclosures',
      'Test user rights implementation',
    ],
    mappings: { 'GDPR': 'Article 13' },
  },
];

// ============================================
// HIPAA SECURITY RULE CONTROLS
// ============================================

export const HIPAA_CONTROLS: ComplianceControl[] = [
  // Administrative Safeguards
  {
    id: '164.308(a)(1)',
    framework: 'HIPAA',
    category: 'Administrative Safeguards',
    name: 'Security Management Process',
    description: 'Implement policies to prevent, detect, contain security violations.',
    requirements: [
      'Risk analysis conducted',
      'Risk management program',
      'Sanction policy for violations',
      'Information system activity review',
    ],
    evidence: [
      'Risk assessment documentation',
      'Risk management plan',
      'Sanction policy',
      'Audit log review procedures',
    ],
    testProcedures: [
      'Review risk assessment completeness',
      'Verify risk treatment',
      'Review sanction policy enforcement',
      'Test audit log review process',
    ],
    mappings: { 'SOC2': 'CC3.1', 'NIST': 'RA-3' },
  },
  {
    id: '164.308(a)(3)',
    framework: 'HIPAA',
    category: 'Administrative Safeguards',
    name: 'Workforce Security',
    description: 'Implement policies ensuring appropriate PHI access.',
    requirements: [
      'Authorization procedures',
      'Workforce clearance procedures',
      'Termination procedures',
    ],
    evidence: [
      'Access authorization policy',
      'Background check records',
      'Termination checklists',
    ],
    testProcedures: [
      'Review authorization process',
      'Verify termination completeness',
    ],
    mappings: { 'SOC2': 'CC5.1', 'NIST': 'PS-3' },
  },
  {
    id: '164.308(a)(4)',
    framework: 'HIPAA',
    category: 'Administrative Safeguards',
    name: 'Information Access Management',
    description: 'Implement policies authorizing access to ePHI.',
    requirements: [
      'Access authorization policy',
      'Access establishment and modification',
      'Minimum necessary standard',
    ],
    evidence: [
      'Access control policy',
      'Access provisioning records',
      'Role definitions',
    ],
    testProcedures: [
      'Review access policy',
      'Test access provisioning',
      'Verify minimum necessary',
    ],
    mappings: { 'SOC2': 'CC5.1', 'NIST': 'AC-1' },
  },
  {
    id: '164.308(a)(5)',
    framework: 'HIPAA',
    category: 'Administrative Safeguards',
    name: 'Security Awareness Training',
    description: 'Implement security awareness and training program.',
    requirements: [
      'Security reminders',
      'Protection from malware',
      'Log-in monitoring',
      'Password management training',
    ],
    evidence: [
      'Training materials',
      'Training completion records',
      'Security awareness communications',
    ],
    testProcedures: [
      'Review training content',
      'Verify completion rates',
      'Test employee awareness',
    ],
    mappings: { 'SOC2': 'CC1.1', 'NIST': 'AT-2' },
  },
  {
    id: '164.308(a)(6)',
    framework: 'HIPAA',
    category: 'Administrative Safeguards',
    name: 'Security Incident Procedures',
    description: 'Implement policies to address security incidents.',
    requirements: [
      'Incident response plan',
      'Incident identification and reporting',
      'Breach notification procedures',
    ],
    evidence: [
      'Incident response plan',
      'Incident logs',
      'Breach notification records',
    ],
    testProcedures: [
      'Review IR plan',
      'Test incident reporting',
      'Verify breach notifications',
    ],
    mappings: { 'SOC2': 'CC7.1', 'NIST': 'IR-1' },
  },
  {
    id: '164.308(a)(7)',
    framework: 'HIPAA',
    category: 'Administrative Safeguards',
    name: 'Contingency Plan',
    description: 'Establish policies for responding to emergencies.',
    requirements: [
      'Data backup plan',
      'Disaster recovery plan',
      'Emergency mode operation plan',
      'Testing and revision procedures',
      'Applications and data criticality analysis',
    ],
    evidence: [
      'Backup documentation',
      'DR plan',
      'Emergency procedures',
      'Test records',
      'BIA documentation',
    ],
    testProcedures: [
      'Review backup completeness',
      'Test DR procedures',
      'Verify testing frequency',
    ],
    mappings: { 'SOC2': 'A1.2', 'NIST': 'CP-2' },
  },

  // Physical Safeguards
  {
    id: '164.310(a)(1)',
    framework: 'HIPAA',
    category: 'Physical Safeguards',
    name: 'Facility Access Controls',
    description: 'Limit physical access to ePHI systems.',
    requirements: [
      'Contingency operations access',
      'Facility security plan',
      'Access control and validation',
      'Maintenance records',
    ],
    evidence: [
      'Physical security policy',
      'Access logs',
      'Visitor procedures',
      'Maintenance records',
    ],
    testProcedures: [
      'Review physical access controls',
      'Test access logging',
      'Verify visitor procedures',
    ],
    mappings: { 'SOC2': 'CC6.4', 'NIST': 'PE-2' },
  },
  {
    id: '164.310(d)(1)',
    framework: 'HIPAA',
    category: 'Physical Safeguards',
    name: 'Device and Media Controls',
    description: 'Implement policies governing hardware and electronic media.',
    requirements: [
      'Disposal procedures',
      'Media re-use procedures',
      'Accountability records',
      'Data backup and storage',
    ],
    evidence: [
      'Media disposal procedures',
      'Disposal certificates',
      'Asset inventory',
      'Backup documentation',
    ],
    testProcedures: [
      'Review disposal process',
      'Verify disposal records',
      'Test asset tracking',
    ],
    mappings: { 'SOC2': 'CC6.5', 'NIST': 'MP-6' },
  },

  // Technical Safeguards
  {
    id: '164.312(a)(1)',
    framework: 'HIPAA',
    category: 'Technical Safeguards',
    name: 'Access Control',
    description: 'Implement technical policies for ePHI access.',
    requirements: [
      'Unique user identification',
      'Emergency access procedure',
      'Automatic logoff',
      'Encryption and decryption',
    ],
    evidence: [
      'User ID policy',
      'Emergency access procedures',
      'Session timeout configuration',
      'Encryption configuration',
    ],
    testProcedures: [
      'Verify unique user IDs',
      'Test emergency access',
      'Verify session timeouts',
      'Test encryption',
    ],
    mappings: { 'SOC2': 'CC5.1', 'NIST': 'AC-2' },
  },
  {
    id: '164.312(b)',
    framework: 'HIPAA',
    category: 'Technical Safeguards',
    name: 'Audit Controls',
    description: 'Implement mechanisms to record and examine ePHI access.',
    requirements: [
      'Audit logging enabled',
      'Audit log review procedures',
      'Audit log protection',
      'Audit log retention',
    ],
    evidence: [
      'Audit logging configuration',
      'Log review procedures',
      'Log protection mechanisms',
      'Retention policy',
    ],
    testProcedures: [
      'Verify audit logging',
      'Review log analysis',
      'Test log protection',
    ],
    mappings: { 'SOC2': 'CC7.2', 'NIST': 'AU-2' },
  },
  {
    id: '164.312(c)(1)',
    framework: 'HIPAA',
    category: 'Technical Safeguards',
    name: 'Integrity',
    description: 'Implement policies protecting ePHI from improper alteration.',
    requirements: [
      'Mechanism to authenticate ePHI',
      'Electronic signatures (if used)',
    ],
    evidence: [
      'Integrity checking mechanisms',
      'Hash verification',
      'Digital signature implementation',
    ],
    testProcedures: [
      'Test integrity controls',
      'Verify authentication mechanisms',
    ],
    mappings: { 'SOC2': 'CC6.1', 'NIST': 'SI-7' },
  },
  {
    id: '164.312(d)',
    framework: 'HIPAA',
    category: 'Technical Safeguards',
    name: 'Person or Entity Authentication',
    description: 'Implement procedures verifying person/entity seeking access.',
    requirements: [
      'Authentication mechanisms',
      'Multi-factor authentication',
      'Token/certificate authentication',
    ],
    evidence: [
      'Authentication policy',
      'MFA configuration',
      'Authentication logs',
    ],
    testProcedures: [
      'Test authentication mechanisms',
      'Verify MFA enforcement',
    ],
    mappings: { 'SOC2': 'CC6.1', 'NIST': 'IA-2' },
  },
  {
    id: '164.312(e)(1)',
    framework: 'HIPAA',
    category: 'Technical Safeguards',
    name: 'Transmission Security',
    description: 'Implement measures guarding against unauthorized ePHI access during transmission.',
    requirements: [
      'Integrity controls for transmission',
      'Encryption for transmission',
    ],
    evidence: [
      'Transmission security policy',
      'TLS configuration',
      'VPN configuration',
    ],
    testProcedures: [
      'Test transmission encryption',
      'Verify TLS versions',
    ],
    mappings: { 'SOC2': 'CC6.6', 'NIST': 'SC-8' },
  },
];

// ============================================
// PCI-DSS v4.0 REQUIREMENTS
// ============================================

export const PCI_DSS_CONTROLS: ComplianceControl[] = [
  // Requirement 1: Network Security
  {
    id: 'PCI-1.1',
    framework: 'PCI_DSS',
    category: 'Network Security Controls',
    name: 'Firewall Configuration Standards',
    description: 'Establish and maintain firewall configuration standards.',
    requirements: [
      'Formal process for approving network connections',
      'Network diagram documenting CDE connections',
      'Data flow diagram for cardholder data',
      'Firewall at each internet connection',
      'Personal firewall on mobile devices',
    ],
    evidence: [
      'Firewall standards document',
      'Network diagrams',
      'Data flow diagrams',
      'Firewall configuration',
    ],
    testProcedures: [
      'Review firewall standards',
      'Verify network diagrams',
      'Test firewall rules',
      'Verify personal firewalls',
    ],
    mappings: { 'SOC2': 'CC6.6', 'NIST': 'SC-7' },
  },
  {
    id: 'PCI-2.1',
    framework: 'PCI_DSS',
    category: 'Secure Configuration',
    name: 'Change Default Credentials',
    description: 'Change vendor-supplied defaults before production deployment.',
    requirements: [
      'Change default passwords',
      'Remove/disable unnecessary accounts',
      'Remove/disable unnecessary services',
      'Configure security parameters',
    ],
    evidence: [
      'Hardening standards',
      'System configuration evidence',
      'Account inventory',
    ],
    testProcedures: [
      'Test for default credentials',
      'Verify service hardening',
      'Review account configurations',
    ],
    mappings: { 'SOC2': 'CC6.1', 'NIST': 'CM-6' },
  },
  {
    id: 'PCI-3.4',
    framework: 'PCI_DSS',
    category: 'Protect Stored Account Data',
    name: 'PAN Encryption',
    description: 'Render PAN unreadable anywhere it is stored.',
    requirements: [
      'One-way hash using strong cryptography',
      'Truncation (only first 6 and last 4 digits)',
      'Index tokens with secure storage',
      'Strong cryptography with key management',
    ],
    evidence: [
      'Encryption standards',
      'Key management procedures',
      'Storage locations inventory',
    ],
    testProcedures: [
      'Verify PAN encryption',
      'Test key management',
      'Review storage locations',
    ],
    mappings: { 'SOC2': 'C1.2', 'NIST': 'SC-28' },
  },
  {
    id: 'PCI-4.1',
    framework: 'PCI_DSS',
    category: 'Encrypt Transmission',
    name: 'Strong Cryptography for Transmission',
    description: 'Use strong cryptography when transmitting PAN over open networks.',
    requirements: [
      'TLS 1.2 or higher',
      'Trusted keys and certificates',
      'Protocol supports only secure versions',
    ],
    evidence: [
      'TLS configuration',
      'Certificate inventory',
      'Protocol scan results',
    ],
    testProcedures: [
      'Test TLS versions',
      'Verify certificate validity',
      'Scan for weak protocols',
    ],
    mappings: { 'SOC2': 'CC6.6', 'NIST': 'SC-8' },
  },
  {
    id: 'PCI-5.1',
    framework: 'PCI_DSS',
    category: 'Malware Protection',
    name: 'Anti-Malware Deployment',
    description: 'Deploy anti-malware mechanisms on all systems commonly affected.',
    requirements: [
      'Anti-malware on all applicable systems',
      'Automatic updates enabled',
      'Periodic scans or real-time protection',
      'Audit logging enabled',
    ],
    evidence: [
      'AV deployment records',
      'Configuration standards',
      'Update logs',
      'Scan reports',
    ],
    testProcedures: [
      'Verify AV coverage',
      'Test update mechanism',
      'Review scan frequency',
    ],
    mappings: { 'SOC2': 'CC6.1', 'NIST': 'SI-3' },
  },
  {
    id: 'PCI-6.4',
    framework: 'PCI_DSS',
    category: 'Secure Development',
    name: 'Change Control Processes',
    description: 'Follow change control processes for all changes to system components.',
    requirements: [
      'Document impact',
      'Management approval',
      'Testing for security impact',
      'Back-out procedures',
    ],
    evidence: [
      'Change management policy',
      'Change records',
      'Testing documentation',
    ],
    testProcedures: [
      'Review change process',
      'Verify approval workflow',
      'Test rollback procedures',
    ],
    mappings: { 'SOC2': 'CC8.1', 'NIST': 'CM-3' },
  },
  {
    id: 'PCI-7.1',
    framework: 'PCI_DSS',
    category: 'Access Control',
    name: 'Restrict Access by Need to Know',
    description: 'Limit access to system components to individuals whose job requires access.',
    requirements: [
      'Access control policy',
      'Role-based access',
      'Documented business need',
      'Automatic access revocation',
    ],
    evidence: [
      'Access policy',
      'RBAC documentation',
      'Access request records',
      'Termination procedures',
    ],
    testProcedures: [
      'Review access policy',
      'Verify RBAC',
      'Test access requests',
      'Verify termination process',
    ],
    mappings: { 'SOC2': 'CC5.1', 'NIST': 'AC-6' },
  },
  {
    id: 'PCI-8.3',
    framework: 'PCI_DSS',
    category: 'Strong Authentication',
    name: 'MFA for CDE Access',
    description: 'Multi-factor authentication for access into the CDE.',
    requirements: [
      'MFA for all CDE access',
      'MFA for remote network access',
      'MFA implementations properly configured',
    ],
    evidence: [
      'MFA configuration',
      'MFA enrollment records',
      'Access logs showing MFA',
    ],
    testProcedures: [
      'Test MFA enforcement',
      'Verify MFA coverage',
      'Review MFA configuration',
    ],
    mappings: { 'SOC2': 'CC6.1', 'NIST': 'IA-2(1)' },
  },
  {
    id: 'PCI-10.1',
    framework: 'PCI_DSS',
    category: 'Logging and Monitoring',
    name: 'Audit Trail for All Access',
    description: 'Implement audit trails linking access to individual users.',
    requirements: [
      'Audit trails enabled',
      'Audit trails link to users',
      'Automated audit trails',
      'Time synchronization',
    ],
    evidence: [
      'Logging configuration',
      'Sample audit logs',
      'NTP configuration',
    ],
    testProcedures: [
      'Verify logging enabled',
      'Review log content',
      'Test time sync',
    ],
    mappings: { 'SOC2': 'CC7.2', 'NIST': 'AU-2' },
  },
  {
    id: 'PCI-11.3',
    framework: 'PCI_DSS',
    category: 'Security Testing',
    name: 'Penetration Testing',
    description: 'Perform internal and external penetration testing regularly.',
    requirements: [
      'Annual penetration testing',
      'Testing after significant changes',
      'Network-layer testing',
      'Application-layer testing',
      'Segmentation testing',
    ],
    evidence: [
      'Penetration test reports',
      'Remediation evidence',
      'Retest results',
    ],
    testProcedures: [
      'Review pentest methodology',
      'Verify scope coverage',
      'Review remediation',
    ],
    mappings: { 'SOC2': 'CC6.1', 'NIST': 'CA-8' },
  },
  {
    id: 'PCI-12.1',
    framework: 'PCI_DSS',
    category: 'Information Security Policy',
    name: 'Security Policy',
    description: 'Establish and maintain a comprehensive information security policy.',
    requirements: [
      'Policy addresses all PCI DSS requirements',
      'Annual policy review',
      'Risk assessment process',
      'Usage policies for critical technologies',
    ],
    evidence: [
      'Security policy',
      'Policy review records',
      'Risk assessment',
      'Acceptable use policies',
    ],
    testProcedures: [
      'Review policy completeness',
      'Verify annual review',
      'Review risk assessment',
    ],
    mappings: { 'SOC2': 'CC2.1', 'NIST': 'PL-1' },
  },
];

// ============================================
// GDPR ARTICLES
// ============================================

export const GDPR_CONTROLS: ComplianceControl[] = [
  {
    id: 'GDPR-5',
    framework: 'GDPR',
    category: 'Principles',
    name: 'Principles of Processing',
    description: 'Personal data processing must follow key principles.',
    requirements: [
      'Lawfulness, fairness, transparency',
      'Purpose limitation',
      'Data minimisation',
      'Accuracy',
      'Storage limitation',
      'Integrity and confidentiality',
      'Accountability',
    ],
    evidence: [
      'Privacy policy',
      'Data processing records',
      'Retention schedules',
      'Security measures documentation',
    ],
    testProcedures: [
      'Review processing activities',
      'Verify purpose documentation',
      'Test data minimisation',
      'Review retention compliance',
    ],
  },
  {
    id: 'GDPR-6',
    framework: 'GDPR',
    category: 'Lawfulness',
    name: 'Lawful Basis for Processing',
    description: 'Processing must have a valid legal basis.',
    requirements: [
      'Documented lawful basis',
      'Consent (where applicable)',
      'Contract necessity',
      'Legal obligation',
      'Vital interests',
      'Public task',
      'Legitimate interests (with balancing test)',
    ],
    evidence: [
      'Records of processing activities',
      'Consent records',
      'Legitimate interest assessments',
    ],
    testProcedures: [
      'Review lawful basis documentation',
      'Verify consent mechanisms',
      'Review LIA documentation',
    ],
  },
  {
    id: 'GDPR-13',
    framework: 'GDPR',
    category: 'Transparency',
    name: 'Information to Data Subjects',
    description: 'Provide specified information when collecting personal data.',
    requirements: [
      'Controller identity and contact',
      'DPO contact details',
      'Processing purposes and lawful basis',
      'Recipients or categories',
      'Transfer intentions',
      'Retention period',
      'Data subject rights',
      'Right to withdraw consent',
      'Right to lodge complaint',
      'Source of data (if not from subject)',
    ],
    evidence: [
      'Privacy notice',
      'Collection forms',
      'Cookie notices',
    ],
    testProcedures: [
      'Review privacy notice completeness',
      'Verify notice accessibility',
      'Test timing of notice provision',
    ],
    mappings: { 'SOC2': 'P1.1' },
  },
  {
    id: 'GDPR-15',
    framework: 'GDPR',
    category: 'Data Subject Rights',
    name: 'Right of Access',
    description: 'Data subjects have the right to access their personal data.',
    requirements: [
      'Confirm processing',
      'Provide copy of data',
      'Provide processing information',
      'Response within one month',
    ],
    evidence: [
      'SAR process documentation',
      'SAR response records',
      'Response time metrics',
    ],
    testProcedures: [
      'Test SAR submission process',
      'Review response completeness',
      'Verify response timing',
    ],
  },
  {
    id: 'GDPR-17',
    framework: 'GDPR',
    category: 'Data Subject Rights',
    name: 'Right to Erasure',
    description: 'Data subjects have the right to have their data deleted.',
    requirements: [
      'Erasure process documented',
      'Criteria for erasure defined',
      'Third-party notification',
      'Exceptions documented',
    ],
    evidence: [
      'Erasure procedures',
      'Erasure request records',
      'Third-party notification records',
    ],
    testProcedures: [
      'Test erasure process',
      'Verify completeness of erasure',
      'Test third-party notification',
    ],
  },
  {
    id: 'GDPR-25',
    framework: 'GDPR',
    category: 'Data Protection by Design',
    name: 'Privacy by Design and Default',
    description: 'Implement appropriate technical and organizational measures.',
    requirements: [
      'Data protection in system design',
      'Default privacy-protective settings',
      'Pseudonymisation where appropriate',
      'Minimisation by default',
    ],
    evidence: [
      'Privacy impact assessments',
      'System design documentation',
      'Default settings configuration',
    ],
    testProcedures: [
      'Review PIA process',
      'Verify default settings',
      'Test privacy features',
    ],
  },
  {
    id: 'GDPR-30',
    framework: 'GDPR',
    category: 'Records',
    name: 'Records of Processing Activities',
    description: 'Maintain records of processing activities.',
    requirements: [
      'Name and contact of controller',
      'Purposes of processing',
      'Categories of data subjects and data',
      'Categories of recipients',
      'Transfers to third countries',
      'Retention periods',
      'Security measures description',
    ],
    evidence: [
      'ROPA (Records of Processing Activities)',
      'Data inventory',
      'System inventory',
    ],
    testProcedures: [
      'Review ROPA completeness',
      'Verify ROPA accuracy',
      'Test ROPA maintenance process',
    ],
  },
  {
    id: 'GDPR-32',
    framework: 'GDPR',
    category: 'Security',
    name: 'Security of Processing',
    description: 'Implement appropriate security measures.',
    requirements: [
      'Pseudonymisation and encryption',
      'Confidentiality, integrity, availability',
      'Restore availability after incident',
      'Regular testing of measures',
    ],
    evidence: [
      'Security policy',
      'Encryption implementation',
      'BCP/DR plans',
      'Security testing records',
    ],
    testProcedures: [
      'Review security measures',
      'Test encryption',
      'Review DR testing',
      'Verify security testing',
    ],
    mappings: { 'SOC2': 'CC6.1', 'ISO27001': 'A.12' },
  },
  {
    id: 'GDPR-33',
    framework: 'GDPR',
    category: 'Breach Notification',
    name: 'Breach Notification to Authority',
    description: 'Notify supervisory authority of breaches within 72 hours.',
    requirements: [
      'Breach detection capability',
      'Notification within 72 hours',
      'Documentation of all breaches',
      'Risk assessment process',
    ],
    evidence: [
      'Breach response procedures',
      'Breach register',
      'Notification records',
    ],
    testProcedures: [
      'Review breach procedures',
      'Test breach detection',
      'Verify notification timing',
    ],
    mappings: { 'SOC2': 'CC7.1', 'HIPAA': '164.308(a)(6)' },
  },
  {
    id: 'GDPR-35',
    framework: 'GDPR',
    category: 'Impact Assessment',
    name: 'Data Protection Impact Assessment',
    description: 'Conduct DPIA for high-risk processing.',
    requirements: [
      'DPIA for high-risk processing',
      'Systematic description of processing',
      'Assessment of necessity and proportionality',
      'Assessment of risks',
      'Measures to address risks',
    ],
    evidence: [
      'DPIA procedure',
      'Completed DPIAs',
      'Risk mitigation documentation',
    ],
    testProcedures: [
      'Review DPIA triggers',
      'Verify DPIA completeness',
      'Review risk treatment',
    ],
  },
  {
    id: 'GDPR-44',
    framework: 'GDPR',
    category: 'International Transfers',
    name: 'Transfer Mechanisms',
    description: 'Use appropriate mechanisms for international data transfers.',
    requirements: [
      'Adequacy decisions',
      'Standard contractual clauses',
      'Binding corporate rules',
      'Transfer impact assessments',
    ],
    evidence: [
      'Transfer documentation',
      'SCCs executed',
      'TIA documentation',
    ],
    testProcedures: [
      'Identify all transfers',
      'Verify transfer mechanisms',
      'Review TIA completeness',
    ],
  },
];

// ============================================
// COMPLIANCE AUDITOR CLASS
// ============================================

export class ComplianceAuditor {
  private findings: Finding[] = [];

  // Get controls for a framework
  getControls(framework: ComplianceFramework): ComplianceControl[] {
    switch (framework) {
      case 'SOC2':
        return SOC2_CONTROLS;
      case 'HIPAA':
        return HIPAA_CONTROLS;
      case 'PCI_DSS':
        return PCI_DSS_CONTROLS;
      case 'GDPR':
        return GDPR_CONTROLS;
      default:
        return [];
    }
  }

  // Generate compliance checklist
  generateChecklist(framework: ComplianceFramework): string {
    const controls = this.getControls(framework);
    let checklist = `# ${framework} Compliance Checklist\n\n`;
    checklist += `Generated: ${new Date().toISOString()}\n\n`;
    checklist += `---\n\n`;

    const categories = [...new Set(controls.map(c => c.category))];

    for (const category of categories) {
      checklist += `## ${category}\n\n`;
      const categoryControls = controls.filter(c => c.category === category);

      for (const control of categoryControls) {
        checklist += `### ${control.id}: ${control.name}\n\n`;
        checklist += `${control.description}\n\n`;

        checklist += `**Requirements:**\n`;
        for (const req of control.requirements) {
          checklist += `- [ ] ${req}\n`;
        }

        checklist += `\n**Evidence Required:**\n`;
        for (const ev of control.evidence) {
          checklist += `- [ ] ${ev}\n`;
        }

        checklist += `\n**Test Procedures:**\n`;
        for (const proc of control.testProcedures) {
          checklist += `- [ ] ${proc}\n`;
        }

        if (control.mappings) {
          checklist += `\n**Framework Mappings:**\n`;
          for (const [fw, id] of Object.entries(control.mappings)) {
            checklist += `- ${fw}: ${id}\n`;
          }
        }

        checklist += `\n---\n\n`;
      }
    }

    return checklist;
  }

  // Assess compliance
  assessCompliance(framework: ComplianceFramework, context: string): Finding[] {
    const controls = this.getControls(framework);
    const findings: Finding[] = [];

    for (const control of controls) {
      findings.push({
        id: `${framework}-${control.id}-${randomUUID().slice(0, 4)}`,
        domain: 'COMPLIANCE',
        severity: 'INFO',
        status: 'REVIEW_REQUIRED',
        title: `${framework} ${control.id}: ${control.name}`,
        description: `**Category:** ${control.category}\n\n${control.description}\n\n**Requirements:**\n${control.requirements.map(r => `- ${r}`).join('\n')}\n\n**Evidence Required:**\n${control.evidence.map(e => `- ${e}`).join('\n')}`,
        evidence: [{
          type: 'DATA',
          description: `${framework} control assessment`,
          source: context,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: `Complete test procedures:\n${control.testProcedures.map(t => `- ${t}`).join('\n')}`,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Map controls between frameworks
  mapControls(sourceFramework: ComplianceFramework, targetFramework: ComplianceFramework): Record<string, string> {
    const sourceControls = this.getControls(sourceFramework);
    const mapping: Record<string, string> = {};

    for (const control of sourceControls) {
      if (control.mappings && control.mappings[targetFramework]) {
        mapping[control.id] = control.mappings[targetFramework];
      }
    }

    return mapping;
  }

  // Calculate compliance score
  calculateComplianceScore(
    framework: ComplianceFramework,
    completedControls: string[]
  ): { score: number; total: number; percentage: number; missing: string[] } {
    const controls = this.getControls(framework);
    const total = controls.length;
    const completed = completedControls.filter(c => controls.some(ctrl => ctrl.id === c)).length;
    const percentage = (completed / total) * 100;
    const missing = controls.filter(c => !completedControls.includes(c.id)).map(c => c.id);

    return {
      score: completed,
      total,
      percentage: Math.round(percentage * 100) / 100,
      missing,
    };
  }

  // Get overlapping requirements
  getFrameworkOverlap(frameworks: ComplianceFramework[]): ComplianceControl[] {
    if (frameworks.length < 2) return [];

    const allControls = frameworks.flatMap(f => this.getControls(f));
    const overlapping: ComplianceControl[] = [];

    for (const control of allControls) {
      if (control.mappings) {
        const mappedFrameworks = Object.keys(control.mappings);
        if (frameworks.some(f => mappedFrameworks.includes(f))) {
          overlapping.push(control);
        }
      }
    }

    return overlapping;
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
export const complianceAuditor = new ComplianceAuditor();
