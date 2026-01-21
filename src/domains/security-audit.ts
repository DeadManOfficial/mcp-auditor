// Security/Penetration Testing Audit Module
// Covers: OWASP, PTES, NIST, network security, cloud security, zero trust, MITRE ATT&CK

import { Finding, Evidence, Severity, AuditDomain } from '../core/types.js';
import { randomUUID } from 'crypto';

// ============================================
// MITRE ATT&CK TACTICS
// ============================================

export type MitreTactic =
  | 'RECONNAISSANCE'
  | 'RESOURCE_DEVELOPMENT'
  | 'INITIAL_ACCESS'
  | 'EXECUTION'
  | 'PERSISTENCE'
  | 'PRIVILEGE_ESCALATION'
  | 'DEFENSE_EVASION'
  | 'CREDENTIAL_ACCESS'
  | 'DISCOVERY'
  | 'LATERAL_MOVEMENT'
  | 'COLLECTION'
  | 'COMMAND_AND_CONTROL'
  | 'EXFILTRATION'
  | 'IMPACT';

export interface MitreMapping {
  tactic: MitreTactic;
  techniqueId: string;
  techniqueName: string;
  description: string;
  detection: string;
  mitigation: string;
}

// Common MITRE ATT&CK Techniques for Detection
export const MITRE_TECHNIQUES: MitreMapping[] = [
  // Credential Access
  {
    tactic: 'CREDENTIAL_ACCESS',
    techniqueId: 'T1558.001',
    techniqueName: 'Golden Ticket',
    description: 'Adversaries forge Kerberos TGTs to access any resource in an Active Directory domain.',
    detection: 'Monitor for TGS requests (Event 4769) without preceding TGT requests (Event 4768). Check for tickets with abnormally long lifetimes (>10 hours).',
    mitigation: 'Reset KRBTGT password twice. Monitor privileged account usage. Implement Privileged Access Workstations.',
  },
  {
    tactic: 'CREDENTIAL_ACCESS',
    techniqueId: 'T1558.003',
    techniqueName: 'Kerberoasting',
    description: 'Adversaries request service tickets for accounts with SPNs to offline crack passwords.',
    detection: 'Monitor for unusual volume of TGS-REQ requests (Event 4769) with RC4 encryption (0x17).',
    mitigation: 'Use strong passwords for service accounts. Prefer gMSA accounts. Monitor for SPN enumeration.',
  },
  {
    tactic: 'CREDENTIAL_ACCESS',
    techniqueId: 'T1003.001',
    techniqueName: 'LSASS Memory',
    description: 'Adversaries dump credentials from LSASS process memory using tools like Mimikatz.',
    detection: 'Monitor for processes accessing lsass.exe. Enable Credential Guard. Alert on LSASS memory read operations.',
    mitigation: 'Enable Credential Guard. Restrict debug privileges. Use Protected Users group.',
  },

  // Lateral Movement
  {
    tactic: 'LATERAL_MOVEMENT',
    techniqueId: 'T1021.002',
    techniqueName: 'SMB/Windows Admin Shares',
    description: 'Adversaries use admin shares (ADMIN$, C$, IPC$) to move laterally.',
    detection: 'Monitor Event ID 5140 (share access) for administrative shares. Alert on unusual access patterns.',
    mitigation: 'Disable administrative shares if not needed. Implement network segmentation. Use host-based firewalls.',
  },
  {
    tactic: 'LATERAL_MOVEMENT',
    techniqueId: 'T1021.001',
    techniqueName: 'Remote Desktop Protocol',
    description: 'Adversaries use RDP to access systems remotely.',
    detection: 'Monitor Event ID 4624 Type 10 (RemoteInteractive logons). Alert on unusual RDP sessions.',
    mitigation: 'Require MFA for RDP. Use RDP Gateway. Restrict RDP access to specific IPs.',
  },
  {
    tactic: 'LATERAL_MOVEMENT',
    techniqueId: 'T1570',
    techniqueName: 'Lateral Tool Transfer',
    description: 'Adversaries transfer tools between systems using SMB, RDP, or other protocols.',
    detection: 'Monitor file transfers to admin shares. Alert on executable transfers.',
    mitigation: 'Implement application whitelisting. Monitor for PsExec, WMI, PowerShell Remoting.',
  },

  // Persistence
  {
    tactic: 'PERSISTENCE',
    techniqueId: 'T1053.005',
    techniqueName: 'Scheduled Task',
    description: 'Adversaries create scheduled tasks for persistence.',
    detection: 'Monitor Event ID 4698 (task created). Alert on tasks created by non-admin users.',
    mitigation: 'Restrict task scheduler permissions. Monitor for unusual scheduled tasks.',
  },
  {
    tactic: 'PERSISTENCE',
    techniqueId: 'T1547.001',
    techniqueName: 'Registry Run Keys',
    description: 'Adversaries add entries to Run/RunOnce registry keys for persistence.',
    detection: 'Monitor registry modifications to HKLM/HKCU Run keys.',
    mitigation: 'Restrict registry permissions. Monitor for unexpected registry changes.',
  },

  // Defense Evasion
  {
    tactic: 'DEFENSE_EVASION',
    techniqueId: 'T1070.001',
    techniqueName: 'Clear Windows Event Logs',
    description: 'Adversaries clear event logs to remove evidence.',
    detection: 'Monitor Event ID 1102 (audit log cleared). Alert on any log clearing.',
    mitigation: 'Forward logs to SIEM in real-time. Restrict log clearing permissions.',
  },
  {
    tactic: 'DEFENSE_EVASION',
    techniqueId: 'T1562.001',
    techniqueName: 'Disable or Modify Tools',
    description: 'Adversaries disable security tools to evade detection.',
    detection: 'Monitor for security tool service stops. Alert on EDR/AV tampering.',
    mitigation: 'Implement tamper protection. Monitor security tool health.',
  },

  // Execution
  {
    tactic: 'EXECUTION',
    techniqueId: 'T1059.001',
    techniqueName: 'PowerShell',
    description: 'Adversaries use PowerShell for execution and post-exploitation.',
    detection: 'Enable PowerShell logging (ScriptBlock, Module, Transcription). Monitor for encoded commands.',
    mitigation: 'Enable Constrained Language Mode. Use AppLocker to restrict PowerShell.',
  },
  {
    tactic: 'EXECUTION',
    techniqueId: 'T1047',
    techniqueName: 'Windows Management Instrumentation',
    description: 'Adversaries use WMI for execution and lateral movement.',
    detection: 'Monitor WMI subscription events. Alert on WMI process creation.',
    mitigation: 'Restrict WMI permissions. Monitor for WMI-based attacks.',
  },
];

// ============================================
// OWASP TOP 10 (2021)
// ============================================

export interface OwaspCategory {
  id: string;
  name: string;
  description: string;
  checkpoints: string[];
  testProcedures: string[];
}

export const OWASP_TOP_10: OwaspCategory[] = [
  {
    id: 'A01:2021',
    name: 'Broken Access Control',
    description: 'Failures allowing users to act outside their intended permissions.',
    checkpoints: [
      'Verify principle of least privilege is applied',
      'Check that default deny is in place for all resources',
      'Verify JWT tokens are validated properly',
      'Test for IDOR vulnerabilities',
      'Check CORS configuration',
      'Verify rate limiting on sensitive endpoints',
      'Test for privilege escalation paths',
    ],
    testProcedures: [
      'Attempt to access resources as unauthenticated user',
      'Modify resource IDs in requests (IDOR test)',
      'Test horizontal privilege escalation (user A accessing user B data)',
      'Test vertical privilege escalation (user to admin)',
      'Verify CORS allows only trusted origins',
      'Check JWT signature validation',
    ],
  },
  {
    id: 'A02:2021',
    name: 'Cryptographic Failures',
    description: 'Failures related to cryptography leading to sensitive data exposure.',
    checkpoints: [
      'Verify TLS 1.2+ is enforced',
      'Check for weak cipher suites',
      'Verify sensitive data is encrypted at rest',
      'Check password hashing algorithm (bcrypt/argon2)',
      'Verify encryption keys are properly managed',
      'Check for hardcoded secrets',
    ],
    testProcedures: [
      'Run SSL Labs test against endpoints',
      'Check for HTTP (non-HTTPS) endpoints',
      'Verify password storage uses appropriate hashing',
      'Test for sensitive data in logs',
      'Check for PII exposure in responses',
    ],
  },
  {
    id: 'A03:2021',
    name: 'Injection',
    description: 'Injection flaws such as SQL, NoSQL, OS, LDAP injection.',
    checkpoints: [
      'Verify parameterized queries are used',
      'Check input validation on all user inputs',
      'Verify ORM is properly configured',
      'Check for command injection points',
      'Verify LDAP queries are properly escaped',
    ],
    testProcedures: [
      'Test SQL injection on all input fields',
      'Test NoSQL injection (MongoDB $where, $regex)',
      'Test OS command injection',
      'Test LDAP injection',
      'Test XPath injection',
      'Use sqlmap for comprehensive SQL injection testing',
    ],
  },
  {
    id: 'A04:2021',
    name: 'Insecure Design',
    description: 'Missing or ineffective security controls in the design phase.',
    checkpoints: [
      'Review threat model documentation',
      'Verify security requirements are defined',
      'Check for defense in depth implementation',
      'Review secure SDLC practices',
      'Verify security testing is in CI/CD',
    ],
    testProcedures: [
      'Review architecture diagrams for security controls',
      'Assess attack surface',
      'Review business logic for abuse cases',
      'Evaluate fail-secure mechanisms',
    ],
  },
  {
    id: 'A05:2021',
    name: 'Security Misconfiguration',
    description: 'Missing or incorrect security hardening, default credentials.',
    checkpoints: [
      'Verify default credentials are changed',
      'Check for unnecessary features/services',
      'Verify security headers are set',
      'Check error handling (no stack traces)',
      'Verify cloud storage permissions',
      'Check for directory listing',
    ],
    testProcedures: [
      'Test for default credentials',
      'Check HTTP security headers (CSP, HSTS, X-Frame-Options)',
      'Test for information disclosure in errors',
      'Check for open S3 buckets / Azure blobs',
      'Verify unnecessary ports are closed',
    ],
  },
  {
    id: 'A06:2021',
    name: 'Vulnerable and Outdated Components',
    description: 'Using components with known vulnerabilities.',
    checkpoints: [
      'Inventory all components and versions',
      'Check against CVE databases',
      'Verify dependency update process exists',
      'Check for components no longer maintained',
    ],
    testProcedures: [
      'Run dependency vulnerability scanner (npm audit, Snyk)',
      'Check for known CVEs in components',
      'Verify SBOM is maintained',
      'Test for exploitation of known vulnerabilities',
    ],
  },
  {
    id: 'A07:2021',
    name: 'Identification and Authentication Failures',
    description: 'Broken authentication, session management, or identity verification.',
    checkpoints: [
      'Verify MFA is available/required',
      'Check password policy strength',
      'Verify session management is secure',
      'Check for brute force protections',
      'Verify secure password recovery',
    ],
    testProcedures: [
      'Test for credential stuffing vulnerabilities',
      'Test session fixation',
      'Test for session hijacking',
      'Verify password reset token security',
      'Test account lockout mechanisms',
    ],
  },
  {
    id: 'A08:2021',
    name: 'Software and Data Integrity Failures',
    description: 'Failures related to code and infrastructure integrity verification.',
    checkpoints: [
      'Verify CI/CD pipeline security',
      'Check for unsigned code/packages',
      'Verify auto-update mechanisms are secure',
      'Check deserialization handling',
    ],
    testProcedures: [
      'Review CI/CD security controls',
      'Test for insecure deserialization',
      'Check for SRI on external resources',
      'Verify code signing is enforced',
    ],
  },
  {
    id: 'A09:2021',
    name: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging, detection, monitoring, and response.',
    checkpoints: [
      'Verify audit logging is enabled',
      'Check log storage and protection',
      'Verify alerting for security events',
      'Check incident response procedures',
    ],
    testProcedures: [
      'Verify failed logins are logged',
      'Check that access to sensitive data is logged',
      'Test alerting mechanisms',
      'Verify logs cannot be tampered with',
    ],
  },
  {
    id: 'A10:2021',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Application fetches remote resources without validating user-supplied URLs.',
    checkpoints: [
      'Verify URL validation on user inputs',
      'Check for internal IP blocking',
      'Verify DNS rebinding protections',
      'Check cloud metadata endpoint blocking',
    ],
    testProcedures: [
      'Test for SSRF to internal services',
      'Test for cloud metadata access (169.254.169.254)',
      'Test for protocol smuggling',
      'Test DNS rebinding attacks',
    ],
  },
];

// ============================================
// NETWORK SECURITY CHECKS
// ============================================

export interface NetworkCheck {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  description: string;
  evidence: string;
  remediation: string;
}

export const NETWORK_SECURITY_CHECKS: NetworkCheck[] = [
  // TLS/SSL
  {
    id: 'NET-001',
    name: 'TLS Version',
    category: 'ENCRYPTION',
    severity: 'HIGH',
    description: 'TLS 1.0 and 1.1 are deprecated and vulnerable.',
    evidence: 'Check supported TLS versions with openssl s_client or SSL Labs.',
    remediation: 'Disable TLS 1.0 and 1.1. Require TLS 1.2 minimum, prefer TLS 1.3.',
  },
  {
    id: 'NET-002',
    name: 'Weak Cipher Suites',
    category: 'ENCRYPTION',
    severity: 'HIGH',
    description: 'Weak ciphers (RC4, DES, export ciphers) allow cryptographic attacks.',
    evidence: 'Enumerate ciphers with nmap --script ssl-enum-ciphers.',
    remediation: 'Configure server to use only strong cipher suites (AES-GCM, ChaCha20-Poly1305).',
  },
  {
    id: 'NET-003',
    name: 'Certificate Validation',
    category: 'ENCRYPTION',
    severity: 'CRITICAL',
    description: 'Certificate issues (expired, self-signed, wrong hostname) enable MITM.',
    evidence: 'Check certificate chain and validity with openssl.',
    remediation: 'Use valid certificates from trusted CAs. Implement certificate pinning for mobile apps.',
  },

  // Firewall/Network Segmentation
  {
    id: 'NET-004',
    name: 'Open Ports',
    category: 'ACCESS_CONTROL',
    severity: 'MEDIUM',
    description: 'Unnecessary open ports increase attack surface.',
    evidence: 'Scan with nmap -sV -sC to enumerate open ports and services.',
    remediation: 'Close unnecessary ports. Implement least privilege network access.',
  },
  {
    id: 'NET-005',
    name: 'Network Segmentation',
    category: 'ACCESS_CONTROL',
    severity: 'HIGH',
    description: 'Flat network allows lateral movement after initial compromise.',
    evidence: 'Review network diagrams and firewall rules.',
    remediation: 'Implement network segmentation. Isolate sensitive systems. Use VLANs and firewalls.',
  },
  {
    id: 'NET-006',
    name: 'Administrative Interface Exposure',
    category: 'ACCESS_CONTROL',
    severity: 'CRITICAL',
    description: 'Admin interfaces exposed to internet are prime targets.',
    evidence: 'Check for accessible admin panels on external IPs.',
    remediation: 'Restrict admin access to VPN or internal networks only.',
  },

  // DNS Security
  {
    id: 'NET-007',
    name: 'DNS Zone Transfer',
    category: 'INFORMATION_DISCLOSURE',
    severity: 'MEDIUM',
    description: 'Unrestricted zone transfers expose internal DNS records.',
    evidence: 'Test with dig axfr @nameserver domain.com.',
    remediation: 'Restrict zone transfers to authorized secondary DNS servers.',
  },
  {
    id: 'NET-008',
    name: 'DNSSEC',
    category: 'INTEGRITY',
    severity: 'LOW',
    description: 'Without DNSSEC, DNS responses can be spoofed.',
    evidence: 'Check DNSSEC deployment with dig +dnssec.',
    remediation: 'Implement DNSSEC for domain integrity verification.',
  },

  // Email Security
  {
    id: 'NET-009',
    name: 'SPF Record',
    category: 'EMAIL_SECURITY',
    severity: 'MEDIUM',
    description: 'Missing or weak SPF allows email spoofing.',
    evidence: 'Query SPF record with dig txt domain.com.',
    remediation: 'Implement strict SPF record (-all). Include all legitimate mail sources.',
  },
  {
    id: 'NET-010',
    name: 'DMARC Policy',
    category: 'EMAIL_SECURITY',
    severity: 'MEDIUM',
    description: 'Missing or weak DMARC allows phishing with your domain.',
    evidence: 'Query DMARC record with dig txt _dmarc.domain.com.',
    remediation: 'Implement DMARC with p=reject policy. Monitor reports.',
  },
  {
    id: 'NET-011',
    name: 'DKIM Signing',
    category: 'EMAIL_SECURITY',
    severity: 'MEDIUM',
    description: 'Without DKIM, email integrity cannot be verified.',
    evidence: 'Check for DKIM records and email headers.',
    remediation: 'Implement DKIM signing for all outbound mail.',
  },
];

// ============================================
// CLOUD SECURITY CHECKS
// ============================================

export interface CloudSecurityCheck {
  id: string;
  name: string;
  provider: 'AWS' | 'AZURE' | 'GCP' | 'ALL';
  category: string;
  severity: Severity;
  description: string;
  checkCommand?: string;
  remediation: string;
}

export const CLOUD_SECURITY_CHECKS: CloudSecurityCheck[] = [
  // AWS
  {
    id: 'AWS-001',
    name: 'S3 Public Access',
    provider: 'AWS',
    category: 'ACCESS_CONTROL',
    severity: 'CRITICAL',
    description: 'S3 buckets with public access can expose sensitive data.',
    checkCommand: 'aws s3api get-bucket-acl --bucket BUCKET_NAME',
    remediation: 'Enable S3 Block Public Access at account level. Review bucket policies.',
  },
  {
    id: 'AWS-002',
    name: 'IAM Root User Usage',
    provider: 'AWS',
    category: 'ACCESS_CONTROL',
    severity: 'HIGH',
    description: 'Root user access should not be used for daily operations.',
    checkCommand: 'aws iam get-credential-report',
    remediation: 'Enable MFA on root. Use IAM users with least privilege. Monitor root usage.',
  },
  {
    id: 'AWS-003',
    name: 'CloudTrail Enabled',
    provider: 'AWS',
    category: 'LOGGING',
    severity: 'HIGH',
    description: 'CloudTrail provides audit logging for AWS API calls.',
    checkCommand: 'aws cloudtrail describe-trails',
    remediation: 'Enable CloudTrail in all regions. Enable log file validation.',
  },
  {
    id: 'AWS-004',
    name: 'Security Groups',
    provider: 'AWS',
    category: 'ACCESS_CONTROL',
    severity: 'HIGH',
    description: 'Overly permissive security groups (0.0.0.0/0) expose resources.',
    checkCommand: 'aws ec2 describe-security-groups',
    remediation: 'Review inbound rules. Restrict to specific IPs. Use VPC endpoints.',
  },
  {
    id: 'AWS-005',
    name: 'RDS Encryption',
    provider: 'AWS',
    category: 'ENCRYPTION',
    severity: 'HIGH',
    description: 'Unencrypted RDS instances expose data at rest.',
    checkCommand: 'aws rds describe-db-instances',
    remediation: 'Enable encryption for RDS instances. Use KMS customer managed keys.',
  },
  {
    id: 'AWS-006',
    name: 'IMDSv2 Enforcement',
    provider: 'AWS',
    category: 'ACCESS_CONTROL',
    severity: 'MEDIUM',
    description: 'IMDSv1 is vulnerable to SSRF attacks.',
    checkCommand: 'aws ec2 describe-instances --query "Reservations[].Instances[].MetadataOptions"',
    remediation: 'Enforce IMDSv2 on all EC2 instances. Block IMDSv1.',
  },

  // Azure
  {
    id: 'AZ-001',
    name: 'Storage Account Public Access',
    provider: 'AZURE',
    category: 'ACCESS_CONTROL',
    severity: 'CRITICAL',
    description: 'Public blob storage can expose sensitive data.',
    checkCommand: 'az storage account list --query "[].{name:name,publicAccess:allowBlobPublicAccess}"',
    remediation: 'Disable public blob access. Use SAS tokens with short expiry.',
  },
  {
    id: 'AZ-002',
    name: 'Azure AD MFA',
    provider: 'AZURE',
    category: 'AUTHENTICATION',
    severity: 'HIGH',
    description: 'Accounts without MFA are vulnerable to credential attacks.',
    checkCommand: 'az ad user list --query "[].{UPN:userPrincipalName,MFA:strongAuthenticationMethods}"',
    remediation: 'Enable MFA for all users. Use Conditional Access policies.',
  },
  {
    id: 'AZ-003',
    name: 'Network Security Groups',
    provider: 'AZURE',
    category: 'ACCESS_CONTROL',
    severity: 'HIGH',
    description: 'Overly permissive NSGs expose resources.',
    checkCommand: 'az network nsg list',
    remediation: 'Review NSG rules. Implement least privilege. Use ASGs.',
  },

  // GCP
  {
    id: 'GCP-001',
    name: 'Cloud Storage Public Access',
    provider: 'GCP',
    category: 'ACCESS_CONTROL',
    severity: 'CRITICAL',
    description: 'Public Cloud Storage buckets can expose data.',
    checkCommand: 'gsutil iam get gs://BUCKET_NAME',
    remediation: 'Remove allUsers and allAuthenticatedUsers. Use IAM conditions.',
  },
  {
    id: 'GCP-002',
    name: 'Service Account Keys',
    provider: 'GCP',
    category: 'ACCESS_CONTROL',
    severity: 'HIGH',
    description: 'User-managed service account keys are security risks.',
    checkCommand: 'gcloud iam service-accounts keys list --iam-account=SA_EMAIL',
    remediation: 'Use Workload Identity. Rotate keys regularly. Monitor key usage.',
  },
  {
    id: 'GCP-003',
    name: 'VPC Firewall Rules',
    provider: 'GCP',
    category: 'ACCESS_CONTROL',
    severity: 'HIGH',
    description: 'Overly permissive firewall rules expose resources.',
    checkCommand: 'gcloud compute firewall-rules list',
    remediation: 'Review rules allowing 0.0.0.0/0. Implement hierarchical firewall policies.',
  },

  // All Clouds
  {
    id: 'CLOUD-001',
    name: 'Encryption at Rest',
    provider: 'ALL',
    category: 'ENCRYPTION',
    severity: 'HIGH',
    description: 'Data should be encrypted at rest using customer-managed keys.',
    remediation: 'Enable encryption for all storage. Use customer-managed KMS keys.',
  },
  {
    id: 'CLOUD-002',
    name: 'Logging Enabled',
    provider: 'ALL',
    category: 'LOGGING',
    severity: 'HIGH',
    description: 'Comprehensive logging is essential for security monitoring.',
    remediation: 'Enable all audit logging. Forward to SIEM. Set retention policies.',
  },
  {
    id: 'CLOUD-003',
    name: 'MFA Enforcement',
    provider: 'ALL',
    category: 'AUTHENTICATION',
    severity: 'CRITICAL',
    description: 'All cloud access should require MFA.',
    remediation: 'Enforce MFA for all users. Use hardware tokens for privileged access.',
  },
];

// ============================================
// ZERO TRUST VALIDATION
// ============================================

export interface ZeroTrustControl {
  id: string;
  pillar: 'IDENTITY' | 'DEVICE' | 'NETWORK' | 'APPLICATION' | 'DATA';
  name: string;
  maturityLevel: 'TRADITIONAL' | 'ADVANCED' | 'OPTIMAL';
  description: string;
  checkpoints: string[];
  evidence: string[];
}

export const ZERO_TRUST_CONTROLS: ZeroTrustControl[] = [
  // Identity Pillar
  {
    id: 'ZT-ID-001',
    pillar: 'IDENTITY',
    name: 'Phishing-Resistant MFA',
    maturityLevel: 'OPTIMAL',
    description: 'All access requires phishing-resistant authentication.',
    checkpoints: [
      'FIDO2/WebAuthn implemented for all users',
      'SMS and email OTP deprecated',
      'Passwordless authentication available',
      'MFA bypass is not possible',
    ],
    evidence: [
      'Authentication policy documentation',
      'MFA enrollment statistics',
      'Phishing simulation results',
    ],
  },
  {
    id: 'ZT-ID-002',
    pillar: 'IDENTITY',
    name: 'Continuous Validation',
    maturityLevel: 'ADVANCED',
    description: 'Identity is continuously validated throughout session.',
    checkpoints: [
      'Session risk is continuously evaluated',
      'Step-up authentication for sensitive actions',
      'Behavioral analytics implemented',
      'Session timeout policies enforced',
    ],
    evidence: [
      'Conditional access policies',
      'UEBA tool configuration',
      'Session management logs',
    ],
  },

  // Device Pillar
  {
    id: 'ZT-DEV-001',
    pillar: 'DEVICE',
    name: 'Device Compliance',
    maturityLevel: 'ADVANCED',
    description: 'Only compliant devices can access resources.',
    checkpoints: [
      'MDM enrollment required',
      'Device health attestation enabled',
      'Encryption verified',
      'Patch compliance checked',
      'EDR agent running',
    ],
    evidence: [
      'MDM compliance reports',
      'Device inventory',
      'Patch management logs',
    ],
  },
  {
    id: 'ZT-DEV-002',
    pillar: 'DEVICE',
    name: 'Real-Time Risk Assessment',
    maturityLevel: 'OPTIMAL',
    description: 'Device risk is assessed in real-time for every access.',
    checkpoints: [
      'Real-time threat detection on devices',
      'Dynamic access based on device risk',
      'Compromised device isolation',
    ],
    evidence: [
      'EDR integration with IAM',
      'Dynamic policy enforcement logs',
    ],
  },

  // Network Pillar
  {
    id: 'ZT-NET-001',
    pillar: 'NETWORK',
    name: 'Micro-Segmentation',
    maturityLevel: 'ADVANCED',
    description: 'Network is segmented at the workload level.',
    checkpoints: [
      'Application-level segmentation implemented',
      'East-west traffic inspected',
      'Default deny between segments',
      'Software-defined perimeter in place',
    ],
    evidence: [
      'Network segmentation diagrams',
      'Firewall rule analysis',
      'Traffic flow logs',
    ],
  },
  {
    id: 'ZT-NET-002',
    pillar: 'NETWORK',
    name: 'Encrypted Traffic',
    maturityLevel: 'ADVANCED',
    description: 'All network traffic is encrypted.',
    checkpoints: [
      'TLS 1.3 for external traffic',
      'mTLS for service-to-service',
      'Encrypted DNS (DoH/DoT)',
      'VPN for remote access',
    ],
    evidence: [
      'TLS configuration audit',
      'Network traffic analysis',
    ],
  },

  // Application Pillar
  {
    id: 'ZT-APP-001',
    pillar: 'APPLICATION',
    name: 'Application Access Control',
    maturityLevel: 'ADVANCED',
    description: 'Access to applications is strictly controlled.',
    checkpoints: [
      'Just-in-time access implemented',
      'Session-based access (not VPN-based)',
      'API authentication enforced',
      'RBAC/ABAC implemented',
    ],
    evidence: [
      'Access control policies',
      'API gateway configuration',
      'RBAC matrix',
    ],
  },

  // Data Pillar
  {
    id: 'ZT-DATA-001',
    pillar: 'DATA',
    name: 'Data Classification and Protection',
    maturityLevel: 'ADVANCED',
    description: 'Data is classified and protected based on sensitivity.',
    checkpoints: [
      'Data classification scheme implemented',
      'DLP policies enforced',
      'Encryption based on classification',
      'Data access logging enabled',
    ],
    evidence: [
      'Data classification policy',
      'DLP incident reports',
      'Encryption audit',
    ],
  },
];

// ============================================
// SECURITY AUDITOR CLASS
// ============================================

export class SecurityAuditor {
  private findings: Finding[] = [];

  // Run OWASP assessment
  async assessOwasp(targetInfo: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const category of OWASP_TOP_10) {
      findings.push({
        id: `OWASP-${category.id}-${randomUUID().slice(0, 4)}`,
        domain: 'SECURITY',
        severity: 'INFO',
        status: 'REVIEW_REQUIRED',
        title: `OWASP ${category.id}: ${category.name}`,
        description: `${category.description}\n\n**Test Checkpoints:**\n${category.checkpoints.map(c => `- ${c}`).join('\n')}\n\n**Test Procedures:**\n${category.testProcedures.map(p => `- ${p}`).join('\n')}`,
        evidence: [{
          type: 'DATA',
          description: 'OWASP Testing Guide Reference',
          source: targetInfo,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: `Complete all test procedures for ${category.id}. Document evidence of controls or identified vulnerabilities.`,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Assess network security
  assessNetworkSecurity(networkInfo: Record<string, unknown>): Finding[] {
    const findings: Finding[] = [];

    for (const check of NETWORK_SECURITY_CHECKS) {
      findings.push({
        id: `NET-${check.id}-${randomUUID().slice(0, 4)}`,
        domain: 'SECURITY',
        severity: check.severity,
        status: 'REVIEW_REQUIRED',
        title: `Network Check: ${check.name}`,
        description: `**Category:** ${check.category}\n\n${check.description}\n\n**Evidence Collection:**\n${check.evidence}`,
        evidence: [{
          type: 'DATA',
          description: 'Network security check',
          content: JSON.stringify(networkInfo, null, 2),
          source: 'Network Assessment',
          collectedAt: new Date().toISOString(),
        }],
        recommendation: check.remediation,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Assess cloud security
  assessCloudSecurity(provider: 'AWS' | 'AZURE' | 'GCP' | 'ALL'): Finding[] {
    const findings: Finding[] = [];
    const checks = provider === 'ALL'
      ? CLOUD_SECURITY_CHECKS
      : CLOUD_SECURITY_CHECKS.filter(c => c.provider === provider || c.provider === 'ALL');

    for (const check of checks) {
      findings.push({
        id: `CLOUD-${check.id}-${randomUUID().slice(0, 4)}`,
        domain: 'SECURITY',
        severity: check.severity,
        status: 'REVIEW_REQUIRED',
        title: `Cloud Security: ${check.name} (${check.provider})`,
        description: `**Category:** ${check.category}\n\n${check.description}${check.checkCommand ? `\n\n**Check Command:**\n\`\`\`\n${check.checkCommand}\n\`\`\`` : ''}`,
        evidence: [{
          type: 'CONFIGURATION',
          description: `${check.provider} security configuration`,
          source: `Cloud Assessment - ${check.provider}`,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: check.remediation,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Assess Zero Trust maturity
  assessZeroTrust(): Finding[] {
    const findings: Finding[] = [];

    for (const control of ZERO_TRUST_CONTROLS) {
      findings.push({
        id: `ZT-${control.id}-${randomUUID().slice(0, 4)}`,
        domain: 'SECURITY',
        severity: control.maturityLevel === 'OPTIMAL' ? 'HIGH' : 'MEDIUM',
        status: 'REVIEW_REQUIRED',
        title: `Zero Trust: ${control.name} (${control.pillar})`,
        description: `**Maturity Level:** ${control.maturityLevel}\n\n${control.description}\n\n**Checkpoints:**\n${control.checkpoints.map(c => `- [ ] ${c}`).join('\n')}\n\n**Required Evidence:**\n${control.evidence.map(e => `- ${e}`).join('\n')}`,
        evidence: [{
          type: 'DATA',
          description: 'Zero Trust assessment checklist',
          source: `CISA Zero Trust Maturity Model - ${control.pillar}`,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: `Implement controls to achieve ${control.maturityLevel} maturity for ${control.name}.`,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Map findings to MITRE ATT&CK
  mapToMitre(indicator: string): MitreMapping[] {
    const mappings: MitreMapping[] = [];

    for (const technique of MITRE_TECHNIQUES) {
      if (
        technique.techniqueName.toLowerCase().includes(indicator.toLowerCase()) ||
        technique.description.toLowerCase().includes(indicator.toLowerCase())
      ) {
        mappings.push(technique);
      }
    }

    return mappings;
  }

  // Generate detection rules
  generateDetectionRules(technique: MitreMapping): string {
    return `# Detection Rule for ${technique.techniqueName} (${technique.techniqueId})
# Tactic: ${technique.tactic}

## Description
${technique.description}

## Detection Logic
${technique.detection}

## Mitigation
${technique.mitigation}

## SIEM Query Example
# This is a template - adjust for your SIEM platform
# Splunk:
index=windows sourcetype=WinEventLog:Security
| search EventCode IN (4768, 4769, 4770)
| stats count by src_user, dest, EventCode
| where count > 100

# Elastic:
event.code: (4768 OR 4769 OR 4770) AND
@timestamp:[now-1h TO now]
`;
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
export const securityAuditor = new SecurityAuditor();
