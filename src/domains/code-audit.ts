// Code/Software Audit Module
// Covers: SAST patterns, code quality, security, dependencies, architecture, technical debt

import { Finding, Evidence, Severity, AuditDomain, Location } from '../core/types.js';
import { RedFlagScanner, redFlagScanner } from '../core/red-flags.js';
import { randomUUID } from 'crypto';

// ============================================
// CODE QUALITY METRICS
// ============================================

export interface CodeMetrics {
  linesOfCode: number;
  linesOfComments: number;
  blankLines: number;
  cyclomaticComplexity: number;
  functions: number;
  classes: number;
  imports: number;
  nestingDepth: number;
  duplicateBlocks: number;
  todoCount: number;
  fixmeCount: number;
}

export interface DependencyInfo {
  name: string;
  version: string;
  type: 'production' | 'development';
  hasKnownVulnerabilities?: boolean;
  isOutdated?: boolean;
  license?: string;
}

// ============================================
// SECURITY VULNERABILITY PATTERNS
// ============================================

export interface SecurityPattern {
  id: string;
  name: string;
  cwe: string;
  severity: Severity;
  pattern: RegExp;
  description: string;
  recommendation: string;
  languages: string[];
}

export const SECURITY_PATTERNS: SecurityPattern[] = [
  // SQL Injection
  {
    id: 'SEC-001',
    name: 'Potential SQL Injection',
    cwe: 'CWE-89',
    severity: 'CRITICAL',
    pattern: /(?:execute|query|raw|exec)\s*\(\s*[`"']?\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?\$\{|\+\s*\w+|\%s/gi,
    description: 'SQL query constructed with string concatenation or template literals may be vulnerable to SQL injection.',
    recommendation: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.',
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
  },
  {
    id: 'SEC-002',
    name: 'SQL Injection via String Concatenation',
    cwe: 'CWE-89',
    severity: 'CRITICAL',
    pattern: /["']\s*\+\s*(?:req(?:uest)?\.(?:body|query|params)|user[Ii]nput|\$_(?:GET|POST|REQUEST))/g,
    description: 'User input directly concatenated into query string.',
    recommendation: 'Use parameterized queries with bound parameters.',
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
  },

  // Command Injection
  {
    id: 'SEC-003',
    name: 'Command Injection Risk',
    cwe: 'CWE-78',
    severity: 'CRITICAL',
    pattern: /(?:exec|spawn|system|popen|subprocess\.(?:call|run|Popen)|child_process\.exec|shell_exec|passthru)\s*\([^)]*(?:\$|`|\+.*(?:req|input|user|param))/gi,
    description: 'Shell command execution with potentially unsanitized input.',
    recommendation: 'Avoid shell execution with user input. Use allowlists and parameterized commands if necessary.',
    languages: ['javascript', 'typescript', 'python', 'php', 'ruby'],
  },

  // XSS
  {
    id: 'SEC-004',
    name: 'Potential Cross-Site Scripting (XSS)',
    cwe: 'CWE-79',
    severity: 'HIGH',
    pattern: /innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|v-html\s*=|\{\{\{.*\}\}\}/g,
    description: 'DOM manipulation that may render unsanitized user input as HTML.',
    recommendation: 'Use textContent instead of innerHTML. Sanitize HTML with DOMPurify or similar library.',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'SEC-005',
    name: 'XSS via Template Injection',
    cwe: 'CWE-79',
    severity: 'HIGH',
    pattern: /\$\{.*(?:req|user|input|param).*\}.*(?:html|render|template)/gi,
    description: 'User input interpolated into HTML templates without escaping.',
    recommendation: 'Use auto-escaping template engines. Explicitly escape user input.',
    languages: ['javascript', 'typescript', 'python'],
  },

  // Path Traversal
  {
    id: 'SEC-006',
    name: 'Path Traversal Vulnerability',
    cwe: 'CWE-22',
    severity: 'HIGH',
    pattern: /(?:readFile|writeFile|createReadStream|open|fs\..*)\s*\([^)]*(?:\+|`\$\{).*(?:req|user|input|param)/gi,
    description: 'File operations with user-controlled paths may allow directory traversal.',
    recommendation: 'Validate and sanitize file paths. Use path.resolve() and verify the result is within expected directory.',
    languages: ['javascript', 'typescript', 'python', 'php'],
  },

  // Hardcoded Secrets
  {
    id: 'SEC-007',
    name: 'Hardcoded Password',
    cwe: 'CWE-798',
    severity: 'CRITICAL',
    pattern: /(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?token|bearer|private[_-]?key)\s*[:=]\s*["'][^"']{8,}["']/gi,
    description: 'Hardcoded credential detected in source code.',
    recommendation: 'Use environment variables or a secrets management solution (Vault, AWS Secrets Manager).',
    languages: ['all'],
  },
  {
    id: 'SEC-008',
    name: 'AWS Access Key',
    cwe: 'CWE-798',
    severity: 'CRITICAL',
    pattern: /(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    description: 'AWS Access Key ID detected. These should never be in source code.',
    recommendation: 'Immediately rotate the exposed key. Use IAM roles or environment variables.',
    languages: ['all'],
  },
  {
    id: 'SEC-009',
    name: 'Private Key in Code',
    cwe: 'CWE-798',
    severity: 'CRITICAL',
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    description: 'Private key embedded in source code.',
    recommendation: 'Remove immediately and rotate the key. Store keys in secure key management systems.',
    languages: ['all'],
  },
  {
    id: 'SEC-010',
    name: 'JWT Secret Hardcoded',
    cwe: 'CWE-798',
    severity: 'CRITICAL',
    pattern: /(?:jwt|token)[_-]?secret\s*[:=]\s*["'][^"']+["']/gi,
    description: 'JWT signing secret hardcoded in source.',
    recommendation: 'Use environment variables for secrets. Consider using asymmetric keys (RS256).',
    languages: ['all'],
  },

  // Insecure Randomness
  {
    id: 'SEC-011',
    name: 'Weak Random Number Generator',
    cwe: 'CWE-330',
    severity: 'MEDIUM',
    pattern: /Math\.random\(\)|random\.random\(\)|rand\(\)|srand\(/g,
    description: 'Non-cryptographic random number generator used. May be predictable.',
    recommendation: 'Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive operations.',
    languages: ['javascript', 'typescript', 'python', 'php'],
  },

  // Insecure Deserialization
  {
    id: 'SEC-012',
    name: 'Insecure Deserialization',
    cwe: 'CWE-502',
    severity: 'HIGH',
    pattern: /(?:pickle\.loads?|yaml\.(?:load|unsafe_load)|unserialize|JSON\.parse\([^)]*(?:req|user|input))|eval\s*\(/gi,
    description: 'Deserialization of untrusted data may lead to remote code execution.',
    recommendation: 'Validate and sanitize serialized data. Use safe deserialization methods (yaml.safe_load).',
    languages: ['python', 'php', 'javascript', 'java'],
  },

  // SSRF
  {
    id: 'SEC-013',
    name: 'Server-Side Request Forgery (SSRF)',
    cwe: 'CWE-918',
    severity: 'HIGH',
    pattern: /(?:fetch|axios|request|http\.get|urllib|requests\.get)\s*\([^)]*(?:req|user|input|param|\$_)/gi,
    description: 'HTTP request with user-controlled URL may allow SSRF attacks.',
    recommendation: 'Validate and allowlist destination URLs. Block internal IP ranges.',
    languages: ['javascript', 'typescript', 'python'],
  },

  // Prototype Pollution
  {
    id: 'SEC-014',
    name: 'Prototype Pollution Risk',
    cwe: 'CWE-1321',
    severity: 'HIGH',
    pattern: /(?:__proto__|constructor\s*\[|Object\.assign\s*\(\s*\{\}.*(?:req|user|input))/g,
    description: 'Potential prototype pollution through object manipulation.',
    recommendation: 'Use Object.create(null) for dictionaries. Validate object keys against allowlist.',
    languages: ['javascript', 'typescript'],
  },

  // Insecure Cookie
  {
    id: 'SEC-015',
    name: 'Insecure Cookie Configuration',
    cwe: 'CWE-614',
    severity: 'MEDIUM',
    pattern: /(?:httpOnly|secure|sameSite)\s*:\s*false|Set-Cookie:(?!.*(?:HttpOnly|Secure))/gi,
    description: 'Cookie configured without security flags.',
    recommendation: 'Set HttpOnly, Secure, and SameSite flags on all sensitive cookies.',
    languages: ['javascript', 'typescript'],
  },

  // XXE
  {
    id: 'SEC-016',
    name: 'XML External Entity (XXE) Risk',
    cwe: 'CWE-611',
    severity: 'HIGH',
    pattern: /(?:parseXML|XMLParser|etree\.parse|DOMParser|xml2js)/gi,
    description: 'XML parsing may be vulnerable to XXE attacks if external entities are enabled.',
    recommendation: 'Disable external entity processing. Use defusedxml in Python.',
    languages: ['javascript', 'python', 'java'],
  },

  // Debug/Development Code
  {
    id: 'SEC-017',
    name: 'Debug Code in Production',
    cwe: 'CWE-489',
    severity: 'MEDIUM',
    pattern: /console\.log\(|debugger;|print\s*\(|var_dump\(|dd\(|Debug\.Log/g,
    description: 'Debug statements should be removed from production code.',
    recommendation: 'Remove or conditionally compile debug statements. Use proper logging framework.',
    languages: ['javascript', 'typescript', 'python', 'php'],
  },

  // Disabled Security
  {
    id: 'SEC-018',
    name: 'Security Feature Disabled',
    cwe: 'CWE-693',
    severity: 'CRITICAL',
    pattern: /(?:verify\s*[:=]\s*false|rejectUnauthorized\s*[:=]\s*false|insecure|disable[_-]?(?:ssl|tls|security|auth)|CURLOPT_SSL_VERIFYPEER.*false)/gi,
    description: 'Security feature explicitly disabled.',
    recommendation: 'Enable all security features. Never disable SSL/TLS verification.',
    languages: ['all'],
  },

  // Open Redirect
  {
    id: 'SEC-019',
    name: 'Open Redirect Vulnerability',
    cwe: 'CWE-601',
    severity: 'MEDIUM',
    pattern: /(?:redirect|location\.href|window\.location)\s*[:=]\s*(?:req|user|input|param|\$_)/gi,
    description: 'Redirect destination controlled by user input.',
    recommendation: 'Validate redirect URLs against allowlist of trusted destinations.',
    languages: ['javascript', 'typescript', 'php'],
  },

  // Regex DoS
  {
    id: 'SEC-020',
    name: 'Regular Expression Denial of Service (ReDoS)',
    cwe: 'CWE-1333',
    severity: 'MEDIUM',
    pattern: /new\s+RegExp\s*\([^)]*(?:req|user|input)|\(\?:[^)]*\)\+\+|\(\?:[^)]*\)\*\*/g,
    description: 'User-controlled regex or catastrophic backtracking pattern.',
    recommendation: 'Avoid user-controlled regex. Use re2 for safe regex. Test patterns for ReDoS.',
    languages: ['javascript', 'typescript', 'python'],
  },
];

// ============================================
// CODE SMELL PATTERNS
// ============================================

export interface CodeSmellPattern {
  id: string;
  name: string;
  severity: Severity;
  pattern: RegExp;
  description: string;
  recommendation: string;
}

export const CODE_SMELL_PATTERNS: CodeSmellPattern[] = [
  {
    id: 'SMELL-001',
    name: 'Magic Numbers',
    severity: 'LOW',
    pattern: /(?:if|while|for|return|===?|!==?|[+\-*/])\s*\d{2,}(?!\d*px|%|em|rem|vh|vw)/g,
    description: 'Unexplained numeric literals reduce code readability.',
    recommendation: 'Extract magic numbers into named constants with descriptive names.',
  },
  {
    id: 'SMELL-002',
    name: 'Long Function',
    severity: 'MEDIUM',
    pattern: /(?:function|const\s+\w+\s*=|def\s+\w+)/g, // Count functions, check length separately
    description: 'Functions exceeding 50 lines are harder to understand and maintain.',
    recommendation: 'Extract logical blocks into smaller, focused functions.',
  },
  {
    id: 'SMELL-003',
    name: 'Deep Nesting',
    severity: 'MEDIUM',
    pattern: /^(\s{12,}|\t{3,})(?:if|for|while|switch|try)/gm,
    description: 'Deeply nested code (4+ levels) indicates excessive complexity.',
    recommendation: 'Use early returns, extract methods, or apply guard clauses.',
  },
  {
    id: 'SMELL-004',
    name: 'God Class',
    severity: 'HIGH',
    pattern: /class\s+\w+[^}]{5000,}/gs,
    description: 'Class exceeds 200 lines, likely has too many responsibilities.',
    recommendation: 'Apply Single Responsibility Principle. Extract cohesive functionality into separate classes.',
  },
  {
    id: 'SMELL-005',
    name: 'Commented Out Code',
    severity: 'LOW',
    pattern: /\/\/\s*(?:function|const|let|var|if|for|while|class|return)\s/gm,
    description: 'Commented code clutters the codebase and should be removed.',
    recommendation: 'Delete commented code. Use version control to retrieve old code if needed.',
  },
  {
    id: 'SMELL-006',
    name: 'Empty Catch Block',
    severity: 'HIGH',
    pattern: /catch\s*\([^)]*\)\s*\{\s*\}/g,
    description: 'Empty catch blocks swallow errors silently.',
    recommendation: 'Log the error or rethrow. Never silently ignore exceptions.',
  },
  {
    id: 'SMELL-007',
    name: 'Console/Print Statements',
    severity: 'LOW',
    pattern: /console\.(log|debug|info|warn|error)|print\s*\(|System\.out\.print/g,
    description: 'Debug statements should use a proper logging framework.',
    recommendation: 'Use structured logging (winston, pino, log4j) with appropriate log levels.',
  },
  {
    id: 'SMELL-008',
    name: 'TODO/FIXME Comments',
    severity: 'INFO',
    pattern: /(?:\/\/|#|\/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)[\s:]/gi,
    description: 'Technical debt markers indicate incomplete work.',
    recommendation: 'Address TODOs or create tracked issues. Remove stale markers.',
  },
  {
    id: 'SMELL-009',
    name: 'Duplicate Code Block',
    severity: 'MEDIUM',
    pattern: /(.{50,})\n(?:.*\n){0,5}\1/g,
    description: 'Duplicate code violates DRY principle and increases maintenance burden.',
    recommendation: 'Extract common code into reusable functions or modules.',
  },
  {
    id: 'SMELL-010',
    name: 'Hardcoded URLs/IPs',
    severity: 'MEDIUM',
    pattern: /["']https?:\/\/(?:localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9.-]+\.[a-z]{2,})(?::\d+)?[^"']*["']/gi,
    description: 'Hardcoded URLs reduce flexibility and may expose internal infrastructure.',
    recommendation: 'Use environment variables or configuration files for URLs.',
  },
];

// ============================================
// CODE AUDITOR CLASS
// ============================================

export class CodeAuditor {
  private findings: Finding[] = [];
  private redFlagScanner: RedFlagScanner;

  constructor() {
    this.redFlagScanner = redFlagScanner;
  }

  // Full code audit
  async auditCode(
    content: string,
    filePath: string,
    language?: string
  ): Promise<Finding[]> {
    this.findings = [];
    const detectedLanguage = language || this.detectLanguage(filePath);

    // 1. Security vulnerability scan
    await this.scanSecurity(content, filePath, detectedLanguage);

    // 2. Code smell detection
    await this.scanCodeSmells(content, filePath);

    // 3. Red flag scan (forensic keywords)
    await this.scanRedFlags(content, filePath);

    // 4. Code metrics analysis
    await this.analyzeMetrics(content, filePath, detectedLanguage);

    // 5. Dependency analysis (if package.json detected)
    if (filePath.includes('package.json')) {
      await this.analyzeDependencies(content, filePath);
    }

    return this.findings;
  }

  // Security vulnerability scan
  private async scanSecurity(
    content: string,
    filePath: string,
    language: string
  ): Promise<void> {
    for (const pattern of SECURITY_PATTERNS) {
      if (pattern.languages.includes('all') || pattern.languages.includes(language)) {
        const matches = content.matchAll(pattern.pattern);

        for (const match of matches) {
          const lineNumber = this.getLineNumber(content, match.index!);
          const context = this.getContext(content, match.index!, 100);

          const evidence: Evidence = {
            type: 'DATA',
            description: `Pattern match: ${match[0].slice(0, 100)}`,
            content: context,
            source: filePath,
            collectedAt: new Date().toISOString(),
          };

          this.findings.push({
            id: `${pattern.id}-${randomUUID().slice(0, 4)}`,
            domain: 'SECURITY',
            severity: pattern.severity,
            status: pattern.severity === 'CRITICAL' ? 'FAIL' : 'WARNING',
            title: pattern.name,
            description: pattern.description,
            evidence: [evidence],
            location: {
              file: filePath,
              line: lineNumber,
            },
            recommendation: pattern.recommendation,
            cwe: pattern.cwe,
            timestamp: new Date().toISOString(),
          });
        }
      }
    }
  }

  // Code smell detection
  private async scanCodeSmells(content: string, filePath: string): Promise<void> {
    for (const smell of CODE_SMELL_PATTERNS) {
      const matches = content.matchAll(smell.pattern);
      let matchCount = 0;

      for (const match of matches) {
        matchCount++;
        if (matchCount > 10) break; // Limit to 10 instances per smell

        const lineNumber = this.getLineNumber(content, match.index!);

        this.findings.push({
          id: `${smell.id}-${randomUUID().slice(0, 4)}`,
          domain: 'CODE',
          severity: smell.severity,
          status: 'WARNING',
          title: smell.name,
          description: smell.description,
          evidence: [{
            type: 'DATA',
            description: `Instance found at line ${lineNumber}`,
            content: match[0].slice(0, 200),
            source: filePath,
            collectedAt: new Date().toISOString(),
          }],
          location: {
            file: filePath,
            line: lineNumber,
          },
          recommendation: smell.recommendation,
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  // Red flag scan
  private async scanRedFlags(content: string, filePath: string): Promise<void> {
    const matches = this.redFlagScanner.scan(content, filePath);
    const redFlagFindings = this.redFlagScanner.matchesToFindings(matches, 'CODE');
    this.findings.push(...redFlagFindings);
  }

  // Code metrics analysis
  private async analyzeMetrics(
    content: string,
    filePath: string,
    language: string
  ): Promise<void> {
    const metrics = this.calculateMetrics(content, language);

    // Check thresholds and create findings
    if (metrics.cyclomaticComplexity > 20) {
      this.findings.push({
        id: `METRIC-CC-${randomUUID().slice(0, 4)}`,
        domain: 'CODE',
        severity: metrics.cyclomaticComplexity > 50 ? 'HIGH' : 'MEDIUM',
        status: 'WARNING',
        title: 'High Cyclomatic Complexity',
        description: `File has cyclomatic complexity of ${metrics.cyclomaticComplexity}. Values above 20 indicate code that is difficult to test and maintain. Industry target: 10-15.`,
        evidence: [{
          type: 'DATA',
          description: 'Complexity metrics',
          content: JSON.stringify(metrics, null, 2),
          source: filePath,
          collectedAt: new Date().toISOString(),
        }],
        location: { file: filePath },
        recommendation: 'Refactor complex functions into smaller, focused units. Apply extract method refactoring.',
        timestamp: new Date().toISOString(),
      });
    }

    if (metrics.nestingDepth > 4) {
      this.findings.push({
        id: `METRIC-NEST-${randomUUID().slice(0, 4)}`,
        domain: 'CODE',
        severity: 'MEDIUM',
        status: 'WARNING',
        title: 'Excessive Nesting Depth',
        description: `Maximum nesting depth of ${metrics.nestingDepth} exceeds recommended limit of 4.`,
        evidence: [{
          type: 'DATA',
          description: 'Nesting analysis',
          source: filePath,
          collectedAt: new Date().toISOString(),
        }],
        location: { file: filePath },
        recommendation: 'Use early returns, guard clauses, and extract methods to reduce nesting.',
        timestamp: new Date().toISOString(),
      });
    }

    if (metrics.linesOfCode > 500) {
      this.findings.push({
        id: `METRIC-LOC-${randomUUID().slice(0, 4)}`,
        domain: 'CODE',
        severity: 'LOW',
        status: 'WARNING',
        title: 'Large File',
        description: `File has ${metrics.linesOfCode} lines of code. Files over 500 lines are harder to navigate and maintain.`,
        evidence: [{
          type: 'DATA',
          description: 'Size metrics',
          content: `LOC: ${metrics.linesOfCode}, Comments: ${metrics.linesOfComments}, Blank: ${metrics.blankLines}`,
          source: filePath,
          collectedAt: new Date().toISOString(),
        }],
        location: { file: filePath },
        recommendation: 'Consider splitting into multiple focused modules.',
        timestamp: new Date().toISOString(),
      });
    }

    if (metrics.todoCount > 5) {
      this.findings.push({
        id: `METRIC-TODO-${randomUUID().slice(0, 4)}`,
        domain: 'CODE',
        severity: 'INFO',
        status: 'REVIEW_REQUIRED',
        title: 'Technical Debt Markers',
        description: `File contains ${metrics.todoCount} TODO/FIXME markers indicating unfinished work.`,
        evidence: [{
          type: 'DATA',
          description: 'Technical debt count',
          source: filePath,
          collectedAt: new Date().toISOString(),
        }],
        location: { file: filePath },
        recommendation: 'Review and address TODO items or create tracked issues.',
        timestamp: new Date().toISOString(),
      });
    }
  }

  // Calculate code metrics
  calculateMetrics(content: string, language: string): CodeMetrics {
    const lines = content.split('\n');

    let linesOfCode = 0;
    let linesOfComments = 0;
    let blankLines = 0;
    let cyclomaticComplexity = 1; // Base complexity
    let nestingDepth = 0;
    let maxNestingDepth = 0;
    let functions = 0;
    let classes = 0;
    let imports = 0;
    let todoCount = 0;
    let fixmeCount = 0;

    const inBlockComment = false;

    for (const line of lines) {
      const trimmed = line.trim();

      // Blank lines
      if (trimmed === '') {
        blankLines++;
        continue;
      }

      // Comments
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
        linesOfComments++;
        if (/TODO/i.test(trimmed)) todoCount++;
        if (/FIXME/i.test(trimmed)) fixmeCount++;
        continue;
      }

      linesOfCode++;

      // Cyclomatic complexity (decision points)
      const decisionKeywords = /\b(if|else\s+if|elif|while|for|foreach|case|catch|&&|\|\||\?)\b/g;
      const matches = trimmed.match(decisionKeywords);
      if (matches) cyclomaticComplexity += matches.length;

      // Nesting depth
      const openBraces = (trimmed.match(/\{/g) || []).length;
      const closeBraces = (trimmed.match(/\}/g) || []).length;
      nestingDepth += openBraces - closeBraces;
      maxNestingDepth = Math.max(maxNestingDepth, nestingDepth);

      // Functions
      if (/\b(function|def|fn|func|sub|procedure)\b/.test(trimmed) || /=>\s*\{/.test(trimmed)) {
        functions++;
      }

      // Classes
      if (/\bclass\s+\w+/.test(trimmed)) {
        classes++;
      }

      // Imports
      if (/^import\s|^from\s.*import|^require\(|^using\s|^#include/.test(trimmed)) {
        imports++;
      }
    }

    return {
      linesOfCode,
      linesOfComments,
      blankLines,
      cyclomaticComplexity,
      functions,
      classes,
      imports,
      nestingDepth: maxNestingDepth,
      duplicateBlocks: 0, // Would require more complex analysis
      todoCount,
      fixmeCount,
    };
  }

  // Analyze dependencies
  private async analyzeDependencies(content: string, filePath: string): Promise<void> {
    try {
      const packageJson = JSON.parse(content);
      const deps = { ...packageJson.dependencies, ...packageJson.devDependencies };

      // Check for known vulnerable patterns
      const vulnerablePatterns: Record<string, { severity: Severity; reason: string }> = {
        'lodash': { severity: 'INFO', reason: 'Multiple historical CVEs. Ensure version >= 4.17.21' },
        'moment': { severity: 'INFO', reason: 'Deprecated. Consider dayjs or date-fns' },
        'request': { severity: 'MEDIUM', reason: 'Deprecated and unmaintained. Use node-fetch or axios' },
        'express': { severity: 'INFO', reason: 'Ensure version >= 4.18.0 for security patches' },
        'axios': { severity: 'INFO', reason: 'Check for SSRF protections if using with user input' },
      };

      for (const [pkg, version] of Object.entries(deps)) {
        if (vulnerablePatterns[pkg]) {
          const vuln = vulnerablePatterns[pkg];
          this.findings.push({
            id: `DEP-${randomUUID().slice(0, 4)}`,
            domain: 'SECURITY',
            severity: vuln.severity,
            status: 'REVIEW_REQUIRED',
            title: `Dependency Review: ${pkg}`,
            description: `Package "${pkg}@${version}" requires attention. ${vuln.reason}`,
            evidence: [{
              type: 'DATA',
              description: 'Dependency information',
              content: `${pkg}: ${version}`,
              source: filePath,
              collectedAt: new Date().toISOString(),
            }],
            location: { file: filePath },
            recommendation: `Review and update "${pkg}" to the latest secure version. Run npm audit for detailed CVE information.`,
            timestamp: new Date().toISOString(),
          });
        }
      }

      // Check for missing security dependencies
      const securityDeps = ['helmet', 'cors', 'express-rate-limit', 'express-validator'];
      const hasSecurity = securityDeps.some(d => deps[d]);

      if (packageJson.dependencies?.express && !hasSecurity) {
        this.findings.push({
          id: `DEP-SEC-${randomUUID().slice(0, 4)}`,
          domain: 'SECURITY',
          severity: 'MEDIUM',
          status: 'WARNING',
          title: 'Missing Security Middleware',
          description: 'Express.js application without common security middleware.',
          evidence: [{
            type: 'DATA',
            description: 'Missing dependencies',
            content: `Recommend adding: ${securityDeps.join(', ')}`,
            source: filePath,
            collectedAt: new Date().toISOString(),
          }],
          location: { file: filePath },
          recommendation: 'Add helmet for security headers, cors for CORS policy, and rate-limit for DoS protection.',
          timestamp: new Date().toISOString(),
        });
      }

    } catch (e) {
      // Invalid JSON, skip
    }
  }

  // Helper: Get line number from character index
  private getLineNumber(content: string, index: number): number {
    return content.slice(0, index).split('\n').length;
  }

  // Helper: Get context around match
  private getContext(content: string, index: number, chars: number): string {
    const start = Math.max(0, index - chars);
    const end = Math.min(content.length, index + chars);
    return content.slice(start, end).replace(/\n/g, '\\n');
  }

  // Helper: Detect language from file extension
  private detectLanguage(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const languageMap: Record<string, string> = {
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'typescript',
      'tsx': 'typescript',
      'py': 'python',
      'rb': 'ruby',
      'php': 'php',
      'java': 'java',
      'go': 'go',
      'rs': 'rust',
      'c': 'c',
      'cpp': 'cpp',
      'cs': 'csharp',
    };
    return languageMap[ext || ''] || 'unknown';
  }

  // Get all findings
  getFindings(): Finding[] {
    return this.findings;
  }
}

// Export singleton
export const codeAuditor = new CodeAuditor();
