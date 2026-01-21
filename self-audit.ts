#!/usr/bin/env npx tsx
/**
 * MCP Auditor Self-Audit
 * The Omniscient Auditor audits itself
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

// Import auditors
import { AuditEngine } from './src/core/engine.js';
import { RedFlagScanner } from './src/core/red-flags.js';
import { CodeAuditor } from './src/domains/code-audit.js';
import { SecurityAuditor } from './src/domains/security-audit.js';
import { Finding } from './src/core/types.js';

// Collect all TypeScript source files
function collectSourceFiles(dir: string, files: string[] = []): string[] {
  const entries = readdirSync(dir);
  for (const entry of entries) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory() && entry !== 'node_modules' && entry !== 'dist') {
      collectSourceFiles(fullPath, files);
    } else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts')) {
      files.push(fullPath);
    }
  }
  return files;
}

async function selfAudit() {
  console.log('='.repeat(80));
  console.log('MCP AUDITOR SELF-AUDIT REPORT');
  console.log('The Omniscient Auditor audits itself');
  console.log('='.repeat(80));
  console.log();

  // Initialize
  const auditEngine = new AuditEngine({
    domains: ['CODE', 'SECURITY'],
    severity_threshold: 'LOW'
  });
  auditEngine.startAudit();

  const redFlagScanner = new RedFlagScanner();
  const codeAuditor = new CodeAuditor();
  const securityAuditor = new SecurityAuditor();

  // Collect source files
  const srcDir = join(process.cwd(), 'src');
  const sourceFiles = collectSourceFiles(srcDir);
  console.log(`Found ${sourceFiles.length} TypeScript source files to audit\n`);

  let totalVulnerabilities = 0;
  let totalCodeSmells = 0;
  let totalRedFlags = 0;
  const allFindings: Finding[] = [];

  // Audit each file
  for (const file of sourceFiles) {
    const relativePath = file.replace(process.cwd() + '\\', '').replace(/\\/g, '/');
    const content = readFileSync(file, 'utf-8');

    console.log(`\n${'─'.repeat(60)}`);
    console.log(`Auditing: ${relativePath}`);
    console.log(`${'─'.repeat(60)}`);

    // Code audit
    const codeFindings = await codeAuditor.auditCode(content, relativePath, 'typescript');
    const vulns = codeFindings.filter(f => f.domain === 'SECURITY');
    const smells = codeFindings.filter(f => f.domain === 'CODE');

    totalVulnerabilities += vulns.length;
    totalCodeSmells += smells.length;
    allFindings.push(...codeFindings);

    if (vulns.length > 0) {
      console.log(`\n  SECURITY FINDINGS: ${vulns.length}`);
      for (const v of vulns.slice(0, 5)) {
        console.log(`    [${v.severity}] ${v.title}`);
        if (v.location?.line) console.log(`      Line: ${v.location.line}`);
      }
      if (vulns.length > 5) console.log(`    ... and ${vulns.length - 5} more`);
    }

    if (smells.length > 0) {
      console.log(`\n  CODE SMELLS: ${smells.length}`);
      for (const s of smells.slice(0, 3)) {
        console.log(`    [${s.severity}] ${s.title}`);
      }
      if (smells.length > 3) console.log(`    ... and ${smells.length - 3} more`);
    }

    // Red flag scan
    const redFlags = redFlagScanner.scan(content, relativePath);
    totalRedFlags += redFlags.length;

    if (redFlags.length > 0) {
      const rfFindings = redFlagScanner.matchesToFindings(redFlags);
      allFindings.push(...rfFindings);
      console.log(`\n  RED FLAGS: ${redFlags.length}`);
      const categories = [...new Set(redFlags.map(r => r.pattern.category))];
      for (const cat of categories) {
        const count = redFlags.filter(r => r.pattern.category === cat).length;
        console.log(`    ${cat}: ${count}`);
      }
    }

    // Add findings to engine
    for (const finding of codeFindings) {
      auditEngine.addFinding(finding);
    }
  }

  // Calculate metrics
  let totalLines = 0;
  let totalFunctions = 0;
  let totalClasses = 0;

  for (const file of sourceFiles) {
    const content = readFileSync(file, 'utf-8');
    const lines = content.split('\n');
    totalLines += lines.filter(l => l.trim().length > 0).length;
    totalFunctions += (content.match(/function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\(|=>\s*\{/g) || []).length;
    totalClasses += (content.match(/class\s+\w+/g) || []).length;
  }

  // Generate summary
  console.log('\n' + '='.repeat(80));
  console.log('SELF-AUDIT SUMMARY');
  console.log('='.repeat(80));

  console.log('\n📊 CODEBASE METRICS:');
  console.log(`   Files analyzed: ${sourceFiles.length}`);
  console.log(`   Lines of code: ${totalLines.toLocaleString()}`);
  console.log(`   Functions: ${totalFunctions}`);
  console.log(`   Classes: ${totalClasses}`);

  console.log('\n🔍 FINDINGS:');
  console.log(`   Security vulnerabilities: ${totalVulnerabilities}`);
  console.log(`   Code smells: ${totalCodeSmells}`);
  console.log(`   Red flags: ${totalRedFlags}`);
  console.log(`   Total findings: ${allFindings.length}`);

  // Severity breakdown
  const bySeverity = {
    CRITICAL: allFindings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: allFindings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: allFindings.filter(f => f.severity === 'MEDIUM').length,
    LOW: allFindings.filter(f => f.severity === 'LOW').length,
    INFO: allFindings.filter(f => f.severity === 'INFO').length,
  };

  console.log('\n📈 SEVERITY BREAKDOWN:');
  console.log(`   🔴 CRITICAL: ${bySeverity.CRITICAL}`);
  console.log(`   🟠 HIGH: ${bySeverity.HIGH}`);
  console.log(`   🟡 MEDIUM: ${bySeverity.MEDIUM}`);
  console.log(`   🟢 LOW: ${bySeverity.LOW}`);
  console.log(`   ⚪ INFO: ${bySeverity.INFO}`);

  // Risk score
  const stats = auditEngine.getStatistics();
  const rating = auditEngine.getOverallRating();
  const riskScore = auditEngine.calculateRiskScore();

  console.log('\n🎯 OVERALL ASSESSMENT:');
  console.log(`   Rating: ${rating}`);
  console.log(`   Risk Score: ${riskScore}/100`);

  // Top findings
  console.log('\n⚠️  TOP FINDINGS:');
  const topFindings = allFindings
    .sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    })
    .slice(0, 10);

  for (const f of topFindings) {
    console.log(`\n   [${f.severity}] ${f.title}`);
    if (f.location?.file) {
      console.log(`   File: ${f.location.file}:${f.location.line || '?'}`);
    }
    if (f.cwe) console.log(`   CWE: ${f.cwe}`);
    console.log(`   ${f.description.split('\n')[0].slice(0, 100)}...`);
  }

  // Recommendations
  console.log('\n📋 RECOMMENDATIONS:');
  if (bySeverity.CRITICAL > 0) {
    console.log('   1. IMMEDIATE: Address critical findings before deployment');
  }
  if (totalRedFlags > 0) {
    console.log('   2. Review red flag matches - some may be false positives in audit tool context');
  }
  if (totalCodeSmells > 10) {
    console.log('   3. Schedule technical debt reduction sprint');
  }
  console.log('   4. Implement pre-commit hooks to catch issues early');
  console.log('   5. Run this self-audit as part of CI/CD pipeline');

  console.log('\n' + '='.repeat(80));
  console.log('Self-audit complete. The auditor has been audited.');
  console.log('='.repeat(80));
}

selfAudit().catch(console.error);
