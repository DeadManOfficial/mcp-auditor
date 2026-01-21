// Operational/Process Audit Module
// Covers: Lean Six Sigma, TIMWOOD, Value Stream Mapping, Process Efficiency, KPI Validation

import { Finding, Evidence, Severity, AuditDomain } from '../core/types.js';
import { randomUUID } from 'crypto';

// ============================================
// TIMWOOD WASTE CATEGORIES
// ============================================

export interface WasteCategory {
  id: string;
  name: string;
  acronym: string;
  description: string;
  indicators: string[];
  questions: string[];
  metrics: string[];
  improvement: string[];
}

export const TIMWOOD_WASTES: WasteCategory[] = [
  {
    id: 'T',
    name: 'Transportation',
    acronym: 'T',
    description: 'Unnecessary movement of products, materials, or information.',
    indicators: [
      'Multiple handoffs between teams/systems',
      'Physical movement of documents',
      'Data transfer between incompatible systems',
      'Routing through unnecessary approval chains',
      'Geographic dispersion of related processes',
    ],
    questions: [
      'How many times does the work product change hands?',
      'Are there unnecessary data transfers between systems?',
      'Could co-location reduce movement?',
      'Are approval chains adding value or just distance?',
    ],
    metrics: [
      'Number of handoffs per process',
      'Distance traveled (physical or logical)',
      'Transfer time between steps',
      'Number of systems data passes through',
    ],
    improvement: [
      'Co-locate related teams/processes',
      'Implement integrated systems',
      'Reduce approval levels',
      'Use digital workflows',
    ],
  },
  {
    id: 'I',
    name: 'Inventory',
    acronym: 'I',
    description: 'Excess work-in-progress, backlog, or stored information.',
    indicators: [
      'Large backlogs of unprocessed requests',
      'Excess raw materials or supplies',
      'Unread emails/tickets piling up',
      'Outdated documentation being maintained',
      'Dormant projects consuming resources',
    ],
    questions: [
      'What is the current backlog size?',
      'How long do items sit in queue?',
      'Are we maintaining information we never use?',
      'What is the cost of carrying this inventory?',
    ],
    metrics: [
      'Backlog size and age',
      'Work-in-progress (WIP) count',
      'Queue wait time',
      'Inventory carrying cost',
    ],
    improvement: [
      'Implement pull systems',
      'Set WIP limits',
      'Regular backlog grooming',
      'Just-in-time processing',
    ],
  },
  {
    id: 'M',
    name: 'Motion',
    acronym: 'M',
    description: 'Unnecessary movement of people or excessive context switching.',
    indicators: [
      'Excessive meetings without outcomes',
      'Context switching between tasks',
      'Searching for information/tools',
      'Walking to printers/equipment',
      'Multiple logins to different systems',
    ],
    questions: [
      'How much time is spent in meetings?',
      'How often do workers switch tasks?',
      'How long does it take to find needed information?',
      'Could tools be better organized?',
    ],
    metrics: [
      'Time in meetings vs. productive work',
      'Context switches per day',
      'Search time for information',
      'Tool/resource access time',
    ],
    improvement: [
      'Consolidate meetings',
      'Implement focused work blocks',
      'Improve information architecture',
      'Single sign-on systems',
    ],
  },
  {
    id: 'W',
    name: 'Waiting',
    acronym: 'W',
    description: 'Idle time while waiting for approvals, resources, or information.',
    indicators: [
      'Approval bottlenecks',
      'Waiting for dependencies',
      'System downtime',
      'Waiting for responses',
      'Resource contention',
    ],
    questions: [
      'What are the major approval bottlenecks?',
      'How long do tasks wait between steps?',
      'What dependencies cause delays?',
      'Are SLAs being met?',
    ],
    metrics: [
      'Wait time between process steps',
      'Approval cycle time',
      'Response time SLAs',
      'Resource availability',
    ],
    improvement: [
      'Parallel processing where possible',
      'Auto-approval for low-risk items',
      'Clear escalation procedures',
      'Capacity planning',
    ],
  },
  {
    id: 'O1',
    name: 'Over-processing',
    acronym: 'O',
    description: 'Doing more work than required to meet customer needs.',
    indicators: [
      'Gold-plating features',
      'Excessive documentation',
      'Multiple levels of review for simple items',
      'Reporting that no one reads',
      'Manual work that could be automated',
    ],
    questions: [
      'Does each step add value for the customer?',
      'Are we producing reports no one uses?',
      'Are review levels appropriate to risk?',
      'What work could be eliminated?',
    ],
    metrics: [
      'Value-added vs. non-value-added time',
      'Report utilization rates',
      'Review cycles per work item',
      'Automation opportunity score',
    ],
    improvement: [
      'Eliminate unnecessary steps',
      'Right-size documentation',
      'Risk-based review levels',
      'Automate repetitive tasks',
    ],
  },
  {
    id: 'O2',
    name: 'Over-production',
    acronym: 'O',
    description: 'Producing more than is needed or before it is needed.',
    indicators: [
      'Features built but never used',
      'Reports generated but unread',
      'Batch processing when not needed',
      'Building to forecast vs. demand',
      'Preemptive work that becomes obsolete',
    ],
    questions: [
      'Are we building what customers need?',
      'What percentage of output is actually used?',
      'Are we producing just-in-time or just-in-case?',
      'What is our feature adoption rate?',
    ],
    metrics: [
      'Feature utilization rate',
      'Lead time from request to delivery',
      'Forecast accuracy',
      'Waste from obsolete work',
    ],
    improvement: [
      'Pull-based systems',
      'Demand-driven production',
      'Smaller batch sizes',
      'Continuous feedback loops',
    ],
  },
  {
    id: 'D',
    name: 'Defects',
    acronym: 'D',
    description: 'Errors requiring rework or causing customer dissatisfaction.',
    indicators: [
      'High bug/defect rates',
      'Frequent rework cycles',
      'Customer complaints',
      'Failed deployments',
      'Data quality issues',
    ],
    questions: [
      'What is our defect rate?',
      'What percentage of work requires rework?',
      'What are the root causes of defects?',
      'What is the cost of poor quality?',
    ],
    metrics: [
      'Defect rate (per unit/per hour)',
      'Rework percentage',
      'First-pass yield',
      'Cost of poor quality (COPQ)',
      'Customer satisfaction scores',
    ],
    improvement: [
      'Root cause analysis',
      'Error-proofing (poka-yoke)',
      'Quality at source',
      'Automated testing',
      'Clear standards and training',
    ],
  },
];

// ============================================
// DMAIC FRAMEWORK
// ============================================

export interface DMAICPhase {
  phase: string;
  name: string;
  description: string;
  objectives: string[];
  tools: string[];
  deliverables: string[];
  questions: string[];
}

export const DMAIC_PHASES: DMAICPhase[] = [
  {
    phase: 'D',
    name: 'Define',
    description: 'Define the problem, project goals, and customer requirements.',
    objectives: [
      'Identify the business problem',
      'Define project scope',
      'Identify stakeholders',
      'Establish project timeline',
      'Define success metrics',
    ],
    tools: [
      'Project Charter',
      'SIPOC Diagram',
      'Voice of Customer (VOC)',
      'Stakeholder Analysis',
      'CTQ Tree (Critical to Quality)',
    ],
    deliverables: [
      'Problem statement',
      'Project charter',
      'SIPOC diagram',
      'Baseline metrics',
      'Project plan',
    ],
    questions: [
      'What is the problem we are trying to solve?',
      'Who is the customer and what do they need?',
      'What is in scope and out of scope?',
      'What are the success criteria?',
      'What are the project constraints?',
    ],
  },
  {
    phase: 'M',
    name: 'Measure',
    description: 'Measure current performance and collect relevant data.',
    objectives: [
      'Map the current process',
      'Identify key metrics',
      'Establish data collection plan',
      'Measure baseline performance',
      'Validate measurement system',
    ],
    tools: [
      'Process Mapping',
      'Value Stream Mapping',
      'Data Collection Plan',
      'Measurement System Analysis (MSA)',
      'Pareto Analysis',
      'Control Charts',
    ],
    deliverables: [
      'Current state process map',
      'Data collection plan',
      'Baseline performance data',
      'Measurement system validation',
    ],
    questions: [
      'What does the current process look like?',
      'What data do we need to collect?',
      'How accurate is our measurement system?',
      'What is the current baseline performance?',
      'Where are the pain points?',
    ],
  },
  {
    phase: 'A',
    name: 'Analyze',
    description: 'Analyze data to identify root causes of problems.',
    objectives: [
      'Identify potential root causes',
      'Validate root causes with data',
      'Prioritize root causes',
      'Quantify improvement opportunity',
    ],
    tools: [
      'Fishbone Diagram (Ishikawa)',
      '5 Whys',
      'Hypothesis Testing',
      'Regression Analysis',
      'FMEA (Failure Mode and Effects Analysis)',
      'Process Capability Analysis',
    ],
    deliverables: [
      'Root cause analysis',
      'Validated root causes',
      'Prioritized improvement opportunities',
      'Statistical analysis results',
    ],
    questions: [
      'What are the potential root causes?',
      'Which root causes are validated by data?',
      'What is the biggest opportunity for improvement?',
      'What would eliminating this root cause achieve?',
    ],
  },
  {
    phase: 'I',
    name: 'Improve',
    description: 'Develop and implement solutions to address root causes.',
    objectives: [
      'Generate potential solutions',
      'Evaluate and select solutions',
      'Pilot solutions',
      'Implement full-scale solution',
      'Verify improvement',
    ],
    tools: [
      'Brainstorming',
      'Solution Selection Matrix',
      'Pilot Planning',
      'Implementation Plan',
      'Before/After Analysis',
      'Cost-Benefit Analysis',
    ],
    deliverables: [
      'Solution alternatives',
      'Selected solution with rationale',
      'Pilot results',
      'Implementation plan',
      'Improved performance data',
    ],
    questions: [
      'What solutions could address the root causes?',
      'Which solution is most feasible and effective?',
      'How can we pilot the solution?',
      'What are the risks of implementation?',
      'Did the solution achieve the expected results?',
    ],
  },
  {
    phase: 'C',
    name: 'Control',
    description: 'Sustain improvements and prevent regression.',
    objectives: [
      'Develop control plan',
      'Implement monitoring',
      'Document new process',
      'Train stakeholders',
      'Hand off to process owner',
    ],
    tools: [
      'Control Plan',
      'Control Charts',
      'Standard Operating Procedures',
      'Training Materials',
      'Response Plan',
    ],
    deliverables: [
      'Control plan',
      'Updated process documentation',
      'Training materials',
      'Monitoring dashboard',
      'Project closure report',
    ],
    questions: [
      'How will we maintain the gains?',
      'What controls are needed to prevent regression?',
      'How will we know if the process is out of control?',
      'Who owns the process going forward?',
      'What did we learn from this project?',
    ],
  },
];

// ============================================
// PROCESS EFFICIENCY METRICS
// ============================================

export interface EfficiencyMetric {
  id: string;
  name: string;
  category: string;
  formula: string;
  description: string;
  target: string;
  interpretation: string;
}

export const EFFICIENCY_METRICS: EfficiencyMetric[] = [
  {
    id: 'PCE',
    name: 'Process Cycle Efficiency',
    category: 'TIME',
    formula: 'PCE = Value-Added Time / Total Lead Time × 100%',
    description: 'Percentage of total time that adds value for the customer.',
    target: '>25% for service processes, >50% for manufacturing',
    interpretation: 'Low PCE indicates significant waste in the process. World-class is >50%.',
  },
  {
    id: 'FPY',
    name: 'First Pass Yield',
    category: 'QUALITY',
    formula: 'FPY = Units passing first time / Total units started × 100%',
    description: 'Percentage of work completed correctly the first time.',
    target: '>95%',
    interpretation: 'Low FPY indicates quality issues requiring rework.',
  },
  {
    id: 'RTY',
    name: 'Rolled Throughput Yield',
    category: 'QUALITY',
    formula: 'RTY = FPY₁ × FPY₂ × ... × FPYₙ',
    description: 'Probability of passing through entire process defect-free.',
    target: '>90%',
    interpretation: 'Multiplies individual step yields; small defects compound.',
  },
  {
    id: 'OEE',
    name: 'Overall Equipment Effectiveness',
    category: 'UTILIZATION',
    formula: 'OEE = Availability × Performance × Quality',
    description: 'Combined measure of equipment effectiveness.',
    target: '>85% (world-class)',
    interpretation: 'Availability = uptime; Performance = speed; Quality = defect-free output.',
  },
  {
    id: 'TAKT',
    name: 'Takt Time',
    category: 'TIME',
    formula: 'Takt = Available Production Time / Customer Demand',
    description: 'Pace of production needed to meet customer demand.',
    target: 'Process cycle time should be ≤ Takt time',
    interpretation: 'If cycle time > Takt, you cannot meet demand.',
  },
  {
    id: 'LT',
    name: 'Lead Time',
    category: 'TIME',
    formula: 'Lead Time = End Time - Start Time (total elapsed)',
    description: 'Total time from request to delivery.',
    target: 'Minimize; benchmark against industry',
    interpretation: 'Includes all waiting time, not just work time.',
  },
  {
    id: 'CT',
    name: 'Cycle Time',
    category: 'TIME',
    formula: 'Cycle Time = Processing time for one unit',
    description: 'Time to complete one cycle of the process.',
    target: 'Should be ≤ Takt time',
    interpretation: 'Does not include waiting; just active processing.',
  },
  {
    id: 'WIP',
    name: 'Work In Progress',
    category: 'INVENTORY',
    formula: 'WIP = Count of items currently in process',
    description: 'Amount of work started but not completed.',
    target: 'Minimize; set WIP limits',
    interpretation: 'High WIP = long queues, hidden problems, slow flow.',
  },
  {
    id: 'THROUGHPUT',
    name: 'Throughput',
    category: 'VOLUME',
    formula: 'Throughput = Units completed / Time period',
    description: 'Rate of completed output.',
    target: 'Should match or exceed demand',
    interpretation: 'Limited by bottleneck capacity.',
  },
  {
    id: 'COPQ',
    name: 'Cost of Poor Quality',
    category: 'COST',
    formula: 'COPQ = Internal failures + External failures + Appraisal + Prevention',
    description: 'Total cost associated with producing poor quality.',
    target: '<5% of revenue',
    interpretation: 'Includes rework, scrap, warranty, inspection, and prevention costs.',
  },
  {
    id: 'SIGMA',
    name: 'Sigma Level',
    category: 'QUALITY',
    formula: 'Based on DPMO (Defects Per Million Opportunities)',
    description: 'Statistical measure of process capability.',
    target: '6σ = 3.4 DPMO (world-class)',
    interpretation: '3σ = 66,807 DPMO; 4σ = 6,210 DPMO; 5σ = 233 DPMO.',
  },
];

// ============================================
// VALUE STREAM MAPPING
// ============================================

export interface ValueStreamElement {
  name: string;
  type: 'PROCESS' | 'INVENTORY' | 'TRANSPORT' | 'DECISION' | 'WAIT';
  cycleTime?: number;
  waitTime?: number;
  valueAdded: boolean;
  resources?: string[];
  defectRate?: number;
}

export class ValueStreamAnalyzer {
  // Analyze value stream
  analyze(elements: ValueStreamElement[]): {
    totalLeadTime: number;
    totalCycleTime: number;
    totalWaitTime: number;
    valueAddedTime: number;
    nonValueAddedTime: number;
    pce: number;
    bottleneck: string;
    recommendations: string[];
  } {
    let totalCycleTime = 0;
    let totalWaitTime = 0;
    let valueAddedTime = 0;
    let nonValueAddedTime = 0;
    let maxCycleTime = 0;
    let bottleneck = '';

    for (const element of elements) {
      const ct = element.cycleTime || 0;
      const wt = element.waitTime || 0;

      totalCycleTime += ct;
      totalWaitTime += wt;

      if (element.valueAdded) {
        valueAddedTime += ct;
      } else {
        nonValueAddedTime += ct;
      }

      if (element.type === 'PROCESS' && ct > maxCycleTime) {
        maxCycleTime = ct;
        bottleneck = element.name;
      }
    }

    const totalLeadTime = totalCycleTime + totalWaitTime;
    const pce = totalLeadTime > 0 ? (valueAddedTime / totalLeadTime) * 100 : 0;

    const recommendations: string[] = [];

    if (pce < 25) {
      recommendations.push('PCE is very low (<25%). Focus on eliminating wait time and non-value-added activities.');
    }

    if (totalWaitTime > totalCycleTime) {
      recommendations.push('Wait time exceeds cycle time. Investigate queue causes and implement flow improvements.');
    }

    if (bottleneck) {
      recommendations.push(`"${bottleneck}" is the bottleneck. Improving this step will increase overall throughput.`);
    }

    const highDefectElements = elements.filter(e => (e.defectRate || 0) > 5);
    if (highDefectElements.length > 0) {
      recommendations.push(`High defect rates at: ${highDefectElements.map(e => e.name).join(', ')}. Apply root cause analysis.`);
    }

    return {
      totalLeadTime,
      totalCycleTime,
      totalWaitTime,
      valueAddedTime,
      nonValueAddedTime,
      pce: Math.round(pce * 100) / 100,
      bottleneck,
      recommendations,
    };
  }
}

// ============================================
// OPERATIONAL AUDITOR CLASS
// ============================================

export class OperationalAuditor {
  private findings: Finding[] = [];
  private vsAnalyzer: ValueStreamAnalyzer;

  constructor() {
    this.vsAnalyzer = new ValueStreamAnalyzer();
  }

  // Assess TIMWOOD wastes
  assessWaste(context: string): Finding[] {
    const findings: Finding[] = [];

    for (const waste of TIMWOOD_WASTES) {
      findings.push({
        id: `TIMWOOD-${waste.id}-${randomUUID().slice(0, 4)}`,
        domain: 'OPERATIONAL',
        severity: 'INFO',
        status: 'REVIEW_REQUIRED',
        title: `TIMWOOD Waste: ${waste.name}`,
        description: `**${waste.acronym} - ${waste.name}**\n\n${waste.description}\n\n**Indicators:**\n${waste.indicators.map(i => `- ${i}`).join('\n')}\n\n**Assessment Questions:**\n${waste.questions.map(q => `- ${q}`).join('\n')}\n\n**Metrics to Track:**\n${waste.metrics.map(m => `- ${m}`).join('\n')}`,
        evidence: [{
          type: 'DATA',
          description: 'TIMWOOD waste assessment',
          source: context,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: `**Improvement Actions:**\n${waste.improvement.map(i => `- ${i}`).join('\n')}`,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Generate DMAIC project plan
  generateDMAICPlan(projectName: string): string {
    let plan = `# DMAIC Project Plan: ${projectName}\n\n`;
    plan += `Generated: ${new Date().toISOString()}\n\n`;
    plan += `---\n\n`;

    for (const phase of DMAIC_PHASES) {
      plan += `## ${phase.phase} - ${phase.name}\n\n`;
      plan += `${phase.description}\n\n`;

      plan += `### Objectives\n`;
      for (const obj of phase.objectives) {
        plan += `- [ ] ${obj}\n`;
      }

      plan += `\n### Tools\n`;
      for (const tool of phase.tools) {
        plan += `- ${tool}\n`;
      }

      plan += `\n### Deliverables\n`;
      for (const del of phase.deliverables) {
        plan += `- [ ] ${del}\n`;
      }

      plan += `\n### Key Questions\n`;
      for (const q of phase.questions) {
        plan += `- ${q}\n`;
      }

      plan += `\n---\n\n`;
    }

    return plan;
  }

  // Analyze efficiency metrics
  analyzeEfficiency(metrics: Record<string, number>): Finding[] {
    const findings: Finding[] = [];

    for (const metric of EFFICIENCY_METRICS) {
      const value = metrics[metric.id];
      if (value === undefined) continue;

      let severity: Severity = 'INFO';
      let status: 'PASS' | 'WARNING' | 'FAIL' = 'PASS';

      // Simple threshold checks (would be more sophisticated in real implementation)
      if (metric.id === 'PCE' && value < 25) {
        severity = 'HIGH';
        status = 'WARNING';
      } else if (metric.id === 'FPY' && value < 95) {
        severity = 'MEDIUM';
        status = 'WARNING';
      } else if (metric.id === 'OEE' && value < 85) {
        severity = 'MEDIUM';
        status = 'WARNING';
      }

      findings.push({
        id: `METRIC-${metric.id}-${randomUUID().slice(0, 4)}`,
        domain: 'OPERATIONAL',
        severity,
        status,
        title: `Efficiency Metric: ${metric.name}`,
        description: `**${metric.name}** (${metric.category})\n\n**Current Value:** ${value}\n\n**Formula:** ${metric.formula}\n\n**Target:** ${metric.target}\n\n**Interpretation:** ${metric.interpretation}`,
        evidence: [{
          type: 'DATA',
          description: `${metric.name} measurement`,
          content: `Value: ${value}`,
          source: 'Process metrics',
          collectedAt: new Date().toISOString(),
        }],
        recommendation: value < parseFloat(metric.target) ? `Investigate root causes for low ${metric.name}. Apply DMAIC methodology.` : 'Continue monitoring. Look for optimization opportunities.',
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Analyze value stream
  analyzeValueStream(elements: ValueStreamElement[], processName: string): Finding {
    const analysis = this.vsAnalyzer.analyze(elements);

    const finding: Finding = {
      id: `VSM-${randomUUID().slice(0, 8)}`,
      domain: 'OPERATIONAL',
      severity: analysis.pce < 25 ? 'HIGH' : analysis.pce < 50 ? 'MEDIUM' : 'INFO',
      status: analysis.pce < 25 ? 'WARNING' : 'PASS',
      title: `Value Stream Analysis: ${processName}`,
      description: `**Value Stream Metrics:**\n\n` +
        `- Total Lead Time: ${analysis.totalLeadTime} units\n` +
        `- Total Cycle Time: ${analysis.totalCycleTime} units\n` +
        `- Total Wait Time: ${analysis.totalWaitTime} units\n` +
        `- Value-Added Time: ${analysis.valueAddedTime} units\n` +
        `- Non-Value-Added Time: ${analysis.nonValueAddedTime} units\n` +
        `- **Process Cycle Efficiency: ${analysis.pce}%**\n` +
        `- Bottleneck: ${analysis.bottleneck || 'None identified'}\n`,
      evidence: [{
        type: 'DATA',
        description: 'Value stream map analysis',
        content: JSON.stringify(analysis, null, 2),
        source: processName,
        collectedAt: new Date().toISOString(),
      }],
      recommendation: analysis.recommendations.join('\n\n'),
      timestamp: new Date().toISOString(),
    };

    this.findings.push(finding);
    return finding;
  }

  // Get efficiency metrics reference
  getMetricsReference(): EfficiencyMetric[] {
    return EFFICIENCY_METRICS;
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
export const operationalAuditor = new OperationalAuditor();
export const valueStreamAnalyzer = new ValueStreamAnalyzer();
