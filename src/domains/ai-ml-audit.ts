// AI/ML Audit Module
// Covers: Model Bias, Fairness, Explainability, Data Quality, Model Drift, Algorithmic Accountability

import { Finding, Evidence, Severity, AuditDomain } from '../core/types.js';
import { randomUUID } from 'crypto';

// ============================================
// AI RISK CATEGORIES
// ============================================

export interface AIRiskCategory {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  indicators: string[];
  assessmentQuestions: string[];
  mitigations: string[];
  regulations: string[];
}

export const AI_RISK_CATEGORIES: AIRiskCategory[] = [
  // Bias and Fairness
  {
    id: 'AI-BIAS-001',
    name: 'Training Data Bias',
    severity: 'HIGH',
    description: 'Model trained on biased or unrepresentative data, leading to discriminatory outcomes.',
    indicators: [
      'Training data not representative of target population',
      'Historical bias embedded in training data',
      'Underrepresentation of protected groups',
      'Proxy variables that correlate with protected attributes',
      'Label bias from human annotators',
    ],
    assessmentQuestions: [
      'What is the source and composition of training data?',
      'Are protected groups adequately represented?',
      'Was the labeling process audited for bias?',
      'Are there proxy variables that correlate with protected attributes?',
      'Has the data been tested for historical bias?',
    ],
    mitigations: [
      'Conduct demographic analysis of training data',
      'Implement stratified sampling',
      'Use bias detection tools (IBM AI Fairness 360)',
      'Apply pre-processing bias mitigation techniques',
      'Document data provenance and limitations',
    ],
    regulations: ['EU AI Act', 'NYC Local Law 144', 'EEOC Guidelines'],
  },
  {
    id: 'AI-BIAS-002',
    name: 'Algorithmic Bias',
    severity: 'HIGH',
    description: 'Model produces systematically different outcomes for different groups.',
    indicators: [
      'Disparate impact across demographic groups',
      'Different error rates by group',
      'Proxy discrimination patterns',
      'Feedback loops amplifying bias',
    ],
    assessmentQuestions: [
      'What are the model outcomes by demographic group?',
      'Are false positive/negative rates equal across groups?',
      'Does the model exhibit disparate impact?',
      'Are there feedback loops that could amplify bias?',
    ],
    mitigations: [
      'Calculate demographic parity metrics',
      'Implement equalized odds constraints',
      'Apply in-processing fairness techniques',
      'Regular disparate impact analysis',
      'Implement fairness-aware learning algorithms',
    ],
    regulations: ['EU AI Act', 'US Equal Credit Opportunity Act', 'Fair Housing Act'],
  },
  {
    id: 'AI-BIAS-003',
    name: 'Output Bias',
    severity: 'HIGH',
    description: 'Model outputs perpetuate or amplify existing societal biases.',
    indicators: [
      'Generated content contains stereotypes',
      'Recommendations reinforce existing patterns',
      'Decisions disproportionately affect certain groups',
    ],
    assessmentQuestions: [
      'Do model outputs contain harmful stereotypes?',
      'Are recommendations diversified or filter-bubbled?',
      'What is the impact of decisions on different groups?',
    ],
    mitigations: [
      'Implement output filters for harmful content',
      'Apply post-processing bias mitigation',
      'Regular human review of outputs',
      'Diverse evaluation teams',
    ],
    regulations: ['EU AI Act', 'Digital Services Act'],
  },

  // Explainability
  {
    id: 'AI-XAI-001',
    name: 'Model Explainability',
    severity: 'MEDIUM',
    description: 'Model decisions cannot be explained or understood by humans.',
    indicators: [
      'Black-box model with no explanation capability',
      'Explanations not provided to affected individuals',
      'Feature importance not documented',
      'Decision rationale not auditable',
    ],
    assessmentQuestions: [
      'Can individual predictions be explained?',
      'Are explanations provided to affected individuals?',
      'Is feature importance documented?',
      'Can decisions be audited and challenged?',
    ],
    mitigations: [
      'Implement LIME or SHAP for local explanations',
      'Use inherently interpretable models where possible',
      'Document feature importance globally',
      'Provide user-facing explanations',
      'Maintain decision audit logs',
    ],
    regulations: ['GDPR Article 22', 'EU AI Act', 'CCPA'],
  },
  {
    id: 'AI-XAI-002',
    name: 'Decision Transparency',
    severity: 'MEDIUM',
    description: 'Lack of transparency about how AI is used in decision-making.',
    indicators: [
      'Users unaware AI is being used',
      'Decision criteria not disclosed',
      'No mechanism to challenge decisions',
      'Automated decisions without human oversight',
    ],
    assessmentQuestions: [
      'Are users informed when AI is used?',
      'Is the role of AI in decisions disclosed?',
      'Can affected individuals challenge decisions?',
      'Is there human oversight of automated decisions?',
    ],
    mitigations: [
      'Disclose AI use in user-facing communications',
      'Document decision criteria',
      'Implement appeals process',
      'Ensure human-in-the-loop for high-stakes decisions',
    ],
    regulations: ['GDPR Article 13-14', 'EU AI Act Article 13', 'NYC Local Law 144'],
  },

  // Data Quality
  {
    id: 'AI-DATA-001',
    name: 'Data Quality Issues',
    severity: 'HIGH',
    description: 'Poor quality training or inference data leading to unreliable model outputs.',
    indicators: [
      'Missing values in critical features',
      'Data entry errors or inconsistencies',
      'Outdated data not reflecting current state',
      'Data leakage between training and test sets',
      'Mislabeled training examples',
    ],
    assessmentQuestions: [
      'What is the completeness of the data?',
      'Are there data quality metrics in place?',
      'How is data freshness maintained?',
      'Has data leakage been tested for?',
      'What is the label quality assurance process?',
    ],
    mitigations: [
      'Implement data quality monitoring',
      'Establish data validation pipelines',
      'Regular data freshness checks',
      'Proper train/test split validation',
      'Label quality assurance processes',
    ],
    regulations: ['GDPR Article 5', 'EU AI Act'],
  },
  {
    id: 'AI-DATA-002',
    name: 'Data Privacy',
    severity: 'CRITICAL',
    description: 'Training data contains personal information without proper consent or safeguards.',
    indicators: [
      'PII in training data without consent',
      'Insufficient anonymization',
      'Model memorization of training data',
      'No data minimization applied',
    ],
    assessmentQuestions: [
      'Is consent obtained for personal data in training?',
      'Is PII properly anonymized or pseudonymized?',
      'Can the model leak training data?',
      'Is data minimization principle applied?',
    ],
    mitigations: [
      'Implement differential privacy',
      'Apply k-anonymity or l-diversity',
      'Test for memorization attacks',
      'Data minimization in feature engineering',
      'Federated learning where applicable',
    ],
    regulations: ['GDPR', 'CCPA', 'HIPAA', 'EU AI Act'],
  },

  // Model Drift
  {
    id: 'AI-DRIFT-001',
    name: 'Data Drift',
    severity: 'HIGH',
    description: 'Distribution of production data differs from training data.',
    indicators: [
      'Feature distributions changing over time',
      'New categories appearing in categorical variables',
      'Statistical properties shifting',
      'Seasonal patterns not captured',
    ],
    assessmentQuestions: [
      'Is input data distribution monitored?',
      'Are there alerts for distribution shifts?',
      'How is drift measured and tracked?',
      'What is the retraining trigger?',
    ],
    mitigations: [
      'Implement continuous distribution monitoring',
      'Use statistical tests for drift detection',
      'Establish drift thresholds and alerts',
      'Automate retraining pipelines',
    ],
    regulations: ['EU AI Act Article 9'],
  },
  {
    id: 'AI-DRIFT-002',
    name: 'Concept Drift',
    severity: 'HIGH',
    description: 'The relationship between inputs and outputs changes over time.',
    indicators: [
      'Model accuracy degrading over time',
      'Ground truth labels no longer matching predictions',
      'Business rules or regulations changed',
      'User behavior patterns evolved',
    ],
    assessmentQuestions: [
      'Is model performance continuously monitored?',
      'How quickly can concept drift be detected?',
      'What is the feedback loop for ground truth?',
      'Are there mechanisms to detect silent failures?',
    ],
    mitigations: [
      'Continuous performance monitoring',
      'Ground truth feedback loops',
      'A/B testing new model versions',
      'Champion-challenger model deployment',
    ],
    regulations: ['EU AI Act Article 9'],
  },

  // Security
  {
    id: 'AI-SEC-001',
    name: 'Adversarial Attacks',
    severity: 'HIGH',
    description: 'Model vulnerable to adversarial inputs designed to cause misclassification.',
    indicators: [
      'No adversarial robustness testing',
      'Model sensitive to small input perturbations',
      'No input validation or sanitization',
    ],
    assessmentQuestions: [
      'Has adversarial robustness been tested?',
      'Are inputs validated and sanitized?',
      'What is the impact of misclassification?',
      'Are there defense mechanisms in place?',
    ],
    mitigations: [
      'Adversarial training',
      'Input validation and anomaly detection',
      'Ensemble methods for robustness',
      'Regular adversarial testing',
    ],
    regulations: ['EU AI Act Article 15', 'NIST AI RMF'],
  },
  {
    id: 'AI-SEC-002',
    name: 'Model Extraction',
    severity: 'MEDIUM',
    description: 'Model intellectual property can be stolen through query access.',
    indicators: [
      'No rate limiting on model API',
      'Detailed prediction outputs exposed',
      'No monitoring for extraction patterns',
    ],
    assessmentQuestions: [
      'Is API access rate limited?',
      'What level of detail is returned in predictions?',
      'Is query pattern monitoring in place?',
      'What is the value of the model IP?',
    ],
    mitigations: [
      'Implement rate limiting',
      'Return only necessary prediction detail',
      'Monitor for extraction attack patterns',
      'Watermark model outputs',
    ],
    regulations: ['Trade secret law', 'Computer Fraud and Abuse Act'],
  },

  // Governance
  {
    id: 'AI-GOV-001',
    name: 'Model Governance',
    severity: 'HIGH',
    description: 'Lack of governance processes for AI model lifecycle.',
    indicators: [
      'No model inventory or registry',
      'Unclear model ownership',
      'No model risk classification',
      'Missing model documentation',
      'No approval process for deployment',
    ],
    assessmentQuestions: [
      'Is there a centralized model inventory?',
      'Are model owners clearly defined?',
      'Is model risk classified?',
      'Is model documentation complete?',
      'What is the model approval process?',
    ],
    mitigations: [
      'Implement model registry (MLflow, etc.)',
      'Define model ownership RACI',
      'Implement model risk tiering',
      'Standardize model documentation (model cards)',
      'Establish model validation and approval process',
    ],
    regulations: ['EU AI Act', 'SR 11-7 (banking)', 'NIST AI RMF'],
  },
  {
    id: 'AI-GOV-002',
    name: 'Human Oversight',
    severity: 'HIGH',
    description: 'Insufficient human oversight of AI systems.',
    indicators: [
      'Fully automated decisions without review',
      'No mechanism to override AI decisions',
      'Operators not trained on AI limitations',
      'Over-reliance on AI outputs',
    ],
    assessmentQuestions: [
      'Is there human-in-the-loop for high-risk decisions?',
      'Can operators override AI recommendations?',
      'Are operators trained on AI capabilities and limitations?',
      'Is there documented guidance on when to trust AI?',
    ],
    mitigations: [
      'Implement human-in-the-loop for high-risk decisions',
      'Provide override mechanisms',
      'Train operators on AI limitations',
      'Document appropriate use guidelines',
    ],
    regulations: ['EU AI Act Article 14', 'GDPR Article 22'],
  },
];

// ============================================
// FAIRNESS METRICS
// ============================================

export interface FairnessMetric {
  id: string;
  name: string;
  formula: string;
  description: string;
  threshold: string;
  tradeoffs: string;
}

export const FAIRNESS_METRICS: FairnessMetric[] = [
  {
    id: 'DI',
    name: 'Disparate Impact',
    formula: 'DI = (Favorable outcome rate for unprivileged) / (Favorable outcome rate for privileged)',
    description: 'Ratio of favorable outcomes between groups. Also known as 80% rule.',
    threshold: 'DI > 0.8 (80% rule) is considered non-discriminatory',
    tradeoffs: 'Does not account for legitimate factors. May conflict with individual fairness.',
  },
  {
    id: 'SPD',
    name: 'Statistical Parity Difference',
    formula: 'SPD = P(Y=1|D=0) - P(Y=1|D=1)',
    description: 'Difference in favorable outcome rates between groups.',
    threshold: 'SPD close to 0 indicates parity',
    tradeoffs: 'Ignores accuracy. May not be appropriate when base rates differ.',
  },
  {
    id: 'EOD',
    name: 'Equal Opportunity Difference',
    formula: 'EOD = TPR(D=0) - TPR(D=1)',
    description: 'Difference in true positive rates between groups.',
    threshold: 'EOD close to 0 indicates equal opportunity',
    tradeoffs: 'Only considers positive class. May not detect discrimination in negative outcomes.',
  },
  {
    id: 'AOD',
    name: 'Average Odds Difference',
    formula: 'AOD = [(TPR(D=0) - TPR(D=1)) + (FPR(D=0) - FPR(D=1))] / 2',
    description: 'Average of TPR and FPR differences.',
    threshold: 'AOD close to 0 indicates equalized odds',
    tradeoffs: 'Balances true positives and false positives. May conflict with calibration.',
  },
  {
    id: 'TI',
    name: 'Theil Index',
    formula: 'TI = (1/n) Σ (benefit_i / μ) * ln(benefit_i / μ)',
    description: 'Inequality measure from economics applied to model benefits.',
    threshold: 'TI = 0 indicates perfect equality',
    tradeoffs: 'Measures overall inequality, not specific to protected groups.',
  },
];

// ============================================
// MODEL CARD TEMPLATE
// ============================================

export interface ModelCard {
  modelDetails: {
    name: string;
    version: string;
    type: string;
    owner: string;
    dateCreated: string;
    lastUpdated: string;
    description: string;
  };
  intendedUse: {
    primaryUse: string;
    outOfScopeUses: string[];
    users: string[];
  };
  trainingData: {
    description: string;
    source: string;
    preprocessing: string;
    size: string;
    demographics?: Record<string, string>;
  };
  evaluation: {
    metrics: Record<string, number>;
    testData: string;
    fairnessMetrics?: Record<string, number>;
  };
  ethicalConsiderations: {
    risks: string[];
    mitigations: string[];
    limitations: string[];
  };
  caveats: string[];
}

// ============================================
// AI/ML AUDITOR CLASS
// ============================================

export class AIMLAuditor {
  private findings: Finding[] = [];

  // Assess AI risks
  assessAIRisks(context: string): Finding[] {
    const findings: Finding[] = [];

    for (const risk of AI_RISK_CATEGORIES) {
      findings.push({
        id: `${risk.id}-${randomUUID().slice(0, 4)}`,
        domain: 'AI_ML',
        severity: risk.severity,
        status: 'REVIEW_REQUIRED',
        title: `AI Risk: ${risk.name}`,
        description: `${risk.description}\n\n**Risk Indicators:**\n${risk.indicators.map(i => `- ${i}`).join('\n')}\n\n**Assessment Questions:**\n${risk.assessmentQuestions.map(q => `- ${q}`).join('\n')}\n\n**Relevant Regulations:**\n${risk.regulations.map(r => `- ${r}`).join('\n')}`,
        evidence: [{
          type: 'DATA',
          description: 'AI/ML risk assessment',
          source: context,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: `**Mitigations:**\n${risk.mitigations.map(m => `- ${m}`).join('\n')}`,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Assess fairness metrics
  assessFairness(metrics: Record<string, number>, context: string): Finding[] {
    const findings: Finding[] = [];

    for (const metric of FAIRNESS_METRICS) {
      const value = metrics[metric.id];
      if (value === undefined) continue;

      let severity: Severity = 'INFO';
      let status: 'PASS' | 'WARNING' | 'FAIL' = 'PASS';

      // Check thresholds
      if (metric.id === 'DI' && value < 0.8) {
        severity = 'HIGH';
        status = 'FAIL';
      } else if (['SPD', 'EOD', 'AOD'].includes(metric.id) && Math.abs(value) > 0.1) {
        severity = 'HIGH';
        status = 'WARNING';
      }

      findings.push({
        id: `FAIR-${metric.id}-${randomUUID().slice(0, 4)}`,
        domain: 'AI_ML',
        severity,
        status,
        title: `Fairness Metric: ${metric.name}`,
        description: `**${metric.name}**\n\n**Current Value:** ${value.toFixed(4)}\n\n**Formula:** ${metric.formula}\n\n**Threshold:** ${metric.threshold}\n\n**Trade-offs:** ${metric.tradeoffs}`,
        evidence: [{
          type: 'DATA',
          description: `${metric.name} measurement`,
          content: `Value: ${value}`,
          source: context,
          collectedAt: new Date().toISOString(),
        }],
        recommendation: status === 'PASS'
          ? 'Continue monitoring. Consider testing with additional demographic slices.'
          : `Investigate root cause of fairness disparity. Apply bias mitigation techniques.`,
        timestamp: new Date().toISOString(),
      });
    }

    this.findings.push(...findings);
    return findings;
  }

  // Generate model card template
  generateModelCardTemplate(modelName: string): string {
    let template = `# Model Card: ${modelName}\n\n`;
    template += `Generated: ${new Date().toISOString()}\n\n`;
    template += `---\n\n`;

    template += `## Model Details\n\n`;
    template += `- **Name:** ${modelName}\n`;
    template += `- **Version:** \n`;
    template += `- **Type:** \n`;
    template += `- **Owner:** \n`;
    template += `- **Date Created:** \n`;
    template += `- **Last Updated:** \n`;
    template += `- **Description:** \n\n`;

    template += `## Intended Use\n\n`;
    template += `- **Primary Use Case:** \n`;
    template += `- **Out-of-Scope Uses:**\n  - \n`;
    template += `- **Intended Users:** \n\n`;

    template += `## Training Data\n\n`;
    template += `- **Description:** \n`;
    template += `- **Source:** \n`;
    template += `- **Preprocessing:** \n`;
    template += `- **Size:** \n`;
    template += `- **Demographics:**\n  - \n\n`;

    template += `## Evaluation\n\n`;
    template += `### Performance Metrics\n\n`;
    template += `| Metric | Value |\n`;
    template += `|--------|-------|\n`;
    template += `| Accuracy | |\n`;
    template += `| Precision | |\n`;
    template += `| Recall | |\n`;
    template += `| F1 Score | |\n`;
    template += `| AUC-ROC | |\n\n`;

    template += `### Fairness Metrics\n\n`;
    template += `| Metric | Value |\n`;
    template += `|--------|-------|\n`;
    template += `| Disparate Impact | |\n`;
    template += `| Statistical Parity Diff | |\n`;
    template += `| Equal Opportunity Diff | |\n\n`;

    template += `## Ethical Considerations\n\n`;
    template += `### Risks\n`;
    template += `- \n\n`;
    template += `### Mitigations\n`;
    template += `- \n\n`;
    template += `### Limitations\n`;
    template += `- \n\n`;

    template += `## Caveats and Recommendations\n\n`;
    template += `- \n\n`;

    template += `---\n`;
    template += `*Model card based on [Mitchell et al., 2019](https://arxiv.org/abs/1810.03993)*\n`;

    return template;
  }

  // Get fairness metrics reference
  getFairnessMetrics(): FairnessMetric[] {
    return FAIRNESS_METRICS;
  }

  // Get AI risk categories
  getAIRiskCategories(): AIRiskCategory[] {
    return AI_RISK_CATEGORIES;
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
export const aimlAuditor = new AIMLAuditor();
