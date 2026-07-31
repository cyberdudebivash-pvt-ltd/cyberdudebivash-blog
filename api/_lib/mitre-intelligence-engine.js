'use strict';

class MITREIntelligenceEngine {
  generateMITREIntelligence(investigation) {
    return {
      techniques: this.analyzeTechniques(investigation),
      tactics: this.analyzeTactics(investigation),
      coverage: this.assessCoverage(investigation),
      gaps: this.identifyGaps(investigation),
      detectionOpportunities: this.identifyDetectionOpportunities(investigation),
    };
  }

  analyzeTechniques(investigation) {
    const techniques = investigation.mitreTechniques || [];
    return techniques.map(t => {
      const techniqueData = this.lookupTechnique(t);
      return {
        id: techniqueData.id || t,
        name: techniqueData.name || t,
        tactic: techniqueData.tactic,
        description: techniqueData.description,
        procedure: this.extractProcedure(investigation, t),
        datasources: techniqueData.dataSources || [],
        detection: techniqueData.detection || 'Difficult to detect',
        mitigation: techniqueData.mitigation || [],
        evidence: this.findEvidenceForTechnique(investigation, t),
        severity: this.assessTechniqueSeverity(t),
      };
    });
  }

  analyzeTactics(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const tactics = [...new Set(techniques.map(t => this.getTactic(t)))];

    return tactics.map(tactic => ({
      tactic,
      displayName: this.getDisplayName(tactic),
      description: this.getTacticDescription(tactic),
      techniquesUsed: techniques.filter(t => this.getTactic(t) === tactic),
      coverage: {
        observed: techniques.filter(t => this.getTactic(t) === tactic).length,
        total: this.getTacticTechniqueCount(tactic),
      },
    }));
  }

  assessCoverage(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const allTechniques = 188; // Approximate MITRE ATT&CK technique count

    const coverage = {
      totalTechniques: techniques.length,
      coveragePercentage: parseFloat(((techniques.length / allTechniques) * 100).toFixed(1)),
      tactics: this.countTactics(investigation),
      tactics_total: 14,
    };

    coverage.tacticalCoverage = parseFloat(((coverage.tactics / coverage.tactics_total) * 100).toFixed(1));

    return coverage;
  }

  identifyGaps(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const allTactics = [
      'Reconnaissance',
      'Resource Development',
      'Initial Access',
      'Execution',
      'Persistence',
      'Privilege Escalation',
      'Defense Evasion',
      'Credential Access',
      'Discovery',
      'Lateral Movement',
      'Collection',
      'Command and Control',
      'Exfiltration',
      'Impact',
    ];

    const usedTactics = [...new Set(techniques.map(t => this.getTactic(t)))];
    const gaps = allTactics.filter(t => !usedTactics.includes(t));

    return {
      missingTactics: gaps,
      tacticalGapCount: gaps.length,
      recommendations: this.generateGapRecommendations(gaps, investigation),
    };
  }

  identifyDetectionOpportunities(investigation) {
    const techniques = investigation.mitreTechniques || [];

    return techniques.slice(0, 10).map(technique => {
      const techniqueData = this.lookupTechnique(technique);
      return {
        technique: technique,
        detectionChallenges: techniqueData.detectionChallenges || [],
        dataSourcesNeeded: techniqueData.dataSources || [],
        detectionStrategies: [
          {
            approach: 'Log Analysis',
            tool: 'SIEM',
            effectiveness: 'Medium',
          },
          {
            approach: 'Behavior Monitoring',
            tool: 'EDR',
            effectiveness: 'High',
          },
          {
            approach: 'Network Detection',
            tool: 'IDS/IPS',
            effectiveness: this.getNetworkDetectionEffectiveness(technique),
          },
        ],
        priority: this.assessDetectionPriority(technique),
      };
    });
  }

  lookupTechnique(technique) {
    const techniqueDatabase = {
      'T1047': {
        id: 'T1047',
        name: 'Windows Management Instrumentation',
        tactic: 'Execution',
        description: 'Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands',
        dataSources: ['Process execution', 'Command line arguments', 'WMI logs'],
        detection: 'Monitor for WMI command line arguments and unusual parent processes',
        mitigation: ['Disable WMI', 'Restrict access', 'Monitor WMI activities'],
      },
      'T1055': {
        id: 'T1055',
        name: 'Process Injection',
        tactic: 'Defense Evasion',
        description: 'Adversaries may inject code into processes to evade process-based defenses',
        dataSources: ['Process monitoring', 'API monitoring'],
        detection: 'Monitor for suspicious process creation and memory writes',
        mitigation: ['Endpoint protection', 'Memory protection', 'Code signing'],
      },
    };

    return techniqueDatabase[technique] || {
      id: technique,
      name: technique,
      description: 'Technique details not available',
    };
  }

  extractProcedure(investigation, technique) {
    const findings = investigation.findings || [];
    const matching = findings.filter(f => f.technique === technique || f.description?.includes(technique));
    return matching.map(m => ({
      description: m.description,
      evidence: m.evidence,
    }));
  }

  findEvidenceForTechnique(investigation, technique) {
    const findings = (investigation.findings || []).filter(f =>
      f.technique === technique || f.description?.includes(technique)
    );
    const iocs = (investigation.iocs || []).filter(i =>
      i.associatedTechniques?.includes(technique)
    );

    return {
      findings: findings.length,
      iocs: iocs.length,
      total: findings.length + iocs.length,
    };
  }

  assessTechniqueSeverity(technique) {
    if (technique.includes('Exploitation') || technique.includes('Privilege Escalation')) return 'Critical';
    if (technique.includes('Persistence') || technique.includes('C2')) return 'High';
    if (technique.includes('Discovery') || technique.includes('Reconnaissance')) return 'Medium';
    return 'Low';
  }

  getTactic(technique) {
    if (technique.includes('Reconnaissance')) return 'Reconnaissance';
    if (technique.includes('Phishing') || technique.includes('Supply')) return 'Initial Access';
    if (technique.includes('Exploit')) return 'Exploitation';
    if (technique.includes('Persistence') || technique.includes('Installation')) return 'Persistence';
    if (technique.includes('Privilege')) return 'Privilege Escalation';
    if (technique.includes('Evasion')) return 'Defense Evasion';
    if (technique.includes('Credential')) return 'Credential Access';
    if (technique.includes('Discovery')) return 'Discovery';
    if (technique.includes('Lateral')) return 'Lateral Movement';
    if (technique.includes('Collection')) return 'Collection';
    if (technique.includes('C2') || technique.includes('Command')) return 'Command and Control';
    if (technique.includes('Exfiltration')) return 'Exfiltration';
    if (technique.includes('Impact')) return 'Impact';
    return 'Unknown';
  }

  getDisplayName(tactic) {
    const names = {
      'Reconnaissance': 'Reconnaissance',
      'Initial Access': 'Initial Access',
      'Exploitation': 'Execution',
      'Persistence': 'Persistence',
      'Privilege Escalation': 'Privilege Escalation',
      'Defense Evasion': 'Defense Evasion',
      'Credential Access': 'Credential Access',
      'Discovery': 'Discovery',
      'Lateral Movement': 'Lateral Movement',
      'Collection': 'Collection',
      'Command and Control': 'Command & Control',
      'Exfiltration': 'Exfiltration',
      'Impact': 'Impact',
    };
    return names[tactic] || tactic;
  }

  getTacticDescription(tactic) {
    const descriptions = {
      'Reconnaissance': 'Gathering information used for targeting',
      'Initial Access': 'Techniques for gaining initial foothold',
      'Execution': 'Techniques for running code',
      'Persistence': 'Techniques for maintaining access',
      'Privilege Escalation': 'Techniques for gaining higher privileges',
      'Defense Evasion': 'Techniques for avoiding detection',
      'Credential Access': 'Techniques for stealing credentials',
      'Discovery': 'Techniques for exploring the network',
      'Lateral Movement': 'Techniques for moving within the network',
      'Collection': 'Techniques for gathering data',
      'Command and Control': 'Techniques for communicating with infrastructure',
      'Exfiltration': 'Techniques for stealing data',
      'Impact': 'Techniques for disrupting operations',
    };
    return descriptions[tactic] || '';
  }

  getTacticTechniqueCount(tactic) {
    const counts = {
      'Reconnaissance': 10,
      'Resource Development': 16,
      'Initial Access': 9,
      'Execution': 14,
      'Persistence': 19,
      'Privilege Escalation': 15,
      'Defense Evasion': 40,
      'Credential Access': 16,
      'Discovery': 14,
      'Lateral Movement': 9,
      'Collection': 18,
      'Command and Control': 16,
      'Exfiltration': 9,
      'Impact': 13,
    };
    return counts[tactic] || 10;
  }

  countTactics(investigation) {
    const techniques = investigation.mitreTechniques || [];
    return [...new Set(techniques.map(t => this.getTactic(t)))].length;
  }

  generateGapRecommendations(gaps, investigation) {
    return gaps.map(gap => ({
      tactic: gap,
      recommendation: `Develop detection and hunting strategies for ${gap} techniques`,
      priority: 'Medium',
    }));
  }

  getNetworkDetectionEffectiveness(technique) {
    if (technique.includes('C2') || technique.includes('Command')) return 'High';
    if (technique.includes('Exfiltration')) return 'High';
    if (technique.includes('Lateral')) return 'Medium';
    return 'Low';
  }

  assessDetectionPriority(technique) {
    if (this.assessTechniqueSeverity(technique) === 'Critical') return 'Immediate';
    if (this.assessTechniqueSeverity(technique) === 'High') return 'High';
    return 'Medium';
  }
}

module.exports = { MITREIntelligenceEngine };
