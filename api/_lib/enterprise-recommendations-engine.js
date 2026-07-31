'use strict';

class EnterpriseRecommendationsEngine {
  generateEnterpriseRecommendations(investigation, report, audience = 'general') {
    const recommendations = {
      executive: this.generateExecutiveActions(investigation),
      soc: this.generateSOCActions(investigation),
      threatHunting: this.generateThreatHuntingGuide(investigation),
      detectionEngineering: this.generateDetectionEngineeringActions(investigation),
      incidentResponse: this.generateIncidentResponseActions(investigation),
      cloudSecurity: this.generateCloudSecurityActions(investigation),
      identityAndAccess: this.generateIdentityActions(investigation),
      endpoint: this.generateEndpointActions(investigation),
      email: this.generateEmailActions(investigation),
      network: this.generateNetworkActions(investigation),
      thirdPartyRisk: this.generateThirdPartyActions(investigation),
      compliance: this.generateComplianceActions(investigation),
      generatedAt: new Date().toISOString(),
    };

    return recommendations;
  }

  generateExecutiveActions(investigation) {
    const threatActors = investigation.threatActors || [];
    const victims = investigation.victims || [];

    return {
      title: 'Executive Actions',
      priority: 'Immediate',
      actions: [
        {
          action: 'Notify Board of Directors',
          rationale: `Breach scope affects ${victims.length} organizations; regulatory notification may be required`,
          timeline: 'Immediate',
          owner: 'CISO',
          successMetrics: ['Board notification completed', 'Regulatory requirements assessed'],
        },
        {
          action: 'Activate Crisis Management',
          rationale: 'Establish incident command structure and communication protocols',
          timeline: '1 hour',
          owner: 'CRO/VP Communications',
          successMetrics: ['Incident command activated', 'Communication plan established'],
        },
        {
          action: 'Engage External Counsel',
          rationale: 'Legal review required for regulatory and contractual obligations',
          timeline: '2 hours',
          owner: 'General Counsel',
          successMetrics: ['Counsel engaged', 'Legal assessment completed'],
        },
        {
          action: 'Notify Key Stakeholders',
          rationale: 'Investors, partners, customers must be informed of impact assessment',
          timeline: '4 hours',
          owner: 'CEO/COO',
          successMetrics: ['Stakeholder notification complete', 'Impact assessment shared'],
        },
        {
          action: 'Establish Incident Budget',
          rationale: 'Forensics, remediation, and notification costs require authorization',
          timeline: '4 hours',
          owner: 'CFO',
          successMetrics: ['Budget approved', 'Vendor contracts activated'],
        },
      ],
      businessContext: `Industry impact: ${this.extractIndustries(investigation).join(', ')} | Victims: ${victims.length} | Attribution: ${threatActors[0]?.name || 'TBD'}`,
    };
  }

  generateSOCActions(investigation) {
    const iocs = investigation.iocs || [];
    const techniques = investigation.mitreTechniques || [];

    return {
      title: 'Security Operations Center Actions',
      priority: 'Urgent',
      immediateActions: [
        {
          action: 'Hunt IOCs Across Infrastructure',
          iocs: iocs.slice(0, 10),
          expectedOutcome: 'Identify active intrusions and lateral movement',
          effort: 'High',
          timeline: '30 minutes',
        },
        {
          action: 'Review EDR/XDR Alerts',
          techniques: techniques.slice(0, 5),
          expectedOutcome: 'Identify missed alerts and detection gaps',
          effort: 'High',
          timeline: '1 hour',
        },
        {
          action: 'Escalate Confirmed Cases',
          expectedOutcome: 'Activate incident response for confirmed compromises',
          effort: 'Medium',
          timeline: 'As detected',
        },
      ],
      continuousMonitoring: [
        {
          detection: 'C2 Beaconing',
          tool: 'Network monitoring',
          indicator: investigation.c2Domains || [],
        },
        {
          detection: 'Privilege Escalation',
          tool: 'EDR/XDR',
          techniques: this.filterTechniquesByTactic(techniques, 'Privilege Escalation'),
        },
        {
          detection: 'Data Exfiltration',
          tool: 'Network/DLP',
          indicators: (investigation.exfiltrationChannels || []).slice(0, 3),
        },
      ],
      iocsForHunting: {
        ips: iocs.filter(i => i.type === 'IP'),
        domains: iocs.filter(i => i.type === 'Domain'),
        hashes: iocs.filter(i => i.type === 'File Hash'),
        urls: iocs.filter(i => i.type === 'URL'),
      },
    };
  }

  generateThreatHuntingGuide(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const threatActors = investigation.threatActors || [];

    return {
      title: 'Threat Hunting Guide',
      objective: `Hunt for activity from ${threatActors[0]?.name || 'similar threat actors'} using observed techniques`,
      priorityTechniques: techniques.slice(0, 8),
      huntingQueries: [
        {
          technique: 'Command and Control',
          query: 'Search for beaconing patterns to identified C2 servers',
          tool: 'Network logs / Zeek',
          searchTerm: investigation.c2Domains?.slice(0, 3) || [],
        },
        {
          technique: 'Data Staging',
          query: 'Search for large file aggregations and compression activities',
          tool: 'File activity monitoring',
          searchTerm: ['7zip', 'WinRAR', 'tar', 'zip'],
        },
        {
          technique: 'Lateral Movement',
          query: 'Search for unusual RDP, WinRM, or SSH connections',
          tool: 'EDR / Network logs',
          searchTerm: ['RDP', 'WinRM', 'SSH'],
        },
        {
          technique: 'Privilege Escalation',
          query: 'Search for token impersonation and elevation attempts',
          tool: 'EDR',
          searchTerm: ['token impersonation', 'UAC bypass', 'runas'],
        },
      ],
      expectedFindings: [
        'Historical intrusion evidence',
        'Undetected lateral movement',
        'Data staging activities',
        'Persistence mechanisms',
      ],
      estimatedTimeToComplete: '24-48 hours',
    };
  }

  generateDetectionEngineeringActions(investigation) {
    const techniques = investigation.mitreTechniques || [];

    return {
      title: 'Detection Engineering Actions',
      priority: 'High',
      detectionGaps: techniques.slice(0, 5).map(t => ({
        technique: t,
        priority: 'High',
        suggestedRules: ['Sigma', 'YARA', 'Suricata'],
        timeline: '4-8 hours',
      })),
      rulesGeneration: {
        sigma: this.generateSigmaRecommendations(investigation),
        yara: this.generateYaraRecommendations(investigation),
        suricata: this.generateSuricataRecommendations(investigation),
      },
      deploymentPlan: [
        {
          phase: 'Phase 1: Develop',
          timeline: '4 hours',
          actions: ['Write Sigma rules for priority techniques'],
        },
        {
          phase: 'Phase 2: Test',
          timeline: '2 hours',
          actions: ['Test against provided sample data'],
        },
        {
          phase: 'Phase 3: Deploy',
          timeline: '1 hour',
          actions: ['Deploy to production SIEM'],
        },
      ],
    };
  }

  generateIncidentResponseActions(investigation) {
    const victims = investigation.victims || [];

    return {
      title: 'Incident Response Actions',
      scope: `${victims.length} confirmed compromised organizations`,
      responsePhases: [
        {
          phase: 'Containment (0-24 hours)',
          actions: [
            'Isolate affected systems from network',
            'Revoke compromised credentials',
            'Block C2 at firewall',
            'Preserve forensic evidence',
          ],
        },
        {
          phase: 'Investigation (24-72 hours)',
          actions: [
            'Conduct digital forensics',
            'Identify breach timeline',
            'Determine data access scope',
            'Document attacker activities',
          ],
        },
        {
          phase: 'Recovery (3-30 days)',
          actions: [
            'Rebuild affected systems',
            'Restore from clean backups',
            'Verify integrity',
            'Return to operations',
          ],
        },
        {
          phase: 'Lessons Learned (30+ days)',
          actions: [
            'Complete incident report',
            'Update security controls',
            'Implement recommendations',
            'Share threat intelligence',
          ],
        },
      ],
      communicationPlan: {
        customers: 'Notify if data compromised',
        regulators: 'File required reports',
        media: 'Coordinate public statements',
        law_enforcement: 'Engage for criminal investigation',
      },
    };
  }

  generateCloudSecurityActions(investigation) {
    const cloudServices = investigation.cloudServicesAffected || [];

    return {
      title: 'Cloud Security Actions',
      affectedServices: cloudServices,
      actions: [
        {
          action: 'Review IAM Policies',
          focus: 'Identify overly permissive roles',
          timeline: '4 hours',
        },
        {
          action: 'Audit Cloud Access Logs',
          focus: 'Identify unauthorized API activity',
          timeline: '8 hours',
        },
        {
          action: 'Implement MFA Enforcement',
          focus: 'Require MFA for privileged accounts',
          timeline: '2 days',
        },
        {
          action: 'Enable Cloud Security Monitoring',
          focus: 'Deploy CSPM and CWPP solutions',
          timeline: '3 days',
        },
      ],
    };
  }

  generateIdentityActions(investigation) {
    return {
      title: 'Identity & Access Management Actions',
      priority: 'High',
      actions: [
        {
          action: 'Perform Credential Audit',
          scope: 'All potentially compromised accounts',
          timeline: '4 hours',
        },
        {
          action: 'Force Password Reset',
          scope: 'Affected user accounts and service accounts',
          timeline: '8 hours',
        },
        {
          action: 'Revoke Active Sessions',
          scope: 'All sessions for affected users',
          timeline: 'Immediate',
        },
        {
          action: 'Review Privileged Access',
          scope: 'Identify and audit elevated privileges',
          timeline: '12 hours',
        },
        {
          action: 'Implement PAM Controls',
          scope: 'Deploy privileged access management',
          timeline: '7 days',
        },
      ],
    };
  }

  generateEndpointActions(investigation) {
    return {
      title: 'Endpoint Security Actions',
      priority: 'High',
      actions: [
        {
          action: 'Deploy IOC Signatures',
          timeline: '2 hours',
          scope: 'All endpoints',
        },
        {
          action: 'Enable EDR/XDR',
          timeline: '4 hours',
          scope: 'Critical systems',
        },
        {
          action: 'Update Malware Definitions',
          timeline: '1 hour',
          scope: 'All endpoints',
        },
        {
          action: 'Review Firewall Rules',
          timeline: '6 hours',
          scope: 'Host-based firewalls',
        },
      ],
    };
  }

  generateEmailActions(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const hasPhishing = techniques.some(t => t.includes('Phishing'));

    return {
      title: 'Email Security Actions',
      priority: hasPhishing ? 'Urgent' : 'High',
      actions: [
        {
          action: 'Search for Related Emails',
          criteria: hasPhishing ? 'Emails from phishing campaign senders' : 'Emails containing IOCs',
          timeline: '4 hours',
        },
        {
          action: 'Update Email Filters',
          criteria: 'Block identified phishing senders and IOCs',
          timeline: '2 hours',
        },
        {
          action: 'Enable Advanced Threat Protection',
          criteria: 'Detonation, sandboxing, behavior analysis',
          timeline: '2 days',
        },
        {
          action: 'User Security Awareness Training',
          criteria: 'Target users who received phishing emails',
          timeline: '1 week',
        },
      ],
    };
  }

  generateNetworkActions(investigation) {
    const c2Servers = investigation.infrastructure?.filter(i => i.type === 'C2') || [];

    return {
      title: 'Network Security Actions',
      priority: 'High',
      actions: [
        {
          action: 'Block C2 Servers',
          targets: c2Servers.slice(0, 5),
          method: 'Firewall rules / DNS sinkhole',
          timeline: '30 minutes',
        },
        {
          action: 'Review Firewall Logs',
          criteria: 'Identify attempts to reach blocked infrastructure',
          timeline: '4 hours',
        },
        {
          action: 'Segment Network',
          criteria: 'Isolate critical systems from general network',
          timeline: '3 days',
        },
        {
          action: 'Deploy Network Detection',
          criteria: 'IDS/IPS for identified malicious traffic',
          timeline: '2 days',
        },
      ],
    };
  }

  generateThirdPartyActions(investigation) {
    return {
      title: 'Third-Party Risk Actions',
      actions: [
        {
          action: 'Notify Vendors',
          criteria: 'Vendors whose systems may be affected',
          timeline: '4 hours',
        },
        {
          action: 'Review Third-Party Access',
          criteria: 'Audit vendor access to affected systems',
          timeline: '8 hours',
        },
        {
          action: 'Request Vendor Incident Response',
          criteria: 'Engage vendors in investigation and remediation',
          timeline: 'As needed',
        },
      ],
    };
  }

  generateComplianceActions(investigation) {
    const hasPersonalData = (investigation.dataTypesAffected || []).includes('PII');

    return {
      title: 'Compliance & Legal Actions',
      regulatoryNotifications: hasPersonalData ? [
        'GDPR (if EU residents affected)',
        'CCPA (if California residents affected)',
        'State breach notification laws',
        'Industry-specific regulations',
      ] : ['Verify requirements for affected sectors'],
      timeline: hasPersonalData ? '30 days' : 'Per regulations',
      actions: [
        {
          action: 'Engage Legal Counsel',
          scope: 'Regulatory compliance requirements',
          timeline: 'Immediate',
        },
        {
          action: 'Document Incident',
          scope: 'Maintain comprehensive incident record',
          timeline: 'Ongoing',
        },
        {
          action: 'Prepare Regulatory Filings',
          scope: 'File required breach notifications',
          timeline: '30 days',
        },
      ],
    };
  }

  extractIndustries(investigation) {
    const industries = investigation.industryImpact || {};
    return Object.keys(industries).slice(0, 3);
  }

  filterTechniquesByTactic(techniques, tactic) {
    return techniques.filter(t => t.tactic === tactic || t.includes(tactic));
  }

  generateSigmaRecommendations(investigation) {
    return {
      rules: 'Generate Sigma YAML rules for detected techniques',
      coverage: `${(investigation.mitreTechniques || []).length} techniques`,
      deployment: 'Splunk, Elastic, Microsoft Defender',
    };
  }

  generateYaraRecommendations(investigation) {
    return {
      rules: 'Generate YARA rules for malware samples',
      coverage: `${(investigation.malwareVariants || []).length} variants`,
      deployment: 'Endpoint agents, YARA scanner',
    };
  }

  generateSuricataRecommendations(investigation) {
    return {
      rules: 'Generate Suricata IDS rules for network detection',
      coverage: 'C2 communication, data exfiltration',
      deployment: 'Network IDS/IPS',
    };
  }
}

module.exports = { EnterpriseRecommendationsEngine };
