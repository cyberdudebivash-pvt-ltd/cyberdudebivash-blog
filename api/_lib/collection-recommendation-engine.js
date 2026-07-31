'use strict';

class CollectionRecommendationEngine {
  analyzeCollectionGaps(investigation) {
    const gaps = {
      dataGaps: this.identifyDataGaps(investigation),
      sourceGaps: this.identifySourceGaps(investigation),
      temporalGaps: this.identifyTemporalGaps(investigation),
      technicalGaps: this.identifyTechnicalGaps(investigation),
      geoGaps: this.identifyGeographicGaps(investigation),
      recommendations: [],
      priorityActions: [],
      estimatedCoverageImprovement: 0,
      analyzedAt: new Date().toISOString(),
    };

    gaps.recommendations = this.generateRecommendations(investigation, gaps);
    gaps.priorityActions = this.prioritizeRecommendations(gaps.recommendations);
    gaps.estimatedCoverageImprovement = this.estimateImprovementPotential(gaps);

    return gaps;
  }

  identifyDataGaps(investigation) {
    const gaps = [];

    if (!investigation.incidentDate) {
      gaps.push({
        gap: 'Missing Incident Timeline',
        impact: 'Cannot establish attack sequence or TTPs',
        priority: 'critical',
        effort: 'low',
      });
    }

    if (!investigation.victims || investigation.victims.length === 0) {
      gaps.push({
        gap: 'No Victim Information',
        impact: 'Cannot assess scope or targeting profile',
        priority: 'critical',
        effort: 'medium',
      });
    }

    if (!investigation.iocs || investigation.iocs.length < 5) {
      gaps.push({
        gap: 'Limited IOC Dataset',
        impact: 'Reduces ability to hunt for additional compromises',
        priority: 'high',
        effort: 'medium',
      });
    }

    if (!investigation.malware || investigation.malware.length === 0) {
      gaps.push({
        gap: 'No Malware Analysis',
        impact: 'Missing technical indicators and capabilities',
        priority: 'high',
        effort: 'high',
      });
    }

    if (!investigation.infrastructure || investigation.infrastructure.length === 0) {
      gaps.push({
        gap: 'Infrastructure Intelligence Missing',
        impact: 'Cannot track command and control or hosting patterns',
        priority: 'high',
        effort: 'medium',
      });
    }

    if (!investigation.threatActors || investigation.threatActors.length === 0) {
      gaps.push({
        gap: 'No Attribution',
        impact: 'Cannot attribute campaign or understand motivation',
        priority: 'medium',
        effort: 'high',
      });
    }

    return gaps;
  }

  identifySourceGaps(investigation) {
    const gaps = [];
    const sources = new Set();

    (investigation.findings || []).forEach(f => {
      if (f.source) sources.add(f.source);
    });

    if (sources.size === 0) {
      gaps.push({
        gap: 'No Source Attribution',
        impact: 'Cannot validate evidence or assess reliability',
        priority: 'medium',
      });
    }

    if (sources.size === 1) {
      gaps.push({
        gap: 'Single Source Only',
        impact: 'High dependency on single intel source',
        recommendation: 'Corroborate findings with additional sources',
        priority: 'high',
      });
    }

    const internalSources = [...sources].filter(s => !s.includes('external'));
    if (internalSources.length === 0) {
      gaps.push({
        gap: 'Missing Internal Forensics',
        impact: 'Lacking direct evidence from victim systems',
        priority: 'high',
      });
    }

    return gaps;
  }

  identifyTemporalGaps(investigation) {
    const gaps = [];

    const startDate = investigation.campaigns?.[0]?.startDate;
    const endDate = investigation.campaigns?.[0]?.endDate;

    if (!startDate || !endDate) {
      gaps.push({
        gap: 'Incomplete Timeline',
        impact: 'Cannot assess campaign duration or activity pattern',
        priority: 'medium',
      });
    } else {
      const durationDays = (new Date(endDate) - new Date(startDate)) / (1000 * 60 * 60 * 24);
      if (durationDays > 180) {
        gaps.push({
          gap: 'Long Campaign Duration - Sparse Documentation',
          impact: 'May be missing intermediate activities or tactical shifts',
          recommendation: 'Conduct timeline deep-dive to identify phases',
          priority: 'medium',
        });
      }
    }

    const activityTimeline = (investigation.findings || [])
      .map(f => new Date(f.date))
      .sort((a, b) => a - b);

    if (activityTimeline.length > 1) {
      for (let i = 1; i < activityTimeline.length; i++) {
        const gap = (activityTimeline[i] - activityTimeline[i - 1]) / (1000 * 60 * 60 * 24);
        if (gap > 30) {
          gaps.push({
            gap: `Long Activity Gap (${Math.floor(gap)} days)`,
            impact: 'May indicate dormant phase or missed activity',
            priority: 'medium',
          });
        }
      }
    }

    return gaps;
  }

  identifyTechnicalGaps(investigation) {
    const gaps = [];

    const techniques = new Set((investigation.mitreTechniques || []).map(t => t.tactic).filter(Boolean));

    if (techniques.size < 3) {
      gaps.push({
        gap: 'Limited Tactical Coverage',
        impact: 'Incomplete picture of attacker capabilities',
        recommendation: 'Expand MITRE ATT&CK mapping through deeper forensic analysis',
        priority: 'medium',
      });
    }

    if (!investigation.malware || investigation.malware.length === 0) {
      gaps.push({
        gap: 'No Malware Samples',
        impact: 'Cannot perform reverse engineering or behavioral analysis',
        priority: 'high',
        recommendation: 'Collect malware samples from victims or sandbox submissions',
      });
    }

    if (!investigation.memory || investigation.memory.length === 0) {
      gaps.push({
        gap: 'No Memory Forensics',
        impact: 'Missing runtime behavior and volatile artifacts',
        priority: 'medium',
      });
    }

    if (!investigation.networkTraffic || investigation.networkTraffic.length === 0) {
      gaps.push({
        gap: 'No Network Capture Data',
        impact: 'Cannot analyze C2 communication or exfiltration channels',
        priority: 'high',
      });
    }

    return gaps;
  }

  identifyGeographicGaps(investigation) {
    const gaps = [];

    const victimRegions = new Set((investigation.victims || []).map(v => v.region));
    if (victimRegions.size === 1) {
      gaps.push({
        gap: 'Single Geographic Region',
        impact: 'Limited evidence of campaign scope',
        priority: 'low',
      });
    }

    const actorOrigins = new Set((investigation.threatActors || []).map(a => a.origin));
    if (actorOrigins.size === 0) {
      gaps.push({
        gap: 'No Geo-Attribution',
        impact: 'Cannot establish actor origin or operational base',
        priority: 'medium',
      });
    }

    return gaps;
  }

  generateRecommendations(investigation, gaps) {
    const recommendations = [];

    gaps.dataGaps.forEach(gap => {
      recommendations.push({
        type: 'data_collection',
        gap: gap.gap,
        recommendation: this.getDataCollectionRecommendation(gap),
        effort: gap.effort,
        priority: gap.priority,
      });
    });

    gaps.sourceGaps.forEach(gap => {
      recommendations.push({
        type: 'source_diversification',
        gap: gap.gap,
        recommendation: gap.recommendation || `Obtain from alternate intelligence sources`,
        priority: gap.priority,
      });
    });

    gaps.temporalGaps.forEach(gap => {
      recommendations.push({
        type: 'temporal_analysis',
        gap: gap.gap,
        recommendation: gap.recommendation || `Analyze historical logs for missed activities`,
        priority: gap.priority,
      });
    });

    gaps.technicalGaps.forEach(gap => {
      recommendations.push({
        type: 'technical_collection',
        gap: gap.gap,
        recommendation: gap.recommendation || `Deploy additional forensic collection`,
        effort: 'high',
        priority: gap.priority,
      });
    });

    return recommendations;
  }

  getDataCollectionRecommendation(gap) {
    const recommendations = {
      'Missing Incident Timeline': 'Contact victim organizations for incident notification logs and timeline documentation',
      'No Victim Information': 'Expand victim identification through threat intelligence feeds and incident notifications',
      'Limited IOC Dataset': 'Conduct deeper analysis of captured artifacts and memory dumps to extract additional IOCs',
      'No Malware Analysis': 'Obtain malware samples from VirusTotal, CAPE, or direct victim collection',
      'Infrastructure Intelligence Missing': 'Query passive DNS, WHOIS, and BGP data for infrastructure correlation',
      'No Attribution': 'Expand source intelligence and reference public threat intelligence databases',
    };
    return recommendations[gap.gap] || 'Conduct additional data collection in this area';
  }

  prioritizeRecommendations(recommendations) {
    return recommendations
      .filter(r => r.priority === 'critical' || r.priority === 'high')
      .sort((a, b) => {
        const priorityOrder = { critical: 1, high: 2, medium: 3, low: 4 };
        return priorityOrder[a.priority] - priorityOrder[b.priority];
      })
      .slice(0, 5);
  }

  estimateImprovementPotential(gaps) {
    const criticalGaps = gaps.dataGaps.filter(g => g.priority === 'critical').length;
    const highGaps = gaps.dataGaps.filter(g => g.priority === 'high').length;

    const improvementPotential = (criticalGaps * 0.2) + (highGaps * 0.1);
    return Math.min(0.5, improvementPotential);
  }
}

module.exports = { CollectionRecommendationEngine };
