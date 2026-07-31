'use strict';

class AIAnalyst {
  constructor(redis, investigationManager, graphEngine, graphTraversal, correlationEngine) {
    this.redis = redis;
    this.investigationManager = investigationManager;
    this.graph = graphEngine;
    this.traversal = graphTraversal;
    this.correlationEngine = correlationEngine;
  }

  async suggestRelatedIntelligence(investigationId, limit = 10) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const suggestions = [];

    // Find threat actors and get related campaigns/malware
    if (investigation.linkedEntities && investigation.linkedEntities.length > 0) {
      for (const entityId of investigation.linkedEntities.slice(0, 5)) {
        try {
          const entity = await this.graph.getEntity(entityId);

          if (entity.type === 'threat_actor') {
            const campaigns = await this.graphEngine.getOutgoingRelationships(entityId, 20);
            for (const rel of campaigns) {
              if (rel.type === 'carries_out') {
                const target = await this.graph.getEntity(rel.target);
                suggestions.push({
                  type: 'campaign',
                  entity: target,
                  confidence: rel.confidence,
                  reason: `Campaign by ${entity.name}`,
                });
              }
            }
          }

          if (entity.type === 'malware_family') {
            const variants = await this.graphEngine.getOutgoingRelationships(entityId, 20);
            for (const rel of variants) {
              if (rel.type === 'variant_of') {
                const target = await this.graph.getEntity(rel.target);
                suggestions.push({
                  type: 'malware',
                  entity: target,
                  confidence: rel.confidence,
                  reason: `Variant of ${entity.name}`,
                });
              }
            }
          }
        } catch (e) {
          // Skip if entity processing fails
        }
      }
    }

    return suggestions.slice(0, limit);
  }

  async suggestMissingEvidence(investigationId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const suggestions = [];

    // Analyze linked entities for missing evidence types
    const entityTypes = new Set();
    if (investigation.linkedEntities) {
      for (const entityId of investigation.linkedEntities) {
        const entity = await this.graph.getEntity(entityId);
        if (entity) entityTypes.add(entity.type);
      }
    }

    // Suggest evidence based on entity types
    if (entityTypes.has('threat_actor')) {
      suggestions.push({
        type: 'THREAT_REPORT',
        reason: 'Threat actor identified - threat report recommended',
        priority: 'high',
      });
      suggestions.push({
        type: 'DETECTION_RULE',
        reason: 'Threat actor identified - detection rules recommended',
        priority: 'high',
      });
    }

    if (entityTypes.has('malware_family')) {
      suggestions.push({
        type: 'PCAP',
        reason: 'Malware identified - packet capture recommended',
        priority: 'medium',
      });
      suggestions.push({
        type: 'HASH',
        reason: 'Malware identified - file hashes recommended',
        priority: 'high',
      });
    }

    if (entityTypes.has('infrastructure') || entityTypes.has('domain')) {
      suggestions.push({
        type: 'URL',
        reason: 'Infrastructure identified - URL samples recommended',
        priority: 'medium',
      });
    }

    return suggestions;
  }

  async generateExecutiveSummary(investigationId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    let threatActors = [];
    let campaigns = [];
    let malware = [];
    let impactedSectors = [];

    if (investigation.linkedEntities) {
      for (const entityId of investigation.linkedEntities) {
        const entity = await this.graph.getEntity(entityId);
        if (!entity) continue;

        if (entity.type === 'threat_actor') threatActors.push(entity);
        if (entity.type === 'campaign') campaigns.push(entity);
        if (entity.type.includes('malware')) malware.push(entity);
      }
    }

    const summary = {
      investigationTitle: investigation.title,
      status: investigation.status,
      priority: investigation.priority,
      threatActorsCount: threatActors.length,
      threatActorsNames: threatActors.map(t => t.name),
      campaignsCount: campaigns.length,
      malwareCount: malware.length,
      narrative: this.generateNarrative(threatActors, campaigns, malware),
      recommendations: this.generateRecommendations(investigation, threatActors),
      nextSteps: this.generateNextSteps(investigation),
    };

    return summary;
  }

  async suggestAttributionTargets(investigationId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const suggestions = [];

    // If we have infrastructure, suggest likely threat actors
    if (investigation.linkedEntities) {
      for (const entityId of investigation.linkedEntities) {
        const entity = await this.graph.getEntity(entityId);
        if (!entity) continue;

        if (entity.type === 'infrastructure' || entity.type === 'c2_server') {
          const operators = await this.correlationEngine.getIncomingByType(entityId, 'operates');

          for (const operator of operators) {
            suggestions.push({
              threatActor: operator,
              confidence: 0.7,
              reason: `Infrastructure operator: ${entity.name}`,
            });
          }
        }
      }
    }

    return suggestions;
  }

  async suggestDetectionRules(investigationId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const suggestions = [];

    // Suggest detection rules based on techniques and IOCs
    const techniques = new Set();
    const iocs = [];

    if (investigation.linkedEntities) {
      for (const entityId of investigation.linkedEntities) {
        const entity = await this.graph.getEntity(entityId);
        if (!entity) continue;

        if (entity.type === 'technique') {
          techniques.add(entity);
        }

        if (['file_hash', 'domain', 'ip_address', 'url'].includes(entity.type)) {
          iocs.push(entity);
        }
      }
    }

    // Suggest YARA/Sigma rules
    if (iocs.length > 0) {
      suggestions.push({
        ruleType: 'YARA',
        reason: `IOCs identified: ${iocs.map(i => i.name).join(', ')}`,
        priority: 'high',
        coverage: iocs.length,
      });
    }

    if (techniques.size > 0) {
      suggestions.push({
        ruleType: 'SIGMA',
        reason: `Techniques identified: ${Array.from(techniques).map(t => t.name).join(', ')}`,
        priority: 'high',
        coverage: techniques.size,
      });
    }

    return suggestions;
  }

  async prioritizeIOCs(investigationId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const iocs = [];

    if (investigation.linkedEntities) {
      for (const entityId of investigation.linkedEntities) {
        const entity = await this.graph.getEntity(entityId);
        if (!entity) continue;

        if (['file_hash', 'domain', 'ip_address', 'url'].includes(entity.type)) {
          const centrality = await this.traversal.calculateCentrality(entityId);

          iocs.push({
            ioc: entity,
            priority: this.calculateIOCPriority(entity, centrality),
            centrality: centrality.centrality,
            reason: this.reasonIOCPriority(entity, centrality),
          });
        }
      }
    }

    return iocs.sort((a, b) => b.priority - a.priority);
  }

  async scoreInvestigationCompleteness(investigationId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    let score = 0;

    // Check for linked intelligence (20%)
    if (investigation.linkedIntelligence && investigation.linkedIntelligence.length > 3) {
      score += 20;
    } else if (investigation.linkedIntelligence && investigation.linkedIntelligence.length > 0) {
      score += 10;
    }

    // Check for linked entities (20%)
    if (investigation.linkedEntities && investigation.linkedEntities.length > 5) {
      score += 20;
    } else if (investigation.linkedEntities && investigation.linkedEntities.length > 0) {
      score += 10;
    }

    // Check for evidence (20%)
    if (investigation.evidenceCount > 10) {
      score += 20;
    } else if (investigation.evidenceCount > 0) {
      score += 10;
    }

    // Check for notes (20%)
    if (investigation.noteCount > 5) {
      score += 20;
    } else if (investigation.noteCount > 0) {
      score += 10;
    }

    // Check for status (20%)
    if (investigation.status === 'closed' || investigation.status === 'pending_review') {
      score += 20;
    } else if (investigation.status === 'in_progress') {
      score += 10;
    }

    return {
      investigationId,
      completenessScore: score,
      maxScore: 100,
      percentage: score,
      recommendations: this.getCompletenessRecommendations(investigation, score),
    };
  }

  generateNarrative(threatActors, campaigns, malware) {
    if (threatActors.length === 0) {
      return 'Investigation in progress - threat actor not yet attributed.';
    }

    let narrative = `Threat actor(s): ${threatActors.map(t => t.name).join(', ')}. `;

    if (campaigns.length > 0) {
      narrative += `Associated with ${campaigns.length} campaign(s). `;
    }

    if (malware.length > 0) {
      narrative += `Deployed malware: ${malware.map(m => m.name).join(', ')}.`;
    }

    return narrative;
  }

  generateRecommendations(investigation, threatActors) {
    const recommendations = [];

    if (investigation.status === 'open') {
      recommendations.push('Escalate to SOC for immediate response');
    }

    if (threatActors.length > 0) {
      recommendations.push('Notify customers of threat actor attribution');
      recommendations.push('Correlate with past incidents from same actor');
    }

    if (investigation.evidenceCount < 3) {
      recommendations.push('Collect additional evidence');
    }

    return recommendations;
  }

  generateNextSteps(investigation) {
    const steps = [];

    switch (investigation.status) {
      case 'open':
        steps.push('Link threat intelligence');
        steps.push('Collect evidence');
        break;
      case 'in_progress':
        steps.push('Add case notes');
        steps.push('Correlation analysis');
        break;
      case 'pending_review':
        steps.push('Request management review');
        steps.push('Prepare closure report');
        break;
      default:
        steps.push('Archive investigation');
    }

    return steps;
  }

  calculateIOCPriority(ioc, centrality) {
    let priority = 0;

    // Base priority on IOC type
    const typeScores = {
      file_hash: 10,
      domain: 8,
      ip_address: 8,
      url: 5,
    };

    priority += typeScores[ioc.type] || 3;

    // Boost for high centrality (well-connected IOCs are more important)
    priority += Math.min(centrality.centrality * 5, 10);

    return priority;
  }

  reasonIOCPriority(ioc, centrality) {
    const reasons = [];

    if (ioc.type === 'file_hash') {
      reasons.push('File hash - high priority for blocking');
    }

    if (centrality.centrality > 5) {
      reasons.push('Well-connected in threat graph');
    }

    return reasons.join('; ');
  }

  getCompletenessRecommendations(investigation, score) {
    const recommendations = [];

    if (investigation.linkedIntelligence.length < 3) {
      recommendations.push('Link additional intelligence objects');
    }

    if (investigation.linkedEntities.length < 5) {
      recommendations.push('Expand graph exploration for related entities');
    }

    if (investigation.evidenceCount < 10) {
      recommendations.push('Collect more evidence pieces');
    }

    if (investigation.noteCount < 5) {
      recommendations.push('Document analysis and findings');
    }

    return recommendations;
  }
}

module.exports = {
  AIAnalyst,
};
