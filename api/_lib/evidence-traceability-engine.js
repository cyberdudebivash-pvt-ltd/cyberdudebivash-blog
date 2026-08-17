'use strict';

class EvidenceTraceabilityEngine {
  ensureTraceability(product, investigation, report) {
    const statements = this.extractAllStatements(product);
    const tracedStatements = [];
    const orphanedStatements = [];

    statements.forEach(statement => {
      const trace = this.traceStatement(statement, investigation, report);
      if (trace.sources.length > 0) {
        tracedStatements.push({ statement, trace });
      } else {
        orphanedStatements.push(statement);
      }
    });

    return {
      totalStatements: statements.length,
      tracedStatements: tracedStatements.length,
      orphanedStatements: orphanedStatements.length,
      coverage: parseFloat(((tracedStatements.length / statements.length) * 100).toFixed(1)) + '%',
      statements: tracedStatements,
      orphaned: orphanedStatements,
      traceabilityMetrics: this.calculateTraceabilityMetrics(tracedStatements),
    };
  }

  traceStatement(statement, investigation, report) {
    const sources = [];

    // Check findings
    (investigation.findings || []).forEach(finding => {
      if (this.matchesStatement(statement, finding)) {
        sources.push({
          type: 'finding',
          id: finding.id,
          evidence: finding.evidence || [],
          confidence: finding.confidence,
          source: finding.source,
        });
      }
    });

    // Check IOCs
    (investigation.iocs || []).forEach(ioc => {
      if (this.matchesStatement(statement, ioc)) {
        sources.push({
          type: 'ioc',
          id: ioc.id,
          value: ioc.value,
          subtype: ioc.ioType,
          firstSeen: ioc.firstSeen,
          lastSeen: ioc.lastSeen,
        });
      }
    });

    // Check techniques
    (investigation.mitreTechniques || []).forEach(technique => {
      if (this.matchesStatement(statement, technique)) {
        sources.push({
          type: 'technique',
          id: technique.id || technique,
          tactic: technique.tactic,
          procedure: technique.procedure,
        });
      }
    });

    // Check threat actors
    (investigation.threatActors || []).forEach(actor => {
      if (this.matchesStatement(statement, actor)) {
        sources.push({
          type: 'threat-actor',
          id: actor.id,
          name: actor.name,
          aliases: actor.aliases,
        });
      }
    });

    // Check infrastructure
    (investigation.infrastructure || []).forEach(infra => {
      if (this.matchesStatement(statement, infra)) {
        sources.push({
          type: 'infrastructure',
          id: infra.id,
          address: infra.address || infra.ip || infra.domain,
          subtype: infra.type,
        });
      }
    });

    // Check campaigns
    (investigation.campaigns || []).forEach(campaign => {
      if (this.matchesStatement(statement, campaign)) {
        sources.push({
          type: 'campaign',
          id: campaign.id,
          name: campaign.name,
        });
      }
    });

    return {
      statement,
      sources,
      evidenceQuality: this.assessEvidenceQuality(sources),
      traceability: sources.length > 0 ? 'Full' : 'None',
    };
  }

  extractAllStatements(product) {
    const statements = [];

    // Recursive extraction from product modules
    const recurse = (obj, path = []) => {
      if (!obj) return;

      if (typeof obj === 'string' && obj.length > 20) {
        statements.push({ text: obj, path: path.join('.') });
      } else if (typeof obj === 'object' && !obj.toISOString) {
        Object.values(obj).forEach((val, idx) => {
          recurse(val, [...path, idx]);
        });
      }
    };

    if (product.modules) {
      Object.entries(product.modules).forEach(([key, value]) => {
        recurse(value, [key]);
      });
    }

    return statements;
  }

  matchesStatement(statement, source) {
    const statementText = (statement.text || '').toLowerCase();
    const sourceText = JSON.stringify(source).toLowerCase();

    // Simple keyword matching
    const keywords = statementText.split(/\s+/).slice(0, 5);
    const matchCount = keywords.filter(kw => sourceText.includes(kw)).length;

    return matchCount >= 2;
  }

  assessEvidenceQuality(sources) {
    if (sources.length === 0) return 'None';
    if (sources.length === 1) return 'Low';
    if (sources.length <= 3) return 'Moderate';
    return 'High';
  }

  calculateTraceabilityMetrics(tracedStatements) {
    if (tracedStatements.length === 0) {
      return {
        averageSourcesPerStatement: 0,
        maxSourcesPerStatement: 0,
        sourceTypeDistribution: {},
      };
    }

    const sourcesCounts = tracedStatements.map(ts => ts.trace.sources.length);
    const sourceTypes = {};

    tracedStatements.forEach(ts => {
      ts.trace.sources.forEach(source => {
        sourceTypes[source.type] = (sourceTypes[source.type] || 0) + 1;
      });
    });

    return {
      averageSourcesPerStatement: (sourcesCounts.reduce((a, b) => a + b, 0) / sourcesCounts.length).toFixed(2),
      maxSourcesPerStatement: Math.max(...sourcesCounts),
      minSourcesPerStatement: Math.min(...sourcesCounts),
      sourceTypeDistribution: sourceTypes,
    };
  }

  validateAllStatementsTraced(product, investigation, report) {
    const result = this.ensureTraceability(product, investigation, report);
    return result.orphanedStatements.length === 0;
  }

  addTraceMetadata(product, traceabilityResult) {
    product.metadata = product.metadata || {};
    product.metadata.traceability = {
      coverage: traceabilityResult.coverage,
      orphanedStatements: traceabilityResult.orphanedStatements.length,
      metrics: traceabilityResult.traceabilityMetrics,
      validatedAt: new Date().toISOString(),
    };
    return product;
  }
}

module.exports = { EvidenceTraceabilityEngine };
