'use strict';

class InfrastructureCorrelationEngine {
  correlateInfrastructure(investigation) {
    const infrastructure = investigation.infrastructure || [];
    const correlations = {
      networkClusters: this.clusterByNetwork(infrastructure),
      operatorClusters: this.clusterByOperator(infrastructure, investigation),
      geographicClusters: this.clusterByGeography(infrastructure),
      hostingClusters: this.clusterByHostingProvider(infrastructure),
      c2Relationships: this.mapC2Relationships(infrastructure, investigation),
      operationalPatterns: this.identifyOperationalPatterns(infrastructure),
      correlatedAt: new Date().toISOString(),
    };

    return correlations;
  }

  clusterByNetwork(infrastructure) {
    const asnMap = new Map();

    infrastructure.forEach(infra => {
      const asn = infra.asn || 'unknown';
      if (!asnMap.has(asn)) {
        asnMap.set(asn, []);
      }
      asnMap.get(asn).push(infra);
    });

    const clusters = [];
    asnMap.forEach((nodes, asn) => {
      if (nodes.length > 1) {
        clusters.push({
          asn,
          nodeCount: nodes.length,
          nodes: nodes.map(n => n.address || n.ip),
          hostingProvider: nodes[0].hostingProvider || 'unknown',
          concentration: (nodes.length / infrastructure.length),
        });
      }
    });

    return clusters.sort((a, b) => b.concentration - a.concentration);
  }

  clusterByOperator(infrastructure, investigation) {
    const operatorMap = new Map();

    (investigation.threatActors || []).forEach(actor => {
      const operatedInfra = infrastructure.filter(i =>
        (i.operatedByActors || []).includes(actor.id)
      );

      if (operatedInfra.length > 0) {
        operatorMap.set(actor.id, {
          actor: actor.name || actor.id,
          infrastructure: operatedInfra.map(i => i.address || i.ip),
          nodeCount: operatedInfra.length,
          confidence: 0.85,
        });
      }
    });

    return Array.from(operatorMap.values());
  }

  clusterByGeography(infrastructure) {
    const geoMap = new Map();

    infrastructure.forEach(infra => {
      const country = infra.country || 'unknown';
      if (!geoMap.has(country)) {
        geoMap.set(country, []);
      }
      geoMap.get(country).push(infra);
    });

    const clusters = [];
    geoMap.forEach((nodes, country) => {
      clusters.push({
        country,
        nodeCount: nodes.length,
        nodes: nodes.map(n => n.address || n.ip),
        providers: [...new Set(nodes.map(n => n.hostingProvider))],
      });
    });

    return clusters.sort((a, b) => b.nodeCount - a.nodeCount);
  }

  clusterByHostingProvider(infrastructure) {
    const providerMap = new Map();

    infrastructure.forEach(infra => {
      const provider = infra.hostingProvider || 'unknown';
      if (!providerMap.has(provider)) {
        providerMap.set(provider, []);
      }
      providerMap.get(provider).push(infra);
    });

    const clusters = [];
    providerMap.forEach((nodes, provider) => {
      if (nodes.length > 1) {
        clusters.push({
          provider,
          nodeCount: nodes.length,
          nodes: nodes.map(n => n.address || n.ip),
          countries: [...new Set(nodes.map(n => n.country))],
          reputationScore: this.calculateProviderReputation(nodes),
        });
      }
    });

    return clusters.sort((a, b) => b.nodeCount - a.nodeCount);
  }

  mapC2Relationships(infrastructure, investigation) {
    const relationships = [];

    infrastructure
      .filter(i => i.type === 'C2' || i.type === 'c2')
      .forEach(c2 => {
        const operators = (investigation.threatActors || []).filter(a =>
          (c2.operatedByActors || []).includes(a.id)
        );

        operators.forEach(op => {
          relationships.push({
            c2: c2.address || c2.ip,
            operator: op.name || op.id,
            protocol: c2.protocol || 'unknown',
            port: c2.port,
            domain: c2.domain,
            lastActive: c2.lastActive,
            confidence: 0.85,
          });
        });
      });

    return relationships;
  }

  identifyOperationalPatterns(infrastructure) {
    const patterns = [];

    const geographicDistribution = this.assessGeographicDistribution(infrastructure);
    if (geographicDistribution.spread === 'global') {
      patterns.push({
        pattern: 'Global infrastructure distribution',
        detail: `${geographicDistribution.countries.length} countries, likely for resilience`,
        implication: 'Sophisticated operator with redundancy planning',
      });
    }

    const providerReuse = this.assessProviderReuse(infrastructure);
    if (providerReuse.concentration > 0.4) {
      patterns.push({
        pattern: 'Concentrated provider usage',
        detail: `Heavy reliance on ${providerReuse.topProvider}`,
        implication: 'Possible cost optimization or previous compromises of single provider',
      });
    }

    const ageDistribution = this.assessInfrastructureAge(infrastructure);
    if (ageDistribution.avgAgeDays < 30) {
      patterns.push({
        pattern: 'Recently established infrastructure',
        detail: `Average node age: ${ageDistribution.avgAgeDays} days`,
        implication: 'Active campaign or response to law enforcement takedowns',
      });
    }

    return patterns;
  }

  calculateProviderReputation(nodes) {
    let reputation = 1.0;

    const isAbused = nodes.some(n => n.abuseReports || n.blacklisted);
    if (isAbused) reputation -= 0.3;

    const hasCompliance = nodes.some(n => n.complianceRating);
    if (hasCompliance) reputation += 0.1;

    return Math.min(1.0, Math.max(0.0, reputation));
  }

  assessGeographicDistribution(infrastructure) {
    const countries = new Set(infrastructure.map(i => i.country).filter(Boolean));

    return {
      countries: [...countries],
      count: countries.size,
      spread: countries.size > 5 ? 'global' : countries.size > 2 ? 'regional' : 'concentrated',
    };
  }

  assessProviderReuse(infrastructure) {
    const providerMap = new Map();

    infrastructure.forEach(i => {
      const provider = i.hostingProvider || 'unknown';
      providerMap.set(provider, (providerMap.get(provider) || 0) + 1);
    });

    const total = infrastructure.length;
    let topProvider = 'unknown';
    let topCount = 0;

    providerMap.forEach((count, provider) => {
      if (count > topCount) {
        topCount = count;
        topProvider = provider;
      }
    });

    return {
      topProvider,
      topCount,
      concentration: topCount / total,
    };
  }

  assessInfrastructureAge(infrastructure) {
    const ages = infrastructure
      .map(i => {
        if (!i.firstSeen) return null;
        const ageMs = new Date().getTime() - new Date(i.firstSeen).getTime();
        return ageMs / (1000 * 60 * 60 * 24);
      })
      .filter(a => a !== null);

    if (ages.length === 0) return { avgAgeDays: null };

    const avgAge = ages.reduce((a, b) => a + b, 0) / ages.length;
    const maxAge = Math.max(...ages);
    const minAge = Math.min(...ages);

    return {
      avgAgeDays: Math.floor(avgAge),
      maxAgeDays: Math.floor(maxAge),
      minAgeDays: Math.floor(minAge),
    };
  }
}

module.exports = { InfrastructureCorrelationEngine };
