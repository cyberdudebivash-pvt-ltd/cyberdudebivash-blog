'use strict';

class InvestigationGraph {
  constructor(redis, investigationManager, graphEngine, graphTraversal) {
    this.redis = redis;
    this.investigationManager = investigationManager;
    this.graph = graphEngine;
    this.traversal = graphTraversal;
  }

  async buildInvestigationGraph(investigationId, maxDepth = 2) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const nodes = [];
    const edges = [];
    const nodeIds = new Set();

    // Add investigation as center node
    nodes.push({
      id: investigationId,
      type: 'investigation',
      label: investigation.title,
      status: investigation.status,
      priority: investigation.priority,
    });
    nodeIds.add(investigationId);

    // Add linked graph entities
    if (investigation.linkedEntities && investigation.linkedEntities.length > 0) {
      for (const entityId of investigation.linkedEntities) {
        try {
          const entity = await this.graph.getEntity(entityId);
          if (entity) {
            nodes.push({
              id: entityId,
              type: entity.type,
              label: entity.name,
              confidence: entity.confidence,
            });
            nodeIds.add(entityId);

            edges.push({
              source: investigationId,
              target: entityId,
              type: 'involves',
            });
          }
        } catch (e) {
          // Skip if entity not found
        }
      }
    }

    // Expand related entities up to maxDepth
    for (const entityId of investigation.linkedEntities || []) {
      try {
        const related = await this.traversal.findRelatedEntitiesBFS(entityId, maxDepth - 1, 50);

        for (const rel of related) {
          if (!nodeIds.has(rel.entity.id)) {
            nodes.push({
              id: rel.entity.id,
              type: rel.entity.type,
              label: rel.entity.name,
              confidence: rel.entity.confidence,
              depth: rel.depth,
            });
            nodeIds.add(rel.entity.id);
          }

          // Create edge from parent entity
          if (rel.path && rel.path.length > 1) {
            const parentId = rel.path[rel.path.length - 2];
            edges.push({
              source: parentId,
              target: rel.entity.id,
              type: 'related',
              depth: rel.depth,
            });
          }
        }
      } catch (e) {
        // Skip if traversal fails
      }
    }

    // Add graph relationships
    for (const nodeId of nodeIds) {
      if (nodeId !== investigationId) {
        const outgoing = await this.graph.getOutgoingRelationships(nodeId, 20);

        for (const rel of outgoing) {
          if (nodeIds.has(rel.target)) {
            edges.push({
              source: nodeId,
              target: rel.target,
              type: rel.type,
              confidence: rel.confidence,
            });
          }
        }
      }
    }

    const graphData = {
      investigationId,
      nodes,
      edges,
      stats: {
        nodeCount: nodes.length,
        edgeCount: edges.length,
        maxDepth,
      },
    };

    // Cache graph
    await this.redis.set(
      `investigation:graph:${investigationId}`,
      JSON.stringify(graphData),
      'EX',
      3600
    );

    return graphData;
  }

  async getInvestigationSubgraph(investigationId, centerEntityId, depth = 1) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const centerEntity = await this.graph.getEntity(centerEntityId);
    if (!centerEntity) throw new Error(`Entity not found: ${centerEntityId}`);

    const nodes = [
      {
        id: centerEntityId,
        type: centerEntity.type,
        label: centerEntity.name,
        confidence: centerEntity.confidence,
        isCenter: true,
      },
    ];
    const edges = [];
    const nodeIds = new Set([centerEntityId]);

    // Expand from center
    const expanded = await this.traversal.findRelatedEntitiesBFS(centerEntityId, depth, 50);

    for (const rel of expanded) {
      nodes.push({
        id: rel.entity.id,
        type: rel.entity.type,
        label: rel.entity.name,
        confidence: rel.entity.confidence,
        depth: rel.depth,
      });
      nodeIds.add(rel.entity.id);
    }

    // Add edges
    for (const nodeId of nodeIds) {
      const outgoing = await this.graph.getOutgoingRelationships(nodeId, 50);

      for (const rel of outgoing) {
        if (nodeIds.has(rel.target)) {
          edges.push({
            source: nodeId,
            target: rel.target,
            type: rel.type,
            confidence: rel.confidence,
          });
        }
      }
    }

    return {
      investigationId,
      centerEntity: centerEntityId,
      nodes,
      edges,
      stats: {
        nodeCount: nodes.length,
        edgeCount: edges.length,
      },
    };
  }

  async getGraphCentralities(investigationId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const centralities = [];

    if (investigation.linkedEntities && investigation.linkedEntities.length > 0) {
      for (const entityId of investigation.linkedEntities) {
        try {
          const entity = await this.graph.getEntity(entityId);
          const centrality = await this.traversal.calculateCentrality(entityId);

          centralities.push({
            entityId,
            name: entity.name,
            type: entity.type,
            ...centrality,
          });
        } catch (e) {
          // Skip if calculation fails
        }
      }
    }

    return centralities.sort((a, b) => b.centrality - a.centrality);
  }

  async findGraphPaths(investigationId, fromEntityId, toEntityId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const paths = await this.traversal.findAllPaths(fromEntityId, toEntityId, 4);

    return {
      investigationId,
      from: fromEntityId,
      to: toEntityId,
      paths,
      pathCount: paths.length,
    };
  }

  async detectGraphClusters(investigationId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const clusters = await this.traversal.findConnectedComponents();

    return {
      investigationId,
      clusters,
      clusterCount: clusters.length,
    };
  }
}

module.exports = {
  InvestigationGraph,
};
