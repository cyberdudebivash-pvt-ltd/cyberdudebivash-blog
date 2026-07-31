'use strict';

class GraphTraversal {
  constructor(graphEngine) {
    this.graph = graphEngine;
  }

  async findRelatedEntitiesBFS(startEntityId, maxDepth = 2, limit = 100) {
    const visited = new Set([startEntityId]);
    const queue = [{ entityId: startEntityId, depth: 0 }];
    const results = [];

    while (queue.length > 0 && results.length < limit) {
      const { entityId, depth } = queue.shift();

      if (depth > 0) {
        const entity = await this.graph.getEntity(entityId);
        if (entity) {
          results.push({
            entity,
            depth,
            path: await this.getPathToEntity(startEntityId, entityId),
          });
        }
      }

      if (depth < maxDepth) {
        const outgoing = await this.graph.getOutgoingRelationships(entityId, 50);

        for (const rel of outgoing) {
          if (!visited.has(rel.target)) {
            visited.add(rel.target);
            queue.push({ entityId: rel.target, depth: depth + 1 });
          }
        }
      }
    }

    return results;
  }

  async findThreatPatternDFS(startEntityId, maxDepth = 3, patternType = 'attack_chain') {
    const visited = new Set();
    const paths = [];

    const dfs = async (entityId, depth, currentPath) => {
      if (depth > maxDepth || visited.has(entityId)) return;
      visited.add(entityId);
      currentPath.push(entityId);

      if (currentPath.length >= 2) {
        paths.push([...currentPath]);
      }

      const outgoing = await this.graph.getOutgoingRelationships(entityId, 20);

      for (const rel of outgoing) {
        await dfs(rel.target, depth + 1, currentPath);
      }

      currentPath.pop();
      visited.delete(entityId);
    };

    await dfs(startEntityId, 0, []);
    return paths;
  }

  async findShortestPath(sourceId, targetId, maxHops = 5) {
    const visited = new Set([sourceId]);
    const queue = [{ entityId: sourceId, path: [sourceId], rels: [] }];

    while (queue.length > 0) {
      const { entityId, path, rels } = queue.shift();

      if (entityId === targetId) {
        return { path, relationships: rels };
      }

      if (path.length - 1 >= maxHops) continue;

      const outgoing = await this.graph.getOutgoingRelationships(entityId, 30);

      for (const rel of outgoing) {
        if (!visited.has(rel.target)) {
          visited.add(rel.target);
          queue.push({
            entityId: rel.target,
            path: [...path, rel.target],
            rels: [...rels, rel],
          });
        }
      }
    }

    return null;
  }

  async findAllPaths(sourceId, targetId, maxHops = 4) {
    const allPaths = [];

    const dfs = async (entityId, targetId, visited, path, rels, depth) => {
      if (depth > maxHops) return;

      if (entityId === targetId) {
        allPaths.push({ path, relationships: rels });
        return;
      }

      const outgoing = await this.graph.getOutgoingRelationships(entityId, 20);

      for (const rel of outgoing) {
        if (!visited.has(rel.target)) {
          visited.add(rel.target);
          await dfs(
            rel.target,
            targetId,
            visited,
            [...path, rel.target],
            [...rels, rel],
            depth + 1
          );
          visited.delete(rel.target);
        }
      }
    };

    const visited = new Set([sourceId]);
    await dfs(sourceId, targetId, visited, [sourceId], [], 0);

    return allPaths;
  }

  async expandEntity(entityId, limit = 50) {
    const [outgoing, incoming] = await Promise.all([
      this.graph.getOutgoingRelationships(entityId, limit),
      this.graph.getIncomingRelationships(entityId, limit),
    ]);

    const relatedOut = [];
    const relatedIn = [];

    for (const rel of outgoing) {
      const target = await this.graph.getEntity(rel.target);
      if (target) relatedOut.push({ entity: target, relationship: rel });
    }

    for (const rel of incoming) {
      const source = await this.graph.getEntity(rel.source);
      if (source) relatedIn.push({ entity: source, relationship: rel });
    }

    return {
      center: await this.graph.getEntity(entityId),
      outgoing: relatedOut,
      incoming: relatedIn,
    };
  }

  async traverseByRelationType(startEntityId, relationType, maxDepth = 3) {
    const visited = new Set([startEntityId]);
    const result = [];

    const traverse = async (entityId, depth) => {
      if (depth > maxDepth) return;

      const outgoing = await this.graph.getOutgoingRelationships(entityId, 50);
      const typeSpecific = outgoing.filter(r => r.type === relationType);

      for (const rel of typeSpecific) {
        if (!visited.has(rel.target)) {
          visited.add(rel.target);
          const entity = await this.graph.getEntity(rel.target);
          if (entity) {
            result.push({
              entity,
              relationship: rel,
              depth,
            });
            await traverse(rel.target, depth + 1);
          }
        }
      }
    };

    await traverse(startEntityId, 0);
    return result;
  }

  async getPathToEntity(sourceId, targetId) {
    const path = await this.findShortestPath(sourceId, targetId);
    return path ? path.path : [];
  }

  async calculateCentrality(entityId) {
    const [outgoing, incoming] = await Promise.all([
      this.graph.getOutgoingRelationships(entityId, 1000),
      this.graph.getIncomingRelationships(entityId, 1000),
    ]);

    return {
      outDegree: outgoing.length,
      inDegree: incoming.length,
      totalDegree: outgoing.length + incoming.length,
      centrality: (outgoing.length + incoming.length) / 2,
    };
  }

  async findConnectedComponents() {
    const allEntities = await this.graph.redis.smembers('graph:entities:all');
    const visited = new Set();
    const components = [];

    for (const entityId of allEntities) {
      if (!visited.has(entityId)) {
        const component = await this.findConnectedComponent(entityId, visited);
        if (component.length > 0) {
          components.push(component);
        }
      }
    }

    return components;
  }

  async findConnectedComponent(startId, globalVisited) {
    const component = [];
    const queue = [startId];
    const visited = new Set([startId]);

    while (queue.length > 0) {
      const entityId = queue.shift();
      component.push(entityId);
      globalVisited.add(entityId);

      const [outgoing, incoming] = await Promise.all([
        this.graph.getOutgoingRelationships(entityId, 100),
        this.graph.getIncomingRelationships(entityId, 100),
      ]);

      const allRels = [...outgoing, ...incoming];

      for (const rel of allRels) {
        const nextId = rel.source === entityId ? rel.target : rel.source;
        if (!visited.has(nextId) && !globalVisited.has(nextId)) {
          visited.add(nextId);
          queue.push(nextId);
        }
      }
    }

    return component;
  }
}

module.exports = {
  GraphTraversal,
};
