'use strict';

const redis = require('../../_lib/redis');
const { IntelligenceManager } = require('../../_lib/intelligence-manager');
const { GraphEngine } = require('../../_lib/graph-engine');
const { RelationshipEngine } = require('../../_lib/relationship-engine');
const { GraphTraversal } = require('../../_lib/graph-traversal');
const { CorrelationEngine } = require('../../_lib/correlation-engine');
const { SimilarityEngine } = require('../../_lib/similarity-engine');

const manager = new IntelligenceManager(redis);
const graphEngine = new GraphEngine(redis, manager);
const relationshipEngine = new RelationshipEngine(redis, manager, graphEngine);
const traversal = new GraphTraversal(graphEngine);
const correlationEngine = new CorrelationEngine(graphEngine, traversal);
const similarityEngine = new SimilarityEngine(graphEngine);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function ok(res, data, status = 200) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: true,
    meta: { timestamp: new Date().toISOString() },
    ...data,
  });
}

function fail(res, status, code, message) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: false,
    error: { code, message },
    meta: { timestamp: new Date().toISOString() },
  });
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
    return res.status(200).end();
  }

  const pathParts = (req.url || '').split('?')[0].split('/').filter(Boolean);
  const action = pathParts[pathParts.length - 1];
  const id = pathParts[pathParts.length - 2];

  if (req.method === 'GET' && action === 'entity' && id) {
    return handleGetEntity(req, res, id);
  }

  if (req.method === 'GET' && action === 'related' && id) {
    return handleGetRelatedEntities(req, res, id);
  }

  if (req.method === 'GET' && pathParts.includes('path')) {
    const targetId = pathParts[pathParts.length - 1];
    return handleFindPath(req, res, id, targetId);
  }

  if (req.method === 'POST' && action === 'relationship') {
    return handleCreateRelationship(req, res);
  }

  if (req.method === 'DELETE' && action === 'relationship' && id) {
    return handleDeleteRelationship(req, res, id);
  }

  if (req.method === 'GET' && action === 'stats') {
    return handleGetStats(req, res);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleGetEntity(req, res, id) {
  try {
    const entity = await graphEngine.getEntity(id);
    if (!entity) {
      return fail(res, 404, 'NOT_FOUND', `Entity not found: ${id}`);
    }

    const outgoing = await graphEngine.getOutgoingRelationships(id, 20);
    const incoming = await graphEngine.getIncomingRelationships(id, 20);

    return ok(res, {
      entity,
      relationships: {
        outgoing: outgoing.length,
        incoming: incoming.length,
      },
    });
  } catch (e) {
    return fail(res, 500, 'ENTITY_FAILED', e.message);
  }
}

async function handleGetRelatedEntities(req, res, id) {
  try {
    const maxDepth = parseInt(req.query.depth || '2', 10);
    const limit = parseInt(req.query.limit || '50', 10);

    const related = await traversal.findRelatedEntitiesBFS(id, maxDepth, limit);

    return ok(res, {
      entityId: id,
      related,
      count: related.length,
    });
  } catch (e) {
    return fail(res, 500, 'TRAVERSAL_FAILED', e.message);
  }
}

async function handleFindPath(req, res, sourceId, targetId) {
  try {
    const maxHops = parseInt(req.query.hops || '5', 10);
    const path = await traversal.findShortestPath(sourceId, targetId, maxHops);

    if (!path) {
      return fail(res, 404, 'NO_PATH', `No path found between ${sourceId} and ${targetId}`);
    }

    return ok(res, {
      source: sourceId,
      target: targetId,
      path: path.path,
      relationshipCount: path.relationships.length,
      hops: path.path.length - 1,
    });
  } catch (e) {
    return fail(res, 500, 'PATH_FAILED', e.message);
  }
}

async function handleCreateRelationship(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { source, target, type, evidence, sources, actor } = body;
    if (!source || !target || !type) {
      return fail(res, 400, 'MISSING_FIELD', 'source, target, and type required');
    }

    const relationship = await relationshipEngine.linkIntelligence(
      source,
      target,
      type,
      {
        evidence,
        sources,
        actor,
        reason: body.reason || '',
      }
    );

    return ok(res, { relationship }, 201);
  } catch (e) {
    return fail(res, 500, 'RELATIONSHIP_FAILED', e.message);
  }
}

async function handleDeleteRelationship(req, res, id) {
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const result = await graphEngine.deleteRelationship(id, body.actor || 'api', body.reason || '');

    if (!result) {
      return fail(res, 404, 'NOT_FOUND', `Relationship not found: ${id}`);
    }

    return ok(res, { deleted: true });
  } catch (e) {
    return fail(res, 500, 'DELETE_FAILED', e.message);
  }
}

async function handleGetStats(req, res) {
  try {
    const stats = await graphEngine.getGraphStats();
    return ok(res, stats);
  } catch (e) {
    return fail(res, 500, 'STATS_FAILED', e.message);
  }
}
