'use strict';

const redis = require('../../_lib/redis');
const { IntelligenceManager } = require('../../_lib/intelligence-manager');
const { GraphEngine } = require('../../_lib/graph-engine');
const { GraphTraversal } = require('../../_lib/graph-traversal');
const { CorrelationEngine } = require('../../_lib/correlation-engine');

const manager = new IntelligenceManager(redis);
const graphEngine = new GraphEngine(redis, manager);
const traversal = new GraphTraversal(graphEngine);
const correlationEngine = new CorrelationEngine(graphEngine, traversal);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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

  if (req.method === 'GET' && action === 'actors' && id) {
    return handleCorrelateActors(req, res, id);
  }

  if (req.method === 'GET' && action === 'campaigns' && id) {
    return handleDetectCampaigns(req, res, id);
  }

  if (req.method === 'GET' && action === 'malware-variants' && id) {
    return handleClusterMalware(req, res, id);
  }

  if (req.method === 'GET' && action === 'infrastructure' && id) {
    return handleClusterInfra(req, res, id);
  }

  if (req.method === 'GET' && action === 'iocs' && id) {
    return handleCorrelateIOCs(req, res, id);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleCorrelateActors(req, res, id) {
  try {
    const confidence = parseFloat(req.query.confidence || '0.6');
    const correlated = await correlationEngine.correlateThreatsActors(id, confidence);

    return ok(res, {
      actorId: id,
      correlated,
      count: correlated.length,
    });
  } catch (e) {
    return fail(res, 500, 'CORRELATION_FAILED', e.message);
  }
}

async function handleDetectCampaigns(req, res, id) {
  try {
    const timeWindow = parseInt(req.query.timeWindow || '90', 10);
    const campaigns = await correlationEngine.detectCampaigns(id, timeWindow);

    return ok(res, {
      actorId: id,
      campaigns,
      count: campaigns.length,
    });
  } catch (e) {
    return fail(res, 500, 'CAMPAIGN_DETECTION_FAILED', e.message);
  }
}

async function handleClusterMalware(req, res, id) {
  try {
    const threshold = parseFloat(req.query.threshold || '0.7');
    const clusters = await correlationEngine.clusterMalwareVariants(id, threshold);

    return ok(res, {
      malwareFamilyId: id,
      clusters,
      count: clusters.length,
    });
  } catch (e) {
    return fail(res, 500, 'MALWARE_CLUSTERING_FAILED', e.message);
  }
}

async function handleClusterInfra(req, res, id) {
  try {
    const cluster = await correlationEngine.clusterInfrastructure(id);

    return ok(res, {
      infrastructureId: id,
      cluster,
    });
  } catch (e) {
    return fail(res, 500, 'INFRA_CLUSTERING_FAILED', e.message);
  }
}

async function handleCorrelateIOCs(req, res, id) {
  try {
    const related = await correlationEngine.correlateIOCs(id);

    return ok(res, {
      iocId: id,
      relatedIOCs: related,
      count: related.length,
    });
  } catch (e) {
    return fail(res, 500, 'IOC_CORRELATION_FAILED', e.message);
  }
}
