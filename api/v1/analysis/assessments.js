'use strict';

const redis = require('../../_lib/redis');
const { AnalysisManager } = require('../../_lib/analysis-manager');

const analysisMgr = new AnalysisManager(redis);

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
  const type = pathParts[pathParts.length - 2];
  const id = pathParts[pathParts.length - 3];

  // Situation Assessment
  if (req.method === 'POST' && action === 'situation') {
    return handleCreateSituationAssessment(req, res);
  }

  if (req.method === 'GET' && type === 'situation' && id) {
    return handleGetSituationAssessment(req, res, id);
  }

  // Threat Actor Assessment
  if (req.method === 'POST' && action === 'actor') {
    return handleCreateThreatActorAssessment(req, res);
  }

  if (req.method === 'GET' && type === 'actor' && id) {
    return handleGetThreatActorAssessment(req, res, id);
  }

  // Technical Assessment
  if (req.method === 'POST' && action === 'technical') {
    return handleCreateTechnicalAssessment(req, res);
  }

  if (req.method === 'GET' && type === 'technical' && id) {
    return handleGetTechnicalAssessment(req, res, id);
  }

  // Executive Assessment
  if (req.method === 'POST' && action === 'executive') {
    return handleCreateExecutiveAssessment(req, res);
  }

  if (req.method === 'GET' && type === 'executive' && id) {
    return handleGetExecutiveAssessment(req, res, id);
  }

  // Information Gaps
  if (req.method === 'POST' && action === 'gaps') {
    return handleGenerateGaps(req, res);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleCreateSituationAssessment(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, overview, scope, affectedSectors, geographicContext, estimatedImpact, timelineEvents } = body;

    if (!investigationId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId required');
    }

    const result = await analysisMgr.createSituationAssessment(investigationId, {
      overview,
      scope,
      affectedSectors: affectedSectors || [],
      geographicContext: geographicContext || [],
      estimatedImpact,
      timelineEvents: timelineEvents || [],
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      assessment: result.assessment,
      validation: result.validation,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleGetSituationAssessment(req, res, id) {
  try {
    const key = `situation:${id}`;
    const data = await redis.hgetall(key);

    if (!data || data.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Situation assessment not found for: ${id}`);
    }

    const assessment = {};
    for (let i = 0; i < data.length; i += 2) {
      assessment[data[i]] = data[i + 1];
    }

    return ok(res, { assessment });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleCreateThreatActorAssessment(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, actorId, attribution, attributionConfidence, supportingEvidence, contradictoryEvidence, aliases, attributionGaps } = body;

    if (!investigationId || !actorId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId and actorId required');
    }

    const result = await analysisMgr.createThreatActorAssessment(investigationId, actorId, {
      attribution,
      attributionConfidence,
      supportingEvidence: supportingEvidence || [],
      contradictoryEvidence: contradictoryEvidence || [],
      aliases: aliases || [],
      attributionGaps: attributionGaps || [],
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      assessment: result.assessment,
      validation: result.validation,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleGetThreatActorAssessment(req, res, id) {
  try {
    const key = `actor:${id}`;
    const data = await redis.hgetall(key);

    if (!data || data.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Threat actor assessment not found for: ${id}`);
    }

    const assessment = {};
    for (let i = 0; i < data.length; i += 2) {
      assessment[data[i]] = data[i + 1];
    }

    return ok(res, { assessment });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleCreateTechnicalAssessment(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, iocs, malwareFindings, techniques, infrastructure, detectionOpportunities } = body;

    if (!investigationId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId required');
    }

    const result = await analysisMgr.createTechnicalAssessment(investigationId, {
      iocs: iocs || [],
      malwareFindings: malwareFindings || [],
      techniques: techniques || [],
      infrastructure: infrastructure || [],
      detectionOpportunities: detectionOpportunities || [],
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      assessment: result.assessment,
      validation: result.validation,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleGetTechnicalAssessment(req, res, id) {
  try {
    const key = `technical:${id}`;
    const data = await redis.hgetall(key);

    if (!data || data.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Technical assessment not found for: ${id}`);
    }

    const assessment = {};
    for (let i = 0; i < data.length; i += 2) {
      assessment[data[i]] = data[i + 1];
    }

    return ok(res, { assessment });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleCreateExecutiveAssessment(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, businessImpact, operationalImpact, strategicImplications, recommendedActions, priorityLevel } = body;

    if (!investigationId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId required');
    }

    const result = await analysisMgr.createExecutiveAssessment(investigationId, {
      businessImpact,
      operationalImpact,
      strategicImplications: strategicImplications || [],
      recommendedActions: recommendedActions || [],
      priorityLevel: priorityLevel || 'medium',
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      assessment: result.assessment,
      validation: result.validation,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleGetExecutiveAssessment(req, res, id) {
  try {
    const key = `executive:${id}`;
    const data = await redis.hgetall(key);

    if (!data || data.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Executive assessment not found for: ${id}`);
    }

    const assessment = {};
    for (let i = 0; i < data.length; i += 2) {
      assessment[data[i]] = data[i + 1];
    }

    return ok(res, { assessment });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleGenerateGaps(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, investigation } = body;

    if (!investigationId || !investigation) {
      return fail(res, 400, 'MISSING_DATA', 'investigationId and investigation object required');
    }

    const result = await analysisMgr.generateInformationGaps(investigationId, investigation);

    return ok(res, result, 201);
  } catch (e) {
    return fail(res, 500, 'GAPS_FAILED', e.message);
  }
}
