'use strict';

const redis = require('../../_lib/redis');
const { InvestigationManager } = require('../../_lib/investigation-manager');
const { CaseManager } = require('../../_lib/case-manager');

const investigationMgr = new InvestigationManager(redis);
const caseMgr = new CaseManager(redis, investigationMgr);

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

  if (req.method === 'POST' && action === 'cases') {
    return handleCreateCase(req, res);
  }

  if (req.method === 'GET' && action && id) {
    const resourceType = pathParts[pathParts.length - 3];
    if (resourceType === 'cases') {
      return handleGetCase(req, res, id);
    }
  }

  if (req.method === 'POST' && pathParts.includes('notes') && id) {
    return handleAddNote(req, res, id);
  }

  if (req.method === 'POST' && pathParts.includes('tasks') && id) {
    return handleAddTask(req, res, id);
  }

  if (req.method === 'PUT' && action === 'close' && id) {
    return handleCloseCase(req, res, id);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleCreateCase(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, title, description } = body;
    if (!investigationId || !title) {
      return fail(res, 400, 'MISSING_FIELD', 'investigationId and title required');
    }

    const caseObj = await caseMgr.createCase(investigationId, title, description || '');

    return ok(res, { case: caseObj }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleGetCase(req, res, id) {
  try {
    const caseObj = await caseMgr.getCase(id);
    if (!caseObj) {
      return fail(res, 404, 'NOT_FOUND', `Case not found: ${id}`);
    }

    const summary = await caseMgr.getCaseSummary(id);

    return ok(res, { case: caseObj, summary });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleAddNote(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { content, author } = body;
    if (!content) {
      return fail(res, 400, 'MISSING_CONTENT', 'content required');
    }

    const note = await caseMgr.addNote(id, content, author || 'analyst');

    return ok(res, { note }, 201);
  } catch (e) {
    return fail(res, 500, 'NOTE_FAILED', e.message);
  }
}

async function handleAddTask(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { description, assignee, dueDate } = body;
    if (!description) {
      return fail(res, 400, 'MISSING_DESCRIPTION', 'description required');
    }

    const task = await caseMgr.addTask(id, description, assignee, dueDate);

    return ok(res, { task }, 201);
  } catch (e) {
    return fail(res, 500, 'TASK_FAILED', e.message);
  }
}

async function handleCloseCase(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { closureReason } = body;
    const result = await caseMgr.closeCase(id, closureReason || 'No reason provided');

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'CLOSE_FAILED', e.message);
  }
}
