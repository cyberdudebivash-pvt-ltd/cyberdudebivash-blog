'use strict';

const redis = require('../../_lib/redis');
const { ProductFactory } = require('../../_lib/product-factory');
const crypto = require('crypto');

const productFactory = new ProductFactory(redis);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const APPROVAL_LEVELS = {
  MANAGER: { level: 1, title: 'Manager Review' },
  EXECUTIVE: { level: 2, title: 'Executive Approval' },
  LEGAL: { level: 3, title: 'Legal Review' },
  COMPLIANCE: { level: 4, title: 'Compliance Review' },
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
  const resourceId = pathParts[pathParts.length - 2];

  // Submit product for review
  if (req.method === 'POST' && action === 'submit-review' && resourceId) {
    return handleSubmitReview(req, res, resourceId);
  }

  // Approve product
  if (req.method === 'POST' && action === 'approve' && resourceId) {
    return handleApproveProduct(req, res, resourceId);
  }

  // Reject product
  if (req.method === 'POST' && action === 'reject' && resourceId) {
    return handleRejectProduct(req, res, resourceId);
  }

  // Get approval history
  if (req.method === 'GET' && action === 'history' && resourceId) {
    return handleGetApprovalHistory(req, res, resourceId);
  }

  // Get pending approvals
  if (req.method === 'GET' && action === 'pending') {
    return handleGetPendingApprovals(req, res);
  }

  // Get approval workflow status
  if (req.method === 'GET' && action === 'status' && resourceId) {
    return handleGetApprovalStatus(req, res, resourceId);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleSubmitReview(req, res, productId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { submitter, reviewLevel, message } = body;

    if (!submitter || !reviewLevel) {
      return fail(res, 400, 'MISSING_FIELD', 'submitter and reviewLevel required');
    }

    if (!APPROVAL_LEVELS[reviewLevel]) {
      return fail(res, 400, 'INVALID_LEVEL', `reviewLevel must be one of: ${Object.keys(APPROVAL_LEVELS).join(', ')}`);
    }

    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    if (product.status === 'PUBLISHED' || product.status === 'ARCHIVED') {
      return fail(res, 400, 'INVALID_STATUS', `Cannot submit ${product.status} product for review`);
    }

    const workflowRecord = {
      id: crypto.randomBytes(8).toString('hex'),
      productId,
      submitter,
      reviewLevel,
      status: 'PENDING',
      submittedAt: new Date().toISOString(),
      message: message || '',
      approvalChain: [],
    };

    product.status = 'UNDER_REVIEW';
    product.updatedAt = new Date().toISOString();

    await productFactory.persistProduct(product);

    const workflowKey = `approval-workflow:${productId}`;
    await redis.hset(workflowKey, Object.entries(workflowRecord).flat());
    await redis.zadd('approval-workflows:pending', Date.now(), productId);

    return ok(res, {
      productId,
      workflow: workflowRecord,
      message: 'Product submitted for review',
    }, 201);
  } catch (e) {
    return fail(res, 500, 'SUBMIT_FAILED', e.message);
  }
}

async function handleApproveProduct(req, res, productId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { approver, approvalLevel, feedback } = body;

    if (!approver || !approvalLevel) {
      return fail(res, 400, 'MISSING_FIELD', 'approver and approvalLevel required');
    }

    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    if (product.status !== 'UNDER_REVIEW') {
      return fail(res, 400, 'INVALID_STATUS', `Product must be UNDER_REVIEW to approve (current: ${product.status})`);
    }

    const workflowKey = `approval-workflow:${productId}`;
    const workflowData = await redis.hgetall(workflowKey);

    if (!workflowData || workflowData.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Approval workflow not found for product: ${productId}`);
    }

    const workflow = parseRedisHash(workflowData);
    const approvalChain = workflow.approvalChain ? JSON.parse(workflow.approvalChain) : [];

    const approval = {
      id: crypto.randomBytes(8).toString('hex'),
      approver,
      level: approvalLevel,
      feedback: feedback || '',
      approvedAt: new Date().toISOString(),
      decision: 'APPROVED',
    };

    approvalChain.push(approval);
    product.approve(approver, approvalLevel);

    workflow.approvalChain = JSON.stringify(approvalChain);
    workflow.lastApprovedAt = new Date().toISOString();
    workflow.lastApprovedBy = approver;

    if (approvalChain.length >= 2) {
      workflow.status = 'APPROVED';
      product.status = 'APPROVED';
      await redis.zrem('approval-workflows:pending', productId);
      await redis.zadd('approval-workflows:approved', Date.now(), productId);
    }

    await redis.hset(workflowKey, Object.entries(workflow).flat());
    await productFactory.persistProduct(product);

    return ok(res, {
      productId,
      approval,
      workflow: { ...workflow, approvalChain },
      message: approvalChain.length >= 2 ? 'Product approved by all reviewers' : 'Approval recorded',
    });
  } catch (e) {
    return fail(res, 500, 'APPROVAL_FAILED', e.message);
  }
}

async function handleRejectProduct(req, res, productId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { reviewer, reason } = body;

    if (!reviewer || !reason) {
      return fail(res, 400, 'MISSING_FIELD', 'reviewer and reason required');
    }

    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    if (product.status !== 'UNDER_REVIEW') {
      return fail(res, 400, 'INVALID_STATUS', `Product must be UNDER_REVIEW to reject (current: ${product.status})`);
    }

    const workflowKey = `approval-workflow:${productId}`;
    const workflowData = await redis.hgetall(workflowKey);

    if (!workflowData || workflowData.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Approval workflow not found for product: ${productId}`);
    }

    const workflow = parseRedisHash(workflowData);

    product.status = 'DRAFT';
    workflow.status = 'REJECTED';
    workflow.rejectedAt = new Date().toISOString();
    workflow.rejectedBy = reviewer;
    workflow.rejectionReason = reason;

    await redis.hset(workflowKey, Object.entries(workflow).flat());
    await redis.zrem('approval-workflows:pending', productId);
    await redis.zadd('approval-workflows:rejected', Date.now(), productId);
    await productFactory.persistProduct(product);

    return ok(res, {
      productId,
      workflow,
      message: 'Product rejected and returned to draft status',
    });
  } catch (e) {
    return fail(res, 500, 'REJECTION_FAILED', e.message);
  }
}

async function handleGetApprovalHistory(req, res, productId) {
  try {
    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    const workflowKey = `approval-workflow:${productId}`;
    const workflowData = await redis.hgetall(workflowKey);

    if (!workflowData || workflowData.length === 0) {
      return ok(res, {
        productId,
        approvalHistory: product.approvals || [],
        message: 'No approval workflow found',
      });
    }

    const workflow = parseRedisHash(workflowData);
    const approvalChain = workflow.approvalChain ? JSON.parse(workflow.approvalChain) : [];

    return ok(res, {
      productId,
      workflowStatus: workflow.status,
      workflowSubmittedAt: workflow.submittedAt,
      approvalHistory: approvalChain,
      productApprovals: product.approvals || [],
      count: approvalChain.length,
    });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleGetPendingApprovals(req, res) {
  try {
    const limit = parseInt(req.query.limit || '50', 10);
    const status = req.query.status || 'PENDING';

    let workflowIds = [];
    if (status === 'PENDING') {
      workflowIds = await redis.zrevrange('approval-workflows:pending', 0, limit - 1);
    } else if (status === 'APPROVED') {
      workflowIds = await redis.zrevrange('approval-workflows:approved', 0, limit - 1);
    } else if (status === 'REJECTED') {
      workflowIds = await redis.zrevrange('approval-workflows:rejected', 0, limit - 1);
    }

    const workflows = [];

    for (const productId of workflowIds) {
      const workflowData = await redis.hgetall(`approval-workflow:${productId}`);
      if (workflowData && workflowData.length > 0) {
        const workflow = parseRedisHash(workflowData);
        workflows.push({
          productId,
          submitter: workflow.submitter,
          status: workflow.status,
          reviewLevel: workflow.reviewLevel,
          submittedAt: workflow.submittedAt,
          approvalCount: workflow.approvalChain ? JSON.parse(workflow.approvalChain).length : 0,
        });
      }
    }

    return ok(res, {
      status,
      workflows,
      count: workflows.length,
    });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleGetApprovalStatus(req, res, productId) {
  try {
    const product = await productFactory.getProduct(productId);
    if (!product) {
      return fail(res, 404, 'NOT_FOUND', `Product not found: ${productId}`);
    }

    const workflowKey = `approval-workflow:${productId}`;
    const workflowData = await redis.hgetall(workflowKey);

    let workflow = null;
    if (workflowData && workflowData.length > 0) {
      workflow = parseRedisHash(workflowData);
    }

    return ok(res, {
      productId,
      productStatus: product.status,
      workflow: workflow || {
        status: 'NOT_SUBMITTED',
        message: 'Product has not been submitted for review',
      },
      approvals: product.approvals || [],
      canPublish: product.status === 'APPROVED',
    });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

function parseRedisHash(data) {
  if (!data || data.length === 0) return {};

  const obj = {};
  for (let i = 0; i < data.length; i += 2) {
    const key = data[i];
    const value = data[i + 1];

    if (['approvalChain'].includes(key)) {
      try {
        obj[key] = JSON.parse(value);
      } catch (e) {
        obj[key] = value;
      }
    } else {
      obj[key] = value;
    }
  }
  return obj;
}
