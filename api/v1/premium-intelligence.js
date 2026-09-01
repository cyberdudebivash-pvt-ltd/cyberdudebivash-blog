'use strict';

const service = require('../_lib/premium-commerce-service');
const store = require('../_lib/premium-commerce-store');
const sec = require('../_lib/security');
const { authenticate } = require('../_lib/middleware');
const { requireAnalyst } = require('../_lib/analyst-auth');

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, X-API-Key, X-Analyst-Key, Content-Type',
};

function send(res, status, body) {
  sec.applySecurityHeaders(res);
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json');
  return res.status(status).json(body);
}

function fail(res, status, code, message, extra = {}) {
  return send(res, status, {
    success: false,
    error: { code, message, ...extra },
    meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
  });
}

function ok(res, data, status = 200) {
  return send(res, status, {
    success: true,
    data,
    meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
  });
}

function errorStatus(code) {
  return ({
    UNAUTHORIZED: 401,
    ORDER_NOT_FOUND: 404,
    ENTITLEMENT_NOT_FOUND: 404,
    REPORT_NOT_SELLABLE: 409,
    REPORT_NOT_PREMIUM_CERTIFIED: 409,
    ARTIFACT_UNAVAILABLE: 503,
    ARTIFACT_VERIFICATION_FAILED: 503,
    ARTIFACT_INTEGRITY_ERROR: 503,
    PAYMENT_GATEWAY_UNAVAILABLE: 503,
    INVALID_PAYMENT_SIGNATURE: 400,
    PAYMENT_ID_MISMATCH: 409,
    PAYMENT_ORDER_MISMATCH: 409,
    PAYMENT_AMOUNT_MISMATCH: 409,
    PAYMENT_CURRENCY_MISMATCH: 409,
    PAYMENT_NOT_CAPTURED: 409,
    PAYMENT_CONFLICT: 409,
    PAYMENT_CLAIM_CONFLICT: 409,
    INVALID_ORDER_STATE: 409,
    INVALID_PRICE: 400,
    UNSUPPORTED_CURRENCY: 400,
    INVALID_REPORT_METADATA: 400,
    INVALID_SLUG: 400,
  })[code] || 500;
}

function sanitizeId(value, max = 180) {
  return String(value || '').trim().slice(0, max);
}

async function requireCustomer(req, res) {
  return authenticate(req, res);
}

module.exports = async function premiumIntelligenceRouter(req, res) {
  const guarded = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes: 4.5 * 1024 * 1024,
  });
  if (!guarded) return;
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String((req.query && req.query.action) || 'catalog').toLowerCase().trim();

  try {
    if (action === 'catalog') {
      if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
      const reportType = sanitizeId(req.query.report_type, 80).toUpperCase();
      const reports = await service.listCatalog({ reportType, limit: req.query.limit });
      return ok(res, { reports, count: reports.length });
    }

    if (action === 'detail') {
      if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
      const id = sanitizeId(req.query.report_id || req.query.slug);
      if (!id) return fail(res, 400, 'MISSING_REPORT_ID', 'report_id or slug required');
      const report = await service.getCatalogItem(id);
      if (!report) return fail(res, 404, 'REPORT_NOT_FOUND', 'Premium report not found or not currently sellable.');
      return ok(res, { report });
    }

    if (action === 'publish-certified') {
      if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');
      const analyst = await requireAnalyst(req, res, fail);
      if (!analyst) return;
      const body = req.body && typeof req.body === 'object' ? req.body : {};
      const whitelistErr = sec.assertFieldWhitelist(body, [
        'reportx_export', 'title', 'slug', 'report_type', 'summary', 'price_minor',
        'currency', 'filename', 'published_at',
      ]);
      if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);
      const report = await service.publishCertifiedReport({
        reportxExport: body.reportx_export,
        title: body.title,
        slug: body.slug,
        reportType: body.report_type,
        summary: body.summary,
        priceMinor: body.price_minor,
        currency: body.currency,
        filename: body.filename,
        publishedAt: body.published_at,
      });
      return ok(res, { report, published_by: analyst.id }, 201);
    }

    if (action === 'set-status') {
      if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');
      const analyst = await requireAnalyst(req, res, fail);
      if (!analyst) return;
      const body = req.body && typeof req.body === 'object' ? req.body : {};
      const whitelistErr = sec.assertFieldWhitelist(body, ['report_id', 'status']);
      if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);
      const changed = await store.setCatalogStatus(sanitizeId(body.report_id), String(body.status || '').toUpperCase());
      if (!changed) return fail(res, 404, 'REPORT_NOT_FOUND', 'Premium report not found.');
      return ok(res, { report_id: sanitizeId(body.report_id), status: String(body.status || '').toUpperCase(), changed_by: analyst.id });
    }

    if (action === 'checkout') {
      if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');
      const user = await requireCustomer(req, res);
      if (!user) return;
      const body = req.body && typeof req.body === 'object' ? req.body : {};
      const whitelistErr = sec.assertFieldWhitelist(body, ['report_id']);
      if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);
      const reportId = sanitizeId(body.report_id);
      if (!reportId) return fail(res, 400, 'MISSING_REPORT_ID', 'report_id required');
      const checkout = await service.createCheckout({ user, reportId });
      return ok(res, checkout, 201);
    }

    if (action === 'verify') {
      if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');
      const user = await requireCustomer(req, res);
      if (!user) return;
      const body = req.body && typeof req.body === 'object' ? req.body : {};
      const whitelistErr = sec.assertFieldWhitelist(body, [
        'razorpay_order_id', 'razorpay_payment_id', 'razorpay_signature',
      ]);
      if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);
      const result = await service.verifyCheckout({
        user,
        razorpayOrderId: sanitizeId(body.razorpay_order_id),
        razorpayPaymentId: sanitizeId(body.razorpay_payment_id),
        razorpaySignature: sanitizeId(body.razorpay_signature, 256),
      });
      return ok(res, result);
    }

    if (action === 'library') {
      if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
      const user = await requireCustomer(req, res);
      if (!user) return;
      const reports = await service.listLibrary(user, req.query.limit);
      return ok(res, { reports, count: reports.length });
    }

    if (action === 'download') {
      if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
      const user = await requireCustomer(req, res);
      if (!user) return;
      const reportId = sanitizeId(req.query.report_id);
      if (!reportId) return fail(res, 400, 'MISSING_REPORT_ID', 'report_id required');
      const artifact = await service.downloadReport({ user, reportId });
      sec.applySecurityHeaders(res);
      res.setHeader('Cache-Control', 'private, no-store, max-age=0');
      res.setHeader('Content-Type', artifact.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${String(artifact.filename).replace(/["\r\n]/g, '_')}"`);
      res.setHeader('X-Content-SHA256', artifact.sha256);
      return res.status(200).send(artifact.bytes);
    }

    return fail(res, 400, 'INVALID_ACTION', 'Valid actions: catalog, detail, publish-certified, set-status, checkout, verify, library, download.');
  } catch (err) {
    const code = err && err.code ? err.code : 'PREMIUM_COMMERCE_ERROR';
    const extra = err && Array.isArray(err.reasons) ? { reasons: err.reasons } : {};
    const message = errorStatus(code) >= 500
      ? 'Premium intelligence commerce is temporarily unavailable. Please retry or contact support.'
      : String(err.message || 'Request could not be completed.');
    return fail(res, errorStatus(code), code, message, extra);
  }
};
