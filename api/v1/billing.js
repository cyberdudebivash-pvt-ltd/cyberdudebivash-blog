'use strict';

/**
 * Revenue-safety gateway around the existing billing router.
 *
 * Subscription/manual-payment billing remains unchanged. The legacy one-time
 * digital-product checkout is deliberately failed closed because its catalog
 * stores USD cents while the old Razorpay path reinterprets those values as
 * INR rupees/paise, and its advertised download backend is not provisioned.
 * Accepting money before both price/currency and delivery truth are fixed is
 * worse than temporarily declining the transaction.
 */
const legacyHandler = require('./billing-legacy');
const sec = require('../_lib/security');

const BLOCKED_PRODUCT_ACTIONS = new Set([
  'create-product-checkout',
  'verify-product-payment',
]);

function failClosed(res) {
  sec.applySecurityHeaders(res);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json');
  return res.status(503).json({
    success: false,
    error: {
      code: 'PRODUCT_COMMERCE_REBUILDING',
      message: 'One-time digital product checkout is temporarily unavailable while secure report delivery is being upgraded. No payment has been accepted by this request.',
    },
    meta: {
      platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0',
      timestamp: new Date().toISOString(),
      support: 'bivash@cyberdudebivash.com',
    },
  });
}

module.exports = async function revenueSafeBillingRouter(req, res) {
  const action = String((req.query && req.query.action) || '').toLowerCase().trim();
  if (BLOCKED_PRODUCT_ACTIONS.has(action)) return failClosed(res);
  return legacyHandler(req, res);
};

module.exports.BLOCKED_PRODUCT_ACTIONS = BLOCKED_PRODUCT_ACTIONS;
