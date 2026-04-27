/**
 * GET /api/v1/billing/payment-status?transaction_id=XXX&email=xxx
 * SENTINEL APEX Manual Payment System — Phase 7 (User Feedback)
 *
 * Lets a user check the status of their submitted payment.
 * No API key required — accessible publicly via email+UTR pair.
 * Email acts as the "secret" — never expose admin-level data.
 *
 * Returns: status, plan, submitted_at, reviewed_at (no IP/UA).
 */
'use strict';
const redis = require('../../_lib/redis');
const {
  sanitize, validateEmail, normalizeEmail,
  parseHash, cors, ok, fail,
} = require('../../_lib/payment-utils');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const txnRaw = sanitize(String(req.query?.transaction_id || ''), 64).toUpperCase();
  const email  = normalizeEmail(req.query?.email || '');

  if (!txnRaw || txnRaw.length < 6) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID', 'transaction_id query parameter is required.');
  }
  if (!validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'Valid email query parameter required.');
  }

  try {
    const raw  = await redis.hgetall(`payment:submission:${txnRaw}`);
    const sub  = parseHash(raw);

    if (!sub) {
      return fail(res, 404, 'NOT_FOUND',
        'No payment submission found for this transaction ID. Verify the UTR or submit at POST /api/v1/billing/submit-payment');
    }

    // Email guard — user can only check their own submissions
    if (sub.email !== email) {
      return fail(res, 403, 'FORBIDDEN',
        'Email does not match this submission. Provide the same email used when submitting.');
    }

    const STATUS_MESSAGES = {
      pending_review: 'Your payment is under review. Typical verification time: 2–6 hours on business days.',
      approved:       'Payment approved! Your API tier has been upgraded. Check /api/v1/auth/me to confirm.',
      rejected:       'Payment could not be verified. Please contact bivash@cyberdudebivash.com for resolution.',
    };

    return ok(res, {
      payment_status: {
        transaction_id: txnRaw,
        plan_type:      sub.planType,
        amount:         parseInt(sub.amount || '0', 10),
        currency:       sub.currency,
        payment_method: sub.paymentMethod,
        status:         sub.status,
        status_message: STATUS_MESSAGES[sub.status] || `Status: ${sub.status}`,
        submitted_at:   sub.submittedAt,
        reviewed_at:    sub.reviewedAt   || null,
        rejection_note: sub.status === 'rejected' ? (sub.rejectionNote || null) : null,
      },
      next_steps: sub.status === 'approved'
        ? ['Visit GET /api/v1/auth/me with your API key to see your upgraded tier.']
        : sub.status === 'rejected'
        ? ['Contact bivash@cyberdudebivash.com with your transaction ID for manual review.']
        : [
          'Please wait 2–6 hours for verification.',
          'Contact bivash@cyberdudebivash.com if pending for more than 24 hours.',
        ],
    });

  } catch (e) {
    return fail(res, 500, 'STATUS_CHECK_FAILED', `Failed to check payment status: ${e.message}`);
  }
};
