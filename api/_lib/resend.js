/**
 * SENTINEL APEX — Resend REST Client (zero npm dependencies)
 * Uses the Resend REST API directly via fetch — secret never leaves the server.
 * Required env vars: RESEND_API_KEY, RESEND_AUDIENCE_ID
 */
'use strict';

const RESEND_API_KEY    = process.env.RESEND_API_KEY    || '';
const RESEND_AUDIENCE_ID = process.env.RESEND_AUDIENCE_ID || '';
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL ||
  'CYBERDUDEBIVASH SENTINEL APEX <noreply@cyberdudebivash.com>';
const RESEND_BASE       = 'https://api.resend.com';

function configured() {
  return Boolean(RESEND_API_KEY && RESEND_AUDIENCE_ID);
}

/** True if transactional sending is possible — only needs the API key,
 * unlike configured() above which also requires an audience for the
 * newsletter's contact-management feature. Two independent capabilities
 * that happen to share one API key. */
function canSendEmail() {
  return Boolean(RESEND_API_KEY);
}

async function resendRequest(method, path, body) {
  const opts = {
    method,
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type':  'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res  = await fetch(`${RESEND_BASE}${path}`, opts);
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Resend error: ${json.message || res.statusText}`);
  return json;
}

/** Add (or update) a contact in the configured audience. */
async function addContact(email, firstName) {
  return resendRequest('POST', `/audiences/${RESEND_AUDIENCE_ID}/contacts`, {
    email,
    first_name:   firstName || undefined,
    unsubscribed: false,
  });
}

/** Send a single transactional email. Does not touch the audience/contacts
 * feature — independent of RESEND_AUDIENCE_ID. */
async function sendEmail({ to, subject, html, text }) {
  return resendRequest('POST', '/emails', {
    from: RESEND_FROM_EMAIL,
    to,
    subject,
    html,
    text,
  });
}

module.exports = { configured, canSendEmail, addContact, sendEmail };
