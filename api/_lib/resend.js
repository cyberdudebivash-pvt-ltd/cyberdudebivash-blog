/**
 * SENTINEL APEX — Resend REST Client (zero npm dependencies)
 * Uses the Resend REST API directly via fetch — secret never leaves the server.
 * Required env vars: RESEND_API_KEY, RESEND_AUDIENCE_ID
 */
'use strict';

const RESEND_API_KEY    = process.env.RESEND_API_KEY    || '';
const RESEND_AUDIENCE_ID = process.env.RESEND_AUDIENCE_ID || '';
const RESEND_BASE       = 'https://api.resend.com';

function configured() {
  return Boolean(RESEND_API_KEY && RESEND_AUDIENCE_ID);
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

module.exports = { configured, addContact };
