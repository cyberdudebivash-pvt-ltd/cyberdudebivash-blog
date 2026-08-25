'use strict';

// Route-handler tests for the new action=dossier action added to
// api/v1/intel.js. Same two-layer pattern as
// api/v1/__tests__/intel-unified-search.test.js:
//
// (1) No mocking at all — an unauthenticated request must 401 before
//     touching any dossier logic (proves this sits behind the same auth
//     gate as every existing action, not a bypass).
// (2) authenticate() mocked to return a controlled {tier} — everything
//     downstream (getDossierAPI -> buildCveDossier/buildCampaignDossier)
//     runs for real against real production data, proving genuine
//     end-to-end wiring and real tier gating, not a mocked stub.
jest.mock('../../_lib/middleware', () => {
  const actual = jest.requireActual('../../_lib/middleware');
  return { ...actual, authenticate: jest.fn(actual.authenticate) };
});

const { authenticate } = require('../../_lib/middleware');
const handler = require('../intel');

function mockReq(query = {}) {
  return { method: 'GET', query, headers: {}, url: '/api/v1/intel' };
}

function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}

function mockUser(tier) {
  return { tier, userId: 'test-user', email: 't@example.com', keyHash: 'x', requestsUsed: 1, requestsLimit: 999999 };
}

beforeEach(() => {
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
});

describe('unauthenticated requests to action=dossier', () => {
  it('returns 401 with no API key', async () => {
    const req = mockReq({ action: 'dossier', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(401);
  });
});

describe('action=dossier, type=cve (authenticated, real production data)', () => {
  it('returns a real, dense, evidence-backed dossier for a known CVE at enterprise tier', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'dossier', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.success).toBe(true);
    const dossier = body.dossier;
    expect(dossier.schema_version).toBe('1.0');
    expect(dossier.entity_id).toBe('CVE-2023-27351');
    expect(dossier.entity_type).toBe('cve');
    expect(dossier.relationships.related_campaigns.length).toBeGreaterThan(0);
    expect(dossier.relationships.related_actors.length).toBeGreaterThan(0);
    expect(dossier.attack_context.status).toBe('established');
    expect(dossier.attack_context.techniques.every(t => t.source === 'linked_actor' || t.source === 'linked_report')).toBe(true);
  });

  it('free tier gets an honestly empty relationships/attack_context section, not fabricated data', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'dossier', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const dossier = res.json.mock.calls[0][0].dossier;
    expect(dossier.relationships.related_campaigns).toEqual([]);
    expect(dossier.relationships.related_actors).toEqual([]);
    expect(dossier.attack_context.status).toBe('not_established');
    // Core risk facts (already free-visible via action=cve) must still be present.
    expect(dossier.risk.cvss).toBeGreaterThan(0);
    // Phase 29: a free-tier dossier for a genuinely dense CVE must be
    // marked as tier-gated, distinguishing "hidden by your plan" from
    // "nothing exists here" -- the UI must never conflate the two.
    expect(dossier.tier_info.relationships_gated).toBe(true);
    expect(dossier.tier_info.upgrade_message).toEqual(expect.any(String));
  });

  it('pro/enterprise tier is never marked relationships_gated', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'dossier', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    const dossier = res.json.mock.calls[0][0].dossier;
    expect(dossier.tier_info.relationships_gated).toBe(false);
    expect(dossier.tier_info.upgrade_message).toBeNull();
  });

  it('a genuinely sparse CVE (no graph relationships) reports honest empty states, never fabricated ones', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const { loadGraph } = require('../../_lib/threat-graph');
    const graph = loadGraph();
    const sparse = Object.values(graph.nodes).find(n =>
      n.type === 'CVE' && !graph.edges.some(e => e.source === n.id || e.target === n.id)
    );
    expect(sparse).toBeDefined();

    const req = mockReq({ action: 'dossier', type: 'cve', id: sparse.id });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const dossier = res.json.mock.calls[0][0].dossier;
    expect(dossier.relationships.related_campaigns).toEqual([]);
    expect(dossier.relationships.related_actors).toEqual([]);
    expect(dossier.relationships.counts).toEqual({ campaigns: 0, actors: 0, cves: 0 });
    expect(dossier.attack_context).toEqual({ status: 'not_established', techniques: [], total_techniques: 0 });
    expect(dossier.reports).toEqual([]);
  });

  it('rejects a malformed CVE ID with 400, not a fabricated empty dossier', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'dossier', type: 'cve', id: 'not-a-real-cve-id' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json.mock.calls[0][0].error.code).toBe('INVALID_CVE_ID');
  });

  it('404s for a well-formed but unknown CVE ID', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'dossier', type: 'cve', id: 'CVE-1999-00001' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json.mock.calls[0][0].error.code).toBe('DOSSIER_NOT_FOUND');
  });
});

describe('action=dossier, type=campaign (authenticated, real production data)', () => {
  it('returns a real, dense campaign dossier with attribution and ATT&CK context', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'dossier', type: 'campaign', id: 'campaign:cve-2024-27199-and-cve-2024-27198' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const dossier = res.json.mock.calls[0][0].dossier;
    expect(dossier.entity_type).toBe('campaign');
    expect(dossier.attribution.status).toBe('ASSESSED');
    expect(dossier.attribution.actors.length).toBeGreaterThan(0);
    expect(dossier.reports.length).toBeGreaterThan(0);
    expect(dossier.attack_context.status).toBe('established');
  });

  it('a campaign with no attributed actor honestly reports UNKNOWN attribution, never a fabricated actor', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const { loadJSON, PATHS } = require('../../_lib/intel');
    const data = loadJSON(PATHS.campaigns);
    const noActor = data.campaigns.find(c => !(c.threat_actors && c.threat_actors.length));
    expect(noActor).toBeDefined();

    const req = mockReq({ action: 'dossier', type: 'campaign', id: noActor.campaign_id });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const dossier = res.json.mock.calls[0][0].dossier;
    expect(dossier.attribution.status).toBe('UNKNOWN');
    expect(dossier.attribution.actors).toEqual([]);
    expect(dossier.attribution.basis).toMatch(/no evidence-backed/i);
  });

  it('a campaign missing a name falls back to its ID, never rendering "undefined"', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const { loadJSON, PATHS } = require('../../_lib/intel');
    const data = loadJSON(PATHS.campaigns);
    const target = data.campaigns[0];
    const originalName = target.name;
    delete target.name; // adversarial: campaign missing a name (Phase 53)
    try {
      const req = mockReq({ action: 'dossier', type: 'campaign', id: target.campaign_id });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
      const dossier = res.json.mock.calls[0][0].dossier;
      expect(dossier.identity.name).toBe(target.campaign_id);
      expect(dossier.assessment.summary).not.toMatch(/^undefined:/);
      expect(dossier.assessment.summary.startsWith(target.campaign_id)).toBe(true);
    } finally {
      target.name = originalName; // restore the shared in-process cache
    }
  });

  it('404s for an unknown campaign ID', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'dossier', type: 'campaign', id: 'campaign:does-not-exist-at-all' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(404);
  });
});

describe('action=dossier — unsupported entity types stay honestly unsupported', () => {
  it.each(['malware', 'actor', 'ioc', 'report', ''])('rejects type=%s with 400 UNSUPPORTED_ENTITY_TYPE, not a fabricated dossier', async (type) => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'dossier', type, id: 'anything' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json.mock.calls[0][0].error.code).toBe('UNSUPPORTED_ENTITY_TYPE');
  });
});

describe('action=dossier — missing id', () => {
  it('400s when id is missing', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'dossier', type: 'cve' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json.mock.calls[0][0].error.code).toBe('MISSING_DOSSIER_ID');
  });
});

describe('backward compatibility: existing actions are untouched by the new dossier action', () => {
  it('action=cve still returns its original shape (no dossier field injected)', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.dossier).toBeUndefined();
    expect(body.item).toBeDefined();
  });

  it('action=campaign still returns its original shape (no dossier field injected)', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'campaign', id: 'campaign:cve-2024-27199-and-cve-2024-27198' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.dossier).toBeUndefined();
    expect(body.campaign).toBeDefined();
  });
});
