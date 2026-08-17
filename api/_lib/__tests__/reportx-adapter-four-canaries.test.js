'use strict';

// System 5 certification (P0-continuation task Section 14/7): proves the
// adapter and the existing, UNMODIFIED ProductCompositionEngine never
// recompute, promote, or lose anything System 3 already validated, using
// the FOUR REAL premium canary exports -- not a hand-written stub, not the
// older partial acceptance-fixture export reportx-adapter.test.js already
// covers. Each fixture here is the literal output of
// `python3 cli.py reportx-gate <bundle.json> --export out.json` run
// against a real, research-backed canary module in reportx-canary/ that
// independently reaches 23/23 PASS -- see that module's own docstring for
// its full source list.

const path = require('path');
const fs = require('fs');
const { loadReportXBundleFromFile } = require('../reportx-adapter');

const EXPORTS_DIR = path.join(__dirname, '..', '..', '..', 'reportx-canary', 'exports');

const CANARIES = [
  {
    label: 'Qilin / Spoonful of Comfort',
    file: 'qilin-spoonful-of-comfort-premium-canary-export.json',
    reportId: 'qilin-spoonful-of-comfort-premium-canary',
    actorName: 'Qilin',
    isRansomware: true,
  },
  {
    label: 'MedusaLocker / Bija Industrie',
    file: 'medusalocker-bija-industrie-premium-canary-export.json',
    reportId: 'medusalocker-bija-industrie-premium-canary',
    actorName: 'MedusaLocker',
    isRansomware: true,
  },
  {
    label: 'DragonForce / Vermont XCenter',
    file: 'dragonforce-vermont-xcenter-premium-canary-export.json',
    reportId: 'dragonforce-vermont-xcenter-premium-canary',
    actorName: 'DragonForce',
    isRansomware: true,
  },
  {
    label: 'CVE-2025-62593 (Ray)',
    file: 'cve-2025-62593-ray-canary-export.json',
    reportId: 'cve-2025-62593-ray-canary',
    actorName: null, // CVE-type product -- no RansomwareVictimClaim actor to extract
    isRansomware: false,
  },
];

describe.each(CANARIES)('System 5 integration -- $label (real 23/23 canary export)', (canary) => {
  const filePath = path.join(EXPORTS_DIR, canary.file);
  const rawExport = JSON.parse(fs.readFileSync(filePath, 'utf8'));

  test('the fixture itself is a real 23/23 PASS, PREMIUM_READY_PENDING_HUMAN export (not a partial acceptance stub)', () => {
    expect(rawExport.commercial_readiness.total_count).toBe(23);
    expect(rawExport.commercial_readiness.pass_count).toBe(23);
    expect(rawExport.commercial_readiness.verdict).toBe('COMMERCIAL-READY');
    expect(rawExport.bundle.is_premium_tier).toBe(true);
    expect(rawExport.bundle.review).toBeNull(); // no fabricated human approval
  });

  describe('does not recompute or promote claim truth', () => {
    test('every claim epistemic status/confidence read through the adapter is byte-identical to the raw export', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      const claims = bundle.getClaims();
      expect(claims.length).toBe(rawExport.bundle.claims.length);
      for (const rawClaim of rawExport.bundle.claims) {
        const viaAdapter = bundle.getClaim(rawClaim.claim_id);
        expect(viaAdapter.status).toBe(rawClaim.status);
        expect(viaAdapter.confidence).toBe(rawClaim.confidence);
        expect(viaAdapter.corroboration_state).toBe(rawClaim.corroboration_state);
        expect(viaAdapter.observed_vs_context).toBe(rawClaim.observed_vs_context);
      }
    });

    test('not every claim is blindly CONFIRMED -- the honest epistemic spread survives the JS boundary', () => {
      // Ransomware canaries carry an UNKNOWN/NOT_ASSESSED victim-compromise
      // claim; the CVE canary's honesty shows up differently (REPORTED/
      // ASSESSED rather than CONFIRMED for its genuinely uncertain
      // exploitation-tension claim) -- both are the same underlying
      // guarantee (System 5 doesn't see, and can't manufacture, false
      // certainty), asserted in the form each threat type actually uses.
      const bundle = loadReportXBundleFromFile(filePath);
      const nonConfirmed = bundle.getClaims().filter(c => c.status !== 'CONFIRMED');
      expect(nonConfirmed.length).toBeGreaterThan(0);
      for (const c of nonConfirmed) {
        // Re-read via the single-claim accessor too -- same guarantee, different path.
        expect(bundle.getClaim(c.claim_id).status).toBe(c.status);
      }
    });

    test('getIncidentSpecificClaims/getActorContextClaims partition exactly matches the raw OBSERVED/CONTEXT tags', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      const observedIds = new Set(bundle.getIncidentSpecificClaims().map(c => c.claim_id));
      const contextIds = new Set(bundle.getActorContextClaims().map(c => c.claim_id));
      for (const c of rawExport.bundle.claims) {
        if (c.observed_vs_context === 'OBSERVED') expect(observedIds.has(c.claim_id)).toBe(true);
        if (c.observed_vs_context === 'CONTEXT') expect(contextIds.has(c.claim_id)).toBe(true);
      }
      // Structural guarantee: no claim is in both partitions.
      for (const id of observedIds) expect(contextIds.has(id)).toBe(false);
    });
  });

  describe('does not promote detection validation', () => {
    test('detection rule validation_state is read exactly as System 3 stored it', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      const rules = bundle.getDetectionRules();
      expect(rules.length).toBe(rawExport.bundle.detection_rules.length);
      for (let i = 0; i < rules.length; i += 1) {
        expect(rules[i].validation_state).toBe(rawExport.bundle.detection_rules[i].validation_state);
        // Every real detection rule in these canaries is SYNTAX_VALIDATED --
        // never LAB_VALIDATED/TELEMETRY_VALIDATED/PRODUCTION_* (no lab or
        // live-telemetry testing was performed this session for any of them).
        expect(rules[i].validation_state).toBe('SYNTAX_VALIDATED');
      }
    });

    test('the investigation-shape bridge never mentions the rule at a higher validation tier than stored', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      const investigation = bundle.toInvestigationShape();
      const serialized = JSON.stringify(investigation);
      expect(serialized).not.toMatch(/production[- ]validated/i);
      expect(serialized).not.toMatch(/lab[- ]validated/i);
      expect(serialized).not.toMatch(/telemetry[- ]validated/i);
    });
  });

  describe('does not lose source or evidence references', () => {
    test('every claim source_ref still resolves to a real source record via the adapter', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      for (const claim of bundle.getClaims()) {
        for (const sourceId of claim.source_refs || []) {
          const source = bundle.getSource(sourceId);
          expect(source).not.toBeNull();
          expect(source.url).toBeTruthy();
        }
      }
    });

    test('every claim evidence_ref still resolves to a real evidence record with its excerpt intact', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      const evidenceById = new Map(bundle.getEvidence().map(e => [e.evidence_id, e]));
      for (const claim of bundle.getClaims()) {
        for (const evidenceId of claim.evidence_refs || []) {
          const ev = evidenceById.get(evidenceId);
          expect(ev).toBeDefined();
          expect(ev.excerpt).toBeTruthy();
          // Matches the raw export byte-for-byte -- not paraphrased in transit.
          const rawEv = rawExport.bundle.evidence.find(e => e.evidence_id === evidenceId);
          expect(ev.excerpt).toBe(rawEv.excerpt);
        }
      }
    });

    test('every source referenced anywhere in the canary carries its real content_sha256 (no integrity data lost)', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      for (const source of bundle.getSources()) {
        const hasIntegrity = Boolean(source.content_sha256) || Boolean(source.excerpt_fingerprint_sha256);
        expect(hasIntegrity).toBe(true);
      }
    });

    test('investigation.sources lists every real source_id, not a subset or a fabricated list', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      const investigation = bundle.toInvestigationShape();
      const realIds = bundle.getSources().map(s => s.source_id).sort();
      expect([...investigation.sources].sort()).toEqual(realIds);
    });
  });

  describe('does not lose commercial-readiness results or certification state', () => {
    test('all 23 control rows are preserved exactly, in the same PASS state, nothing dropped or added', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      const controls = bundle.getControlResults();
      expect(controls.length).toBe(23);
      expect(controls.every(c => c.status === 'PASS')).toBe(true);
      const rawIds = new Set(rawExport.commercial_readiness.controls.map(c => c.control_id));
      const adapterIds = new Set(controls.map(c => c.control_id));
      expect(adapterIds).toEqual(rawIds);
    });

    test('getVerdict/getPassCount/isCommercialReady reflect the real 23/23 result unmodified', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      expect(bundle.getPassCount()).toBe(23);
      expect(bundle.getTotalControlCount()).toBe(23);
      expect(bundle.getVerdict()).toBe('COMMERCIAL-READY');
      expect(bundle.isCommercialReady()).toBe(true);
      expect(bundle.getFailingControls()).toEqual([]);
    });

    test('getReview() surfaces the real (null) review -- System 5 cannot fabricate an approval', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      expect(bundle.getReview()).toBeNull();
    });

    test('the ingredients Python-side resolve_certification_state() needs (is_premium_tier + review) both survive the JS boundary', () => {
      // System 5 does not itself compute PREMIUM_READY_PENDING_HUMAN --
      // that resolution lives in human_review.py -- but this proves the
      // two fields it depends on are not lost or altered in transit, so
      // no downstream consumer could derive a wrong state from missing data.
      const bundle = loadReportXBundleFromFile(filePath);
      expect(bundle.isPremiumTier).toBe(true);
      expect(bundle.getReview()).toBe(rawExport.bundle.review);
    });

    test('reportXGate embedded in the investigation shape matches the real gate, not a fabricated one', () => {
      const bundle = loadReportXBundleFromFile(filePath);
      const investigation = bundle.toInvestigationShape();
      expect(investigation.reportXGate.verdict).toBe('COMMERCIAL-READY');
      expect(investigation.reportXGate.passCount).toBe(23);
      expect(investigation.reportXGate.totalCount).toBe(23);
    });
  });

  if (canary.isRansomware) {
    describe('real integration with the existing, unmodified ProductCompositionEngine', () => {
      const originalRedisUrl = process.env.UPSTASH_REDIS_REST_URL;
      const originalRedisToken = process.env.UPSTASH_REDIS_REST_TOKEN;

      beforeAll(() => {
        process.env.UPSTASH_REDIS_REST_URL = 'https://synthetic-test.upstash.io';
        process.env.UPSTASH_REDIS_REST_TOKEN = 'synthetic_test_token';
      });

      afterAll(() => {
        process.env.UPSTASH_REDIS_REST_URL = originalRedisUrl;
        process.env.UPSTASH_REDIS_REST_TOKEN = originalRedisToken;
      });

      test('composes a real threat-actor-profile product carrying the real actor name, not a placeholder', async () => {
        // eslint-disable-next-line global-require
        const { ProductCompositionEngine } = require('../product-composition-engine');
        const bundle = loadReportXBundleFromFile(filePath);
        const investigation = bundle.toInvestigationShape();
        const report = { id: `rpt-reportx-${canary.reportId}`, createdAt: new Date().toISOString() };

        const engine = new ProductCompositionEngine();
        const product = await engine.composeThreatActorProfile(investigation, report);

        expect(product.productType).toBe('threat-intelligence');
        expect(product.modules.overview.content.name).toBe(canary.actorName);
      });
    });
  } else {
    describe('CVE-type canary does not fabricate a ransomware actor', () => {
      test('threatActors stays empty and the engine adds no overview module for it (no invented actor)', async () => {
        // eslint-disable-next-line global-require
        const { ProductCompositionEngine } = require('../product-composition-engine');
        const bundle = loadReportXBundleFromFile(filePath);
        const investigation = bundle.toInvestigationShape();
        expect(investigation.threatActors).toEqual([]);

        const report = { id: `rpt-reportx-${canary.reportId}`, createdAt: new Date().toISOString() };
        const engine = new ProductCompositionEngine();
        const product = await engine.composeThreatActorProfile(investigation, report);
        // ProductCompositionEngine's composeThreatActorProfile() only calls
        // addModule('overview', ...) inside its own `if (threatActors.length
        // > 0)` guard -- with zero threat actors that branch never runs, so
        // .modules.overview stays at the product model's own unset default
        // (null) rather than an engine-fabricated actor. The title falls
        // back to the engine's own 'Unknown' literal, not an invented name.
        expect(product.modules.overview).toBeFalsy();
        expect(product.metadata.title).toContain('Unknown');
      });
    });
  }
});

describe('System 5 -- all four real canaries share zero investigation-shape identity collisions', () => {
  test('report_id (and therefore investigation.id) is unique across all four real exports', () => {
    const ids = CANARIES.map((c) => {
      const raw = JSON.parse(fs.readFileSync(path.join(EXPORTS_DIR, c.file), 'utf8'));
      return raw.bundle.report_id;
    });
    expect(new Set(ids).size).toBe(ids.length);
  });
});
