'use strict';

const { detectChanges, makeEventId, IMPORTANCE } = require('../change-detector');

function cveState(overrides = {}) {
  return {
    schema_version: '1.0', entity_type: 'cve', entity_id: 'CVE-2026-1234',
    cvss: 7.5, severity: 'high', kev: false, active_exploitation: 'UNKNOWN',
    campaign_ids: [], actor_ids: [], report_ids: [],
    ...overrides,
  };
}
function campaignState(overrides = {}) {
  return {
    schema_version: '1.0', entity_type: 'campaign', entity_id: 'campaign:x',
    severity: 'high', confidence_bucket: 'MEDIUM', last_seen: '2026-08-01',
    actor_ids: [], cve_ids: [], report_ids: [],
    has_kev: false, has_exploited: false, has_ransomware: false,
    ...overrides,
  };
}

describe('detectChanges — baseline and no-op contract', () => {
  test('no prior state -> baseline_established, zero events (Phase 52)', () => {
    const result = detectChanges({ entityType: 'cve', before: null, after: cveState() });
    expect(result.status).toBe('baseline_established');
    expect(result.events).toEqual([]);
  });

  test('identical before/after -> unchanged, zero events', () => {
    const state = cveState();
    const result = detectChanges({ entityType: 'cve', before: state, after: { ...state } });
    expect(result.status).toBe('unchanged');
    expect(result.events).toEqual([]);
  });
});

describe('detectChanges — noise suppression (Phase 22/71)', () => {
  test('relationship array reordering produces zero events', () => {
    const before = cveState({ campaign_ids: ['campaign:a', 'campaign:b'] });
    const after  = cveState({ campaign_ids: ['campaign:b', 'campaign:a'] });
    const result = detectChanges({ entityType: 'cve', before, after });
    expect(result.status).toBe('unchanged');
  });

  test('CVSS 9.8 vs "9.8" (numeric vs string) compares equal -- no event', () => {
    const before = cveState({ cvss: 9.8 });
    const after  = cveState({ cvss: '9.8' });
    const result = detectChanges({ entityType: 'cve', before, after });
    expect(result.status).toBe('unchanged');
  });

  test('KEV true -> true produces zero events (not just false->true guarded)', () => {
    const before = cveState({ kev: true });
    const after  = cveState({ kev: true });
    const result = detectChanges({ entityType: 'cve', before, after });
    expect(result.events.filter(e => e.change_type === 'CVE_KEV_ADDED')).toHaveLength(0);
  });

  test('a field absent from watchable state (e.g. generated_at) cannot cause an event -- the detector only ever sees the fields the state object defines', () => {
    // watchable-state.js deliberately excludes generated_at entirely; this
    // test documents that guarantee at the detector boundary: passing two
    // states that differ only in an extraneous, non-schema field produces
    // no event, because the detector never reads it.
    const before = cveState();
    const after = { ...cveState(), generated_at: '2026-01-01T00:00:00Z' };
    const result = detectChanges({ entityType: 'cve', before, after });
    expect(result.status).toBe('unchanged');
  });
});

describe('detectChanges — CVE change types', () => {
  test('KEV false -> true produces CVE_KEV_ADDED at HIGH importance', () => {
    const result = detectChanges({ entityType: 'cve', before: cveState({ kev: false }), after: cveState({ kev: true }) });
    const ev = result.events.find(e => e.change_type === 'CVE_KEV_ADDED');
    expect(ev).toBeDefined();
    expect(ev.importance).toBe('HIGH');
    expect(ev.before).toBe(false);
    expect(ev.after).toBe(true);
    expect(ev.reason).toMatch(/CVE-2026-1234/);
  });

  test('exploitation UNKNOWN -> CONFIRMED produces CVE_ACTIVE_EXPLOITATION_CONFIRMED at CRITICAL', () => {
    const result = detectChanges({
      entityType: 'cve',
      before: cveState({ active_exploitation: 'UNKNOWN' }),
      after: cveState({ active_exploitation: 'CONFIRMED' }),
    });
    const ev = result.events.find(e => e.change_type === 'CVE_ACTIVE_EXPLOITATION_CONFIRMED');
    expect(ev).toBeDefined();
    expect(ev.importance).toBe('CRITICAL');
  });

  test('exploitation ASSESSED -> CONFIRMED also fires (any non-CONFIRMED -> CONFIRMED transition)', () => {
    const result = detectChanges({
      entityType: 'cve',
      before: cveState({ active_exploitation: 'ASSESSED' }),
      after: cveState({ active_exploitation: 'CONFIRMED' }),
    });
    expect(result.events.some(e => e.change_type === 'CVE_ACTIVE_EXPLOITATION_CONFIRMED')).toBe(true);
  });

  test('CONFIRMED -> ASSESSED (a reversal) produces NO event -- v1 is addition-only (Phase 74)', () => {
    const result = detectChanges({
      entityType: 'cve',
      before: cveState({ active_exploitation: 'CONFIRMED' }),
      after: cveState({ active_exploitation: 'ASSESSED' }),
    });
    expect(result.events.some(e => e.change_type === 'CVE_ACTIVE_EXPLOITATION_CONFIRMED')).toBe(false);
  });

  test('KEV true -> false (a reversal) produces NO event', () => {
    const result = detectChanges({ entityType: 'cve', before: cveState({ kev: true }), after: cveState({ kev: false }) });
    expect(result.events.some(e => e.change_type === 'CVE_KEV_ADDED')).toBe(false);
  });

  test('CVSS genuinely changing (7.5 -> 9.8) produces CVE_CVSS_CHANGED at MEDIUM', () => {
    const result = detectChanges({ entityType: 'cve', before: cveState({ cvss: 7.5 }), after: cveState({ cvss: 9.8 }) });
    const ev = result.events.find(e => e.change_type === 'CVE_CVSS_CHANGED');
    expect(ev).toBeDefined();
    expect(ev.importance).toBe('MEDIUM');
    expect(ev.before).toBe(7.5);
    expect(ev.after).toBe(9.8);
  });

  test('severity change produces CVE_SEVERITY_CHANGED', () => {
    const result = detectChanges({ entityType: 'cve', before: cveState({ severity: 'high' }), after: cveState({ severity: 'critical' }) });
    expect(result.events.some(e => e.change_type === 'CVE_SEVERITY_CHANGED')).toBe(true);
  });

  test('a new campaign association produces one CVE_NEW_CAMPAIGN_ASSOCIATION event carrying the related entity', () => {
    const before = cveState({ campaign_ids: ['campaign:a'] });
    const after  = cveState({ campaign_ids: ['campaign:a', 'campaign:b'] });
    const result = detectChanges({ entityType: 'cve', before, after });
    const ev = result.events.find(e => e.change_type === 'CVE_NEW_CAMPAIGN_ASSOCIATION');
    expect(ev).toBeDefined();
    expect(ev.related).toEqual({ id: 'campaign:b', type: 'campaign' });
    // pre-existing "campaign:a" must NOT re-fire
    expect(result.events.filter(e => e.change_type === 'CVE_NEW_CAMPAIGN_ASSOCIATION')).toHaveLength(1);
  });

  test('two new campaigns produce two distinct, individually-evidenced events', () => {
    const before = cveState({ campaign_ids: [] });
    const after  = cveState({ campaign_ids: ['campaign:a', 'campaign:b'] });
    const result = detectChanges({ entityType: 'cve', before, after });
    const evs = result.events.filter(e => e.change_type === 'CVE_NEW_CAMPAIGN_ASSOCIATION');
    expect(evs).toHaveLength(2);
    expect(evs.map(e => e.related.id).sort()).toEqual(['campaign:a', 'campaign:b']);
  });

  test('a campaign disappearing from campaign_ids produces NO removal event (Phase 77: additions only)', () => {
    const before = cveState({ campaign_ids: ['campaign:a', 'campaign:b'] });
    const after  = cveState({ campaign_ids: ['campaign:a'] });
    const result = detectChanges({ entityType: 'cve', before, after });
    expect(result.events).toHaveLength(0);
  });

  test('new actor association produces CVE_NEW_ACTOR_ASSOCIATION', () => {
    const result = detectChanges({
      entityType: 'cve',
      before: cveState({ actor_ids: [] }),
      after: cveState({ actor_ids: ['actor:lockbit'] }),
    });
    expect(result.events.find(e => e.change_type === 'CVE_NEW_ACTOR_ASSOCIATION').related).toEqual({ id: 'actor:lockbit', type: 'actor' });
  });

  test('new report produces CVE_NEW_REPORT', () => {
    const result = detectChanges({
      entityType: 'cve',
      before: cveState({ report_ids: [] }),
      after: cveState({ report_ids: ['SA-2026-0001'] }),
    });
    expect(result.events.find(e => e.change_type === 'CVE_NEW_REPORT').related).toEqual({ id: 'SA-2026-0001', type: 'report' });
  });
});

describe('detectChanges — Campaign change types', () => {
  test('has_kev false -> true produces CAMPAIGN_KEV_FLAG_ADDED', () => {
    const result = detectChanges({ entityType: 'campaign', before: campaignState({ has_kev: false }), after: campaignState({ has_kev: true }) });
    expect(result.events.some(e => e.change_type === 'CAMPAIGN_KEV_FLAG_ADDED')).toBe(true);
  });

  test('has_exploited false -> true produces CAMPAIGN_EXPLOITED_FLAG_ADDED', () => {
    const result = detectChanges({ entityType: 'campaign', before: campaignState({ has_exploited: false }), after: campaignState({ has_exploited: true }) });
    expect(result.events.some(e => e.change_type === 'CAMPAIGN_EXPLOITED_FLAG_ADDED')).toBe(true);
  });

  test('has_ransomware false -> true produces CAMPAIGN_RANSOMWARE_FLAG_ADDED', () => {
    const result = detectChanges({ entityType: 'campaign', before: campaignState({ has_ransomware: false }), after: campaignState({ has_ransomware: true }) });
    expect(result.events.some(e => e.change_type === 'CAMPAIGN_RANSOMWARE_FLAG_ADDED')).toBe(true);
  });

  test('confidence_bucket change produces CAMPAIGN_CONFIDENCE_CHANGED', () => {
    const result = detectChanges({ entityType: 'campaign', before: campaignState({ confidence_bucket: 'MEDIUM' }), after: campaignState({ confidence_bucket: 'HIGH' }) });
    expect(result.events.some(e => e.change_type === 'CAMPAIGN_CONFIDENCE_CHANGED')).toBe(true);
  });

  test('last_seen advancing produces CAMPAIGN_LAST_SEEN_ADVANCED at LOW importance', () => {
    const result = detectChanges({ entityType: 'campaign', before: campaignState({ last_seen: '2026-08-01' }), after: campaignState({ last_seen: '2026-08-20' }) });
    const ev = result.events.find(e => e.change_type === 'CAMPAIGN_LAST_SEEN_ADVANCED');
    expect(ev).toBeDefined();
    expect(ev.importance).toBe('LOW');
  });

  test('last_seen moving backward (a correction, not fresh activity) produces NO event', () => {
    const result = detectChanges({ entityType: 'campaign', before: campaignState({ last_seen: '2026-08-20' }), after: campaignState({ last_seen: '2026-08-01' }) });
    expect(result.events.some(e => e.change_type === 'CAMPAIGN_LAST_SEEN_ADVANCED')).toBe(false);
  });

  test('new attributed actor produces CAMPAIGN_NEW_ACTOR', () => {
    const result = detectChanges({
      entityType: 'campaign',
      before: campaignState({ actor_ids: [] }),
      after: campaignState({ actor_ids: ['actor:apt41'] }),
    });
    expect(result.events.find(e => e.change_type === 'CAMPAIGN_NEW_ACTOR').related).toEqual({ id: 'actor:apt41', type: 'actor' });
  });

  test('new linked CVE produces CAMPAIGN_NEW_CVE', () => {
    const result = detectChanges({
      entityType: 'campaign',
      before: campaignState({ cve_ids: ['CVE-2026-0001'] }),
      after: campaignState({ cve_ids: ['CVE-2026-0001', 'CVE-2026-0002'] }),
    });
    expect(result.events.find(e => e.change_type === 'CAMPAIGN_NEW_CVE').related).toEqual({ id: 'CVE-2026-0002', type: 'cve' });
  });

  test('an attributed actor disappearing produces NO removal event', () => {
    const result = detectChanges({
      entityType: 'campaign',
      before: campaignState({ actor_ids: ['actor:apt41'] }),
      after: campaignState({ actor_ids: [] }),
    });
    expect(result.events).toHaveLength(0);
  });
});

describe('detectChanges — idempotency and replay safety (Phase 31/32)', () => {
  test('makeEventId is deterministic for the same semantic change', () => {
    const id1 = makeEventId({ entityType: 'cve', entityId: 'CVE-2026-1234', changeType: 'CVE_KEV_ADDED', after: true });
    const id2 = makeEventId({ entityType: 'cve', entityId: 'CVE-2026-1234', changeType: 'CVE_KEV_ADDED', after: true });
    expect(id1).toBe(id2);
    expect(id1).toMatch(/^IEV-[0-9a-f]{24}$/);
  });

  test('replaying the exact same before/after pair produces identical event_ids (safe to persist idempotently)', () => {
    const before = cveState({ kev: false });
    const after = cveState({ kev: true });
    const run1 = detectChanges({ entityType: 'cve', before, after }).events.map(e => e.event_id);
    const run2 = detectChanges({ entityType: 'cve', before, after }).events.map(e => e.event_id);
    expect(run1).toEqual(run2);
  });

  test('different resulting values produce different event_ids even for the same change_type', () => {
    const id1 = makeEventId({ entityType: 'cve', entityId: 'CVE-2026-1234', changeType: 'CVE_CVSS_CHANGED', after: 9.8 });
    const id2 = makeEventId({ entityType: 'cve', entityId: 'CVE-2026-1234', changeType: 'CVE_CVSS_CHANGED', after: 7.2 });
    expect(id1).not.toBe(id2);
  });
});

describe('detectChanges — entity mismatch and unsupported types', () => {
  test('before/after entity_id mismatch is rejected rather than silently diffed', () => {
    const result = detectChanges({ entityType: 'cve', before: cveState({ entity_id: 'CVE-2026-1111' }), after: cveState({ entity_id: 'CVE-2026-2222' }) });
    expect(result.status).toBe('entity_mismatch');
    expect(result.events).toEqual([]);
  });

  test('no current state at all -> no_current_state, zero events', () => {
    const result = detectChanges({ entityType: 'cve', before: cveState(), after: null });
    expect(result.status).toBe('no_current_state');
  });
});

describe('IMPORTANCE table', () => {
  test('every change type used by the detector has a documented importance level', () => {
    const used = [
      'CVE_KEV_ADDED', 'CVE_ACTIVE_EXPLOITATION_CONFIRMED', 'CVE_CVSS_CHANGED', 'CVE_SEVERITY_CHANGED',
      'CVE_NEW_CAMPAIGN_ASSOCIATION', 'CVE_NEW_ACTOR_ASSOCIATION', 'CVE_NEW_REPORT',
      'CAMPAIGN_KEV_FLAG_ADDED', 'CAMPAIGN_EXPLOITED_FLAG_ADDED', 'CAMPAIGN_RANSOMWARE_FLAG_ADDED',
      'CAMPAIGN_NEW_ACTOR', 'CAMPAIGN_NEW_CVE', 'CAMPAIGN_SEVERITY_CHANGED', 'CAMPAIGN_CONFIDENCE_CHANGED',
      'CAMPAIGN_NEW_REPORT', 'CAMPAIGN_LAST_SEEN_ADVANCED',
    ];
    for (const type of used) {
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).toContain(IMPORTANCE[type]);
    }
  });
});
