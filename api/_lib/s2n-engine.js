/**
 * CYBERDUDEBIVASH SENTINEL APEX — Signal-to-Noise Engine (S2N)
 * ============================================================
 * Phases 1–11: Source trust weighting, quality scoring, PS rebalance,
 * semantic deduplication (Jaccard), suppression, signal boosting,
 * three-tier feed outputs, explainability, Tier-4 rate-limiting,
 * and performance guards.
 *
 * Entry point : runS2N(items, windowItems)
 * Feed builder: formatForFeed(s2nResult)
 *
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 1 — SOURCE TRUST WEIGHTS
// ─────────────────────────────────────────────────────────────────────────────
const SOURCE_TRUST = {
  // Tier 1 — Authoritative CVE / government bodies (weight 1.0)
  nvd:                  1.00,
  cisa_kev:             1.00,
  cisa_alerts:          1.00,
  msrc:                 1.00,
  github_advisories:    0.95,
  cert_eu:              0.95,

  // Tier 2 — Premier threat intel vendors (weight 0.85)
  talos:                0.85,
  unit42:               0.85,
  crowdstrike:          0.85,
  sentinelone:          0.85,
  rapid7:               0.85,
  google_project_zero:  0.85,
  exploitdb:            0.82,
  packetstorm:          0.80,
  fulldisclosure:       0.78,

  // Tier 3 — Trusted security media (weight 0.70)
  bleepingcomputer:     0.72,
  the_hacker_news:      0.70,
  krebs:                0.70,
  securityweek:         0.70,
  sans:                 0.70,
  dark_reading:         0.68,
  microsoft_sec_blog:   0.72,
  wired_security:       0.65,
  recorded_future:      0.75,
  urlhaus:              0.80,
  threatfox:            0.80,

  // Tier 4 — Community / social signals (weight 0.40)
  reddit_netsec:        0.42,
  reddit_cybersecurity: 0.40,
};

// Helper: resolve source string → trust weight
function getTrustWeight(source) {
  const s = (source || '').toLowerCase().replace(/[^a-z0-9_]/g, '_');
  if (SOURCE_TRUST[s] !== undefined) return SOURCE_TRUST[s];
  // Fuzzy fallback
  for (const [k, w] of Object.entries(SOURCE_TRUST)) {
    if (s.includes(k) || k.includes(s.split('_')[0])) return w;
  }
  return 0.55; // unknown source default
}

// Tier 4 source detection
function isTier4(source) {
  return getTrustWeight(source) <= 0.45;
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 2 — QUALITY SCORE (QS) FORMULA
// ─────────────────────────────────────────────────────────────────────────────
/**
 * QS = (source_weight  * 0.25)
 *    + (data_confidence* 0.20)
 *    + (ioc_presence   * 0.15)
 *    + (multi_source   * 0.15)
 *    + (recency_norm   * 0.10)
 *    + (actor_conf     * 0.10)
 *    + (structured_flds* 0.05)
 *
 * Returns [0.00 – 1.00]
 */
function computeQualityScore(item, explanations) {
  const expl = [];

  // ── Source weight component ──────────────────────────────────────────
  const sw = getTrustWeight(item.source);
  const sourceComp = sw * 0.25;
  expl.push(`source_weight=${sw.toFixed(2)} (${item.source})`);

  // ── Data confidence component ────────────────────────────────────────
  let dataConf = 0.0;
  if (item.cvss && item.cvss >= 7.0)  dataConf += 0.35;
  else if (item.cvss && item.cvss > 0) dataConf += 0.15;
  if (item.desc && item.desc.length > 80)  dataConf += 0.25;
  if (item.vendor && item.vendor.length > 0) dataConf += 0.20;
  if (item.product && item.product.length > 0) dataConf += 0.10;
  if ((item.refs || []).length > 0)   dataConf += 0.10;
  dataConf = Math.min(1.0, dataConf);
  const dataComp = dataConf * 0.20;
  expl.push(`data_confidence=${dataConf.toFixed(2)}`);

  // ── IOC presence component ───────────────────────────────────────────
  const iocCount = (item.iocs || []).length;
  const iocScore = Math.min(1.0, iocCount / 5);
  const iocComp  = iocScore * 0.15;
  if (iocCount > 0) expl.push(`ioc_presence=${iocCount} IOCs`);

  // ── Multi-source corroboration component ─────────────────────────────
  const srcCount  = item.sourceCount || item._sources?.length || 1;
  const multiScore = Math.min(1.0, (srcCount - 1) / 4);  // 5+ sources = 1.0
  const multiComp  = multiScore * 0.15;
  if (srcCount > 1) expl.push(`multi_source=${srcCount} sources`);

  // ── Recency normalization component ──────────────────────────────────
  const daysOld  = item.daysOld || 0;
  let recencyScore = 0.0;
  if (daysOld === 0)       recencyScore = 1.0;
  else if (daysOld <= 1)   recencyScore = 0.85;
  else if (daysOld <= 3)   recencyScore = 0.65;
  else if (daysOld <= 7)   recencyScore = 0.40;
  else if (daysOld <= 14)  recencyScore = 0.20;
  else                     recencyScore = 0.05;
  const recencyComp = recencyScore * 0.10;
  expl.push(`recency=${daysOld}d (score=${recencyScore.toFixed(2)})`);

  // ── Actor / campaign confidence component ─────────────────────────────
  let actorConf = 0.0;
  if (item.type === 'THREAT_ACTOR') actorConf = 0.8;
  const text = `${item.title || ''} ${item.desc || ''}`;
  if (/apt\d{1,3}|lazarus|volt typhoon|sandworm|cozy bear|fancy bear|salt typhoon|scattered spider|lockbit|alphv/i.test(text)) {
    actorConf = Math.max(actorConf, 0.7);
    expl.push('actor_confidence=named_actor');
  }
  if (item.cisaKev || item.exploited) {
    actorConf = Math.max(actorConf, 0.6);
  }
  const actorComp = actorConf * 0.10;

  // ── Structured fields component ───────────────────────────────────────
  let structScore = 0.0;
  if (item.id   && item.id.match(/^CVE-\d{4}-\d+$/))  structScore += 0.4;
  if (item.dueDate)                                     structScore += 0.2;
  if ((item.cves || []).length > 0)                     structScore += 0.2;
  if (item.type && item.type !== 'INTEL')               structScore += 0.1;
  if (item.pubDate)                                     structScore += 0.1;
  structScore = Math.min(1.0, structScore);
  const structComp = structScore * 0.05;

  const qs = Math.min(1.0, sourceComp + dataComp + iocComp + multiComp + recencyComp + actorComp + structComp);

  if (explanations) {
    explanations.push(...expl);
    explanations.push(`QS=${qs.toFixed(3)}`);
  }

  return Math.round(qs * 1000) / 1000; // 3dp precision
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 3 — PRIORITY SCORE REBALANCE
// ─────────────────────────────────────────────────────────────────────────────
/**
 * PS_rebalanced = (raw_risk_norm * 0.60) + (QS * 0.40) → 0–100
 * raw_risk_norm: existing priority / 100
 */
function rebalancePriorityScore(item, qs) {
  const rawPs = Math.min(100, item.priority || 0);
  const riskNorm = rawPs / 100;
  return Math.min(100, Math.round((riskNorm * 0.60 + qs * 0.40) * 100));
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 4 — TOKENIZATION (performance-cached)
// ─────────────────────────────────────────────────────────────────────────────
const TOKEN_CACHE = new Map(); // id → {titleTokens, iocSet, cveSet}

const STOPWORDS = new Set([
  'the','a','an','is','are','was','were','be','been','being','have','has','had',
  'do','does','did','will','would','could','should','may','might','shall','can',
  'in','on','at','to','for','of','and','or','but','if','with','from','by','as',
  'this','that','these','those','it','its','new','via','using','about','after',
  'before','into','out','up','down','across','through','over','under','between',
  'vulnerability','vulnerabilities','exploit','exploitation','attack','advisory',
  'security','threat','intelligence','report','update','patch','fix','issue',
  'researcher','found','discovered','allows','enable','could','allow','remote',
  'attacker','attackers','users','user','code','execution','arbitrary','systems',
  'system','affected','affecting','affects','multiple','version','versions',
  'product','vendor','software','hardware','device','devices','network','web',
]);

function tokenizeTitle(text) {
  if (!text) return new Set();
  return new Set(
    String(text)
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 2 && !STOPWORDS.has(w))
  );
}

function getTokens(item) {
  if (TOKEN_CACHE.has(item.id)) return TOKEN_CACHE.get(item.id);
  const t = {
    titleTokens: tokenizeTitle(item.title),
    iocSet:      new Set((item.iocs || []).map(i => i.value).filter(Boolean)),
    cveSet:      new Set(item.cves || (item.id.startsWith('CVE-') ? [item.id] : [])),
  };
  TOKEN_CACHE.set(item.id, t);
  return t;
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 5 — JACCARD SIMILARITY
// ─────────────────────────────────────────────────────────────────────────────
function jaccardSets(a, b) {
  if (a.size === 0 && b.size === 0) return 0;
  let inter = 0;
  a.forEach(v => { if (b.has(v)) inter++; });
  return inter / (a.size + b.size - inter);
}

/**
 * Composite similarity:
 *   title   tokens  → weight 0.50
 *   IOC     set     → weight 0.30
 *   CVE     IDs     → weight 0.20
 *
 * Returns [0.0 – 1.0]. Threshold 0.70 → semantic duplicate.
 */
function semanticSimilarity(a, b) {
  const ta = getTokens(a), tb = getTokens(b);
  const titleJ = jaccardSets(ta.titleTokens, tb.titleTokens);
  const iocJ   = jaccardSets(ta.iocSet, tb.iocSet);
  const cveJ   = jaccardSets(ta.cveSet, tb.cveSet);

  // If both have CVE IDs and they overlap perfectly → very high similarity
  const cveBump = (ta.cveSet.size > 0 && cveJ > 0.8) ? 0.15 : 0;
  return Math.min(1.0, (titleJ * 0.50) + (iocJ * 0.30) + (cveJ * 0.20) + cveBump);
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 6 — SEMANTIC DEDUP + MERGE
// ─────────────────────────────────────────────────────────────────────────────
const SIMILARITY_THRESHOLD = 0.70;

function mergeDuplicates(a, b) {
  // Winner: higher source trust wins on base fields
  const aWt = getTrustWeight(a.source);
  const bWt = getTrustWeight(b.source);
  const [winner, loser] = aWt >= bWt ? [a, b] : [b, a];

  const merged = {
    ...loser,   // base from loser
    ...winner,  // override with winner's fields

    // Temporal: take earliest first_seen, latest last_seen
    first_seen:   winner.first_seen && loser.first_seen
                    ? (new Date(winner.first_seen) < new Date(loser.first_seen) ? winner.first_seen : loser.first_seen)
                    : winner.first_seen || loser.first_seen || winner.pubDate || loser.pubDate,
    last_seen:    winner.last_seen && loser.last_seen
                    ? (new Date(winner.last_seen) > new Date(loser.last_seen) ? winner.last_seen : loser.last_seen)
                    : winner.last_seen || loser.last_seen || winner.pubDate || loser.pubDate,

    // Flags: logical OR
    exploited:    winner.exploited    || loser.exploited,
    cisaKev:      winner.cisaKev      || loser.cisaKev,
    ransomware:   winner.ransomware   || loser.ransomware,
    dueDate:      winner.dueDate      || loser.dueDate,
    reqAction:    winner.reqAction    || loser.reqAction,

    // Numeric: best verified value. Unknown remains null; zero must not be
    // manufactured by the merge because consumers present this as CVSS.
    cvss:         (() => {
      const scores = [winner.cvss, loser.cvss]
        .filter(v => typeof v === 'number' && v >= 0 && v <= 10);
      return scores.length ? Math.max(...scores) : null;
    })(),
    daysOld:      Math.min(winner.daysOld || 999, loser.daysOld || 999),

    // Set unions
    cves:         [...new Set([...(winner.cves || []), ...(loser.cves || [])])],
    refs:         [...new Set([...(winner.refs || []), ...(loser.refs || [])])].filter(Boolean).slice(0, 8),
    _sources:     [...new Set([...(winner._sources || [winner.source]), ...(loser._sources || [loser.source])])],

    // IOC union (deduplicated by type:value)
    iocs: (() => {
      const iocMap = new Map();
      [...(winner.iocs || []), ...(loser.iocs || [])].forEach(ioc => {
        if (ioc && ioc.value) {
          const k = `${ioc.type}:${ioc.value}`;
          if (!iocMap.has(k)) iocMap.set(k, ioc);
          else {
            const ex = iocMap.get(k);
            ex.source_count = (ex.source_count || 1) + 1;
            ex.confidence_score = Math.min(0.99, (ex.confidence_score || 0.5) + 0.08);
          }
        }
      });
      return Array.from(iocMap.values()).slice(0, 20);
    })(),
  };
  merged.sourceCount = merged._sources.length;

  // Update token cache for merged item
  TOKEN_CACHE.delete(merged.id);

  return merged;
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 7 — NOISE SUPPRESSION RULES
// ─────────────────────────────────────────────────────────────────────────────
const SUPPRESSION_RULES = [
  {
    name: 'low_quality',
    test: (item, qs) => qs < 0.35,
    reason: 'Quality score below minimum threshold (QS < 0.35)',
  },
  {
    name: 'no_signal',
    test: (item, qs) => {
      const hasCve  = item.id.startsWith('CVE-') || (item.cves||[]).length > 0;
      const hasIoc  = (item.iocs||[]).length > 0;
      const multiSrc = (item.sourceCount || 1) > 1;
      return !hasCve && !hasIoc && !multiSrc;
    },
    reason: 'Single-source item with no CVE IDs or IOCs',
  },
  {
    name: 'tier4_solo',
    test: (item, qs) => {
      const allTier4 = (item._sources || [item.source]).every(s => isTier4(s));
      return allTier4 && !(item.exploited || item.cisaKev || item.ransomware);
    },
    reason: 'Tier-4 (social/community) source only, no authoritative confirmation',
  },
  {
    name: 'stale_low_priority',
    test: (item, qs, ps) => {
      const daysOld = item.daysOld || 0;
      return daysOld > 48 && (ps || 0) < 40;
    },
    reason: 'Item is older than 48h and priority score is below 40',
  },
];

function checkSuppression(item, qs, ps) {
  for (const rule of SUPPRESSION_RULES) {
    if (rule.test(item, qs, ps)) {
      return rule.reason;
    }
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 8 — SIGNAL BOOSTING (capped per category)
// ─────────────────────────────────────────────────────────────────────────────
function applySignalBoosts(item, basePs, explanations) {
  let boost = 0;
  const boostLog = [];
  const text = `${item.title || ''} ${item.desc || ''}`.toLowerCase();

  // CISA KEV — actively exploited by US federal advisory (+15, cap 15)
  if (item.cisaKev && boost < 15) {
    const add = Math.min(15, 15 - boost); boost += add;
    boostLog.push(`+${add} CISA_KEV`);
  }

  // PoC / public exploit code available (+12, cap 12)
  if (/proof.of.concept|poc|exploit.code|weaponized|metasploit|exploit.?db/i.test(text) || item.source === 'exploitdb' || item.source === 'packetstorm') {
    const cap = 12; const add = Math.min(cap, cap - Math.min(cap, boost)); boost += add;
    boostLog.push(`+${add} PoC_available`);
  }

  // Ransomware confirmed (+10, cap 10)
  if (item.ransomware) {
    const cap = 10; const add = Math.min(cap, cap); boost += add;
    boostLog.push(`+${add} ransomware_confirmed`);
  }

  // CVSS ≥ 9.0 (+10, cap 10)
  if ((item.cvss || 0) >= 9.0) {
    const add = 10; boost += add;
    boostLog.push(`+${add} CVSS≥9`);
  }

  // Active exploitation confirmed (+8, cap 8)
  if (item.exploited) {
    const add = 8; boost += add;
    boostLog.push(`+${add} exploited_in_wild`);
  }

  // 3+ corroborating sources (+8, cap 8)
  if ((item.sourceCount || 1) >= 3) {
    const add = 8; boost += add;
    boostLog.push(`+${add} multi_source≥3`);
  }

  // Zero-day / unpatched (+7, cap 7)
  if (/zero.?day|0.?day|unpatched|no.?patch|before.?patch/i.test(text) || item.type === 'ZERO_DAY') {
    const add = 7; boost += add;
    boostLog.push(`+${add} zero_day`);
  }

  // Nation-state / APT actor (+5, cap 5)
  if (/nation.?state|apt\d{1,3}|lazarus|volt.?typhoon|sandworm|cozy.?bear|fancy.?bear|salt.?typhoon|state.?sponsored/i.test(text)) {
    const add = 5; boost += add;
    boostLog.push(`+${add} nation_state`);
  }

  // Critical infrastructure (+4, cap 4)
  if (/federal|critical.infra|scada|ics|election|nuclear|power.grid|hospital|utility|water.treatment/i.test(text)) {
    const add = 4; boost += add;
    boostLog.push(`+${add} critical_infra`);
  }

  // Supply chain / open source ecosystem (+3, cap 3)
  if (/supply.chain|open.?source|npm|pypi|rubygems|dependency|package.manager/i.test(text)) {
    const add = 3; boost += add;
    boostLog.push(`+${add} supply_chain`);
  }

  // Cap total boost at 35 to avoid inflation
  boost = Math.min(35, boost);

  if (explanations && boostLog.length > 0) {
    explanations.push(...boostLog);
  }

  return Math.min(100, basePs + boost);
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 9 — TIER 4 RATE LIMITING
// ─────────────────────────────────────────────────────────────────────────────
const TIER4_KEEP_TOP_K = 5; // retain only top-K Tier-4 items by QS per run

function applyTier4RateLimit(items) {
  const tier4      = items.filter(i => isTier4(i.source));
  const nonTier4   = items.filter(i => !isTier4(i.source));
  // Sort Tier-4 by QS desc, keep top K
  const kept = tier4.sort((a, b) => (b.quality_score || 0) - (a.quality_score || 0)).slice(0, TIER4_KEEP_TOP_K);
  return [...nonTier4, ...kept];
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 10 — THREE FEED OUTPUTS
// ─────────────────────────────────────────────────────────────────────────────
/**
 * formatForFeed(s2nResult) → { live, topThreats, raw }
 *
 * live        : top 50 by final_ps, suppressed items excluded
 * topThreats  : final_ps ≥ 70 AND quality_score ≥ 0.60
 * raw         : ALL items including suppressed (unfiltered, paid tier)
 */
function formatForFeed(s2nResult) {
  const { passed, suppressed, all } = s2nResult;

  const live = passed
    .sort((a, b) => (b.final_ps || 0) - (a.final_ps || 0))
    .slice(0, 50)
    .map(i => formatItem(i, false));

  const topThreats = passed
    .filter(i => (i.final_ps || 0) >= 70 && (i.quality_score || 0) >= 0.60)
    .sort((a, b) => (b.final_ps || 0) - (a.final_ps || 0))
    .slice(0, 20)
    .map(i => formatItem(i, false));

  const raw = all
    .sort((a, b) => (b.final_ps || 0) - (a.final_ps || 0))
    .map(i => formatItem(i, true)); // include suppression reason in raw

  return { live, topThreats, raw };
}

function formatItem(item, includeRaw) {
  const base = {
    id:                item.id,
    title:             (item.title || '').slice(0, 120),
    description:       (item.desc  || '').slice(0, 300),
    cvss:              typeof item.cvss === 'number' ? item.cvss : null,
    final_ps:          item.final_ps || 0,
    quality_score:     item.quality_score || 0,
    threat_level:      finalThreatLevel(item.final_ps || 0),
    type:              item.type || 'INTEL',
    source:            item.source || '',
    sources_confirmed: item.sourceCount || 1,
    merged_sources:    item._sources || [item.source],
    first_seen:        item.first_seen || item.pubDate,
    last_seen:         item.last_seen  || item.pubDate,
    exploited:         !!item.exploited,
    cisa_kev:          !!item.cisaKev,
    ransomware:        !!item.ransomware,
    vendor:            item.vendor || '',
    product:           item.product || '',
    due_date:          item.dueDate || null,
    cves:              item.cves || [],
    ioc_count:         (item.iocs || []).length,
    refs:              (item.refs || []).slice(0, 4),
    explanation:       item.explanation || null,
  };
  if (includeRaw) {
    base.suppressed    = item.suppressed || false;
    base.suppression_reason = item.suppression_reason || null;
    base.iocs          = item.iocs || [];
  }
  return base;
}

function finalThreatLevel(ps) {
  if (ps >= 85) return 'CRITICAL';
  if (ps >= 65) return 'HIGH';
  if (ps >= 45) return 'MEDIUM';
  return 'LOW';
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 11 — PERFORMANCE GUARD + EXPLAINABILITY
// ─────────────────────────────────────────────────────────────────────────────
const SIMILARITY_WINDOW = 200; // compare against last N items only

/**
 * Main S2N pipeline entry point.
 *
 * @param {Array}  items        — fresh items from current pipeline run (enriched)
 * @param {Array}  windowItems  — last N items from existing live-intel.json (for semantic dedup)
 * @returns {{ passed, suppressed, all, stats }}
 */
function runS2N(items, windowItems) {
  const T0 = Date.now();
  TOKEN_CACHE.clear();

  // ── Step 1: Validate inputs ─────────────────────────────────────────
  const inItems  = (Array.isArray(items)       ? items       : []).filter(i => i && i.id);
  const winItems = (Array.isArray(windowItems) ? windowItems : []).filter(i => i && i.id);

  // ── Step 2: Semantic dedup against window (Phase 5/6) ──────────────
  // Limit comparison window for performance (Phase 11)
  const compWindow = winItems.slice(0, SIMILARITY_WINDOW);
  const semanticMergeLog = [];
  const mergedItems = [];

  for (const item of inItems) {
    const itemTokens = getTokens(item);
    let merged = false;

    for (let w = 0; w < compWindow.length; w++) {
      const win = compWindow[w];
      if (item.id === win.id) { merged = true; break; } // exact ID match already handled upstream

      const sim = semanticSimilarity(item, win);
      if (sim >= SIMILARITY_THRESHOLD) {
        // Merge item into window slot (update in-place)
        compWindow[w] = mergeDuplicates(win, item);
        compWindow[w].first_seen = win.first_seen || win.pubDate || item.pubDate;
        compWindow[w].last_seen  = item.pubDate || win.pubDate;
        semanticMergeLog.push(`MERGED: ${item.id} → ${win.id} (sim=${sim.toFixed(2)})`);
        merged = true;
        break;
      }
    }
    if (!merged) {
      item.first_seen = item.first_seen || item.pubDate;
      item.last_seen  = item.last_seen  || item.pubDate;
      mergedItems.push(item);
    }
  }

  // Combined set: newly merged + updated window entries
  const allCandidates = [...mergedItems, ...compWindow.filter(w =>
    inItems.some(i => {
      const sim = semanticSimilarity(i, w);
      return sim >= SIMILARITY_THRESHOLD || i.id === w.id;
    })
  )];

  // Deduplicate allCandidates by id
  const candidateMap = new Map();
  [...mergedItems, ...compWindow].forEach(i => {
    if (!candidateMap.has(i.id) || (i.last_seen > (candidateMap.get(i.id).last_seen || ''))) {
      candidateMap.set(i.id, i);
    }
  });
  const candidates = Array.from(candidateMap.values());

  // ── Step 3: Quality scoring + PS rebalance (Phase 2/3) ─────────────
  for (const item of candidates) {
    const qsExpl  = [];
    const qs       = computeQualityScore(item, qsExpl);
    const basePsRe = rebalancePriorityScore(item, qs);

    // Signal boosts (Phase 8)
    const boostExpl = [];
    const finalPs   = applySignalBoosts(item, basePsRe, boostExpl);

    item.quality_score = qs;
    item.final_ps      = finalPs;

    // Suppression check (Phase 7)
    const suppressionReason = checkSuppression(item, qs, finalPs);
    item.suppressed         = !!suppressionReason;
    item.suppression_reason = suppressionReason || null;

    // ── Phase 11: Explainability block ─────────────────────────────
    item.explanation = {
      quality:     qsExpl,
      priority:    boostExpl.length > 0 ? boostExpl : [`base_ps=${basePsRe} (no boosts)`],
      suppression: suppressionReason || null,
      merge:       semanticMergeLog.filter(m => m.includes(item.id)).length > 0
                     ? semanticMergeLog.filter(m => m.includes(item.id))
                     : null,
    };
  }

  // ── Step 4: Tier-4 rate limiting (Phase 9) ─────────────────────────
  const rateFiltered = applyTier4RateLimit(candidates);

  // ── Step 5: Split into passed / suppressed ──────────────────────────
  const passed     = rateFiltered.filter(i => !i.suppressed);
  const suppressed = rateFiltered.filter(i =>  i.suppressed);

  const elapsed = Date.now() - T0;

  const stats = {
    input_items:       inItems.length,
    window_items:      winItems.length,
    semantic_merges:   semanticMergeLog.length,
    candidates:        candidates.length,
    passed:            passed.length,
    suppressed:        suppressed.length,
    tier4_kept:        rateFiltered.filter(i => isTier4(i.source)).length,
    elapsed_ms:        elapsed,
    avg_qs:            passed.length > 0
                         ? Math.round(passed.reduce((s, i) => s + (i.quality_score || 0), 0) / passed.length * 1000) / 1000
                         : 0,
    avg_final_ps:      passed.length > 0
                         ? Math.round(passed.reduce((s, i) => s + (i.final_ps || 0), 0) / passed.length)
                         : 0,
    semantic_merge_log: semanticMergeLog,
  };

  return { passed, suppressed, all: rateFiltered, stats };
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────
module.exports = {
  runS2N,
  formatForFeed,
  computeQualityScore,
  rebalancePriorityScore,
  applySignalBoosts,
  semanticSimilarity,
  getTrustWeight,
  finalThreatLevel,
  SOURCE_TRUST,
  SIMILARITY_THRESHOLD,
};
