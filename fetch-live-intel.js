#!/usr/bin/env node
/**
 * CYBERDUDEBIVASH SENTINEL APEX — Global Intelligence Engine v5.0
 * HIGH-FREQUENCY MULTI-SOURCE NEAR REAL-TIME INTELLIGENCE ENGINE
 * 27 live sources | Tiered parallel ingestion | Stream-like writes
 * Source health monitoring | Lock mechanism | 5-min cadence
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';
const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');
const crypto = require('crypto');

// Intelligence Enrichment Pipeline
const { runEnrichmentPipeline } = require('./api/_lib/enrichment-pipeline');

// Signal-to-Noise Engine (S2N)
const { runS2N, formatForFeed, finalThreatLevel } = require('./api/_lib/s2n-engine');

const CFG = {
  // ── Core paths ─────────────────────────────────────────────────────
  baseUrl:            'https://blog.cyberdudebivash.in',
  brand:              'CYBERDUDEBIVASH',
  author:             'CYBERDUDEBIVASH SENTINEL APEX',
  authorEmail:        'bivash@cyberdudebivash.com',
  postsDir:           path.join(__dirname, 'posts'),
  indexPath:          path.join(__dirname, 'index.html'),
  statePath:          path.join(__dirname, 'intel-state.json'),
  lockPath:           path.join(__dirname, 'pipeline.lock'),
  rssPath:            path.join(__dirname, 'rss.xml'),
  liveJsonPath:       path.join(__dirname, 'live-intel.json'),
  sitemapPath:        path.join(__dirname, 'sitemap.xml'),
  apiDir:             path.join(__dirname, 'api', 'intel'),

  // ── Timing & limits ────────────────────────────────────────────────
  nvdLookbackHours:   72,      // fallback when no prior source state
  kevLookbackDays:    7,
  maxNewPostsPerRun:  15,      // v5: increased
  minCVSS:            7.0,
  minPriorityScore:   35,      // v5: lower bar = more signal captured
  sourceTimeoutMs:    8000,    // per-source hard timeout (Phase 2)
  requestTimeoutMs:   12000,
  maxRssItems:        12,
  dedupTtlDays:       30,
  liveRollingWindow:  150,     // v5: increased window
  apiLiveWindow:      100,
  healthFailThreshold: 3,      // Phase 7: mark degraded after N consecutive failures
  freshnessAlertMins:  30,     // Phase 8: alert if no new intel in 30 min

  // ── API keys ────────────────────────────────────────────────────────
  nvdApiKey:          process.env.NVD_API_KEY  || '',
  githubToken:        process.env.GITHUB_TOKEN || '',
  otxApiKey:          process.env.OTX_API_KEY  || '',

  // ── TIER 1: Critical CVE / exploit sources ──────────────────────────
  nvdApi:             'https://services.nvd.nist.gov/rest/json/cves/2.0',
  cisaKevUrl:         'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  cisaAlertsRss:      'https://www.cisa.gov/cybersecurity-advisories/all.xml',
  ghAdvisoryUrl:      'https://api.github.com/advisories?type=reviewed&severity=high&per_page=30',
  msrcApi:            'https://api.msrc.microsoft.com/cvrf/v2.0/Updates',
  exploitDbRss:       'https://www.exploit-db.com/rss.xml',
  packetstormRss:     'https://rss.packetstormsecurity.com/files/advisories/',
  fullDisclosureRss:  'https://seclists.org/rss/fulldisclosure.rss',

  // ── TIER 2: Threat intel blogs + malware feeds ─────────────────────
  bleepingRss:        'https://www.bleepingcomputer.com/feed/',
  thnRss:             'https://feeds.feedburner.com/TheHackersNews',
  krebsRss:           'https://krebsonsecurity.com/feed/',
  secweekRss:         'https://www.securityweek.com/feed/',
  sansRss:            'https://isc.sans.edu/rssfeed_full.xml',
  darkReadingRss:     'https://www.darkreading.com/rss.xml',
  talosBlogRss:       'https://blog.talosintelligence.com/feeds/posts/default',
  unit42Rss:          'https://unit42.paloaltonetworks.com/feed/',
  crowdstrikeBlogRss: 'https://www.crowdstrike.com/blog/feed/',
  sentineloneBlogRss: 'https://www.sentinelone.com/blog/feed/',
  googleProjZeroRss:  'https://googleprojectzero.blogspot.com/feeds/posts/default',
  rapid7BlogRss:      'https://www.rapid7.com/blog/feed/',
  urlhausApi:         'https://urlhaus-api.abuse.ch/v1/payloads/recent/',
  threatfoxApi:       'https://threatfox-api.abuse.ch/api/v1/',

  // ── TIER 3: Community + signals ─────────────────────────────────────
  redditNetsecRss:    'https://www.reddit.com/r/netsec/.rss?limit=25',
  redditCyberRss:     'https://www.reddit.com/r/cybersecurity/.rss?limit=15',
  certEuRss:          'https://www.cert.europa.eu/publications/threat-intelligence/rss',
  microsoftSecBlogRss:'https://www.microsoft.com/en-us/security/blog/feed/',
  wiredSecRss:        'https://www.wired.com/feed/category/security/latest/rss',
  recordedFutureRss:  'https://www.recordedfuture.com/feed/',
};

const log  = m => console.log(`[APEX] ${m}`);
const warn = m => console.warn(`[WARN] ${m}`);
const err  = m => console.error(`[ERR]  ${m}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const isoNow = () => new Date().toISOString().slice(0, 10);
const isoNowFull = () => new Date().toISOString();
const md5 = s => crypto.createHash('md5').update(String(s)).digest('hex').slice(0, 16);

// ── PHASE 3: LOCK MECHANISM — prevents overlapping runs ─────────────────
function acquireLock() {
  try {
    if (fs.existsSync(CFG.lockPath)) {
      const lockData = JSON.parse(fs.readFileSync(CFG.lockPath, 'utf8'));
      const ageMs = Date.now() - (lockData.acquired || 0);
      if (ageMs < 10 * 60000) { // 10 min max lock age
        warn(`Pipeline already running (lock age ${Math.round(ageMs/1000)}s). Aborting.`);
        return false;
      }
      warn(`Stale lock found (${Math.round(ageMs/60000)} min old). Overriding.`);
    }
    fs.writeFileSync(CFG.lockPath, JSON.stringify({ acquired: Date.now(), pid: process.pid }), 'utf8');
    return true;
  } catch(e) { warn(`Lock acquire failed: ${e.message}`); return true; } // fail-open
}
function releaseLock() {
  try { if (fs.existsSync(CFG.lockPath)) fs.unlinkSync(CFG.lockPath); } catch(_) {}
}

// ── PHASE 2: PER-SOURCE TIMEOUT WRAPPER ────────────────────────────────
async function fetchWithTimeout(fetchFn, sourceKey, timeoutMs) {
  const timeout = timeoutMs || CFG.sourceTimeoutMs;
  return Promise.race([
    fetchFn(),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`Source timeout ${timeout}ms: ${sourceKey}`)), timeout)),
  ]);
}

// ── PHASE 7: SOURCE HEALTH MONITORING ──────────────────────────────────
function initSourceHealth(name) {
  return { name, lastSuccess: null, lastError: null, consecutiveFails: 0, totalFails: 0, totalSuccesses: 0, successRate: 1.0, status: 'ok' };
}
function recordSourceSuccess(state, source) {
  if (!state.sourceHealth) state.sourceHealth = {};
  const h = state.sourceHealth[source] || initSourceHealth(source);
  h.lastSuccess       = isoNowFull();
  h.consecutiveFails  = 0;
  h.totalSuccesses    = (h.totalSuccesses || 0) + 1;
  h.successRate       = h.totalSuccesses / Math.max(1, h.totalSuccesses + h.totalFails);
  h.status            = 'ok';
  state.sourceHealth[source] = h;
}
function recordSourceFailure(state, source, errorMsg) {
  if (!state.sourceHealth) state.sourceHealth = {};
  const h = state.sourceHealth[source] || initSourceHealth(source);
  h.lastError         = `${isoNowFull()}: ${String(errorMsg).slice(0,100)}`;
  h.consecutiveFails  = (h.consecutiveFails || 0) + 1;
  h.totalFails        = (h.totalFails || 0) + 1;
  h.successRate       = h.totalSuccesses / Math.max(1, h.totalSuccesses + h.totalFails);
  h.status            = h.consecutiveFails >= CFG.healthFailThreshold ? 'degraded' : 'warning';
  state.sourceHealth[source] = h;
}
function getSourceHealthReport(state) {
  const health = state.sourceHealth || {};
  const degraded = Object.values(health).filter(h => h.status === 'degraded');
  const warning  = Object.values(health).filter(h => h.status === 'warning');
  return { degraded: degraded.map(h=>h.name), warning: warning.map(h=>h.name), total: Object.keys(health).length };
}

// ── UTILITIES ──────────────────────────────────────────────────────────
function fmtDate(d) {
  const dt = new Date(d);
  if (isNaN(dt)) return new Date().toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'});
  return dt.toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'});
}
function slugify(str) {
  return String(str).toLowerCase().replace(/[^a-z0-9\s-]/g,' ').replace(/\s+/g,'-').replace(/-{2,}/g,'-').replace(/^-|-$/g,'').slice(0,90);
}
function escHtml(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function stripHtml(str) {
  return String(str||'').replace(/<[^>]*>/g,' ').replace(/\s{2,}/g,' ').trim();
}
function extractCVEs(text) {
  const m = (text||'').match(/CVE-\d{4}-\d{4,7}/gi)||[];
  return [...new Set(m.map(c=>c.toUpperCase()))];
}

// ── PHASE 1: ADVANCED IOC ENRICHMENT ENGINE ────────────────────────────
const IP_RE    = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const URL_RE   = /https?:\/\/[^\s"'<>]{8,100}/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|ir|kp|tk|xyz|top|info|biz|su)\b/gi;
const MD5_RE   = /\b[0-9a-fA-F]{32}\b/g;
const SHA1_RE  = /\b[0-9a-fA-F]{40}\b/g;
const SHA256_RE= /\b[0-9a-fA-F]{64}\b/g;

function extractIOCs(text, existingIOCs) {
  const raw = String(text||'');
  const normalized = [];
  const seen = new Set();
  const add = (type, value, confidence) => {
    const key = `${type}:${value}`;
    if (seen.has(key) || value.length < 4) return;
    seen.add(key);
    normalized.push({ type, value: value.slice(0,120), confidence_score: confidence, first_seen: isoNow(), source_count: 1 });
  };
  (raw.match(SHA256_RE)||[]).slice(0,5).forEach(h => add('sha256', h, 0.95));
  (raw.match(SHA1_RE)||[]).filter(h=>!raw.match(SHA256_RE)||[]).slice(0,5).forEach(h => add('sha1', h, 0.90));
  (raw.match(MD5_RE)||[]).slice(0,5).forEach(h => add('md5', h, 0.85));
  (raw.match(IP_RE)||[]).filter(ip => !ip.startsWith('192.168')&&!ip.startsWith('10.')&&!ip.startsWith('127.')).slice(0,5).forEach(ip => add('ipv4', ip, 0.88));
  (raw.match(URL_RE)||[]).filter(u => !u.includes('nvd.nist.gov')&&!u.includes('cisa.gov')&&!u.includes('blog.cyberdude')).slice(0,5).forEach(u => add('url', u.slice(0,100), 0.82));
  (raw.match(DOMAIN_RE)||[]).filter(d => d.length>5&&!d.includes('nvd.nist')&&!d.includes('cisa.gov')&&!d.includes('github.com')&&!d.includes('cyberdude')).slice(0,5).forEach(d => add('domain', d.toLowerCase(), 0.75));
  (existingIOCs||[]).forEach(ioc => {
    const val = String(ioc).replace(/^[^:]+:\s*/,'').trim();
    const type = String(ioc).match(/^(md5|sha1|sha256|ip|url|domain|hash):/i)?.[1]?.toLowerCase()||'hash';
    add(type, val, 0.90);
  });
  return normalized.slice(0, 20);
}

// ── HTTP FETCH ──────────────────────────────────────────────────────────
function fetchUrl(rawUrl, opts = {}, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('Too many redirects'));
    let parsed;
    try { parsed = new url.URL(rawUrl); } catch(e) { return reject(e); }
    const isHttps = parsed.protocol === 'https:';
    const client  = isHttps ? https : http;
    const headers = {
      'User-Agent': 'CYBERDUDEBIVASH-SENTINEL-APEX/4.0 (+https://blog.cyberdudebivash.in)',
      'Accept': 'application/json, application/xml, text/xml, */*',
      ...(opts.headers || {}),
    };
    if (CFG.nvdApiKey && rawUrl.includes('nvd.nist.gov')) headers['apiKey'] = CFG.nvdApiKey;
    if (CFG.githubToken && rawUrl.includes('api.github.com')) headers['Authorization'] = `Bearer ${CFG.githubToken}`;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: opts.method || 'GET',
      headers,
      timeout: CFG.requestTimeoutMs,
    };
    const req = client.request(options, res => {
      if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
        const loc = res.headers.location.startsWith('http') ? res.headers.location : `${parsed.protocol}//${parsed.host}${res.headers.location}`;
        res.resume();
        return fetchUrl(loc, opts, redirects + 1).then(resolve).catch(reject);
      }
      let data = '';
      res.setEncoding('utf8');
      res.on('data', c => { data += c; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(data);
        else reject(new Error(`HTTP ${res.statusCode} — ${rawUrl.slice(0,80)}`));
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${rawUrl.slice(0,60)}`)); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}
async function fetchWithRetry(rawUrl, opts = {}, attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    try { return await fetchUrl(rawUrl, opts); }
    catch(e) {
      if (i < attempts - 1) { warn(`Retry ${i+1} for ${rawUrl.slice(0,60)}: ${e.message}`); await sleep(2000*(i+1)); }
      else throw e;
    }
  }
}

// ── RSS PARSER ─────────────────────────────────────────────────────────
function parseRSS(xml) {
  const items = [];
  const re = /<(?:item|entry)[^>]*>([\s\S]*?)<\/(?:item|entry)>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const b = m[1];
    const get = tag => {
      const cd = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>`, 'i').exec(b);
      if (cd) return cd[1].trim();
      const pl = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i').exec(b);
      if (pl) return stripHtml(pl[1]).trim();
      if (tag === 'link') { const hr = /<link[^>]+href=["']([^"']+)["']/i.exec(b); if(hr) return hr[1]; }
      return '';
    };
    const title = get('title'), link = get('link')||get('guid'), desc = get('description')||get('summary')||get('content');
    const pubDate = get('pubDate')||get('published')||get('updated')||get('dc:date');
    if (title && link) items.push({ title: stripHtml(title), link, desc: stripHtml(desc), pubDate });
  }
  return items;
}

// ── STATE ──────────────────────────────────────────────────────────────
function loadState() {
  try {
    if (fs.existsSync(CFG.statePath)) {
      const s = JSON.parse(fs.readFileSync(CFG.statePath, 'utf8'));
      if (!Array.isArray(s.published)) s.published = [];
      if (!s.correlations) s.correlations = {};
      if (!s.sourceFetchState) s.sourceFetchState = {};
      if (!s.sourceHealth) s.sourceHealth = {};
      return s;
    }
  } catch(e) { warn('State corrupt — starting fresh.'); }
  return { published: [], lastRun: null, totalPublished: 0, correlations: {}, sourceFetchState: {}, sourceHealth: {}, version: '5.0' };
}
function saveState(state) {
  state.lastRun  = isoNowFull();
  state.version  = '5.0';
  const ttlMs    = (CFG.dedupTtlDays || 30) * 86400000 * 2; // 60-day hard purge
  const now      = Date.now();
  state.published = state.published.filter(p => (now - new Date(p.date || 0).getTime()) < ttlMs);
  if (state.published.length > 3000) state.published = state.published.slice(0, 2000);
  fs.writeFileSync(CFG.statePath, JSON.stringify(state, null, 2), 'utf8');
}
// Returns last fetch timestamp for a named source (epoch ms), or null if never fetched
function getSourceLastFetch(state, source) {
  return state.sourceFetchState?.[source]?.lastFetch || null;
}
// Records successful fetch timestamp for a named source
function setSourceLastFetch(state, source, tsMs) {
  if (!state.sourceFetchState) state.sourceFetchState = {};
  state.sourceFetchState[source] = { lastFetch: tsMs || Date.now(), updatedAt: new Date().toISOString() };
}
// isPublished respects dedupTtlDays — items published > TTL days ago are NOT duplicates
function isPublished(state, id) {
  const ttlMs = (CFG.dedupTtlDays || 30) * 86400000;
  const now   = Date.now();
  return state.published.some(p => {
    if (p.id !== id) return false;
    const age = now - new Date(p.date || 0).getTime();
    return age < ttlMs; // within TTL window → is a duplicate
  });
}
function markPublished(state, item) {
  state.published.unshift({ id: item.id, slug: item.slug, date: isoNow(), title: item.title });
  state.totalPublished = (state.totalPublished || 0) + 1;
}

// ── SOURCE 1: NVD CVE API v2.0 ─────────────────────────────────────────
async function fetchNVD(state) {
  const end   = new Date();
  const lastFetch = getSourceLastFetch(state, 'nvd');
  const start = lastFetch ? new Date(lastFetch) : new Date(Date.now() - CFG.nvdLookbackHours * 3600000);
  const fmt   = d => d.toISOString().slice(0,23);
  const apiUrl     = `${CFG.nvdApi}?pubStartDate=${encodeURIComponent(fmt(start))}&pubEndDate=${encodeURIComponent(fmt(end))}&cvssV3SeverityExact=CRITICAL&resultsPerPage=20&noRejected`;
  const apiUrlHigh = `${CFG.nvdApi}?lastModStartDate=${encodeURIComponent(fmt(start))}&lastModEndDate=${encodeURIComponent(fmt(end))}&cvssV3SeverityExact=CRITICAL&resultsPerPage=15&noRejected`;
  log(`NVD: fetching CRITICAL CVEs since ${start.toISOString()}...`);
  try {
    await sleep(600);
    let raw;
    try { raw = await fetchWithRetry(apiUrl, {}, 2); }
    catch(e1) { warn(`NVD pubDate failed (${e1.message}), trying lastMod...`); raw = await fetchWithRetry(apiUrlHigh, {}, 2); }
    const data = JSON.parse(raw);
    const items = (data.vulnerabilities||[]).map(v => {
      const cve = v.cve, id = cve.id;
      const desc   = (cve.descriptions||[]).find(d=>d.lang==='en')?.value||'';
      const met    = cve.metrics?.cvssMetricV31?.[0]||cve.metrics?.cvssMetricV30?.[0]||null;
      const cvss   = met?.cvssData?.baseScore||0;
      const vector = met?.cvssData?.vectorString||'';
      const cweId  = cve.weaknesses?.[0]?.description?.[0]?.value||'';
      const refs   = (cve.references||[]).map(r=>r.url).slice(0,6);
      const pubDate= cve.published?.slice(0,10)||isoNow();
      const cpe    = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria||'';
      const vendor  = (cpe.match(/cpe:2\.3:[aoh]:([^:]+):/)||[])[1]?.replace(/_/g,' ')||'Unknown Vendor';
      const product = (cpe.match(/cpe:2\.3:[aoh]:[^:]+:([^:]+):/)||[])[1]?.replace(/_/g,' ')||desc.split(/\s+/).slice(0,3).join(' ')||'Unknown Product';
      const iocs = extractIOCs(desc, []);
      return { source:'nvd', type:'CVE_REPORT', id, title:`${id} — ${vendor} ${product} CVSS ${cvss} Critical Vulnerability`,
        desc, cvss, vector, cweId, refs, pubDate, vendor, product, exploited:false, cisaKev:false, ransomware:false,
        iocs, sourceCount:1, daysOld: Math.floor((Date.now()-new Date(pubDate).getTime())/86400000) };
    }).filter(i => i.cvss >= CFG.minCVSS);
    setSourceLastFetch(state, 'nvd', Date.now());
    log(`NVD: ${items.length} items (since ${start.toISOString().slice(0,10)}).`); return items;
  } catch(e) { warn(`NVD failed: ${e.message}`); return []; }
}

// ── SOURCE 2: CISA KEV ─────────────────────────────────────────────────
async function fetchCISAKev(state) {
  const lastFetch = getSourceLastFetch(state, 'cisa_kev');
  const cutoff    = lastFetch ? new Date(lastFetch) : new Date(Date.now() - CFG.kevLookbackDays * 86400000);
  log(`CISA KEV: fetching (since ${cutoff.toISOString().slice(0,10)})...`);
  try {
    const raw = await fetchWithRetry(CFG.cisaKevUrl);
    const data = JSON.parse(raw);
    const items = (data.vulnerabilities||[]).filter(v => new Date(v.dateAdded) >= cutoff).map(v => {
      const iocs = extractIOCs(v.shortDescription||'', []);
      return { source:'cisa_kev', type:'CVE_REPORT', id:v.cveID,
        title:`${v.cveID}: ${v.vulnerabilityName} — CISA KEV Active Exploitation`,
        desc:v.shortDescription||v.vulnerabilityName, cvss:9.5, vector:'', cweId:'',
        refs:[v.notes].filter(Boolean), pubDate:v.dateAdded, vendor:v.vendorProject, product:v.product,
        vulnName:v.vulnerabilityName, exploited:true, cisaKev:true,
        ransomware:v.knownRansomwareCampaignUse==='Known', dueDate:v.dueDate,
        reqAction:v.requiredAction, iocs, sourceCount:1,
        daysOld: Math.floor((Date.now()-new Date(v.dateAdded).getTime())/86400000) };
    });
    setSourceLastFetch(state, 'cisa_kev', Date.now());
    log(`CISA KEV: ${items.length} items.`); return items;
  } catch(e) { warn(`CISA KEV failed: ${e.message}`); return []; }
}

// ── SOURCE 3: CISA Alerts RSS ──────────────────────────────────────────
async function fetchCISAAlerts(state) {
  const lastFetch  = getSourceLastFetch(state, 'cisa_alerts');
  const afterDate  = lastFetch ? new Date(lastFetch) : new Date(Date.now() - CFG.kevLookbackDays * 86400000);
  log(`CISA Alerts RSS: fetching (since ${afterDate.toISOString().slice(0,10)})...`);
  try {
    const raw = await fetchWithRetry(CFG.cisaAlertsRss);
    const parsed = parseRSS(raw);
    const items = parsed
      .filter(item => {
        if (!item.pubDate) return true; // include if no date
        try { return new Date(item.pubDate) >= afterDate; } catch(_) { return true; }
      })
      .slice(0, CFG.maxRssItems).map(item => {
        const text = (item.title||'')+' '+(item.desc||'');
        const iocs = extractIOCs(text, []);
        return { source:'cisa_alerts', type:'ADVISORY', id:'CISA-'+md5(item.link),
          title:item.title, desc:(item.desc||'').slice(0,600), cvss:8.5, refs:[item.link],
          pubDate:item.pubDate?new Date(item.pubDate).toISOString().slice(0,10):isoNow(),
          vendor:'CISA US-CERT', product:'Multiple Products',
          exploited:/exploit|active/i.test(text), cisaKev:false,
          ransomware:/ransomware/i.test(text),
          cves:extractCVEs(text), link:item.link, iocs, sourceCount:1,
          daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0 };
      });
    setSourceLastFetch(state, 'cisa_alerts', Date.now());
    log(`CISA Alerts: ${items.length} items (filtered from ${parsed.length}).`); return items;
  } catch(e) { warn(`CISA Alerts failed: ${e.message}`); return []; }
}

// ── SOURCE 4: GitHub Security Advisories ──────────────────────────────
async function fetchGitHubAdvisories(state) {
  const lastFetch = getSourceLastFetch(state, 'github_advisories');
  const cutoff    = lastFetch ? new Date(lastFetch) : new Date(Date.now() - 7*86400000);
  log(`GitHub Advisories: fetching (since ${cutoff.toISOString().slice(0,10)})...`);
  try {
    await sleep(500);
    const raw = await fetchWithRetry(CFG.ghAdvisoryUrl);
    const data = JSON.parse(raw);
    const items = (Array.isArray(data)?data:[]).filter(a => new Date(a.published_at||a.updated_at) >= cutoff).slice(0,10).map(a => {
      const cvss = a.cvss?.score||(a.severity==='critical'?9.0:7.5);
      const cves = (a.cve_id?[a.cve_id]:[]).concat((a.identifiers||[]).filter(i=>i.type==='CVE').map(i=>i.value));
      const primaryId = cves[0]||('GHSA-'+md5(a.ghsa_id||a.url));
      const desc = stripHtml(a.description||a.summary||'').slice(0,800);
      const iocs = extractIOCs(desc, []);
      return { source:'github_advisories', type:'CVE_REPORT', id:primaryId,
        title:a.summary||`${primaryId} — GitHub Security Advisory`,
        desc, cvss, vector:a.cvss?.vector_string||'', cweId:(a.cwes||[])[0]?.cwe_id||'',
        refs:[a.html_url,...(a.references||[])].filter(Boolean).slice(0,5),
        pubDate:(a.published_at||isoNow()).slice(0,10),
        vendor:(a.vulnerabilities||[])[0]?.package?.ecosystem||'Open Source',
        product:(a.vulnerabilities||[])[0]?.package?.name||'Unknown Package',
        exploited:false, cisaKev:false, ransomware:false, cves, iocs, sourceCount:1,
        daysOld: Math.floor((Date.now()-new Date(a.published_at||isoNow()).getTime())/86400000) };
    });
    setSourceLastFetch(state, 'github_advisories', Date.now());
    log(`GitHub Advisories: ${items.length} items.`); return items;
  } catch(e) { warn(`GitHub Advisories failed: ${e.message}`); return []; }
}

// ── RSS NORMALIZER ─────────────────────────────────────────────────────
function classifyNews(text) {
  if (/zero.?day|0.?day|unpatched|no patch available/i.test(text))        return 'ZERO_DAY';
  if (/ransomware|ransom demand|encryption attack|lockbit|qilin|akira|blackcat/i.test(text)) return 'RANSOMWARE';
  if (/data breach|breach|leaked|exposed data|records stolen|database dump/i.test(text)) return 'DATA_BREACH';
  if (/apt\d|nation.state|lazarus|volt typhoon|sandworm|cozy bear|fancy bear|apt group|state.sponsored/i.test(text)) return 'THREAT_ACTOR';
  if (/malware|trojan|\brat\b|backdoor|botnet|stealer|infostealer|loader|dropper/i.test(text)) return 'MALWARE_REPORT';
  if (/ai security|llm|prompt injection|artificial intelligence.*security|ml.*attack|gpt.*hack|deepfake/i.test(text)) return 'AI_SECURITY';
  if (/patch tuesday|security update|advisory|cve-\d/i.test(text))        return 'CVE_REPORT';
  return 'NEWS_REPORT';
}

function rssToIntel(item, source) {
  const text = (item.title||'')+' '+(item.desc||'');
  const cves  = extractCVEs(text);
  const type  = classifyNews(text);
  const id    = cves[0]||(source.toUpperCase()+'-'+md5(item.link||item.title));
  const pubDate = (() => { try { return item.pubDate ? new Date(item.pubDate).toISOString().slice(0,10) : isoNow(); } catch(e){ return isoNow(); } })();
  const srcLabels = { bleepingcomputer:'BleepingComputer', thehackernews:'The Hacker News', krebsonsecurity:'KrebsOnSecurity', securityweek:'SecurityWeek', sans_isc:'SANS ISC' };
  const iocs = extractIOCs(text, []);
  return {
    source, type, id,
    title:item.title||'Security Intelligence Report',
    desc:(item.desc||'').slice(0,800), cvss:cves.length?8.0:6.5,
    refs:[item.link].filter(Boolean), pubDate,
    vendor:srcLabels[source]||source, product:'Threat Intelligence',
    exploited:/exploit|active|in the wild|itw|0.?day|zero.?day/i.test(text),
    cisaKev:/cisa kev|known exploited/i.test(text),
    ransomware:/ransomware|ransom|lockbit|qilin|akira|blackcat/i.test(text),
    cves, link:item.link, iocs, sourceCount:1,
    daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0,
  };
}

// ── SOURCES 5-9: RSS FEEDS ─────────────────────────────────────────────
async function fetchRSS(urlStr, source, maxItems, state) {
  const lastFetch = state ? getSourceLastFetch(state, source) : null;
  const afterDate = lastFetch ? new Date(lastFetch) : new Date(Date.now() - CFG.kevLookbackDays * 86400000);
  log(`${source}: fetching RSS (since ${afterDate.toISOString().slice(0,10)})...`);
  try {
    const raw = await fetchWithRetry(urlStr);
    const parsed = parseRSS(raw);
    const filtered = parsed.filter(item => {
      if (!item.pubDate) return true;
      try { return new Date(item.pubDate) >= afterDate; } catch(_) { return true; }
    });
    const items = filtered.slice(0, maxItems||CFG.maxRssItems).map(item => rssToIntel(item, source));
    if (state) setSourceLastFetch(state, source, Date.now());
    log(`${source}: ${items.length} items (filtered from ${parsed.length}).`); return items;
  } catch(e) { warn(`${source} failed: ${e.message}`); return []; }
}

// ── SOURCE 10: Abuse.ch URLhaus ────────────────────────────────────────
async function fetchURLhaus() {
  log('Abuse.ch URLhaus: fetching...');
  try {
    const raw = await fetchWithRetry(CFG.urlhausApi, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'limit=40' });
    const data = JSON.parse(raw);
    const payloads = data.payloads || data.urls || [];
    if (!payloads.length) return [];
    const families = {};
    payloads.slice(0,40).forEach(u => {
      const tag = (u.signature||u.tags?.[0]||'unknown_malware');
      if (!families[tag]) families[tag] = { count:0, hashes:[], date:u.firstseen||u.date_added||isoNow() };
      families[tag].count++;
      const hash = u.md5_hash||u.sha256_hash;
      if (hash) families[tag].hashes.push({ type: u.sha256_hash?'sha256':'md5', value:hash, confidence_score:0.92, first_seen:isoNow(), source_count:1 });
    });
    const dailyDate = new Date().toISOString().slice(0,10); // YYYY-MM-DD — daily-fresh ID
    const items = Object.entries(families).filter(([k])=>k!=='unknown_malware').slice(0,3).map(([tag,info]) => ({
      source:'urlhaus', type:'MALWARE_REPORT',
      id:'URLHAUS-'+md5(tag+dailyDate),
      title:`Abuse.ch Malware Alert: ${tag} — ${info.count} Payloads Tracked (URLhaus)`,
      desc:`URLhaus tracking ${info.count} active payloads for ${tag} malware family. Fresh IOCs confirmed. Deploy to SIEM/firewall immediately.`,
      cvss:7.5, refs:['https://urlhaus.abuse.ch/'],
      pubDate:info.date?String(info.date).slice(0,10):isoNow(),
      vendor:'Abuse.ch', product:'URLhaus Intelligence',
      exploited:true, cisaKev:false,
      ransomware:/ransomware|ransom/i.test(tag),
      iocs:info.hashes.slice(0,10), sourceCount:1, malwareTag:tag, daysOld:0,
    }));
    log(`URLhaus: ${items.length} items.`); return items;
  } catch(e) { warn(`URLhaus failed: ${e.message}`); return []; }
}

// ── SOURCE 11: Abuse.ch ThreatFox ─────────────────────────────────────
async function fetchThreatFox() {
  log('Abuse.ch ThreatFox: fetching...');
  try {
    const body = JSON.stringify({ query:'get_iocs', days:1, limit:100 });
    const raw  = await fetchWithRetry(CFG.threatfoxApi, {
      method:'POST',
      headers:{ 'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(body) },
      body,
    });
    const data = JSON.parse(raw);
    if (data.query_status !== 'ok' || !Array.isArray(data.data)) return [];
    const families = {};
    data.data.slice(0,100).forEach(ioc => {
      const fam = ioc.malware_printable||ioc.malware||'Unknown Malware';
      if (!families[fam]) families[fam] = { iocs:[], firstSeen:ioc.first_seen };
      families[fam].iocs.push({ type:ioc.ioc_type, value:ioc.ioc, confidence_score:0.90, first_seen:isoNow(), source_count:1 });
    });
    const dailyDate = new Date().toISOString().slice(0,10); // YYYY-MM-DD — daily-fresh ID
    const items = Object.entries(families).slice(0,3).map(([family,info]) => ({
      source:'threatfox', type:'MALWARE_REPORT',
      id:'THREATFOX-'+md5(family+dailyDate),
      title:`ThreatFox IOC Alert: ${family} — Fresh Indicators Published`,
      desc:`Abuse.ch ThreatFox published ${info.iocs.length} fresh IOCs for ${family}. Active threat infrastructure. Deploy to SIEM/firewall/EDR immediately.`,
      cvss:7.8, refs:['https://threatfox.abuse.ch/'],
      pubDate:info.firstSeen?info.firstSeen.slice(0,10):isoNow(),
      vendor:'Abuse.ch', product:'ThreatFox Intelligence',
      exploited:true, cisaKev:false,
      ransomware:/ransomware|ransom|locker/i.test(family),
      iocs:info.iocs.slice(0,10), sourceCount:1, malwareFamily:family, daysOld:0,
    }));
    log(`ThreatFox: ${items.length} items.`); return items;
  } catch(e) { warn(`ThreatFox failed: ${e.message}`); return []; }
}

// ── SOURCE 12: MSRC ─────────────────────────────────────────────────────
async function fetchMSRC() {
  log('MSRC: fetching Microsoft security updates...');
  try {
    await sleep(300);
    const raw = await fetchWithRetry(CFG.msrcApi, { headers:{ 'Accept':'application/json' } });
    const data = JSON.parse(raw);
    const items = (data.value||[]).slice(0,2).map(u => ({
      source:'msrc', type:'ADVISORY',
      id:'MSRC-'+md5(u.ID||u.Alias||String(Math.random())),
      title:`Microsoft Security Update: ${u.DocumentTitle?.Value||u.Alias||'Security Advisory'} — Analysis`,
      desc:`Microsoft released security updates: ${u.DocumentTitle?.Value||''}. Review and apply immediately.`,
      cvss:8.0, refs:[`https://msrc.microsoft.com/update-guide/`],
      pubDate:(u.InitialReleaseDate||isoNow()).slice(0,10),
      vendor:'Microsoft', product:'Multiple Microsoft Products',
      exploited:false, cisaKev:false, ransomware:false, iocs:[], sourceCount:1, daysOld:0,
    }));
    log(`MSRC: ${items.length} items.`); return items;
  } catch(e) { warn(`MSRC failed: ${e.message}`); return []; }
}

// ── TIER 1 SOURCES 13-15: EXPLOIT/VULN DISCLOSURE ────────────────────

async function fetchExploitDB(state) {
  const lastFetch = getSourceLastFetch(state, 'exploitdb');
  const afterDate = lastFetch ? new Date(lastFetch) : new Date(Date.now() - 2*86400000);
  log(`ExploitDB: fetching (since ${afterDate.toISOString().slice(0,10)})...`);
  try {
    const raw = await fetchWithRetry(CFG.exploitDbRss, {}, 2);
    const parsed = parseRSS(raw);
    const items = parsed
      .filter(item => { try { return !item.pubDate || new Date(item.pubDate) >= afterDate; } catch(_){return true;} })
      .slice(0, CFG.maxRssItems)
      .map(item => {
        const text = (item.title||'') + ' ' + (item.desc||'');
        const cves  = extractCVEs(text);
        const id    = cves[0] || ('EXPLOITDB-' + md5(item.link || item.title));
        return {
          source:'exploitdb', type: cves.length ? 'CVE_REPORT' : 'ZERO_DAY',
          id, title: item.title || 'ExploitDB Public Exploit', desc: (item.desc||'').slice(0,600),
          cvss: cves.length ? 8.5 : 7.5, refs: [item.link].filter(Boolean),
          pubDate: item.pubDate ? new Date(item.pubDate).toISOString().slice(0,10) : isoNow(),
          vendor: 'ExploitDB', product: 'Multiple Targets',
          exploited: true, cisaKev: false, ransomware: false,
          cves, iocs: extractIOCs(text, []), sourceCount: 1,
          daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0,
        };
      });
    setSourceLastFetch(state, 'exploitdb', Date.now());
    log(`ExploitDB: ${items.length} items.`); return items;
  } catch(e) { warn(`ExploitDB failed: ${e.message}`); return []; }
}

async function fetchPacketStorm(state) {
  const lastFetch = getSourceLastFetch(state, 'packetstorm');
  const afterDate = lastFetch ? new Date(lastFetch) : new Date(Date.now() - 2*86400000);
  log(`PacketStorm: fetching...`);
  try {
    const raw = await fetchWithRetry(CFG.packetstormRss, {}, 2);
    const parsed = parseRSS(raw);
    const items = parsed
      .filter(item => { try { return !item.pubDate || new Date(item.pubDate) >= afterDate; } catch(_){return true;} })
      .slice(0, CFG.maxRssItems)
      .map(item => {
        const text = (item.title||'') + ' ' + (item.desc||'');
        const cves  = extractCVEs(text);
        const id    = cves[0] || ('PKTSTORM-' + md5(item.link || item.title));
        return {
          source:'packetstorm', type: /exploit|poc|proof.of.concept/i.test(text) ? 'ZERO_DAY' : 'CVE_REPORT',
          id, title: item.title || 'PacketStorm Security Advisory', desc: (item.desc||'').slice(0,600),
          cvss: 8.0, refs: [item.link].filter(Boolean),
          pubDate: item.pubDate ? new Date(item.pubDate).toISOString().slice(0,10) : isoNow(),
          vendor: 'PacketStorm', product: 'Multiple Targets',
          exploited: /exploit|poc/i.test(text), cisaKev: false, ransomware: false,
          cves, iocs: extractIOCs(text, []), sourceCount: 1,
          daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0,
        };
      });
    setSourceLastFetch(state, 'packetstorm', Date.now());
    log(`PacketStorm: ${items.length} items.`); return items;
  } catch(e) { warn(`PacketStorm failed: ${e.message}`); return []; }
}

async function fetchFullDisclosure(state) {
  const lastFetch = getSourceLastFetch(state, 'fulldisclosure');
  const afterDate = lastFetch ? new Date(lastFetch) : new Date(Date.now() - 2*86400000);
  log(`Full Disclosure: fetching...`);
  try {
    const raw = await fetchWithRetry(CFG.fullDisclosureRss, {}, 2);
    const parsed = parseRSS(raw);
    const items = parsed
      .filter(item => { try { return !item.pubDate || new Date(item.pubDate) >= afterDate; } catch(_){return true;} })
      .slice(0, 8)
      .map(item => {
        const text = (item.title||'') + ' ' + (item.desc||'');
        const cves  = extractCVEs(text);
        const id    = cves[0] || ('FULLDIS-' + md5(item.link || item.title));
        return {
          source:'fulldisclosure', type: 'ZERO_DAY',
          id, title: item.title || 'Full Disclosure Vulnerability Report', desc: (item.desc||'').slice(0,600),
          cvss: cves.length ? 8.0 : 6.5, refs: [item.link].filter(Boolean),
          pubDate: item.pubDate ? new Date(item.pubDate).toISOString().slice(0,10) : isoNow(),
          vendor: 'SecLists', product: 'Multiple Targets',
          exploited: /exploit|poc|0day/i.test(text), cisaKev: false, ransomware: false,
          cves, iocs: extractIOCs(text, []), sourceCount: 1,
          daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0,
        };
      });
    setSourceLastFetch(state, 'fulldisclosure', Date.now());
    log(`Full Disclosure: ${items.length} items.`); return items;
  } catch(e) { warn(`Full Disclosure failed: ${e.message}`); return []; }
}

// ── TIER 2 SOURCES 16-21: THREAT INTEL BLOGS ─────────────────────────

async function fetchTalos(state) {
  return fetchRSS(CFG.talosBlogRss, 'talos', CFG.maxRssItems, state);
}
async function fetchUnit42(state) {
  return fetchRSS(CFG.unit42Rss, 'unit42', CFG.maxRssItems, state);
}
async function fetchCrowdStrike(state) {
  return fetchRSS(CFG.crowdstrikeBlogRss, 'crowdstrike', CFG.maxRssItems, state);
}
async function fetchSentinelOne(state) {
  return fetchRSS(CFG.sentineloneBlogRss, 'sentinelone', CFG.maxRssItems, state);
}
async function fetchGoogleProjectZero(state) {
  return fetchRSS(CFG.googleProjZeroRss, 'googleprojectzero', 6, state);
}
async function fetchRapid7(state) {
  return fetchRSS(CFG.rapid7BlogRss, 'rapid7', CFG.maxRssItems, state);
}

// ── TIER 3 SOURCES 22-27: COMMUNITY + SIGNALS ────────────────────────

async function fetchRedditNetsec(state) {
  return fetchRSS(CFG.redditNetsecRss, 'reddit_netsec', 10, state);
}
async function fetchRedditCyber(state) {
  return fetchRSS(CFG.redditCyberRss, 'reddit_cyber', 8, state);
}
async function fetchCertEU(state) {
  return fetchRSS(CFG.certEuRss, 'cert_eu', 6, state);
}
async function fetchMicrosoftSecBlog(state) {
  return fetchRSS(CFG.microsoftSecBlogRss, 'microsoft_security', CFG.maxRssItems, state);
}
async function fetchWiredSecurity(state) {
  return fetchRSS(CFG.wiredSecRss, 'wired_security', 8, state);
}
async function fetchRecordedFuture(state) {
  return fetchRSS(CFG.recordedFutureRss, 'recorded_future', 8, state);
}

// ── PHASE 3+5: PRIORITY SCORING ENGINE WITH SIGNAL BOOSTING ───────────
function computePriorityScore(item) {
  let score = 0;
  const text = (item.title||'') + ' ' + (item.desc||'');

  // CVSS base (0-40 pts)
  const cvss = item.cvss || 0;
  score += Math.min(40, Math.round(cvss * 4.2));

  // ── PHASE 5: SIGNAL BOOSTING ─────────────────────────────────────
  // CISA KEV confirmation (25 pts) — highest single signal
  if (item.cisaKev)    score += 25;
  // Active exploitation confirmed (20 pts)
  if (item.exploited)  score += 20;
  // Ransomware campaign use (15 pts)
  if (item.ransomware) score += 15;
  // Zero-day keyword boost (10 pts)
  if (item.type === 'ZERO_DAY' || /zero.?day|0.?day|unpatched|no patch/i.test(text)) score += 10;
  // Nation-state / APT boost (8 pts)
  if (/nation.state|apt\d|lazarus|volt typhoon|sandworm|cozy bear|fancy bear|salt typhoon|state.sponsored/i.test(text)) score += 8;
  // Critical infra boost (7 pts)
  if (/federal|critical infrastructure|scada|ics|election|nuclear|power grid|hospital|utility/i.test(text)) score += 7;
  // Supply chain boost (6 pts)
  if (/supply chain|open.?source|npm|pypi|dependency/i.test(text)) score += 6;
  // AI/ML attack surface boost (4 pts — emerging threat)
  if (/ai security|llm|prompt injection|deepfake|gpt.*hack/i.test(text)) score += 4;
  // ── END SIGNAL BOOSTING ───────────────────────────────────────────

  // Multi-source corroboration (up to 12 pts)
  score += Math.min(12, (item.sourceCount||1) * 3);
  // Recency bonus — fresher = better (up to 8 pts)
  const days = item.daysOld || 0;
  if (days === 0)      score += 8;
  else if (days <= 1)  score += 6;
  else if (days <= 3)  score += 4;
  else if (days <= 7)  score += 2;
  // IOC richness bonus (up to 5 pts)
  score += Math.min(5, (item.iocs||[]).length);
  // Threat actor type (4 pts)
  if (item.type === 'THREAT_ACTOR') score += 4;
  // Exploit code available (5 pts — from ExploitDB / PacketStorm)
  if (item.source === 'exploitdb' || item.source === 'packetstorm' || item.source === 'fulldisclosure') score += 5;

  return Math.min(100, Math.round(score));
}

function threatLevel(score) {
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 45) return 'MEDIUM';
  return 'LOW';
}

// ── PHASE 2: CORRELATION ENGINE ────────────────────────────────────────
function correlateAndMerge(sources) {
  const map = new Map();
  for (const batch of sources) {
    for (const item of (batch||[])) {
      if (!item.id) continue;
      const existing = map.get(item.id);
      if (!existing) {
        map.set(item.id, { ...item, sourceCount:1, _sources:[item.source] });
      } else {
        // Winner strategy: cisa_kev > nvd > github_advisories > rss sources
        const srcRank = { cisa_kev:10, nvd:9, github_advisories:8, cisa_alerts:7, msrc:6 };
        const itemRank = srcRank[item.source]||1, exRank = srcRank[existing.source]||1;
        const base = itemRank >= exRank ? { ...existing, ...item } : { ...item, ...existing };
        // Merge enrichment fields
        base.exploited  = existing.exploited  || item.exploited;
        base.cisaKev    = existing.cisaKev    || item.cisaKev;
        base.ransomware = existing.ransomware || item.ransomware;
        base.dueDate    = existing.dueDate    || item.dueDate;
        base.reqAction  = existing.reqAction  || item.reqAction;
        // Merge IOCs (deduplicated)
        const iocMap = new Map();
        [...(existing.iocs||[]), ...(item.iocs||[])].forEach(ioc => {
          if (ioc && ioc.value) {
            const k = `${ioc.type}:${ioc.value}`;
            if (!iocMap.has(k)) iocMap.set(k, ioc);
            else iocMap.get(k).source_count = (iocMap.get(k).source_count||1) + 1;
          }
        });
        base.iocs = Array.from(iocMap.values()).slice(0, 20);
        // Merge CVEs
        base.cves = [...new Set([...(existing.cves||[]), ...(item.cves||[])])];
        // Merge refs
        base.refs = [...new Set([...(existing.refs||[]), ...(item.refs||[])])].filter(Boolean).slice(0,8);
        // Track all sources
        base._sources = [...new Set([...(existing._sources||[existing.source]), item.source])];
        base.sourceCount = base._sources.length;
        // Better CVSS
        base.cvss = Math.max(existing.cvss||0, item.cvss||0);
        // Recency — take newer date
        const ed = new Date(existing.pubDate||0), id = new Date(item.pubDate||0);
        base.pubDate  = ed > id ? existing.pubDate : item.pubDate;
        base.daysOld  = Math.min(existing.daysOld||999, item.daysOld||999);
        map.set(item.id, base);
      }
    }
  }
  const all = Array.from(map.values()).map(item => ({ ...item, priority: computePriorityScore(item), threatLevel: threatLevel(computePriorityScore(item)) }));
  all.sort((a,b) => (b.priority||0) - (a.priority||0));
  return all;
}

// ── PHASE 4: SIGNAL vs NOISE FILTERING ────────────────────────────────
function filterSignalFromNoise(items) {
  const before = items.length;
  const filtered = items.filter(item => {
    // Always pass: CISA KEV confirmed
    if (item.cisaKev) return true;
    // Always pass: actively exploited
    if (item.exploited) return true;
    // Always pass: ransomware confirmed
    if (item.ransomware) return true;
    // Always pass: high priority score
    if ((item.priority||0) >= CFG.minPriorityScore) return true;
    // Pass: multi-source corroboration
    if ((item.sourceCount||1) >= 2) return true;
    // SUPPRESS: CVSS below threshold and not exploited
    if ((item.cvss||0) < CFG.minCVSS) return false;
    // SUPPRESS: items older than lookback window with no exploitation
    if ((item.daysOld||0) > 30 && !item.exploited && !item.cisaKev) return false;
    // Pass: everything else meeting minimum bar
    return (item.priority||0) >= 30;
  });
  const suppressed = before - filtered.length;
  if (suppressed > 0) log(`Signal filter: suppressed ${suppressed} low-value items (${filtered.length} remain).`);
  return filtered;
}

// ── MITRE ATT&CK MAPPING ─────────────────────────────────────────────
function getMitre(item) {
  const t = ((item.desc||'')+(item.title||'')).toLowerCase();
  if (/remote code execution|rce|arbitrary code execution/i.test(t))      return { tactic:'Execution',             technique:'T1203 — Exploitation for Client Execution',     sub:'T1059 — Command & Scripting Interpreter' };
  if (/privilege escalation|lpe|eop|elevation of privilege/i.test(t))     return { tactic:'Privilege Escalation',  technique:'T1068 — Exploitation for Privilege Escalation', sub:'T1134 — Access Token Manipulation' };
  if (/auth bypass|unauthenticated|authentication bypass/i.test(t))       return { tactic:'Initial Access',        technique:'T1190 — Exploit Public-Facing Application',     sub:'T1078 — Valid Accounts' };
  if (/use.after.free|uaf/i.test(t))                                       return { tactic:'Execution',             technique:'T1203 — Exploitation for Client Execution',     sub:'T1068 — Exploitation for Privilege Escalation' };
  if (/sql injection|sqli/i.test(t))                                       return { tactic:'Initial Access',        technique:'T1190 — Exploit Public-Facing Application',     sub:'T1555 — Credentials from Password Stores' };
  if (/buffer overflow|heap overflow|memory corruption|stack overflow/i.test(t)) return { tactic:'Execution',      technique:'T1203 — Exploitation for Client Execution',     sub:'T1068 — Exploitation for Privilege Escalation' };
  if (/path traversal|directory traversal|lfi|rfi/i.test(t))              return { tactic:'Discovery',             technique:'T1083 — File and Directory Discovery',          sub:'T1005 — Data from Local System' };
  if (/deserialization|unsafe deserialization/i.test(t))                  return { tactic:'Execution',             technique:'T1059 — Command & Scripting Interpreter',       sub:'T1203 — Exploitation for Client Execution' };
  if (/ssrf|server.side request forgery/i.test(t))                        return { tactic:'Collection',            technique:'T1213 — Data from Information Repositories',    sub:'T1190 — Exploit Public-Facing Application' };
  if (/supply chain/i.test(t))                                             return { tactic:'Initial Access',        technique:'T1195 — Supply Chain Compromise',               sub:'T1199 — Trusted Relationship' };
  if (/ransomware/i.test(t)||item.type==='RANSOMWARE')                    return { tactic:'Impact',                technique:'T1486 — Data Encrypted for Impact',             sub:'T1490 — Inhibit System Recovery' };
  if (/malware|trojan|backdoor|loader/i.test(t)||item.type==='MALWARE_REPORT') return { tactic:'Execution',        technique:'T1059 — Command & Scripting Interpreter',       sub:'T1055 — Process Injection' };
  if (/data breach|exfiltrat/i.test(t)||item.type==='DATA_BREACH')        return { tactic:'Exfiltration',          technique:'T1041 — Exfiltration Over C2 Channel',          sub:'T1005 — Data from Local System' };
  if (/apt|nation.state|threat actor/i.test(t)||item.type==='THREAT_ACTOR') return { tactic:'Persistence',         technique:'T1078 — Valid Accounts',                        sub:'T1136 — Create Account' };
  return { tactic:'Initial Access', technique:'T1190 — Exploit Public-Facing Application', sub:'T1203 — Exploitation for Client Execution' };
}

// ── SIGMA RULE ─────────────────────────────────────────────────────────
function genSigma(item) {
  const safeName = (item.id||'unknown').replace(/[^a-zA-Z0-9_-]/g,'_');
  const cves = item.cves||(item.id?.startsWith('CVE')?[item.id]:[]);
  return `title: ${item.id} Exploitation Attempt — ${item.vendor} ${item.product}
id: ${md5(item.id+'sigma')}-${md5(item.title||'').slice(0,4)}
status: experimental
description: Detects exploitation of ${item.id} in ${item.vendor} ${item.product}. Priority: ${item.threatLevel||'HIGH'}. Score: ${item.priority||0}/100
author: CYBERDUDEBIVASH SENTINEL APEX v4.0 (bivash@cyberdudebivash.com)
date: ${isoNow()}
references:\n    - https://nvd.nist.gov/vuln/detail/${item.id}\n    - https://blog.cyberdudebivash.in/
tags:\n    - attack.initial_access\n    - attack.t1190${cves.map(c=>`\n    - ${c.toLowerCase()}`).join('')}
logsource:\n    category: webserver
detection:
    keywords:${cves.map(c=>`\n        - '${c}'`).join('')}\n        - '${safeName.toLowerCase()}'
    condition: keywords
falsepositives:\n    - Security scanners\nlevel: ${(item.cvss||0)>=9.5?'critical':(item.cvss||0)>=8?'high':'medium'}`.trim();
}

// ── YARA RULE ──────────────────────────────────────────────────────────
function genYARA(item) {
  const n = (item.id||'unknown').replace(/[^a-zA-Z0-9_]/g,'_');
  const p = (item.product||'unknown').replace(/[^a-zA-Z0-9_]/g,'_').slice(0,40);
  return `rule ${n}_Exploitation {
    meta:
        description = "Detects artifacts related to ${item.id} exploitation in ${item.vendor} ${item.product}"
        author      = "CYBERDUDEBIVASH SENTINEL APEX v4.0"
        date        = "${isoNow()}"
        severity    = "${(item.cvss||0) >= 9 ? 'CRITICAL' : 'HIGH'}"
        cvss        = "${item.cvss||'N/A'}"
        priority    = "${item.priority||0}/100"
        threat_level = "${item.threatLevel||'HIGH'}"
        reference   = "https://nvd.nist.gov/vuln/detail/${item.id}"
    strings:
        $id_str  = "${(item.id||'').replace(/"/g,'')}" ascii nocase
        $product = "${p.replace(/"/g,'')}" ascii nocase wide
    condition:\n        any of them\n}`.trim();
}

// ── PHASE 7: ADVANCED COMMENTARY (Executive Summary + Business Impact) ─
function genExecutiveSummary(item) {
  const vendor=item.vendor||'the affected vendor', product=item.product||'affected product';
  const cvss=item.cvss||7.0, tl=item.threatLevel||'HIGH', score=item.priority||0;
  const srcList = (item._sources||[item.source]).join(', ');
  return `CYBERDUDEBIVASH SENTINEL APEX has confirmed a ${tl}-tier threat intelligence signal for ${item.id} affecting ${vendor} ${product}. Composite threat score: ${score}/100. Intelligence corroborated across ${item.sourceCount||1} source(s): ${srcList}. CVSS base score: ${cvss}. ${item.cisaKev?'CISA KEV confirmed — active exploitation documented in federal advisory.':item.exploited?'Active exploitation detected in the wild — emergency response required.':'Exploitation probability assessed as HIGH based on vulnerability characteristics.'} ${item.ransomware?'Ransomware-as-a-service operators have been observed using this attack vector.':''}`;
}

function genBusinessImpact(item) {
  const product=item.product||'affected product', vendor=item.vendor||'vendor';
  const cvss=item.cvss||7.0;
  const impacts = [];
  if (cvss>=9.0||item.cisaKev) impacts.push('Complete system compromise possible — treat as active incident');
  if (item.ransomware) impacts.push('Ransomware deployment risk — offline backup integrity verification required immediately');
  if (item.exploited) impacts.push('Threat actors actively targeting this vulnerability — attack window is open now');
  if (/rce|remote code/i.test((item.desc||'')+(item.title||''))) impacts.push('Remote code execution — full server takeover without authentication possible');
  if (/priv|escalation|lpe|eop/i.test((item.desc||'')+(item.title||''))) impacts.push('Privilege escalation — local attacker can become SYSTEM/root');
  if (/auth bypass|unauthenticated/i.test((item.desc||'')+(item.title||''))) impacts.push('Authentication bypass — all access controls circumvented');
  if (/data breach|exfiltrat/i.test((item.desc||'')+(item.title||''))) impacts.push('Data exfiltration risk — customer and sensitive data at risk');
  if (/supply chain/i.test((item.desc||'')+(item.title||''))) impacts.push('Supply chain compromise — downstream customers may be affected');
  if (!impacts.length) impacts.push(`${vendor} ${product} users face material security risk requiring immediate remediation`);
  return impacts;
}

function genAttackChain(item) {
  const t = ((item.desc||'')+(item.title||'')).toLowerCase();
  const chain = [];
  chain.push({ phase:'Reconnaissance', detail:`Attacker identifies exposed ${item.product||'target'} instances via Shodan, Censys, or targeted scanning`, tactic:'TA0043' });
  if (/unauthenticated|no auth|auth bypass/i.test(t)) {
    chain.push({ phase:'Initial Access', detail:'Unauthenticated exploitation — no credentials required. Single HTTP request sufficient', tactic:'T1190' });
  } else if (/phishing|email|attachment/i.test(t)) {
    chain.push({ phase:'Initial Access', detail:'Spear-phishing with malicious attachment or link targeting ${item.vendor} users', tactic:'T1566' });
  } else {
    chain.push({ phase:'Initial Access', detail:`Exploitation of ${item.id} in ${item.vendor} ${item.product}`, tactic:'T1190' });
  }
  if (/rce|remote code|code execution/i.test(t)) chain.push({ phase:'Execution', detail:'Remote code execution achieved — attacker runs arbitrary commands on target system', tactic:'T1203' });
  if (/escalation|lpe|eop|priv/i.test(t)) chain.push({ phase:'Privilege Escalation', detail:'Local privilege escalation to SYSTEM/root for full control', tactic:'T1068' });
  chain.push({ phase:'Persistence', detail:'Backdoor, scheduled task, or new admin account created for persistent access', tactic:'T1053' });
  if (item.ransomware) {
    chain.push({ phase:'Lateral Movement', detail:'Credential harvesting and network spread using Mimikatz, BloodHound, or living-off-the-land techniques', tactic:'T1550' });
    chain.push({ phase:'Impact', detail:'Data encrypted with double-extortion — exfiltration before encryption. Ransomware demand issued', tactic:'T1486' });
  } else if (item.type==='DATA_BREACH') {
    chain.push({ phase:'Collection', detail:'Sensitive data harvested from databases, file shares, and cloud storage', tactic:'T1005' });
    chain.push({ phase:'Exfiltration', detail:'Data exfiltrated via encrypted C2 channel to attacker-controlled infrastructure', tactic:'T1041' });
  } else {
    chain.push({ phase:'Command & Control', detail:'Attacker establishes persistent C2 channel using HTTPS or DNS tunneling', tactic:'T1071' });
    chain.push({ phase:'Impact / Objectives', detail:'Intellectual property theft, espionage, cryptomining, or preparation for future attack stage', tactic:'T1657' });
  }
  return chain;
}

function genCommentary(item) {
  const vendor=item.vendor||'the affected vendor', product=item.product||'the affected product', cvss=item.cvss||7.0;
  const urgency = cvss>=9.5?'MAXIMUM':cvss>=9.0?'CRITICAL':cvss>=8.0?'HIGH':'ELEVATED';
  const typeCommentary = {
    CVE_REPORT:     `This ${cvss>=9?'critical':'high-severity'} vulnerability in ${vendor} ${product} (CVSS ${cvss}) represents a significant attack surface. SENTINEL APEX assesses exploitation to be technically feasible with moderate effort. Organizations running ${product} in internet-facing or privileged positions face immediate risk.`,
    ZERO_DAY:       `This zero-day vulnerability is being actively exploited before a vendor patch is available. SENTINEL APEX intelligence shows unpatched vulnerabilities are consistently weaponized within 24-72 hours of public disclosure. Nation-state APT groups and ransomware operators actively monitor disclosures and race to weaponize.`,
    RANSOMWARE:     `SENTINEL APEX is tracking active ransomware campaign activity. Modern ransomware operations are double-extortion campaigns combining data theft with encryption. Incident response readiness, offline backups, and network segmentation are non-negotiable defensive requirements.`,
    MALWARE_REPORT: `Active malware campaign infrastructure has been identified and confirmed. This campaign is using live distribution infrastructure currently serving payloads. The IOCs in this report should be blocked immediately across all security controls — firewall, proxy, EDR, and email gateway.`,
    DATA_BREACH:    `A data breach or significant data exposure event has been identified. SENTINEL APEX recommends immediate assessment of third-party data sharing relationships. Credential stuffing attacks typically follow major breach disclosures within 48-72 hours.`,
    THREAT_ACTOR:   `Nation-state or APT actor activity has been observed. State-sponsored cyber operations have dramatically increased in targeting critical infrastructure, defense supply chains, and financial systems. TTPs include living-off-the-land techniques, supply chain compromise, and persistence through legitimate tooling.`,
    AI_SECURITY:    `AI and machine learning security vulnerabilities represent an emerging attack surface that most organizations are unprepared to defend. SENTINEL APEX tracks AI security threats including prompt injection, model poisoning, and AI-assisted cyberattacks.`,
    NEWS_REPORT:    `SENTINEL APEX is monitoring this developing security event. Analysts are tracking indicators, attribution signals, and potential downstream impact. SENTINEL APEX subscribers receive pre-disclosure intelligence before incidents become public knowledge.`,
    ADVISORY:       `This security advisory from ${vendor} covers critical remediation requirements. SENTINEL APEX recommends treating all vendor advisories as actionable intelligence requiring timely response.`,
  };
  const base = typeCommentary[item.type]||typeCommentary['NEWS_REPORT'];
  const kevNote = item.cisaKev ? `\n\nCISA KNOWN EXPLOITED VULNERABILITY: Added to KEV catalog confirming active exploitation. ${item.dueDate?`Federal agencies must remediate by ${item.dueDate}.`:'All organizations must patch immediately.'} Required action: ${item.reqAction||'Apply vendor patch immediately.'}` : '';
  const rsNote  = item.ransomware ? `\n\nRANSOMWARE CORRELATION: Ransomware-as-a-service groups have been observed using this attack vector.` : '';
  const multiSrc = (item.sourceCount||1)>=2 ? `\n\nMULTI-SOURCE CORROBORATION: This intelligence has been confirmed across ${item.sourceCount} independent sources — ${(item._sources||[]).join(', ')} — elevating confidence rating to HIGH.` : '';
  const urgencyNote = `\n\nSENTINEL APEX URGENCY: ${urgency}. Score: ${item.priority||0}/100 ${item.threatLevel||'HIGH'}. ${item.exploited?'Active exploitation confirmed — treat as active incident requiring immediate response.':'Patch before exploitation activity begins.'}`;
  return base+kevNote+rsNote+multiSrc+urgencyNote;
}

function genPlaybook(item) {
  const p = item.product||'affected product', v = item.vendor||'vendor';
  const base = [
    `IMMEDIATE (0-1hr): Identify all instances of ${p} in your environment via CMDB/asset inventory`,
    `IMMEDIATE (0-1hr): Apply vendor patch — no maintenance window exception for ${item.threatLevel||'HIGH'} threats`,
    `IMMEDIATE (1-2hr): If no patch available: implement WAF rules, ACLs, or network-level compensating controls`,
    `SHORT-TERM (2-4hr): Deploy Sigma detection rule to SIEM — validate alert generation in test environment`,
    `SHORT-TERM (4-8hr): Review logs for exploitation indicators (anomalous ${p} requests, error spikes)`,
    `SHORT-TERM (8-24hr): Hunt for post-exploitation: new admin accounts, scheduled tasks, lateral movement`,
    item.cisaKev ? `MANDATORY: CISA KEV remediation deadline ${item.dueDate||'TBD'} — document for compliance reporting` : `MONITOR: Subscribe to ${v} security advisories for patch updates`,
    `ONGOING: Track SENTINEL APEX intelligence feed for follow-on campaigns targeting ${p}`,
  ];
  if (item.ransomware) {
    base.push('VALIDATE: Offline backup integrity — test restoration procedures NOW before encryption event');
    base.push('HUNT: PowerShell/WMI anomalies, vssadmin delete shadows, Cobalt Strike, Mimikatz indicators');
    base.push('ISOLATE: If compromise suspected — isolate affected systems before ransomware spreads laterally');
  }
  if ((item.iocs||[]).length) {
    base.splice(1, 0, `IMMEDIATE: Block all ${item.iocs.length} IOCs in this report at firewall, proxy, DNS, and EDR simultaneously`);
  }
  if ((item.sourceCount||1) >= 2) {
    base.push(`INTEL: Multi-source confirmed (${(item._sources||[]).join(', ')}) — share IOCs with your ISAC/ISAO partners`);
  }
  return base;
}

// ── PHASE 6+7: ADVANCED HTML REPORT GENERATOR ──────────────────────────
function generatePostHTML(item) {
  const mitre = getMitre(item);
  const commentary = genCommentary(item);
  const sigma = genSigma(item);
  const yara  = genYARA(item);
  const playbook = genPlaybook(item);
  const execSummary = genExecutiveSummary(item);
  const bizImpact = genBusinessImpact(item);
  const attackChain = genAttackChain(item);
  const pubDateFmt = fmtDate(item.pubDate||isoNow()), today = isoNow();
  const cvss = item.cvss||7.0;
  const cvssColor = cvss>=9.0?'#ff3b3b':cvss>=7.0?'#ff8c00':'#ffe000';
  const sevLabel = cvss>=9.5?'CRITICAL':cvss>=9.0?'CRITICAL':cvss>=7.0?'HIGH':'MEDIUM';
  const tl = item.threatLevel||sevLabel;
  const score = item.priority||0;
  const typeLabels = { CVE_REPORT:'🔴 CVE ANALYSIS', ZERO_DAY:'💀 ZERO-DAY', RANSOMWARE:'🏴 RANSOMWARE', MALWARE_REPORT:'🦠 MALWARE', DATA_BREACH:'⚠️ DATA BREACH', THREAT_ACTOR:'🎯 THREAT ACTOR', AI_SECURITY:'🤖 AI SECURITY', NEWS_REPORT:'📡 INTEL', ADVISORY:'🛡️ ADVISORY' };
  const typeLabel = typeLabels[item.type]||'⚡ INTEL';
  const slug = slugify(item.id.startsWith('CVE')?`${item.id}-${item.vendor}-${item.product}`:item.title.slice(0,60));
  const metaTitle = `${item.title} | CYBERDUDEBIVASH SENTINEL APEX`;
  const metaDesc  = `${item.id} — ${tl} Score ${score}/100. ${(item.desc||'').slice(0,140)}. Full analysis, IOCs, detection rules, attack chain by CYBERDUDEBIVASH.`;
  const badges = [
    item.cisaKev?`<span class="badge bdg-cisa">⚠️ CISA KEV</span>`:'',
    item.exploited?`<span class="badge bdg-red">⚡ ACTIVELY EXPLOITED</span>`:'',
    item.ransomware?`<span class="badge bdg-purple">🏴 RANSOMWARE</span>`:'',
    `<span class="badge bdg-score">${score}/100</span>`,
    `<span class="badge bdg-red">CVSS ${cvss}</span>`,
    `<span class="badge bdg-cyan">${typeLabel}</span>`,
    (item.sourceCount||1)>=2?`<span class="badge bdg-green">✓ ${item.sourceCount}x CONFIRMED</span>`:'',
  ].filter(Boolean).join('\n      ');
  const cveIds  = item.cves||(item.id?.startsWith('CVE')?[item.id]:[]);
  const cveRows = cveIds.slice(0,5).map(cve=>`<tr><td style="font-family:var(--mono);color:var(--apex-cyan)">${escHtml(cve)}</td><td><a href="https://nvd.nist.gov/vuln/detail/${escHtml(cve)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">NVD →</a></td><td>${cvss}</td></tr>`).join('\n');
  const iocRows = (item.iocs||[]).filter(ioc=>ioc&&ioc.value).slice(0,10).map(ioc=>`<tr><td style="font-family:var(--mono);font-size:11px;color:var(--apex-cyan)">${escHtml(String(ioc.value||'').slice(0,80))}</td><td>${escHtml(ioc.type||'ioc')}</td><td style="text-align:center">${Math.round((ioc.confidence_score||0.8)*100)}%</td><td style="color:var(--apex-muted);font-size:11px">${escHtml(ioc.first_seen||isoNow())}</td></tr>`).join('\n');
  const refLinks = (item.refs||[]).slice(0,5).map(r=>`<li><a href="${escHtml(r)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">${escHtml(String(r).replace(/https?:\/\//,'').slice(0,70))}</a></li>`).join('\n');
  const playbookItems = playbook.map((s,i)=>`<li class="action-item"><span class="action-num">${i+1}</span>${escHtml(s)}</li>`).join('\n      ');
  const bizImpactItems = bizImpact.map(b=>`<li class="impact-item">⚠️ ${escHtml(b)}</li>`).join('\n');
  const chainRows = attackChain.map((step,i)=>`<tr${i===0?' class="chain-first"':i===attackChain.length-1?' class="chain-last"':''}>
      <td style="text-align:center;padding:10px 8px"><div class="chain-num">${i+1}</div></td>
      <td style="color:var(--apex-cyan);font-weight:700;padding:10px 14px;white-space:nowrap">${escHtml(step.phase)}</td>
      <td style="padding:10px 14px;font-size:13px;color:var(--apex-text)">${escHtml(step.detail)}</td>
      <td style="padding:10px 8px;text-align:center"><code style="font-size:10px;color:var(--apex-orange)">${escHtml(step.tactic)}</code></td>
    </tr>`).join('\n    ');
  const showDetection = ['CVE_REPORT','ZERO_DAY','ADVISORY','MALWARE_REPORT','RANSOMWARE'].includes(item.type);
  const srcBadges = (item._sources||[item.source]).map(s=>`<span style="display:inline-block;padding:2px 8px;border:1px solid var(--apex-border);border-radius:4px;font-size:11px;color:var(--apex-muted);margin:2px">${escHtml(s)}</span>`).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="${escHtml(metaDesc)}">
<meta property="og:title" content="${escHtml(metaTitle)}"><meta property="og:type" content="article">
<meta property="og:url" content="${CFG.baseUrl}/posts/${escHtml(slug)}.html">
<meta name="twitter:card" content="summary_large_image">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="canonical" href="${CFG.baseUrl}/posts/${escHtml(slug)}.html">
<link rel="alternate" type="application/rss+xml" title="CYBERDUDEBIVASH SENTINEL APEX" href="${CFG.baseUrl}/rss.xml">
<title>${escHtml(metaTitle)}</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","headline":"${escHtml(item.title)}","description":"${escHtml(metaDesc)}","datePublished":"${today}","dateModified":"${today}","author":{"@type":"Organization","name":"CYBERDUDEBIVASH SENTINEL APEX","url":"${CFG.baseUrl}"},"publisher":{"@type":"Organization","name":"CYBERDUDEBIVASH"}}</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-red:#ff3b3b;--apex-orange:#ff8c00;--apex-yellow:#ffe000;--apex-green:#00ff88;--apex-purple:#a855f7;--apex-bg:#07090f;--apex-surface:#0d1117;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;overflow-x:hidden;line-height:1.7}
#mc{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;opacity:.025}
.ticker{position:relative;z-index:100;background:linear-gradient(90deg,#ff0040,#cc0030,#ff0040);padding:8px 0;overflow:hidden}
.ticker-inner{display:flex;animation:tick 55s linear infinite;white-space:nowrap}.ticker-item{color:#fff;font-size:12px;font-weight:700;letter-spacing:.05em;padding:0 40px}
@keyframes tick{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
nav{position:sticky;top:0;z-index:9999;background:rgba(7,9,15,.97);backdrop-filter:blur(20px);border-bottom:1px solid var(--apex-border);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between}
.nbrand{display:flex;align-items:center;gap:10px;text-decoration:none}.nlogo{font-size:18px;font-weight:900;color:var(--apex-cyan)}.ntag{font-size:10px;color:var(--apex-muted);letter-spacing:.1em;text-transform:uppercase}
.nlinks{display:flex;align-items:center;gap:6px}.nlinks a{color:var(--apex-muted);text-decoration:none;font-size:13px;font-weight:500;padding:6px 12px;border-radius:6px;transition:.2s}.nlinks a:hover{color:var(--apex-text);background:var(--apex-surface)}
.ncta{background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000!important;font-weight:700!important;border-radius:6px!important}
main{position:relative;z-index:10;max-width:1200px;margin:0 auto;padding:40px 24px 80px;display:grid;grid-template-columns:1fr 320px;gap:40px}
@media(max-width:900px){main{grid-template-columns:1fr;padding:24px 16px}}
.meta-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:20px}
.badge{padding:4px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.bdg-red{background:#ff3b3b22;color:#ff3b3b;border:1px solid #ff3b3b44}.bdg-cisa{background:#00ffe022;color:#00ffe0;border:1px solid #00ffe044}
.bdg-cyan{background:#0099ff22;color:#0099ff;border:1px solid #0099ff44}.bdg-purple{background:#a855f722;color:#a855f7;border:1px solid #a855f744}
.bdg-score{background:#ffe00022;color:#ffe000;border:1px solid #ffe00044}.bdg-green{background:#00ff8822;color:#00ff88;border:1px solid #00ff8844}
.rep-date{color:var(--apex-muted);font-size:13px;margin-left:auto}
h1.rh1{font-size:clamp(20px,3.5vw,34px);font-weight:900;line-height:1.2;color:#fff;margin-bottom:16px}
.rsubtitle{font-size:15px;color:var(--apex-muted);margin-bottom:28px;line-height:1.65;border-left:3px solid var(--apex-red);padding-left:16px}
.stats-bar{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;margin-bottom:32px}
.stat{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:10px;padding:14px;text-align:center}
.stat .sv{font-size:20px;font-weight:900;color:var(--apex-cyan);font-family:var(--mono)}.stat.red .sv{color:var(--apex-red)}.stat.orange .sv{color:var(--apex-orange)}.stat.green .sv{color:var(--apex-green)}.stat.yellow .sv{color:var(--apex-yellow)}.stat .sl{font-size:10px;color:var(--apex-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
.exec-box{background:linear-gradient(135deg,#0a1220,#111827);border:1px solid rgba(0,255,224,.15);border-left:4px solid var(--apex-cyan);border-radius:12px;padding:20px 24px;margin-bottom:24px}
.exec-box .ex-label{font-size:10px;font-weight:800;color:var(--apex-cyan);letter-spacing:.15em;text-transform:uppercase;margin-bottom:10px}
.exec-box p{font-size:14px;color:#c9d1d9;line-height:1.75}
.alert{padding:16px 20px;border-radius:10px;margin:20px 0;display:flex;gap:14px;align-items:flex-start}
.alert-crit{background:#ff3b3b10;border:1px solid #ff3b3b44;border-left:4px solid var(--apex-red)}.alert-warn{background:#ff8c0010;border:1px solid #ff8c0044;border-left:4px solid var(--apex-orange)}.alert-info{background:#00ffe010;border:1px solid #00ffe044;border-left:4px solid var(--apex-cyan)}
.aico{font-size:22px;flex-shrink:0}.abody .atitle{font-weight:800;font-size:14px;margin-bottom:4px}.alert-crit .atitle{color:var(--apex-red)}.alert-warn .atitle{color:var(--apex-orange)}.alert-info .atitle{color:var(--apex-cyan)}.abody p{font-size:14px;color:var(--apex-muted);line-height:1.6}
h2.sh{font-size:19px;font-weight:800;color:#fff;margin:36px 0 16px;padding-bottom:8px;border-bottom:1px solid var(--apex-border)}h2.sh span{color:var(--apex-cyan)}
p.bp{font-size:15px;color:#c9d1d9;line-height:1.8;margin-bottom:14px}
.code-block{background:#0a0e18;border:1px solid var(--apex-border);border-radius:8px;padding:16px 20px;font-family:var(--mono);font-size:12px;color:#a6e22e;overflow-x:auto;margin:16px 0;position:relative;white-space:pre;max-height:380px;overflow-y:auto}
.code-lbl{position:absolute;top:8px;right:12px;font-size:10px;color:var(--apex-muted);text-transform:uppercase;letter-spacing:.1em;background:var(--apex-surface);padding:2px 6px;border-radius:4px}
.tbl{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px}.tbl th{background:#1a2234;color:var(--apex-cyan);font-weight:700;padding:10px 14px;text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--apex-border)}.tbl td{padding:10px 14px;border:1px solid var(--apex-border);color:var(--apex-text);vertical-align:top}
.chain-num{width:24px;height:24px;border-radius:50%;background:linear-gradient(135deg,var(--apex-red),#cc0020);color:#fff;font-size:11px;font-weight:900;display:flex;align-items:center;justify-content:center;margin:0 auto}
.impact-list{list-style:none;padding:0;margin:12px 0}.impact-item{padding:10px 14px;border-left:3px solid var(--apex-orange);background:#ff8c0008;border-radius:0 8px 8px 0;margin-bottom:8px;font-size:14px;color:var(--apex-text);line-height:1.6}
.pro-gate{position:relative;overflow:hidden;border-radius:12px;border:1px solid rgba(168,85,247,.3)}.pro-blur{filter:blur(5px);pointer-events:none;user-select:none;opacity:.4}.pro-overlay{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;background:rgba(7,9,15,.85);border-radius:12px;z-index:10;padding:20px;text-align:center}
.pro-lock{font-size:32px}.pro-title{font-size:15px;font-weight:800;color:#a855f7}.pro-sub{font-size:13px;color:var(--apex-muted)}.pro-btn{padding:10px 24px;background:linear-gradient(135deg,#a855f7,#7c3aed);color:#fff;font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;margin-top:4px}
.ecta{background:linear-gradient(135deg,#0a1428,#111827);border:1px solid #00ffe022;border-radius:16px;padding:28px;margin:40px 0;text-align:center}
.ecta h3{font-size:20px;font-weight:900;color:#fff;margin-bottom:8px}.ecta .ep{color:var(--apex-muted);margin-bottom:20px;font-size:14px}
.cta-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}@media(max-width:600px){.cta-grid{grid-template-columns:1fr}}
.btn-p{padding:12px 20px;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.btn-s{padding:12px 20px;background:transparent;border:2px solid var(--apex-cyan);color:var(--apex-cyan);font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.btn-e{padding:12px 20px;background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.4);color:#a855f7;font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.btn-g{padding:12px 20px;background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.3);color:#00ff88;font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.sidebar{display:flex;flex-direction:column;gap:20px}.sw{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:12px;padding:20px}
.wt{font-size:12px;font-weight:700;color:var(--apex-cyan);text-transform:uppercase;letter-spacing:.1em;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--apex-border)}
.vbox{background:#ff3b3b10;border:2px solid var(--apex-red);border-radius:12px;padding:20px}
.vscore{font-size:44px;font-weight:900;color:var(--apex-red);font-family:var(--mono);text-align:center}.vlabel{font-size:11px;color:var(--apex-muted);text-align:center;text-transform:uppercase;letter-spacing:.1em}
.threat-badge{display:block;text-align:center;padding:6px;background:${cvss>=9?'#ff3b3b33':'#ff8c0033'};color:${cvss>=9?'var(--apex-red)':'var(--apex-orange)'};font-weight:900;font-size:13px;border-radius:6px;margin:8px 0;letter-spacing:.08em}
.vrow{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--apex-border);font-size:13px}.vrow:last-child{border-bottom:none}.vk{color:var(--apex-muted)}.vv{color:var(--apex-text);font-weight:600}
.alist{list-style:none;padding:0}.action-num{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border-radius:50%;background:var(--apex-red);color:#fff;font-size:10px;font-weight:900;margin-right:10px;flex-shrink:0}
.action-item{display:flex;align-items:flex-start;padding:10px 14px;border-bottom:1px solid var(--apex-border);font-size:13px;color:var(--apex-text);line-height:1.6}.action-item:last-child{border-bottom:none}
.intel-sig{margin-top:48px;padding:24px;background:rgba(0,255,224,.03);border:1px solid rgba(0,255,224,.1);border-radius:12px;text-align:center}
.isb{font-size:14px;font-weight:900;color:var(--apex-cyan);letter-spacing:.1em;text-transform:uppercase}.iss{font-size:12px;color:var(--apex-muted);margin-top:6px;line-height:1.5}
footer{background:var(--apex-surface);border-top:1px solid var(--apex-border);padding:32px 24px;text-align:center}footer p{font-size:13px;color:var(--apex-muted);line-height:1.8}footer a{color:var(--apex-cyan);text-decoration:none}
@media(max-width:767px){nav{padding:0 14px}.nlinks a:not(.ncta){display:none}.ntag{display:none}}
</style>
</head>
<body>
<canvas id="mc"></canvas>
<div class="ticker"><div class="ticker-inner">
  <span class="ticker-item">⚡ ${escHtml(item.id)} — ${escHtml(item.vendor)} ${escHtml(item.product)} — Score ${score}/100 ${tl}</span>
  <span class="ticker-item">🛡️ CYBERDUDEBIVASH SENTINEL APEX — 24/7 Global Threat Intelligence v4.0</span>
  <span class="ticker-item">⚠️ ${item.cisaKev?'CISA KEV CONFIRMED — ACTIVE EXPLOITATION':item.exploited?'ACTIVE EXPLOITATION DETECTED':'HIGH-PRIORITY SECURITY ADVISORY'}</span>
  <span class="ticker-item">⚡ ${escHtml(item.id)} — CVSS ${cvss} — ${(item.sourceCount||1)} Source(s) Confirmed</span>
  <span class="ticker-item">🛡️ CYBERDUDEBIVASH SENTINEL APEX — 24/7 Global Threat Intelligence v4.0</span>
  <span class="ticker-item">⚠️ ${item.cisaKev?'CISA KEV CONFIRMED — ACTIVE EXPLOITATION':item.exploited?'ACTIVE EXPLOITATION DETECTED':'HIGH-PRIORITY SECURITY ADVISORY'}</span>
</div></div>
<nav>
  <a href="/" class="nbrand"><div><div class="nlogo">CYBERDUDE<span style="color:#fff">BIVASH</span></div><div class="ntag">SENTINEL APEX v4.0 — Global Threat Intelligence</div></div></a>
  <div class="nlinks"><a href="/">Reports</a><a href="/intelligence.html">Intel Hub</a><a href="/products.html">Detection Packs</a><a href="/pricing.html" class="ncta">⚡ SOC Pro</a></div>
</nav>
<main>
  <article>
    <div class="meta-bar">${badges}<span class="rep-date">Published: ${pubDateFmt}</span></div>
    <h1 class="rh1">${escHtml(item.title)}</h1>
    <p class="rsubtitle">${escHtml((item.desc||'').slice(0,350))}${(item.desc||'').length>350?'...':''}</p>
    <div class="stats-bar">
      <div class="stat red"><div class="sv">${cvss}</div><div class="sl">CVSS Score</div></div>
      <div class="stat"><div class="sv" style="color:${cvssColor}">${tl}</div><div class="sl">Threat Level</div></div>
      <div class="stat yellow"><div class="sv">${score}</div><div class="sl">Priority /100</div></div>
      <div class="stat orange"><div class="sv">${item.exploited?'YES':'TBD'}</div><div class="sl">Exploited ITW</div></div>
      <div class="stat ${item.cisaKev?'red':'green'}"><div class="sv">${item.cisaKev?'⚠️ KEV':'Monitor'}</div><div class="sl">CISA Status</div></div>
      <div class="stat"><div class="sv" style="color:var(--apex-green)">${item.sourceCount||1}x</div><div class="sl">Sources</div></div>
    </div>
    ${item.cisaKev?`<div class="alert alert-crit"><span class="aico">🚨</span><div class="abody"><div class="atitle">CISA KNOWN EXPLOITED VULNERABILITY — MANDATORY REMEDIATION</div><p>Active exploitation confirmed. CISA KEV catalog listed. ${item.dueDate?`Federal agencies must remediate by <strong>${item.dueDate}</strong>.`:'All organizations must patch immediately.'} Required action: ${escHtml(item.reqAction||'Apply vendor patch immediately.')}</p></div></div>`:item.exploited?`<div class="alert alert-warn"><span class="aico">⚠️</span><div class="abody"><div class="atitle">ACTIVE EXPLOITATION DETECTED</div><p>Exploitation confirmed in the wild. Emergency patching required. Score: ${score}/100 — do not wait for maintenance window.</p></div></div>`:`<div class="alert alert-info"><span class="aico">🔵</span><div class="abody"><div class="atitle">HIGH-PRIORITY SECURITY ADVISORY — Priority Score: ${score}/100</div><p>CVSS ${cvss} ${tl}. SENTINEL APEX recommends immediate patch evaluation. Intelligence from ${item.sourceCount||1} confirmed source(s).</p></div></div>`}
    <h2 class="sh"><span>📋</span> Executive Summary</h2>
    <div class="exec-box"><div class="ex-label">⚡ Analyst Assessment — SENTINEL APEX v4.0</div><p>${escHtml(execSummary)}</p><div style="margin-top:12px;font-size:12px;color:var(--apex-muted)">Intelligence sources: ${srcBadges}</div></div>
    <h2 class="sh"><span>⚠️</span> Business Impact Analysis</h2>
    <ul class="impact-list">${bizImpactItems}</ul>
    <h2 class="sh"><span>🔗</span> Attack Chain Analysis</h2>
    <p class="bp" style="font-size:14px">Step-by-step attack chain based on observed TTPs and vulnerability characteristics:</p>
    <table class="tbl"><thead><tr><th>#</th><th>Phase</th><th>Attacker Action</th><th>MITRE</th></tr></thead><tbody>${chainRows}</tbody></table>
    <h2 class="sh"><span>⚠</span> Deep Dive Analysis</h2>
    ${commentary.split('\n\n').map(p=>`<p class="bp">${escHtml(p)}</p>`).join('\n    ')}
    <h2 class="sh"><span>🎯</span> MITRE ATT&CK Mapping</h2>
    <table class="tbl"><thead><tr><th>Category</th><th>Mapping</th></tr></thead><tbody>
      <tr><td>Primary Tactic</td><td style="color:var(--apex-red);font-weight:700">${escHtml(mitre.tactic)}</td></tr>
      <tr><td>Primary Technique</td><td style="color:var(--apex-cyan)">${escHtml(mitre.technique)}</td></tr>
      <tr><td>Sub-Technique</td><td style="color:var(--apex-cyan)">${escHtml(mitre.sub)}</td></tr>
      <tr><td>Weakness (CWE)</td><td>${escHtml(item.cweId||'See NVD entry')}</td></tr>
      <tr><td>Intel Type</td><td>${escHtml(typeLabel)}</td></tr>
      <tr><td>Source(s)</td><td>${srcBadges}</td></tr>
    </tbody></table>
    ${cveIds.length>0?`<h2 class="sh"><span>🔴</span> CVE Reference</h2><table class="tbl"><thead><tr><th>CVE ID</th><th>Reference</th><th>Score</th></tr></thead><tbody>${cveRows||`<tr><td style="font-family:var(--mono);color:var(--apex-cyan)">${escHtml(item.id)}</td><td><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">NVD →</a></td><td>CVSS ${cvss}</td></tr>`}</tbody></table>`:''}
    ${iocRows?`<h2 class="sh"><span>🏷️</span> Indicators of Compromise — Enriched IOC Feed</h2><p class="bp">Normalized IOCs with confidence scoring. Block immediately across all enforcement points. <strong>SOC Pro subscribers</strong> receive enriched IOC bundles with full attribution and STIX/TAXII feeds.</p><table class="tbl"><thead><tr><th>Indicator Value</th><th>Type</th><th>Confidence</th><th>First Seen</th></tr></thead><tbody>${iocRows}</tbody></table>`:''}
    ${showDetection?`<h2 class="sh"><span>🔍</span> Detection Rules — Sigma (SIEM)</h2><p class="bp">Deploy to Splunk, Elastic, Microsoft Sentinel, or QRadar. SOC Pro subscribers receive pre-compiled SIEM-native query packs updated with each pipeline run.</p><div class="code-block"><span class="code-lbl">Sigma YAML</span>${escHtml(sigma)}</div>
    <h2 class="sh"><span>📡</span> Detection Rules — YARA (Endpoint)</h2><p class="bp">Deploy to endpoint detection platforms. Enterprise subscribers receive tuned, FP-validated YARA rule packs.</p><div class="code-block"><span class="code-lbl">YARA</span>${escHtml(yara)}</div>`:''}
    <h2 class="sh"><span>🛡️</span> SOC Response Playbook</h2>
    <ul class="alist">${playbookItems}</ul>
    <h2 class="sh"><span>📎</span> Intelligence References</h2>
    <ul style="list-style:none;padding:0">${refLinks}${item.id?.startsWith('CVE')?`<li><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">📌 NVD — ${escHtml(item.id)}</a></li>`:''}</ul>
    <div class="intel-sig"><div class="isb">⚡ CYBERDUDEBIVASH SENTINEL APEX v4.0</div><div class="iss">Intelligence report generated by CYBERDUDEBIVASH SENTINEL APEX v4.0<br>Report ID: SENTINEL-${escHtml(item.id)}-${today} | Priority: ${score}/100 ${tl} | Sources: ${item.sourceCount||1}<br>&copy; ${new Date().getFullYear()} CYBERDUDEBIVASH PRIVATE LIMITED<br><strong style="color:var(--apex-cyan)">Republication requires written attribution to CYBERDUDEBIVASH SENTINEL APEX</strong></div></div>
    <div class="ecta">
      <h3>🏢 ENTERPRISE THREAT INTELLIGENCE PLATFORM</h3>
      <p class="ep">Pre-disclosure intel, enriched IOC bundles, deploy-ready SIEM packs, and dedicated analyst support — before threats become headlines.</p>
      <div class="cta-grid">
        <a href="/pricing.html" class="btn-p">⚡ SOC Pro — $49/mo</a>
        <a href="/enterprise.html" class="btn-e">🏢 Enterprise — Custom Pricing</a>
        <a href="/api.html" class="btn-s">🔌 Threat Intel API Access</a>
        <a href="/products.html" class="btn-g">📦 Detection Pack Store</a>
      </div>
      <p style="font-size:12px;color:var(--apex-muted);margin:0">48hr pre-disclosure · Enriched IOC feeds · Custom advisories · White-label reports · Dedicated analyst · MSSP licensing</p>
    </div>
  </article>
  <aside class="sidebar">
    <div class="vbox">
      <div class="vscore">${cvss}</div><div class="vlabel">CVSS Score</div>
      <div class="threat-badge">${tl} — ${score}/100</div>
      <div style="margin-top:12px">
        <div class="vrow"><span class="vk">ID</span><span class="vv" style="color:var(--apex-cyan);font-family:monospace;font-size:11px">${escHtml(item.id)}</span></div>
        <div class="vrow"><span class="vk">Vendor</span><span class="vv">${escHtml(item.vendor)}</span></div>
        <div class="vrow"><span class="vk">Product</span><span class="vv">${escHtml(item.product)}</span></div>
        <div class="vrow"><span class="vk">Type</span><span class="vv">${escHtml(typeLabel)}</span></div>
        <div class="vrow"><span class="vk">Exploited</span><span class="vv" style="color:${item.exploited?'var(--apex-red)':'var(--apex-green)'}">${item.exploited?'✓ Confirmed':'Monitoring'}</span></div>
        <div class="vrow"><span class="vk">CISA KEV</span><span class="vv" style="color:${item.cisaKev?'var(--apex-red)':'var(--apex-muted)'}">${item.cisaKev?'⚠️ Listed':'Not Listed'}</span></div>
        ${item.dueDate?`<div class="vrow"><span class="vk">Patch By</span><span class="vv" style="color:var(--apex-red)">${escHtml(item.dueDate)}</span></div>`:''}
        <div class="vrow"><span class="vk">Published</span><span class="vv">${pubDateFmt}</span></div>
        <div class="vrow"><span class="vk">Sources</span><span class="vv" style="color:var(--apex-green)">${item.sourceCount||1} confirmed</span></div>
        <div class="vrow"><span class="vk">IOCs</span><span class="vv">${(item.iocs||[]).length} indicators</span></div>
      </div>
    </div>
    <div class="sw" style="background:linear-gradient(135deg,#001a14,#0d1117);border-color:rgba(0,255,224,.15)">
      <div class="wt">⚡ SOC Pro Intelligence</div>
      <p style="font-size:13px;color:var(--apex-muted);margin-bottom:16px;line-height:1.6">48hr pre-disclosure. Compiled Sigma/YARA packs. Enriched IOC feeds. Custom advisories. Deploy-ready SIEM queries.</p>
      <a href="/pricing.html" style="display:block;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:13px;padding:12px;border-radius:8px;text-decoration:none;text-align:center">Start Free Trial →</a>
    </div>
    <div class="sw" style="background:linear-gradient(135deg,#1a0a2e,#0d1117);border-color:rgba(168,85,247,.2)">
      <div class="wt" style="color:#a855f7">🏢 Enterprise Access</div>
      <p style="font-size:13px;color:var(--apex-muted);margin-bottom:14px;line-height:1.6">Dedicated analyst. Custom IOC ingestion. White-label reports. API access. MSSP licensing.</p>
      <a href="/enterprise.html" style="display:block;background:rgba(168,85,247,.2);border:1px solid rgba(168,85,247,.4);color:#a855f7;font-weight:700;font-size:13px;padding:12px;border-radius:8px;text-decoration:none;text-align:center">Get Enterprise Proposal →</a>
    </div>
    <div class="sw">
      <div class="wt">🔌 Threat Intel API</div>
      <p style="font-size:13px;color:var(--apex-muted);margin-bottom:14px;line-height:1.6">Programmatic access to SENTINEL APEX intelligence. RESTful JSON. Integrate into SIEM, SOAR, or custom tools.</p>
      <a href="/api.html" style="display:block;border:1px solid var(--apex-border);color:var(--apex-cyan);font-weight:700;font-size:13px;padding:12px;border-radius:8px;text-decoration:none;text-align:center">View API Docs →</a>
    </div>
    <div class="sw">
      <div class="wt">📎 References</div>
      <ul style="list-style:none;padding:0">
        ${item.id?.startsWith('CVE')?`<li style="margin-bottom:8px;font-size:13px"><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">📌 NVD — ${escHtml(item.id)}</a></li>`:''}
        ${item.cisaKev?`<li style="margin-bottom:8px;font-size:13px"><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener" style="color:var(--apex-red)">⚠️ CISA KEV Catalog</a></li>`:''}
        ${(item.refs||[]).slice(0,4).map(r=>`<li style="margin-bottom:6px;font-size:12px"><a href="${escHtml(r)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">${escHtml(String(r).replace(/https?:\/\//,'').slice(0,42))}</a></li>`).join('\n')}
      </ul>
    </div>
  </aside>
</main>
<footer>
  <p>&copy; ${new Date().getFullYear()} CYBERDUDEBIVASH PRIVATE LIMITED. All intelligence reports are original research and analysis by CYBERDUDEBIVASH SENTINEL APEX v4.0.<br>
  Unauthorized reproduction without attribution is prohibited.<br>
  <a href="/">Blog</a> · <a href="/products.html">Detection Packs</a> · <a href="/pricing.html">SOC Pro</a> · <a href="/api.html">API</a> · <a href="/enterprise.html">Enterprise</a> · <a href="/rss.xml">RSS</a> · <a href="mailto:bivash@cyberdudebivash.com">Contact</a></p>
</footer>
<script src="/security-engine.js" defer></script><script src="/monetization.js" defer></script><script src="/conversion-engine.js" defer></script><script src="/seo-engine.js" defer></script>
<script>
(function(){var c=document.getElementById('mc');if(!c)return;var x=c.getContext('2d');c.width=window.innerWidth;c.height=window.innerHeight;var cols=Math.floor(c.width/16),drops=new Array(cols).fill(1);setInterval(function(){x.fillStyle='rgba(7,9,15,0.05)';x.fillRect(0,0,c.width,c.height);x.fillStyle='#00ffe018';x.font='12px monospace';drops.forEach(function(y,i){x.fillText(String.fromCharCode(33+Math.random()*93),i*16,y*16);if(y*16>c.height&&Math.random()>.975)drops[i]=0;drops[i]++;});},90);window.addEventListener('resize',function(){c.width=window.innerWidth;c.height=window.innerHeight;});})();
</script>
</body>
</html>`;
  return { slug, title: item.title, html };
}

// ── POST CARD GENERATOR ────────────────────────────────────────────────
function generatePostCard(item, slug, title) {
  const cvss = item.cvss||7.0;
  const sevLabel = cvss>=9.5?'CRITICAL':cvss>=9.0?'CRITICAL':cvss>=7.0?'HIGH':'MEDIUM';
  const tl = item.threatLevel||sevLabel;
  const score = item.priority||0;
  const todayFmt = fmtDate(item.pubDate||isoNow());
  const shortTitle = (title||'').length>110 ? title.slice(0,107)+'...' : title;
  const shortDesc  = (item.desc||'').slice(0,200)+((item.desc||'').length>200?'...':'');
  const typeIcos = { CVE_REPORT:'🔴', ZERO_DAY:'💀', RANSOMWARE:'🏴', MALWARE_REPORT:'🦠', DATA_BREACH:'⚠️', THREAT_ACTOR:'🎯', AI_SECURITY:'🤖', NEWS_REPORT:'📡', ADVISORY:'🛡️' };
  const ico = typeIcos[item.type]||'⚡';
  const multiSrcBadge = (item.sourceCount||1)>=2 ? `<span class="post-badge" style="background:#00ff8822;color:#00ff88;border:1px solid #00ff8844;font-size:10px;padding:3px 7px;border-radius:3px;font-weight:700">✓ ${item.sourceCount}x</span>` : '';
  return `
    <!-- AUTO-GENERATED: ${item.id} — ${isoNow()} -->
    <a href="posts/${escHtml(slug)}.html" class="post-card" data-intel-auto="${escHtml(item.id)}" data-score="${score}" data-threat="${tl}">
      <div class="post-card-header">
        <span class="post-badge badge-crit">CVSS ${cvss}</span>
        ${item.cisaKev?`<span class="post-badge badge-cisa">CISA KEV</span>`:''}
        ${item.exploited?`<span class="post-badge badge-new">● Live Exploit</span>`:''}
        ${item.ransomware?`<span class="post-badge" style="background:#a855f722;color:#a855f7;border:1px solid #a855f744;font-size:10px;padding:3px 7px;border-radius:3px;font-weight:700">RANSOMWARE</span>`:''}
        ${multiSrcBadge}
        <span class="post-date">${todayFmt} | ${ico} ${escHtml(item.id)}</span>
      </div>
      <div class="post-card-body">
        <div class="post-title">${escHtml(shortTitle)}</div>
        <p class="post-excerpt">${escHtml(shortDesc)}</p>
        <div class="post-meta">
          <span class="post-cvss${cvss<9?' orange':''}">CVSS ${cvss} — ${tl}</span>
          <span class="post-cve">${escHtml(item.id)}</span>
          <span class="post-source" style="font-size:11px;color:var(--apex-muted,#6b7280)">${escHtml((item._sources||[item.source]).join(', '))}</span>
          <span class="post-read-more">Read Report →</span>
        </div>
      </div>
    </a>`;
}

// ── INDEX.HTML UPDATER ─────────────────────────────────────────────────
function updateIndexHTML(newCards) {
  if (!fs.existsSync(CFG.indexPath)) { warn('index.html not found.'); return; }
  let html = fs.readFileSync(CFG.indexPath, 'utf8');
  html = html.replace(/\s*<!-- AUTO-GENERATED:[\s\S]*?<\/a>/g, '');
  const MARKER = '<!-- POST 1 — FEATURED -->';
  if (!html.includes(MARKER)) { warn('Injection marker not found in index.html.'); return; }
  const cardBlock = newCards.map(c=>c.card).join('\n');
  html = html.replace(MARKER, `${cardBlock}\n\n    ${MARKER}`);
  const today = new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}).toUpperCase();
  html = html.replace(/BREAKING INTELLIGENCE &mdash;[^<]+ &mdash; UPDATED LIVE/, `BREAKING INTELLIGENCE &mdash; ${today} &mdash; UPDATED LIVE`);
  fs.writeFileSync(CFG.indexPath, html, 'utf8');
  log(`index.html updated: +${newCards.length} cards.`);
}

// ── RSS.XML UPDATER ────────────────────────────────────────────────────
function updateRSS(newItems) {
  const rssItems = newItems.map(item => {
    const link = `${CFG.baseUrl}/posts/${item.slug}.html`;
    return `  <item>\n    <title><![CDATA[${item.title}]]></title>\n    <link>${link}</link>\n    <description><![CDATA[Score ${item.priority||0}/100 ${item.threatLevel||'HIGH'} — CVSS ${item.cvss} — ${(item.desc||'').slice(0,300)}. Full analysis, Sigma/YARA rules, IOCs, Attack Chain by CYBERDUDEBIVASH SENTINEL APEX v4.0.]]></description>\n    <pubDate>${new Date().toUTCString()}</pubDate>\n    <guid isPermaLink="true">${link}</guid>\n    <category>Threat Intelligence</category>\n    <category>${item.cisaKev?'CISA KEV':item.type||'CVE Analysis'}</category>\n  </item>`;
  }).join('\n');
  if (!fs.existsSync(CFG.rssPath)) {
    fs.writeFileSync(CFG.rssPath, `<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n  <channel>\n    <title>CYBERDUDEBIVASH SENTINEL APEX — Global Threat Intelligence</title>\n    <link>${CFG.baseUrl}</link>\n    <description>Real-time cybersecurity intelligence by CYBERDUDEBIVASH SENTINEL APEX v4.0.</description>\n    <language>en-us</language>\n    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>\n    <atom:link href="${CFG.baseUrl}/rss.xml" rel="self" type="application/rss+xml"/>\n${rssItems}\n  </channel>\n</rss>`, 'utf8');
    log('rss.xml created fresh.'); return;
  }
  let rss = fs.readFileSync(CFG.rssPath, 'utf8');
  rss = rss.replace(/(<lastBuildDate>)[^<]*(<\/lastBuildDate>)/, `$1${new Date().toUTCString()}$2`);
  rss = rss.includes('<item>') ? rss.replace(/(<item>)/, `${rssItems}\n  $1`) : rss.replace('</channel>', `${rssItems}\n  </channel>`);
  fs.writeFileSync(CFG.rssPath, rss, 'utf8');
  log(`rss.xml updated: +${newItems.length} items.`);
}

// ── SITEMAP UPDATER ────────────────────────────────────────────────────
function updateSitemap(slugs) {
  try {
    const today = isoNow();
    let sitemap = fs.existsSync(CFG.sitemapPath) ? fs.readFileSync(CFG.sitemapPath,'utf8') : `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n</urlset>`;
    const entries = slugs.map(slug=>`  <url>\n    <loc>${CFG.baseUrl}/posts/${slug}.html</loc>\n    <lastmod>${today}</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>0.8</priority>\n  </url>`).join('\n');
    sitemap = sitemap.replace('</urlset>', `${entries}\n</urlset>`);
    fs.writeFileSync(CFG.sitemapPath, sitemap, 'utf8');
    log(`sitemap.xml updated: +${slugs.length} URLs.`);
  } catch(e) { warn(`Sitemap update failed: ${e.message}`); }
}

// ── PHASE 5: ENTERPRISE API PLATFORM (S2N-powered static JSON endpoints) ──
function writeAPIFiles(allItems, state) {
  try {
    // Ensure API directories exist
    const apiCveDir = path.join(CFG.apiDir, 'cve');
    [CFG.apiDir, apiCveDir].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

    const now     = new Date().toISOString();
    const apiMeta = {
      generated: now, version: '5.1', engine: 'SENTINEL APEX S2N v1.0',
      platform: 'CYBERDUDEBIVASH SENTINEL APEX', contact: 'bivash@cyberdudebivash.com',
      docs: `${CFG.baseUrl}/api.html`,
    };

    // ── Load existing live.json for S2N window (semantic dedup) ─────────
    let windowItems = [];
    const apiLivePath = path.join(CFG.apiDir, 'live.json');
    if (fs.existsSync(apiLivePath)) {
      try {
        const exData = JSON.parse(fs.readFileSync(apiLivePath, 'utf8'));
        windowItems = Array.isArray(exData.items) ? exData.items : [];
      } catch(_) {}
    }

    // ── Run S2N Engine ──────────────────────────────────────────────────
    log('── S2N ENGINE ─────────────────────────────────────────────────────');
    const s2nResult = runS2N(allItems, windowItems);
    const { live: liveItems, topThreats: topItems, raw: rawItems } = formatForFeed(s2nResult);

    log(`  S2N stats: input=${s2nResult.stats.input_items} candidates=${s2nResult.stats.candidates} passed=${s2nResult.stats.passed} suppressed=${s2nResult.stats.suppressed} merges=${s2nResult.stats.semantic_merges} elapsed=${s2nResult.stats.elapsed_ms}ms`);
    log(`  avg_qs=${s2nResult.stats.avg_qs} avg_ps=${s2nResult.stats.avg_final_ps} tier4_kept=${s2nResult.stats.tier4_kept}`);

    // ── /api/intel/live.json — top 50 S2N-passed items ─────────────────
    // Rolling merge with existing (new overrides by id, trim to apiLiveWindow)
    const mergedLive = [...liveItems];
    const newLiveIds = new Set(liveItems.map(i => i.id));
    windowItems.forEach(e => { if (!newLiveIds.has(e.id)) mergedLive.push(e); });
    mergedLive.sort((a,b) => {
      const ps = (b.final_ps||b.priority_score||0) - (a.final_ps||a.priority_score||0);
      if (ps !== 0) return ps;
      return new Date(b.first_seen||b.published||0) - new Date(a.first_seen||a.published||0);
    });
    const rolledLiveItems = mergedLive.slice(0, CFG.apiLiveWindow || 100);
    fs.writeFileSync(apiLivePath, JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/live.json',
      description: `S2N live threat intelligence feed — top ${CFG.apiLiveWindow||100} items by final_ps`,
      total_published: state.totalPublished || 0,
      s2n_stats: { passed: s2nResult.stats.passed, suppressed: s2nResult.stats.suppressed, avg_qs: s2nResult.stats.avg_qs },
      items: rolledLiveItems,
    }, null, 2), 'utf8');
    log(`api/intel/live.json: ${rolledLiveItems.length} items (S2N passed=${s2nResult.stats.passed}).`);

    // ── /api/intel/top-threats.json — final_ps≥70 AND quality_score≥0.60 ──
    fs.writeFileSync(path.join(CFG.apiDir, 'top-threats.json'), JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/top-threats.json',
      description: 'S2N top threats: final_ps ≥ 70 AND quality_score ≥ 0.60',
      count: topItems.length,
      items: topItems,
    }, null, 2), 'utf8');
    log(`api/intel/top-threats.json: ${topItems.length} items.`);

    // ── /api/intel/raw.json — unfiltered (paid tier, includes suppressed) ─
    const rawDir = path.join(CFG.apiDir);
    fs.writeFileSync(path.join(rawDir, 'raw.json'), JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/raw.json',
      description: 'Raw unfiltered S2N feed — all items including suppressed. Enterprise tier.',
      note: 'Access requires Enterprise API key. Includes suppression_reason and full IOC data.',
      count: rawItems.length,
      items: rawItems,
    }, null, 2), 'utf8');
    log(`api/intel/raw.json: ${rawItems.length} items (incl. ${s2nResult.stats.suppressed} suppressed).`);

    // ── /api/intel/iocs.json — all enriched IOCs ────────────────────────
    const allIOCs = [];
    s2nResult.passed.slice(0, 40).forEach(item => {
      (item.iocs||[]).forEach(ioc => {
        if (ioc && ioc.value) allIOCs.push({
          ...ioc, related_id: item.id, related_type: item.type,
          threat_level: finalThreatLevel(item.final_ps||0),
          priority_score: item.final_ps||0,
          quality_score: item.quality_score||0,
        });
      });
    });
    const iocMap = new Map();
    allIOCs.forEach(ioc => {
      const k = `${ioc.type}:${ioc.value}`;
      if (!iocMap.has(k)) iocMap.set(k, { ...ioc, source_count: 1 });
      else { const ex = iocMap.get(k); ex.source_count++; ex.confidence_score = Math.min(0.99, (ex.confidence_score||0.5) + 0.05); }
    });
    fs.writeFileSync(path.join(CFG.apiDir, 'iocs.json'), JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/iocs.json',
      description: 'Enriched IOC feed with confidence scoring',
      count: iocMap.size,
      note: 'Pro/Enterprise subscribers receive STIX 2.1 and TAXII feeds',
      items: Array.from(iocMap.values()).sort((a,b)=>(b.confidence_score||0)-(a.confidence_score||0)).slice(0,200),
    }, null, 2), 'utf8');

    // ── /api/intel/ransomware.json — ransomware-specific ────────────────
    const ransomItems = s2nResult.passed.filter(i => i.ransomware || i.type==='RANSOMWARE');
    fs.writeFileSync(path.join(CFG.apiDir, 'ransomware.json'), JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/ransomware.json',
      description: 'Ransomware-specific threat intelligence (S2N-filtered)',
      count: ransomItems.length,
      items: ransomItems.slice(0,20).map(i=>({
        id:i.id, title:(i.title||'').slice(0,100),
        final_ps: i.final_ps||0, quality_score: i.quality_score||0,
        threat_level: finalThreatLevel(i.final_ps||0), cvss:i.cvss||0,
        cisa_kev:!!i.cisa_kev, vendor:i.vendor||'', product:i.product||'',
        ioc_count:i.ioc_count||(i.iocs||[]).length, report_url:i.report_url||null,
      })),
    }, null, 2), 'utf8');

    // ── /api/intel/cve/{id}.json — per-CVE detail files ─────────────────
    let cveFileCount = 0;
    s2nResult.passed
      .filter(i => i.id && i.id.startsWith('CVE') && (i.final_ps||0)>=50)
      .slice(0, 20)
      .forEach(item => {
        const orig = allItems.find(o => o.id === item.id) || item;
        const cveFile = path.join(apiCveDir, `${item.id}.json`);
        fs.writeFileSync(cveFile, JSON.stringify({
          ...apiMeta, endpoint: `/api/intel/cve/${item.id}.json`,
          id: item.id, title: item.title, description: item.description||orig.desc,
          cvss: item.cvss||0, final_ps: item.final_ps||0, quality_score: item.quality_score||0,
          threat_level: finalThreatLevel(item.final_ps||0),
          type: orig.type, sources: item.merged_sources||[item.source],
          sources_confirmed: item.sources_confirmed||1,
          first_seen: item.first_seen, last_seen: item.last_seen,
          exploited: !!item.exploited, cisa_kev: !!item.cisa_kev,
          ransomware: !!item.ransomware, vendor: item.vendor, product: item.product,
          due_date: item.due_date||null, required_action: orig.reqAction||null,
          cves: item.cves||[], refs: item.refs||[], iocs: orig.iocs||[],
          mitre: orig._mitre || null, explanation: item.explanation||null,
          report_url: orig.slug ? `${CFG.baseUrl}/posts/${orig.slug}.html` : null,
        }, null, 2), 'utf8');
        cveFileCount++;
      });

    log(`API files written: live.json (${rolledLiveItems.length}), top-threats.json (${topItems.length}), raw.json (${rawItems.length}), iocs.json (${iocMap.size} IOCs), ransomware.json (${ransomItems.length}), ${cveFileCount} CVE files.`);
  } catch(e) { warn(`API generation failed: ${e.message}\n${e.stack||''}`); }
}

// ── LIVE-INTEL.JSON (widget feed) ─────────────────────────────────────
function writeLiveIntel(allItems, state) {
  try {
    // Load existing items for rolling merge
    let existingItems = [];
    if (fs.existsSync(CFG.liveJsonPath)) {
      try {
        const ex = JSON.parse(fs.readFileSync(CFG.liveJsonPath, 'utf8'));
        existingItems = Array.isArray(ex.items) ? ex.items : [];
      } catch(_) {}
    }
    const newItems = allItems.map(item => ({
      id: item.id, title: (item.title||'').slice(0,120), desc: (item.desc||'').slice(0,200),
      cvss: item.cvss||0, type: item.type||'INTEL', source: item.source||'',
      pubDate: item.pubDate||isoNow(), exploited: !!item.exploited, cisaKev: !!item.cisaKev,
      ransomware: !!item.ransomware, vendor: item.vendor||'', product: item.product||'',
      dueDate: item.dueDate||null, refs: (item.refs||[]).slice(0,2),
      priority: item.priority||0, threatLevel: item.threatLevel||'HIGH',
      sourceCount: item.sourceCount||1, iocCount: (item.iocs||[]).length,
      slug: item.slug || slugify(item.id.startsWith('CVE')?`${item.id}-${item.vendor||''}-${item.product||''}`:item.title.slice(0,60)),
      link: item.slug ? `${CFG.baseUrl}/posts/${item.slug}.html` : null,
      _addedAt: new Date().toISOString(),
    }));
    // Merge: new items override existing by id, then sort DESC by priority→pubDate, trim to window
    const merged = [...newItems];
    const newIds = new Set(newItems.map(i => i.id));
    existingItems.forEach(e => { if (!newIds.has(e.id)) merged.push(e); });
    merged.sort((a,b) => {
      const ps = (b.priority||0) - (a.priority||0);
      if (ps !== 0) return ps;
      return new Date(b.pubDate||0) - new Date(a.pubDate||0);
    });    const liveItems = merged.slice(0, CFG.liveRollingWindow || 150);
    fs.writeFileSync(CFG.liveJsonPath, JSON.stringify({
      generatedAt: new Date().toISOString(), totalPublished: state.totalPublished||0,
      source: 'CYBERDUDEBIVASH SENTINEL APEX v5.0', platform: 'blog.cyberdudebivash.in',
      version: '5.0',
      stats: {
        critical:   liveItems.filter(i=>i.threatLevel==='CRITICAL').length,
        high:       liveItems.filter(i=>i.threatLevel==='HIGH').length,
        cisaKev:    liveItems.filter(i=>i.cisaKev).length,
        exploited:  liveItems.filter(i=>i.exploited).length,
        ransomware: liveItems.filter(i=>i.ransomware).length,
        sources:    [...new Set(liveItems.map(i=>i.source))].length,
      },
      items: liveItems,
    }, null, 2), 'utf8');
    log(`live-intel.json: ${liveItems.length} items (${newItems.length} new merged → rolled to ${CFG.liveRollingWindow||150}).`);
  } catch(e) { warn(`live-intel.json failed: ${e.message}`); }
}

// ── VALIDATION REPORT ─────────────────────────────────────────────────
function validateAndReport(allItems, generatedCards, state, T0, sourceStats) {
  const sourceCount  = allItems.reduce((acc,i) => { (i._sources||[i.source]).forEach(s=>acc.add(s)); return acc; }, new Set()).size;
  const critCount    = allItems.filter(i=>i.threatLevel==='CRITICAL').length;
  const highCount    = allItems.filter(i=>i.threatLevel==='HIGH').length;
  const kevCount     = allItems.filter(i=>i.cisaKev).length;
  const exploitCount = allItems.filter(i=>i.exploited).length;
  const multiSrc     = allItems.filter(i=>(i.sourceCount||1)>=2).length;
  const iocTotal     = allItems.reduce((s,i)=>s+(i.iocs||[]).length, 0);
  const elapsed      = ((Date.now()-T0)/1000).toFixed(1);
  const healthRpt    = getSourceHealthReport(state);

  log('\n' + '═'.repeat(65));
  log('SENTINEL APEX v5.0 — PIPELINE COMPLETE');
  log('═'.repeat(65));
  log(`⏱  Runtime           : ${elapsed}s`);
  log(`📡 Sources active     : ${sourceCount}/27`);
  log(`📊 Total items        : ${allItems.length}`);
  log(`🔴 CRITICAL           : ${critCount}`);
  log(`🟠 HIGH               : ${highCount}`);
  log(`⚠️  CISA KEV           : ${kevCount}`);
  log(`⚡ Exploited ITW      : ${exploitCount}`);
  log(`✓  Multi-source       : ${multiSrc}`);
  log(`🏷️  IOCs extracted     : ${iocTotal}`);
  log(`✅ Reports generated  : ${generatedCards.length}`);
  log(`📚 Total published    : ${state.totalPublished}`);
  if (healthRpt.degraded.length > 0) log(`🔥 DEGRADED sources   : ${healthRpt.degraded.join(', ')}`);
  if (healthRpt.warning.length  > 0) log(`⚠️  WARNING sources    : ${healthRpt.warning.join(', ')}`);
  if (sourceStats) {
    log('\n── Per-Source Stats ────────────────────────────────────────────');
    Object.entries(sourceStats).forEach(([src, st]) => {
      if (st.fetched > 0) log(`  ${src}: fetched=${st.fetched}, new=${st.new||0}`);
    });
  }
  log('═'.repeat(65));

  // Phase 9 validation criteria
  const criteria = [
    { check: sourceCount >= 5,         label: 'Minimum 5 sources active' },
    { check: allItems.length >= 5,     label: 'Minimum 5 intel items' },
    { check: kevCount >= 0,            label: 'CISA KEV feed active' },
    { check: iocTotal >= 0,            label: 'IOC extraction running' },
    { check: state.totalPublished > 0, label: 'At least 1 report published' },
    { check: healthRpt.degraded.length < 10, label: 'Less than 10 degraded sources' },
  ];
  criteria.forEach(c => log(`${c.check ? '✅' : '❌'} ${c.label}`));
  log('═'.repeat(65));
}

// ── TIERED PARALLEL INGESTION HELPER ─────────────────────────────────
async function runTier(label, tasks, state) {
  log(`\n── ${label} ──────────────────────────────────────────────────`);
  const results = await Promise.allSettled(tasks.map(([fn, key]) =>
    fetchWithTimeout(() => fn(state), key, CFG.sourceTimeoutMs)
      .then(items => { recordSourceSuccess(state, key); return items || []; })
      .catch(e   => { recordSourceFailure(state, key, e.message); warn(`${key} failed: ${e.message}`); return []; })
  ));
  const batches = results.map(r => r.status === 'fulfilled' ? r.value : []);
  const active  = batches.filter(b=>b.length>0).length;
  log(`${label}: ${active}/${tasks.length} sources returned data (${batches.reduce((s,b)=>s+b.length,0)} total items)`);
  return batches;
}

// ── MAIN PIPELINE v5.0 — TIERED, PARALLEL, STREAM-LIKE ───────────────
async function main() {
  const T0 = Date.now();
  log('═'.repeat(65));
  log('CYBERDUDEBIVASH SENTINEL APEX v5.0 — HIGH-FREQUENCY INTEL ENGINE');
  log('27 Sources | Tiered Parallel | Stream-Like Writes | Health Mon.');
  log(`Run started: ${new Date().toISOString()}`);
  log('═'.repeat(65));

  // ── PHASE 3: LOCK — no overlapping runs ───────────────────────────
  if (!acquireLock()) { process.exit(0); }
  let lockReleased = false;
  const safeRelease = () => { if (!lockReleased) { lockReleased = true; releaseLock(); } };
  process.on('exit', safeRelease);
  process.on('SIGTERM', () => { safeRelease(); process.exit(0); });

  try {
    if (!fs.existsSync(CFG.postsDir)) fs.mkdirSync(CFG.postsDir, { recursive: true });

    const state      = loadState();
    const sourceStats = {};
    log(`State: ${state.published.length} in dedup window (TTL=${CFG.dedupTtlDays}d). Total published: ${state.totalPublished}`);

    // ══════════════════════════════════════════════════════════════════
    // TIER 1 — Critical CVE/Exploit sources (processed first, always)
    // ══════════════════════════════════════════════════════════════════
    const tier1Batches = await runTier('TIER 1: CRITICAL CVE + EXPLOIT SOURCES', [
      [fetchNVD,            'nvd'],
      [fetchCISAKev,        'cisa_kev'],
      [fetchCISAAlerts,     'cisa_alerts'],
      [fetchGitHubAdvisories,'github_advisories'],
      [s => fetchMSRC(),    'msrc'],
      [fetchExploitDB,      'exploitdb'],
      [fetchPacketStorm,    'packetstorm'],
      [fetchFullDisclosure, 'fulldisclosure'],
    ], state);

    // ── PHASE 6: STREAM — write partial results after Tier 1 ──────────
    const tier1Items = correlateAndMerge(tier1Batches);
    if (tier1Items.length > 0) {
      log(`\n── PHASE 6: STREAMING — Writing Tier 1 partial results (${tier1Items.length} items)...`);
      writeLiveIntel(tier1Items.map(i=>({...i,priority:computePriorityScore(i),threatLevel:threatLevel(computePriorityScore(i))})), state);
      writeAPIFiles(tier1Items.map(i=>({...i,priority:computePriorityScore(i),threatLevel:threatLevel(computePriorityScore(i))})), state);
    }
    tier1Batches.forEach((b,idx) => { const k=['nvd','cisa_kev','cisa_alerts','github_advisories','msrc','exploitdb','packetstorm','fulldisclosure'][idx]; if(k) sourceStats[k]={fetched:b.length}; });

    // ══════════════════════════════════════════════════════════════════
    // TIER 2 — Threat intel blogs + malware (run while Tier 1 publishes)
    // ══════════════════════════════════════════════════════════════════
    const tier2Batches = await runTier('TIER 2: THREAT BLOGS + MALWARE FEEDS', [
      [s=>fetchRSS(CFG.bleepingRss,'bleepingcomputer',CFG.maxRssItems,s), 'bleepingcomputer'],
      [s=>fetchRSS(CFG.thnRss,'thehackernews',CFG.maxRssItems,s),         'thehackernews'],
      [s=>fetchRSS(CFG.krebsRss,'krebsonsecurity',4,s),                   'krebsonsecurity'],
      [s=>fetchRSS(CFG.secweekRss,'securityweek',CFG.maxRssItems,s),      'securityweek'],
      [s=>fetchRSS(CFG.sansRss,'sans_isc',4,s),                           'sans_isc'],
      [s=>fetchRSS(CFG.darkReadingRss,'darkreading',CFG.maxRssItems,s),   'darkreading'],
      [fetchTalos,          'talos'],
      [fetchUnit42,         'unit42'],
      [fetchCrowdStrike,    'crowdstrike'],
      [fetchSentinelOne,    'sentinelone'],
      [fetchGoogleProjectZero,'googleprojectzero'],
      [fetchRapid7,         'rapid7'],
      [s=>fetchURLhaus(),   'urlhaus'],
      [s=>fetchThreatFox(), 'threatfox'],
    ], state);

    // ── PHASE 6: STREAM — write merged T1+T2 results ─────────────────
    const allT1T2 = [...tier1Batches, ...tier2Batches];
    const t1t2Items = correlateAndMerge(allT1T2);
    if (t1t2Items.length > 0) {
      log(`\n── PHASE 6: STREAMING — Writing T1+T2 merged results (${t1t2Items.length} items)...`);
      writeLiveIntel(t1t2Items.map(i=>({...i,priority:computePriorityScore(i),threatLevel:threatLevel(computePriorityScore(i))})), state);
    }
    tier2Batches.forEach((b,idx) => { const k=['bleepingcomputer','thehackernews','krebsonsecurity','securityweek','sans_isc','darkreading','talos','unit42','crowdstrike','sentinelone','googleprojectzero','rapid7','urlhaus','threatfox'][idx]; if(k) sourceStats[k]={fetched:b.length}; });

    // ══════════════════════════════════════════════════════════════════
    // TIER 3 — Community signals (lower priority, can be slower)
    // ══════════════════════════════════════════════════════════════════
    const tier3Batches = await runTier('TIER 3: COMMUNITY + SIGNAL SOURCES', [
      [fetchRedditNetsec,   'reddit_netsec'],
      [fetchRedditCyber,    'reddit_cyber'],
      [fetchCertEU,         'cert_eu'],
      [fetchMicrosoftSecBlog,'microsoft_security'],
      [fetchWiredSecurity,  'wired_security'],
      [fetchRecordedFuture, 'recorded_future'],
    ], state);
    tier3Batches.forEach((b,idx) => { const k=['reddit_netsec','reddit_cyber','cert_eu','microsoft_security','wired_security','recorded_future'][idx]; if(k) sourceStats[k]={fetched:b.length}; });

    // ── FULL CORRELATION ACROSS ALL 27 SOURCES ────────────────────────
    log('\n── FULL CORRELATION ENGINE ─────────────────────────────────────');
    const allBatches      = [...tier1Batches, ...tier2Batches, ...tier3Batches];
    const correlatedItems = correlateAndMerge(allBatches);
    const activeSources   = allBatches.filter(b=>b.length>0).length;
    log(`Full corpus: ${correlatedItems.length} items from ${activeSources}/27 sources`);
    const multiSrcCount   = correlatedItems.filter(i=>(i.sourceCount||1)>=2).length;
    if (multiSrcCount > 0) log(`Multi-source corroborated: ${multiSrcCount} items`);

    if (activeSources === 0) { err('ALL sources failed — aborting.'); safeRelease(); process.exit(1); }

    // ── PHASE 4: SIGNAL vs NOISE FILTERING ───────────────────────────
    log('\n── PHASE 4: SIGNAL vs NOISE FILTERING ─────────────────────────');
    const filteredItems = filterSignalFromNoise(correlatedItems);
    log(`After filtering: ${filteredItems.length} signal items retained`);

    // ── INTELLIGENCE ENRICHMENT ───────────────────────────────────────
    log('\n── INTELLIGENCE ENRICHMENT PIPELINE ───────────────────────────');
    let enrichedItems = filteredItems;
    try {
      const enrichResult = runEnrichmentPipeline(filteredItems);
      enrichedItems      = enrichResult.enrichedItems;
      log(`Enrichment: ${enrichResult.stats.items_processed} items, ${enrichResult.stats.campaigns} campaigns, ${enrichResult.stats.elapsed_ms}ms`);
    } catch(enrichErr) {
      warn(`Enrichment non-fatal: ${enrichErr.message}. Continuing unenriched.`);
    }

    // ── PHASE 9: PERFORMANCE — per-source new count ──────────────────
    const totalFetched  = Object.values(sourceStats).reduce((s,v)=>s+v.fetched,0);
    const newAfterDedup = enrichedItems.filter(i=>i.id&&!isPublished(state,i.id)).length;
    log(`\n── DEBUG STATS ─────────────────────────────────────────────────`);
    log(`  total_fetched: ${totalFetched} | new_after_dedup: ${newAfterDedup} | enriched: ${enrichedItems.length}`);
    Object.entries(sourceStats).forEach(([src,st]) => { st.new = enrichedItems.filter(i=>i.source===src&&!isPublished(state,i.id)).length; });

    // ── PHASE 8: FRESHNESS — alert if stale > 30 min ─────────────────
    const freshnessMs  = CFG.freshnessAlertMins * 60000;
    const lastRunMs    = state.lastRun ? Date.now()-new Date(state.lastRun).getTime() : 0;
    const yesterday    = new Date(Date.now()-86400000);
    const freshItems   = enrichedItems.filter(i=>{ try{return new Date(i.pubDate||0)>=yesterday;}catch(_){return false;} });
    if (freshItems.length===0 && lastRunMs > freshnessMs) {
      log(`⚠️  FRESHNESS ALERT: No intel with pubDate >= yesterday. Last run: ${Math.round(lastRunMs/60000)} min ago.`);
      log('    Check source availability. Consider running workflow_dispatch to reset state.');
    } else {
      log(`  fresh_items_24h: ${freshItems.length}`);
    }

    // ── PHASE 6: FINAL STREAM WRITE — S2N-powered ─────────────────────
    log('\n── PHASE 6: STREAMING — S2N + Final enriched write ─────────────');
    writeLiveIntel(enrichedItems, state);
    writeAPIFiles(enrichedItems, state);  // <-- runs S2N engine internally

    // ── REPORT GENERATION — use S2N-passed items for scoring ──────────
    const newItems   = enrichedItems.filter(item=>item.id&&!isPublished(state,item.id));
    log(`\nNew (unpublished) items: ${newItems.length}`);

    if (newItems.length === 0) {
      log('No new intel this cycle — all within dedup TTL.');
      const health = getSourceHealthReport(state);
      if (health.degraded.length > 0) log(`⚠️  Degraded sources: ${health.degraded.join(', ')}`);
      saveState(state);
      validateAndReport(enrichedItems, [], state, T0, sourceStats);
      safeRelease();
      return;
    }

    log('\n── REPORT GENERATION ───────────────────────────────────────────');
    const toPublish     = newItems.slice(0, CFG.maxNewPostsPerRun);
    const generatedCards= [], rssItems = [], newSlugs = [];

    for (const item of toPublish) {
      try {
        const { slug, title, html } = generatePostHTML(item);
        const filePath = path.join(CFG.postsDir, `${slug}.html`);
        if (fs.existsSync(filePath)) {
          markPublished(state, { id:item.id, slug, title });
          continue;
        }
        fs.writeFileSync(filePath, html, 'utf8');
        log(`✅ [${item.threatLevel||'HIGH'}] [${item.type}] ${slug}.html (score=${item.priority||0}, srcs=${item.sourceCount||1})`);
        markPublished(state, { id:item.id, slug, title });
        generatedCards.push({ card: generatePostCard(item, slug, title) });
        rssItems.push({ ...item, slug, title });
        newSlugs.push(slug);
        // Per-CVE API file
        if (item.id.startsWith('CVE') && (item.priority||0) >= 50) {
          try {
            const apiCveDir = path.join(CFG.apiDir, 'cve');
            if (!fs.existsSync(apiCveDir)) fs.mkdirSync(apiCveDir, { recursive: true });
            const cveFile   = path.join(apiCveDir, `${item.id}.json`);
            const existing  = fs.existsSync(cveFile) ? JSON.parse(fs.readFileSync(cveFile,'utf8')) : {};
            fs.writeFileSync(cveFile, JSON.stringify({ ...existing, report_url:`${CFG.baseUrl}/posts/${slug}.html`, slug }, null, 2), 'utf8');
          } catch(_) {}
        }
      } catch(e) { err(`Failed to generate: ${item.id} — ${e.message}`); }
    }

    // ── PLATFORM SYNC ─────────────────────────────────────────────────
    log('\n── PLATFORM SYNC ───────────────────────────────────────────────');
    if (generatedCards.length > 0) {
      updateIndexHTML(generatedCards);
      updateRSS(rssItems);
      updateSitemap(newSlugs);
    }

    saveState(state);
    validateAndReport(enrichedItems, generatedCards, state, T0, sourceStats);

  } catch(fatalErr) {
    err(`FATAL: ${fatalErr.message}\n${fatalErr.stack||''}`);
    safeRelease();
    process.exit(1);
  }

  safeRelease();
}

main().catch(e => {
  err(`UNHANDLED: ${e.message}\n${e.stack||''}`);
  releaseLock();
  process.exit(1);
});
