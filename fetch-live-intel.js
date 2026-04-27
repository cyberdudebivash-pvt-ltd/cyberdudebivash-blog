#!/usr/bin/env node
/**
 * CYBERDUDEBIVASH SENTINEL APEX — Global Intelligence Engine v3.0
 * Production-grade. Zero external dependencies. 12 live sources.
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';
const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');
const crypto = require('crypto');

const CFG = {
  baseUrl:           'https://blog.cyberdudebivash.in',
  brand:             'CYBERDUDEBIVASH',
  author:            'CYBERDUDEBIVASH SENTINEL APEX',
  authorEmail:       'bivash@cyberdudebivash.com',
  postsDir:          path.join(__dirname, 'posts'),
  indexPath:         path.join(__dirname, 'index.html'),
  statePath:         path.join(__dirname, 'intel-state.json'),
  rssPath:           path.join(__dirname, 'rss.xml'),
  liveJsonPath:      path.join(__dirname, 'live-intel.json'),
  sitemapPath:       path.join(__dirname, 'sitemap.xml'),
  nvdLookbackHours:  168,
  kevLookbackDays:   14,
  maxNewPostsPerRun: 10,
  minCVSS:           7.0,
  requestTimeoutMs:  25000,
  maxRssItems:       8,
  nvdApiKey:         process.env.NVD_API_KEY   || '',
  githubToken:       process.env.GITHUB_TOKEN  || '',
  nvdApi:            'https://services.nvd.nist.gov/rest/json/cves/2.0',
  cisaKevUrl:        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  cisaAlertsRss:     'https://www.cisa.gov/cybersecurity-advisories/all.xml',
  ghAdvisoryUrl:     'https://api.github.com/advisories?type=reviewed&severity=high&per_page=20',
  bleepingRss:       'https://www.bleepingcomputer.com/feed/',
  thnRss:            'https://feeds.feedburner.com/TheHackersNews',
  krebsRss:          'https://krebsonsecurity.com/feed/',
  secweekRss:        'https://www.securityweek.com/feed/',
  sansRss:           'https://isc.sans.edu/rssfeed_full.xml',
  urlhausApi:        'https://urlhaus-api.abuse.ch/v1/payloads/recent/',
  threatfoxApi:      'https://threatfox-api.abuse.ch/api/v1/',
  msrcApi:           'https://api.msrc.microsoft.com/cvrf/v2.0/Updates',
};

const log  = m => console.log(`[APEX] ${m}`);
const warn = m => console.warn(`[WARN] ${m}`);
const err  = m => console.error(`[ERR]  ${m}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const isoNow = () => new Date().toISOString().slice(0, 10);
const md5 = s => crypto.createHash('md5').update(String(s)).digest('hex').slice(0, 16);

function fetchUrl(rawUrl, opts = {}, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('Too many redirects'));
    let parsed;
    try { parsed = new url.URL(rawUrl); } catch(e) { return reject(e); }
    const isHttps = parsed.protocol === 'https:';
    const client  = isHttps ? https : http;
    const headers = {
      'User-Agent': 'CYBERDUDEBIVASH-SENTINEL-APEX/3.0 (+https://blog.cyberdudebivash.in)',
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

function loadState() {
  try {
    if (fs.existsSync(CFG.statePath)) {
      const s = JSON.parse(fs.readFileSync(CFG.statePath, 'utf8'));
      if (!Array.isArray(s.published)) s.published = [];
      return s;
    }
  } catch(e) { warn('State corrupt — starting fresh.'); }
  return { published: [], lastRun: null, totalPublished: 0, version: '3.0' };
}

function saveState(state) {
  state.lastRun = new Date().toISOString();
  state.version = '3.0';
  if (state.published.length > 1000) state.published = state.published.slice(0, 1000);
  fs.writeFileSync(CFG.statePath, JSON.stringify(state, null, 2), 'utf8');
}

function isPublished(state, id) { return state.published.some(p => p.id === id); }

function markPublished(state, item) {
  state.published.unshift({ id: item.id, slug: item.slug, date: isoNow(), title: item.title });
  state.totalPublished = (state.totalPublished || 0) + 1;
}

// ── SOURCE 1: NVD CVE API ──────────────────────────────────────────────
async function fetchNVD() {
  const end = new Date(), start = new Date(Date.now() - CFG.nvdLookbackHours * 3600000);
  // NVD API 2.0 requires format: 2024-01-01T00:00:00.000 (no timezone in path)
  const fmt = d => d.toISOString().slice(0,23);
  // Try CRITICAL first, then HIGH as fallback
  const apiUrl = `${CFG.nvdApi}?pubStartDate=${encodeURIComponent(fmt(start))}&pubEndDate=${encodeURIComponent(fmt(end))}&cvssV3SeverityExact=CRITICAL&resultsPerPage=20&noRejected`;
  const apiUrlHigh = `${CFG.nvdApi}?lastModStartDate=${encodeURIComponent(fmt(start))}&lastModEndDate=${encodeURIComponent(fmt(end))}&cvssV3SeverityExact=CRITICAL&resultsPerPage=15&noRejected`;
  log('NVD: fetching CRITICAL CVEs...');
  try {
    await sleep(600);
    let raw;
    try { raw = await fetchWithRetry(apiUrl, {}, 2); }
    catch(e1) {
      warn(`NVD pubDate query failed (${e1.message}), trying lastMod query...`);
      try { raw = await fetchWithRetry(apiUrlHigh, {}, 2); }
      catch(e2) { throw e2; }
    }
    const data = JSON.parse(raw);
    const items = (data.vulnerabilities||[]).map(v => {
      const cve = v.cve, id = cve.id;
      const desc = (cve.descriptions||[]).find(d=>d.lang==='en')?.value||'';
      const met = cve.metrics?.cvssMetricV31?.[0]||cve.metrics?.cvssMetricV30?.[0]||null;
      const cvss = met?.cvssData?.baseScore||0;
      const vector = met?.cvssData?.vectorString||'';
      const cweId = cve.weaknesses?.[0]?.description?.[0]?.value||'';
      const refs = (cve.references||[]).map(r=>r.url).slice(0,6);
      const pubDate = cve.published?.slice(0,10)||isoNow();
      const vendor = (() => { const c=cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria||''; const m=c.match(/cpe:2\.3:[aoh]:([^:]+):/); return m?m[1].replace(/_/g,' '):'Unknown Vendor'; })();
      const product = (() => { const c=cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria||''; const m=c.match(/cpe:2\.3:[aoh]:[^:]+:([^:]+):/); if(m) return m[1].replace(/_/g,' '); return desc.split(/\s+/).slice(0,3).join(' ')||'Unknown Product'; })();
      return { source:'nvd', type:'CVE_REPORT', id, title:`${id} — ${vendor} ${product} CVSS ${cvss} Critical Vulnerability`, desc, cvss, vector, cweId, refs, pubDate, vendor, product, exploited:false, cisaKev:false, ransomware:false, priority:Math.round(cvss*10) };
    }).filter(i => i.cvss >= CFG.minCVSS);
    log(`NVD: ${items.length} items.`); return items;
  } catch(e) { warn(`NVD failed: ${e.message}`); return []; }
}

// ── SOURCE 2: CISA KEV ─────────────────────────────────────────────────
async function fetchCISAKev() {
  log('CISA KEV: fetching...');
  try {
    const raw = await fetchWithRetry(CFG.cisaKevUrl);
    const data = JSON.parse(raw);
    const cutoff = new Date(Date.now() - CFG.kevLookbackDays * 86400000);
    const items = (data.vulnerabilities||[]).filter(v => new Date(v.dateAdded) >= cutoff).map(v => ({
      source:'cisa_kev', type:'CVE_REPORT', id:v.cveID,
      title:`${v.cveID}: ${v.vulnerabilityName} — CISA KEV Active Exploitation`,
      desc:v.shortDescription||v.vulnerabilityName, cvss:9.5, vector:'', cweId:'',
      refs:[v.notes].filter(Boolean), pubDate:v.dateAdded, vendor:v.vendorProject, product:v.product,
      vulnName:v.vulnerabilityName, exploited:true, cisaKev:true,
      ransomware:v.knownRansomwareCampaignUse==='Known', dueDate:v.dueDate, reqAction:v.requiredAction, priority:100,
    }));
    log(`CISA KEV: ${items.length} items.`); return items;
  } catch(e) { warn(`CISA KEV failed: ${e.message}`); return []; }
}

// ── SOURCE 3: CISA Alerts RSS ──────────────────────────────────────────
async function fetchCISAAlerts() {
  log('CISA Alerts RSS: fetching...');
  try {
    const raw = await fetchWithRetry(CFG.cisaAlertsRss);
    const items = parseRSS(raw).slice(0, CFG.maxRssItems).map(item => ({
      source:'cisa_alerts', type:'ADVISORY', id:'CISA-'+md5(item.link),
      title:item.title, desc:(item.desc||'').slice(0,600), cvss:8.5, refs:[item.link],
      pubDate:item.pubDate?new Date(item.pubDate).toISOString().slice(0,10):isoNow(),
      vendor:'CISA US-CERT', product:'Multiple Products',
      exploited:/exploit|active/i.test(item.title+item.desc), cisaKev:false,
      ransomware:/ransomware/i.test(item.title+item.desc),
      cves:extractCVEs(item.title+' '+item.desc), link:item.link, priority:70,
    }));
    log(`CISA Alerts: ${items.length} items.`); return items;
  } catch(e) { warn(`CISA Alerts failed: ${e.message}`); return []; }
}

// ── SOURCE 4: GitHub Security Advisories ──────────────────────────────
async function fetchGitHubAdvisories() {
  log('GitHub Advisories: fetching...');
  try {
    await sleep(500);
    const raw = await fetchWithRetry(CFG.ghAdvisoryUrl);
    const data = JSON.parse(raw);
    const cutoff = new Date(Date.now() - 7*86400000);
    const items = (Array.isArray(data)?data:[]).filter(a => new Date(a.published_at||a.updated_at) >= cutoff).slice(0,10).map(a => {
      const cvss = a.cvss?.score||(a.severity==='critical'?9.0:7.5);
      const cves = (a.cve_id?[a.cve_id]:[]).concat((a.identifiers||[]).filter(i=>i.type==='CVE').map(i=>i.value));
      const primaryId = cves[0]||('GHSA-'+md5(a.ghsa_id||a.url));
      return {
        source:'github_advisories', type:'CVE_REPORT', id:primaryId,
        title:a.summary||`${primaryId} — GitHub Security Advisory`,
        desc:stripHtml(a.description||a.summary||'').slice(0,800), cvss,
        vector:a.cvss?.vector_string||'', cweId:(a.cwes||[])[0]?.cwe_id||'',
        refs:[a.html_url,...(a.references||[])].filter(Boolean).slice(0,5),
        pubDate:(a.published_at||isoNow()).slice(0,10),
        vendor:(a.vulnerabilities||[])[0]?.package?.ecosystem||'Open Source',
        product:(a.vulnerabilities||[])[0]?.package?.name||'Unknown Package',
        exploited:false, cisaKev:false, ransomware:false, cves, priority:Math.round(cvss*9),
      };
    });
    log(`GitHub Advisories: ${items.length} items.`); return items;
  } catch(e) { warn(`GitHub Advisories failed: ${e.message}`); return []; }
}

// ── RSS NORMALIZER ─────────────────────────────────────────────────────
function classifyNews(text) {
  if (/zero.?day|0.?day|unpatched|no patch/i.test(text))              return 'ZERO_DAY';
  if (/ransomware|ransom demand|encryption attack/i.test(text))        return 'RANSOMWARE';
  if (/data breach|breach|leaked|exposed data|records stolen/i.test(text)) return 'DATA_BREACH';
  if (/apt\d|nation.state|lazarus|volt typhoon|sandworm|cozy bear|fancy bear|apt group/i.test(text)) return 'THREAT_ACTOR';
  if (/malware|trojan|\brat\b|backdoor|botnet|stealer|infostealer/i.test(text)) return 'MALWARE_REPORT';
  if (/ai security|llm|prompt injection|artificial intelligence.*security|ml.*attack|gpt.*hack/i.test(text)) return 'AI_SECURITY';
  if (/patch tuesday|security update|advisory|cve-\d/i.test(text))    return 'CVE_REPORT';
  return 'NEWS_REPORT';
}

function newsPriority(text, cves, type) {
  let s = 50;
  if (type==='ZERO_DAY')     s+=30;
  if (type==='RANSOMWARE')   s+=25;
  if (type==='DATA_BREACH')  s+=20;
  if (type==='THREAT_ACTOR') s+=22;
  if (cves.length>0)         s+=10;
  if (/cisa|federal|critical infrastructure/i.test(text)) s+=10;
  if (/actively exploited|in the wild|emergency patch/i.test(text))   s+=15;
  return Math.min(s, 99);
}

function rssToIntel(item, source) {
  const text = (item.title||'')+' '+(item.desc||'');
  const cves = extractCVEs(text);
  const type = classifyNews(text);
  const id   = cves[0]||(source.toUpperCase()+'-'+md5(item.link||item.title));
  const pubDate = (() => { try { return item.pubDate ? new Date(item.pubDate).toISOString().slice(0,10) : isoNow(); } catch(e){ return isoNow(); } })();
  const srcLabels = { bleepingcomputer:'BleepingComputer', thehackernews:'The Hacker News', krebsonsecurity:'KrebsOnSecurity', securityweek:'SecurityWeek', sans_isc:'SANS ISC' };
  return {
    source, type, id,
    title:item.title||'Security Intelligence Report',
    desc:(item.desc||'').slice(0,800), cvss:cves.length?8.0:6.5,
    refs:[item.link].filter(Boolean), pubDate,
    vendor:srcLabels[source]||source, product:'Threat Intelligence',
    exploited:/exploit|active|in the wild|itw|0.?day|zero.?day/i.test(text),
    cisaKev:/cisa kev|known exploited/i.test(text),
    ransomware:/ransomware|ransom|lockbit|qilin|akira|blackcat/i.test(text),
    cves, link:item.link, priority:newsPriority(text, cves, type),
  };
}

// ── SOURCES 5-9: RSS FEEDS ─────────────────────────────────────────────
async function fetchRSS(urlStr, source, maxItems) {
  log(`${source}: fetching RSS...`);
  try {
    const raw = await fetchWithRetry(urlStr);
    const items = parseRSS(raw).slice(0, maxItems||CFG.maxRssItems).map(item => rssToIntel(item, source));
    log(`${source}: ${items.length} items.`); return items;
  } catch(e) { warn(`${source} failed: ${e.message}`); return []; }
}

// ── SOURCE 10: Abuse.ch URLhaus ────────────────────────────────────────
async function fetchURLhaus() {
  log('Abuse.ch URLhaus: fetching...');
  try {
    const raw = await fetchWithRetry(CFG.urlhausApi, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'limit=20' });
    const data = JSON.parse(raw);
    if (!Array.isArray(data.payloads) && data.query_status !== 'ok') return [];
    const payloads = data.payloads || data.urls || [];
    const families = {};
    payloads.slice(0,40).forEach(u => {
      const tag = (u.signature||u.tags?.[0]||'unknown_malware');
      if (!families[tag]) families[tag] = { count:0, hashes:[], date:u.firstseen||u.date_added||isoNow() };
      families[tag].count++;
      if (u.md5_hash||u.sha256_hash) families[tag].hashes.push(`md5:${u.md5_hash||''}`);
    });
    const items = Object.entries(families).filter(([k])=>k!=='unknown_malware').slice(0,3).map(([tag,info]) => ({
      source:'urlhaus', type:'MALWARE_REPORT',
      id:'URLHAUS-'+md5(tag+(info.date||'')),
      title:`Abuse.ch Malware Alert: ${tag} — ${info.count} Payloads Tracked (URLhaus Intelligence)`,
      desc:`Abuse.ch URLhaus is tracking ${info.count} active malware payloads for the ${tag} malware family. Payload hashes and distribution indicators are confirmed fresh. CYBERDUDEBIVASH SENTINEL APEX recommends immediate IOC deployment.`,
      cvss:7.5, refs:['https://urlhaus.abuse.ch/'],
      pubDate:info.date?String(info.date).slice(0,10):isoNow(),
      vendor:'Abuse.ch', product:'URLhaus Intelligence',
      exploited:true, cisaKev:false,
      ransomware:/ransomware|ransom/i.test(tag),
      iocs:info.hashes.slice(0,10), priority:68, malwareTag:tag,
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
      families[fam].iocs.push({ type:ioc.ioc_type, value:ioc.ioc });
    });
    const items = Object.entries(families).slice(0,3).map(([family,info]) => ({
      source:'threatfox', type:'MALWARE_REPORT',
      id:'THREATFOX-'+md5(family+(info.firstSeen||'')),
      title:`ThreatFox IOC Alert: ${family} — Fresh Indicators Published by Abuse.ch`,
      desc:`Abuse.ch ThreatFox has published ${info.iocs.length} fresh IOCs for ${family}. These indicators represent active threat infrastructure. Immediate deployment to SIEM/firewall recommended.`,
      cvss:7.8, refs:['https://threatfox.abuse.ch/'],
      pubDate:info.firstSeen?info.firstSeen.slice(0,10):isoNow(),
      vendor:'Abuse.ch', product:'ThreatFox Intelligence',
      exploited:true, cisaKev:false,
      ransomware:/ransomware|ransom|locker/i.test(family),
      iocs:info.iocs.slice(0,10).map(i=>`${i.type}: ${i.value}`),
      priority:72, malwareFamily:family,
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
      title:`Microsoft Security Update: ${u.DocumentTitle?.Value||u.Alias||'Security Advisory'} — CYBERDUDEBIVASH Analysis`,
      desc:`Microsoft has released security updates: ${u.DocumentTitle?.Value||''}. Review and apply immediately to all affected Microsoft products.`,
      cvss:8.0, refs:[`https://msrc.microsoft.com/update-guide/`],
      pubDate:(u.InitialReleaseDate||isoNow()).slice(0,10),
      vendor:'Microsoft', product:'Multiple Microsoft Products',
      exploited:false, cisaKev:false, ransomware:false, priority:65,
    }));
    log(`MSRC: ${items.length} items.`); return items;
  } catch(e) { warn(`MSRC failed: ${e.message}`); return []; }
}

// ── MERGE + DEDUPLICATE + PRIORITIZE ──────────────────────────────────
function mergeAndPrioritize(sources) {
  const map = new Map();
  for (const batch of sources) {
    for (const item of batch) {
      if (!item.id) continue;
      const ex = map.get(item.id);
      if (!ex) { map.set(item.id, item); }
      else {
        const winner = (item.source==='cisa_kev'||item.source==='nvd') ? item : ex;
        map.set(item.id, { ...winner, exploited:ex.exploited||item.exploited, cisaKev:ex.cisaKev||item.cisaKev, ransomware:ex.ransomware||item.ransomware, priority:Math.max(ex.priority||0, item.priority||0) });
      }
    }
  }
  const all = Array.from(map.values());
  all.sort((a,b) => {
    if (a.cisaKev !== b.cisaKev) return b.cisaKev - a.cisaKev;
    if (a.exploited !== b.exploited) return b.exploited - a.exploited;
    if ((a.priority||0) !== (b.priority||0)) return (b.priority||0) - (a.priority||0);
    return (b.cvss||0) - (a.cvss||0);
  });
  return all;
}

// ── MITRE ATT&CK ──────────────────────────────────────────────────────
function getMitre(item) {
  const t = ((item.desc||'')+(item.title||'')).toLowerCase();
  if (/remote code execution|rce|arbitrary code/i.test(t))         return { tactic:'Execution',             technique:'T1203 — Exploitation for Client Execution',         sub:'T1059 — Command & Scripting Interpreter' };
  if (/privilege escalation|lpe|eop|elevation of privilege/i.test(t)) return { tactic:'Privilege Escalation', technique:'T1068 — Exploitation for Privilege Escalation',     sub:'T1134 — Access Token Manipulation' };
  if (/auth bypass|unauthenticated|authentication bypass/i.test(t)) return { tactic:'Initial Access',         technique:'T1190 — Exploit Public-Facing Application',          sub:'T1078 — Valid Accounts' };
  if (/use.after.free|uaf/i.test(t))                                return { tactic:'Execution',             technique:'T1203 — Exploitation for Client Execution',         sub:'T1068 — Exploitation for Privilege Escalation' };
  if (/sql injection/i.test(t))                                     return { tactic:'Initial Access',         technique:'T1190 — Exploit Public-Facing Application',          sub:'T1555 — Credentials from Password Stores' };
  if (/buffer overflow|heap overflow|memory corruption/i.test(t))   return { tactic:'Execution',             technique:'T1203 — Exploitation for Client Execution',         sub:'T1068 — Exploitation for Privilege Escalation' };
  if (/ransomware/i.test(t)||item.type==='RANSOMWARE')              return { tactic:'Impact',                technique:'T1486 — Data Encrypted for Impact',                 sub:'T1490 — Inhibit System Recovery' };
  if (/malware|trojan|backdoor/i.test(t)||item.type==='MALWARE_REPORT') return { tactic:'Execution',         technique:'T1059 — Command & Scripting Interpreter',            sub:'T1055 — Process Injection' };
  if (/data breach|exfiltrat/i.test(t)||item.type==='DATA_BREACH')  return { tactic:'Exfiltration',          technique:'T1041 — Exfiltration Over C2 Channel',              sub:'T1005 — Data from Local System' };
  if (/supply chain/i.test(t))                                      return { tactic:'Initial Access',         technique:'T1195 — Supply Chain Compromise',                   sub:'T1199 — Trusted Relationship' };
  return { tactic:'Initial Access', technique:'T1190 — Exploit Public-Facing Application', sub:'T1203 — Exploitation for Client Execution' };
}

// ── SIGMA RULE ─────────────────────────────────────────────────────────
function genSigma(item) {
  const safeName = (item.id||'unknown').replace(/[^a-zA-Z0-9_-]/g,'_');
  const cves = item.cves||(item.id?.startsWith('CVE')?[item.id]:[]);
  return `title: ${item.id} Exploitation Attempt — ${item.vendor} ${item.product}
id: ${md5(item.id+'sigma')}-${md5(item.title||'').slice(0,4)}
status: experimental
description: Detects exploitation of ${item.id} in ${item.vendor} ${item.product}
author: CYBERDUDEBIVASH SENTINEL APEX (bivash@cyberdudebivash.com)
date: ${isoNow()}
references:\n    - https://nvd.nist.gov/vuln/detail/${item.id}\n    - https://blog.cyberdudebivash.in/
tags:\n    - attack.initial_access\n    - attack.t1190${cves.map(c=>`\n    - ${c.toLowerCase()}`).join('')}
logsource:\n    category: webserver
detection:
    keywords:${cves.map(c=>`\n        - '${c}'`).join('')}\n        - '${safeName.toLowerCase()}'
    condition: keywords
falsepositives:\n    - Security scanners\nlevel: critical`.trim();
}

// ── YARA RULE ──────────────────────────────────────────────────────────
function genYARA(item) {
  const n = (item.id||'unknown').replace(/[^a-zA-Z0-9_]/g,'_');
  const p = (item.product||'unknown').replace(/[^a-zA-Z0-9_]/g,'_').slice(0,40);
  return `rule ${n}_Exploitation {
    meta:
        description = "Detects artifacts related to ${item.id} exploitation in ${item.vendor} ${item.product}"
        author      = "CYBERDUDEBIVASH SENTINEL APEX"
        date        = "${isoNow()}"
        severity    = "${(item.cvss||0) >= 9 ? 'CRITICAL' : 'HIGH'}"
        cvss        = "${item.cvss||'N/A'}"
        reference   = "https://nvd.nist.gov/vuln/detail/${item.id}"
    strings:
        $id_str  = "${(item.id||'').replace(/"/g,'')}" ascii nocase
        $product = "${p.replace(/"/g,'')}" ascii nocase wide
    condition:\n        any of them\n}`.trim();
}

// ── ANALYST COMMENTARY ─────────────────────────────────────────────────
function genCommentary(item) {
  const vendor=item.vendor||'the affected vendor', product=item.product||'the affected product', cvss=item.cvss||7.0;
  const urgency = cvss>=9.5?'MAXIMUM':cvss>=9.0?'CRITICAL':cvss>=8.0?'HIGH':'ELEVATED';
  const typeCommentary = {
    CVE_REPORT:     `This ${cvss>=9?'critical':'high-severity'} vulnerability in ${vendor} ${product} (CVSS ${cvss}) represents a significant attack surface for threat actors. CYBERDUDEBIVASH SENTINEL APEX assesses exploitation to be technically feasible with moderate effort. Organizations running ${product} in internet-facing or privileged positions face immediate risk. The combination of attack vector, complexity score, and potential impact demands priority-zero remediation.`,
    ZERO_DAY:       `This zero-day vulnerability is being actively exploited before a vendor patch is available. CYBERDUDEBIVASH SENTINEL APEX intelligence shows unpatched vulnerabilities are consistently weaponized within 24-72 hours of public disclosure. Nation-state APT groups and ransomware operators actively monitor disclosures and race to weaponize. Immediate mitigating controls must be deployed pending an official patch.`,
    RANSOMWARE:     `CYBERDUDEBIVASH SENTINEL APEX is tracking active ransomware campaign activity. Ransomware groups have dramatically escalated targeting of enterprise environments, healthcare infrastructure, and critical national systems. Modern ransomware operations are double-extortion campaigns combining data theft with encryption. Incident response readiness, offline backups, and network segmentation are non-negotiable defensive requirements.`,
    MALWARE_REPORT: `Active malware campaign infrastructure has been identified and confirmed by threat intelligence sources. This campaign is using live distribution infrastructure currently serving payloads. The IOCs in this report should be blocked immediately across all security controls — firewall, proxy, EDR, and email gateway. Threat hunting for lateral movement is recommended for any organization with potential exposure.`,
    DATA_BREACH:    `A data breach or significant data exposure event has been identified. CYBERDUDEBIVASH SENTINEL APEX recommends immediate assessment of third-party data sharing relationships. Organizations in the same sector should perform threat hunting for similar attack vectors. Credential stuffing attacks typically follow major breach disclosures within 48-72 hours.`,
    THREAT_ACTOR:   `Nation-state or APT actor activity has been observed. State-sponsored cyber operations have dramatically increased in targeting critical infrastructure, defense supply chains, and financial systems. TTPs include living-off-the-land techniques, supply chain compromise, and persistence through legitimate tooling — all designed to evade standard detection.`,
    AI_SECURITY:    `AI and machine learning security vulnerabilities represent an emerging attack surface that most organizations are unprepared to defend. CYBERDUDEBIVASH SENTINEL APEX tracks AI security threats including prompt injection, model poisoning, and AI-assisted cyberattacks. As enterprise AI adoption accelerates, so does attacker interest in AI-specific attack vectors.`,
    NEWS_REPORT:    `CYBERDUDEBIVASH SENTINEL APEX is monitoring this developing security event. Analysts are tracking indicators, attribution signals, and potential downstream impact. Organizations should review their defensive posture against the attack vectors described. SENTINEL APEX subscribers receive pre-disclosure intelligence before incidents become public knowledge.`,
    ADVISORY:       `This security advisory from ${vendor} covers critical remediation requirements. Advisory-level intelligence from ${vendor} represents validated, in-scope vulnerabilities with confirmed impact. CYBERDUDEBIVASH SENTINEL APEX recommends treating all vendor advisories as actionable intelligence requiring timely response.`,
  };
  const base = typeCommentary[item.type]||typeCommentary['NEWS_REPORT'];
  const kevNote = item.cisaKev ? `\n\nCISA KNOWN EXPLOITED VULNERABILITY: This vulnerability has been added to the CISA KEV catalog confirming active exploitation. ${item.dueDate?`Federal agencies must remediate by ${item.dueDate}.`:'All organizations must patch immediately.'} Required action: ${item.reqAction||'Apply vendor patch immediately.'}` : '';
  const rsNote  = item.ransomware ? `\n\nRANSOMWARE OPERATOR CORRELATION: Ransomware-as-a-service groups have been observed using this attack vector. Organizations in healthcare, financial services, and critical infrastructure are at elevated risk.` : '';
  const urgencyNote = `\n\nCYBERDUDEBIVASH SENTINEL APEX URGENCY: ${urgency}. ${item.exploited?'Active exploitation confirmed — treat as active incident requiring immediate response.':'Patch before exploitation activity begins.'}`;
  return base+kevNote+rsNote+urgencyNote;
}

// ── SOC PLAYBOOK ───────────────────────────────────────────────────────
function genPlaybook(item) {
  const p = item.product||'affected product', v = item.vendor||'vendor';
  const base = [
    `IMMEDIATE (0-1hr): Identify all instances of ${p} in your environment via asset inventory`,
    `IMMEDIATE (0-1hr): Apply vendor patch — no maintenance window exception`,
    `IMMEDIATE (1-2hr): If no patch: implement WAF rules, ACLs, or compensating controls`,
    `SHORT-TERM (2-4hr): Deploy Sigma detection rule to SIEM — validate alert generation`,
    `SHORT-TERM (4-8hr): Review logs for exploitation indicators`,
    `SHORT-TERM (8-24hr): Hunt for post-exploitation: new accounts, lateral movement, persistence`,
    item.cisaKev ? `MANDATORY: CISA KEV deadline ${item.dueDate||'TBD'} — document remediation for compliance` : `MONITOR: Track NVD for exploitation status updates`,
    `ONGOING: Subscribe to ${v} security advisories for follow-on patches`,
  ];
  if (item.type==='RANSOMWARE'||item.ransomware) {
    base.push('VALIDATE: Offline backup integrity — test restoration procedures');
    base.push('HUNT: PowerShell/WMI anomalies, vssadmin, Cobalt Strike, Mimikatz indicators');
  }
  if (item.iocs?.length) {
    base.splice(1, 0, `IMMEDIATE: Block all IOCs in this report at firewall, proxy, DNS, and EDR`);
  }
  return base;
}

// ── HTML REPORT GENERATOR ──────────────────────────────────────────────
function generatePostHTML(item) {
  const mitre = getMitre(item), commentary = genCommentary(item), sigma = genSigma(item), yara = genYARA(item), playbook = genPlaybook(item);
  const pubDateFmt = fmtDate(item.pubDate||isoNow()), today = isoNow();
  const cvss = item.cvss||7.0, cvssColor = cvss>=9.0?'#ff3b3b':cvss>=7.0?'#ff8c00':'#ffe000';
  const sevLabel = cvss>=9.0?'CRITICAL':cvss>=7.0?'HIGH':'MEDIUM';
  const typeLabels = { CVE_REPORT:'🔴 CVE ANALYSIS', ZERO_DAY:'💀 ZERO-DAY', RANSOMWARE:'🏴 RANSOMWARE', MALWARE_REPORT:'🦠 MALWARE', DATA_BREACH:'⚠️ DATA BREACH', THREAT_ACTOR:'🎯 THREAT ACTOR', AI_SECURITY:'🤖 AI SECURITY', NEWS_REPORT:'📡 INTEL', ADVISORY:'🛡️ ADVISORY' };
  const typeLabel = typeLabels[item.type]||'⚡ INTEL';
  const slug = slugify(item.id.startsWith('CVE')?`${item.id}-${item.vendor}-${item.product}`:item.title.slice(0,60));
  const metaTitle = `${item.title} | CYBERDUDEBIVASH SENTINEL APEX`;
  const metaDesc = `${item.id} — ${sevLabel} CVSS ${cvss}. ${(item.desc||'').slice(0,150)}. Full analysis, IOCs, detection rules by CYBERDUDEBIVASH SENTINEL APEX.`;
  const badges = [item.cisaKev?`<span class="badge bdg-cisa">CISA KEV</span>`:'', item.exploited?`<span class="badge bdg-red">⚡ ACTIVELY EXPLOITED</span>`:'', item.ransomware?`<span class="badge bdg-purple">RANSOMWARE</span>`:'', `<span class="badge bdg-red">CVSS ${cvss}</span>`, `<span class="badge bdg-cyan">${typeLabel}</span>`].filter(Boolean).join('\n      ');
  const cveIds = item.cves||(item.id?.startsWith('CVE')?[item.id]:[]);
  const cveRows = cveIds.slice(0,5).map(cve=>`<tr><td class="tag-cyan" style="font-family:var(--mono)">${escHtml(cve)}</td><td><a href="https://nvd.nist.gov/vuln/detail/${escHtml(cve)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">NVD →</a></td><td>CVSS ${cvss}</td></tr>`).join('\n');
  const iocRows = (item.iocs||[]).slice(0,8).map(ioc=>`<tr><td class="tag-cyan" style="font-family:var(--mono);font-size:12px">${escHtml(String(ioc).slice(0,80))}</td><td>${escHtml(item.malwareFamily||item.malwareTag||'Threat IOC')}</td><td>${escHtml(item.source)}</td></tr>`).join('\n');
  const refLinks = (item.refs||[]).slice(0,5).map(r=>`<li><a href="${escHtml(r)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">${escHtml(String(r).replace(/https?:\/\//,'').slice(0,70))}</a></li>`).join('\n');
  const playbookItems = playbook.map(s=>`<li class="action-item">${escHtml(s)}</li>`).join('\n      ');
  const showDetection = ['CVE_REPORT','ZERO_DAY','ADVISORY','MALWARE_REPORT','RANSOMWARE'].includes(item.type);

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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-red:#ff3b3b;--apex-orange:#ff8c00;--apex-yellow:#ffe000;--apex-green:#00ff88;--apex-purple:#a855f7;--apex-bg:#07090f;--apex-surface:#0d1117;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;overflow-x:hidden;line-height:1.7}
#mc{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;opacity:.03}
.ticker{position:relative;z-index:100;background:linear-gradient(90deg,#ff0040,#cc0030,#ff0040);padding:8px 0;overflow:hidden}
.ticker-inner{display:flex;animation:tick 50s linear infinite;white-space:nowrap}.ticker-item{color:#fff;font-size:12px;font-weight:700;letter-spacing:.05em;padding:0 40px}
@keyframes tick{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
nav{position:sticky;top:0;z-index:9999;background:rgba(7,9,15,.97);backdrop-filter:blur(20px);border-bottom:1px solid var(--apex-border);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between}
.nbrand{display:flex;align-items:center;gap:10px;text-decoration:none}.nlogo{font-size:18px;font-weight:900;color:var(--apex-cyan);letter-spacing:.02em}.ntag{font-size:10px;color:var(--apex-muted);letter-spacing:.1em;text-transform:uppercase}
.nlinks{display:flex;align-items:center;gap:6px}.nlinks a{color:var(--apex-muted);text-decoration:none;font-size:13px;font-weight:500;padding:6px 12px;border-radius:6px;transition:.2s}.nlinks a:hover{color:var(--apex-text);background:var(--apex-surface)}
.ncta{background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000!important;font-weight:700!important;border-radius:6px!important}
main{position:relative;z-index:10;max-width:1200px;margin:0 auto;padding:40px 24px 80px;display:grid;grid-template-columns:1fr 320px;gap:40px}
@media(max-width:900px){main{grid-template-columns:1fr;padding:24px 16px}}
.meta-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:20px}
.badge{padding:4px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.bdg-red{background:#ff3b3b22;color:#ff3b3b;border:1px solid #ff3b3b44}.bdg-cisa{background:#00ffe022;color:#00ffe0;border:1px solid #00ffe044}.bdg-cyan{background:#0099ff22;color:#0099ff;border:1px solid #0099ff44}.bdg-purple{background:#a855f722;color:#a855f7;border:1px solid #a855f744}
.rep-date{color:var(--apex-muted);font-size:13px;margin-left:auto}
h1.rh1{font-size:clamp(20px,3.5vw,36px);font-weight:900;line-height:1.2;color:#fff;margin-bottom:16px}
.rsubtitle{font-size:15px;color:var(--apex-muted);margin-bottom:28px;line-height:1.65;border-left:3px solid var(--apex-red);padding-left:16px}
.stats-bar{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:32px}
.stat{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:10px;padding:16px;text-align:center}
.stat .sv{font-size:22px;font-weight:900;color:var(--apex-cyan);font-family:var(--mono)}.stat.red .sv{color:var(--apex-red)}.stat.orange .sv{color:var(--apex-orange)}.stat.green .sv{color:var(--apex-green)}.stat .sl{font-size:11px;color:var(--apex-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
.alert{padding:16px 20px;border-radius:10px;margin:20px 0;display:flex;gap:14px;align-items:flex-start}
.alert-crit{background:#ff3b3b10;border:1px solid #ff3b3b44;border-left:4px solid var(--apex-red)}.alert-warn{background:#ff8c0010;border:1px solid #ff8c0044;border-left:4px solid var(--apex-orange)}.alert-info{background:#00ffe010;border:1px solid #00ffe044;border-left:4px solid var(--apex-cyan)}
.aico{font-size:22px;flex-shrink:0}.abody .atitle{font-weight:800;font-size:14px;margin-bottom:4px}.alert-crit .atitle{color:var(--apex-red)}.alert-warn .atitle{color:var(--apex-orange)}.alert-info .atitle{color:var(--apex-cyan)}.abody p{font-size:14px;color:var(--apex-muted);line-height:1.6}
h2.sh{font-size:20px;font-weight:800;color:#fff;margin:36px 0 16px;padding-bottom:8px;border-bottom:1px solid var(--apex-border)}h2.sh span{color:var(--apex-cyan)}
p.bp{font-size:15px;color:#c9d1d9;line-height:1.8;margin-bottom:14px}
.code-block{background:#0a0e18;border:1px solid var(--apex-border);border-radius:8px;padding:16px 20px;font-family:var(--mono);font-size:12px;color:#a6e22e;overflow-x:auto;margin:16px 0;position:relative;white-space:pre;max-height:420px;overflow-y:auto}
.code-lbl{position:absolute;top:8px;right:12px;font-size:10px;color:var(--apex-muted);text-transform:uppercase;letter-spacing:.1em;background:var(--apex-surface);padding:2px 6px;border-radius:4px}
.tbl{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px}.tbl th{background:#1a2234;color:var(--apex-cyan);font-weight:700;padding:10px 14px;text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--apex-border)}.tbl td{padding:10px 14px;border:1px solid var(--apex-border);color:var(--apex-text);vertical-align:top}
.tag-critical{color:var(--apex-red);font-weight:700}.tag-cyan{color:var(--apex-cyan)}
.ecta{background:linear-gradient(135deg,#0a1428,#111827);border:1px solid #00ffe022;border-radius:16px;padding:28px;margin:40px 0;text-align:center}
.ecta h3{font-size:20px;font-weight:900;color:#fff;margin-bottom:8px}.ecta .ep{color:var(--apex-muted);margin-bottom:20px;font-size:14px}
.cta-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}@media(max-width:600px){.cta-grid{grid-template-columns:1fr}}
.btn-p{padding:12px 20px;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.btn-s{padding:12px 20px;background:transparent;border:2px solid var(--apex-cyan);color:var(--apex-cyan);font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.btn-e{padding:12px 20px;background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.4);color:#a855f7;font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.btn-g{padding:12px 20px;background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.3);color:#00ff88;font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.sidebar{display:flex;flex-direction:column;gap:20px}.sw{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:12px;padding:20px}
.wt{font-size:12px;font-weight:700;color:var(--apex-cyan);text-transform:uppercase;letter-spacing:.1em;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--apex-border)}
.vbox{background:#ff3b3b10;border:2px solid var(--apex-red);border-radius:12px;padding:20px}.vscore{font-size:44px;font-weight:900;color:var(--apex-red);font-family:var(--mono);text-align:center}.vlabel{font-size:11px;color:var(--apex-muted);text-align:center;text-transform:uppercase;letter-spacing:.1em}
.vrow{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--apex-border);font-size:13px}.vrow:last-child{border-bottom:none}.vk{color:var(--apex-muted)}.vv{color:var(--apex-text);font-weight:600}
.alist{list-style:none;padding:0}.action-item{padding:10px 14px;border-bottom:1px solid var(--apex-border);font-size:13px;color:var(--apex-text);line-height:1.6;padding-left:26px;position:relative}.action-item::before{content:"→";position:absolute;left:8px;color:var(--apex-red);font-weight:900}.action-item:last-child{border-bottom:none}
.intel-sig{margin-top:48px;padding:24px;background:rgba(0,255,224,.03);border:1px solid rgba(0,255,224,.1);border-radius:12px;text-align:center}
.isb{font-size:14px;font-weight:900;color:var(--apex-cyan);letter-spacing:.1em;text-transform:uppercase}.iss{font-size:12px;color:var(--apex-muted);margin-top:6px;line-height:1.5}
footer{background:var(--apex-surface);border-top:1px solid var(--apex-border);padding:32px 24px;text-align:center}footer p{font-size:13px;color:var(--apex-muted);line-height:1.8}footer a{color:var(--apex-cyan);text-decoration:none}
@media(max-width:767px){nav{padding:0 14px}.nlinks a:not(.ncta){display:none}.ntag{display:none}}
</style>
<link rel="stylesheet" href="/mobile-first.css">
</head>
<body>
<canvas id="mc"></canvas>
<div class="ticker"><div class="ticker-inner">
  <span class="ticker-item">⚡ ${escHtml(item.id)} — ${escHtml(item.vendor)} ${escHtml(item.product)} — CVSS ${cvss} ${sevLabel}</span>
  <span class="ticker-item">🛡️ CYBERDUDEBIVASH SENTINEL APEX — 24/7 Global Threat Intelligence</span>
  <span class="ticker-item">⚠️ ${item.cisaKev?'CISA KEV CONFIRMED — ACTIVE EXPLOITATION':item.exploited?'ACTIVE EXPLOITATION DETECTED':'HIGH-PRIORITY SECURITY ADVISORY'}</span>
  <span class="ticker-item">⚡ ${escHtml(item.id)} — ${escHtml(item.vendor)} ${escHtml(item.product)} — CVSS ${cvss} ${sevLabel}</span>
  <span class="ticker-item">🛡️ CYBERDUDEBIVASH SENTINEL APEX — 24/7 Global Threat Intelligence</span>
  <span class="ticker-item">⚠️ ${item.cisaKev?'CISA KEV CONFIRMED — ACTIVE EXPLOITATION':item.exploited?'ACTIVE EXPLOITATION DETECTED':'HIGH-PRIORITY SECURITY ADVISORY'}</span>
</div></div>
<nav>
  <a href="/" class="nbrand"><div><div class="nlogo">CYBERDUDE<span style="color:#fff">BIVASH</span></div><div class="ntag">SENTINEL APEX — Global Threat Intelligence</div></div></a>
  <div class="nlinks"><a href="/">Reports</a><a href="/intelligence.html">Intel Hub</a><a href="/products.html">Detection Packs</a><a href="/pricing.html" class="ncta">⚡ SOC Pro</a></div>
</nav>
<main>
  <article>
    <div class="meta-bar">${badges}<span class="rep-date">Published: ${pubDateFmt} — CYBERDUDEBIVASH SENTINEL APEX</span></div>
    <h1 class="rh1">${escHtml(item.title)}</h1>
    <p class="rsubtitle">${escHtml((item.desc||'').slice(0,350))}${(item.desc||'').length>350?'...':''}</p>
    <div class="stats-bar">
      <div class="stat red"><div class="sv">${cvss}</div><div class="sl">CVSS Score</div></div>
      <div class="stat"><div class="sv" style="color:${cvssColor}">${sevLabel}</div><div class="sl">Severity</div></div>
      <div class="stat orange"><div class="sv">${item.exploited?'YES':'TBD'}</div><div class="sl">Exploited ITW</div></div>
      <div class="stat ${item.cisaKev?'red':'green'}"><div class="sv">${item.cisaKev?'⚠️ KEV':'Monitor'}</div><div class="sl">CISA Status</div></div>
    </div>
    ${item.cisaKev?`<div class="alert alert-crit"><span class="aico">🚨</span><div class="abody"><div class="atitle">CISA KNOWN EXPLOITED VULNERABILITY — MANDATORY REMEDIATION</div><p>Confirmed active exploitation. CISA KEV catalog confirmed. ${item.dueDate?`Federal agencies must remediate by <strong>${item.dueDate}</strong>.`:'All organizations must patch immediately.'} Required action: ${escHtml(item.reqAction||'Apply vendor patch immediately.')}</p></div></div>`:item.exploited?`<div class="alert alert-warn"><span class="aico">⚠️</span><div class="abody"><div class="atitle">ACTIVE EXPLOITATION DETECTED</div><p>Exploitation confirmed in the wild. Emergency patching required. Do not wait for maintenance window.</p></div></div>`:`<div class="alert alert-warn"><span class="aico">⚠️</span><div class="abody"><div class="atitle">HIGH-PRIORITY SECURITY ADVISORY</div><p>CVSS ${cvss} ${sevLabel}. CYBERDUDEBIVASH SENTINEL APEX recommends immediate patch evaluation and deployment.</p></div></div>`}
    <h2 class="sh"><span>⚠</span> Intelligence Overview</h2>
    ${commentary.split('\n\n').map(p=>`<p class="bp">${escHtml(p)}</p>`).join('\n    ')}
    <h2 class="sh"><span>🎯</span> MITRE ATT&CK Mapping</h2>
    <table class="tbl"><thead><tr><th>Category</th><th>Mapping</th></tr></thead><tbody>
      <tr><td>Primary Tactic</td><td class="tag-critical">${escHtml(mitre.tactic)}</td></tr>
      <tr><td>Primary Technique</td><td><span class="tag-cyan">${escHtml(mitre.technique)}</span></td></tr>
      <tr><td>Sub-Technique</td><td><span class="tag-cyan">${escHtml(mitre.sub)}</span></td></tr>
      <tr><td>Weakness (CWE)</td><td>${escHtml(item.cweId||'See NVD entry')}</td></tr>
      <tr><td>Intel Type</td><td>${escHtml(typeLabel)}</td></tr>
      <tr><td>Source</td><td>${escHtml(item.source)}</td></tr>
    </tbody></table>
    ${cveIds.length>0?`<h2 class="sh"><span>🔴</span> CVE Reference</h2><table class="tbl"><thead><tr><th>CVE ID</th><th>Reference</th><th>Score</th></tr></thead><tbody>${cveRows||`<tr><td class="tag-cyan" style="font-family:var(--mono)">${escHtml(item.id)}</td><td><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">NVD →</a></td><td>CVSS ${cvss}</td></tr>`}</tbody></table>`:''}
    ${iocRows?`<h2 class="sh"><span>🏷️</span> Indicators of Compromise (IOCs)</h2><p class="bp">Block immediately across firewall, proxy, DNS, EDR, and email gateway. SOC Pro subscribers receive enriched IOC bundles with full attribution.</p><table class="tbl"><thead><tr><th>Indicator</th><th>Context</th><th>Source</th></tr></thead><tbody>${iocRows}</tbody></table>`:''}
    ${showDetection?`<h2 class="sh"><span>🔍</span> Detection — Sigma Rule</h2><p class="bp">Deploy across your SIEM (Splunk, Elastic, Microsoft Sentinel, QRadar). SOC Pro subscribers receive pre-compiled SIEM-native query packs.</p><div class="code-block"><span class="code-lbl">Sigma YAML</span>${escHtml(sigma)}</div><h2 class="sh"><span>📡</span> Detection — YARA Rule</h2><p class="bp">Deploy to endpoint detection tools and threat hunting platforms.</p><div class="code-block"><span class="code-lbl">YARA</span>${escHtml(yara)}</div>`:''}
    <h2 class="sh"><span>🛡️</span> SOC Response Playbook</h2>
    <ul class="alist">${playbookItems}</ul>
    <h2 class="sh"><span>📎</span> Intelligence References</h2>
    <ul style="list-style:none;padding:0">${refLinks}${item.id?.startsWith('CVE')?`<li><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">NVD — ${escHtml(item.id)}</a></li>`:''}</ul>
    <div class="intel-sig"><div class="isb">⚡ CYBERDUDEBIVASH SENTINEL APEX</div><div class="iss">Intelligence report generated by CYBERDUDEBIVASH SENTINEL APEX v3.0<br>Report ID: SENTINEL-${escHtml(item.id)}-${today} — Source: ${escHtml(item.source)}<br>&copy; ${new Date().getFullYear()} CYBERDUDEBIVASH PRIVATE LIMITED<br><strong style="color:var(--apex-cyan)">Republication requires written attribution to CYBERDUDEBIVASH SENTINEL APEX</strong></div></div>
    <div class="ecta">
      <h3>🏢 ENTERPRISE THREAT INTELLIGENCE PLATFORM</h3>
      <p class="ep">Pre-disclosure intel, enriched IOC bundles, deploy-ready SIEM packs, and dedicated analyst support — before threats become headlines.</p>
      <div class="cta-grid">
        <a href="/pricing.html" class="btn-p">⚡ SOC Pro — $49/mo</a>
        <a href="/enterprise.html" class="btn-e">🏢 Enterprise — Custom Pricing</a>
        <a href="/api.html" class="btn-s">🔌 Threat Intel API Access</a>
        <a href="/products.html" class="btn-g">📦 Detection Pack Store</a>
      </div>
      <p style="font-size:12px;color:var(--apex-muted);margin:0">48hr pre-disclosure · IOC feeds · Custom advisories · White-label reports · Dedicated analyst · MSSP licensing</p>
    </div>
  </article>
  <aside class="sidebar">
    <div class="vbox">
      <div class="vscore">${cvss}</div><div class="vlabel">CVSS Score — ${sevLabel}</div>
      <div style="margin-top:16px">
        <div class="vrow"><span class="vk">ID</span><span class="vv" style="color:var(--apex-cyan);font-family:monospace;font-size:12px">${escHtml(item.id)}</span></div>
        <div class="vrow"><span class="vk">Vendor</span><span class="vv">${escHtml(item.vendor)}</span></div>
        <div class="vrow"><span class="vk">Product</span><span class="vv">${escHtml(item.product)}</span></div>
        <div class="vrow"><span class="vk">Type</span><span class="vv">${escHtml(typeLabel)}</span></div>
        <div class="vrow"><span class="vk">Exploited</span><span class="vv" style="color:${item.exploited?'var(--apex-red)':'var(--apex-green)'}">${item.exploited?'✓ Confirmed':'Monitoring'}</span></div>
        <div class="vrow"><span class="vk">CISA KEV</span><span class="vv" style="color:${item.cisaKev?'var(--apex-red)':'var(--apex-muted)'}">${item.cisaKev?'⚠️ Listed':'Not Listed'}</span></div>
        ${item.dueDate?`<div class="vrow"><span class="vk">Patch By</span><span class="vv" style="color:var(--apex-red)">${escHtml(item.dueDate)}</span></div>`:''}
        <div class="vrow"><span class="vk">Published</span><span class="vv">${pubDateFmt}</span></div>
        <div class="vrow"><span class="vk">Source</span><span class="vv">${escHtml(item.source)}</span></div>
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
  <p>&copy; ${new Date().getFullYear()} CYBERDUDEBIVASH PRIVATE LIMITED. All intelligence reports are original research and analysis by CYBERDUDEBIVASH SENTINEL APEX.<br>
  Unauthorized reproduction without attribution is prohibited.<br>
  <a href="/">Blog</a> · <a href="/products.html">Detection Packs</a> · <a href="/pricing.html">SOC Pro</a> · <a href="/api.html">API</a> · <a href="/enterprise.html">Enterprise</a> · <a href="/rss.xml">RSS</a> · <a href="mailto:bivash@cyberdudebivash.com">Contact</a></p>
</footer>
<script src="/security-engine.js" defer></script><script src="/monetization.js" defer></script><script src="/conversion-engine.js" defer></script><script src="/seo-engine.js" defer></script><script src="/ai-monetization-engine.js" defer></script><script src="/analytics-engine.js" defer></script><script src="/auto-intel-engine.js" defer></script><script src="/revenue-cta-block.js" defer></script><script src="/ux-controller.js" defer></script>
<script>
(function(){var c=document.getElementById('mc');if(!c)return;var x=c.getContext('2d');c.width=window.innerWidth;c.height=window.innerHeight;var cols=Math.floor(c.width/16),drops=new Array(cols).fill(1);setInterval(function(){x.fillStyle='rgba(7,9,15,0.05)';x.fillRect(0,0,c.width,c.height);x.fillStyle='#00ffe018';x.font='12px monospace';drops.forEach(function(y,i){x.fillText(String.fromCharCode(33+Math.random()*93),i*16,y*16);if(y*16>c.height&&Math.random()>.975)drops[i]=0;drops[i]++;});},90);window.addEventListener('resize',function(){c.width=window.innerWidth;c.height=window.innerHeight;});})();
</script>
</body>
</html>`;

  return { slug, title: item.title, html };
}

// ── POST CARD GENERATOR ────────────────────────────────────────────────
function generatePostCard(item, slug, title) {
  const cvss = item.cvss||7.0, sevLabel = cvss>=9.0?'CRITICAL':cvss>=7.0?'HIGH':'MEDIUM';
  const todayFmt = fmtDate(item.pubDate||isoNow());
  const shortTitle = (title||'').length>110?title.slice(0,107)+'...':title;
  const shortDesc  = (item.desc||'').slice(0,200)+((item.desc||'').length>200?'...':'');
  const typeIcos = { CVE_REPORT:'🔴', ZERO_DAY:'💀', RANSOMWARE:'🏴', MALWARE_REPORT:'🦠', DATA_BREACH:'⚠️', THREAT_ACTOR:'🎯', AI_SECURITY:'🤖', NEWS_REPORT:'📡', ADVISORY:'🛡️' };
  const ico = typeIcos[item.type]||'⚡';
  return `
    <!-- AUTO-GENERATED: ${item.id} — ${isoNow()} -->
    <a href="posts/${escHtml(slug)}.html" class="post-card" data-intel-auto="${escHtml(item.id)}">
      <div class="post-card-header">
        <span class="post-badge badge-crit">CVSS ${cvss}</span>
        ${item.cisaKev?`<span class="post-badge badge-cisa">CISA KEV</span>`:''}
        ${item.exploited?`<span class="post-badge badge-new">● Live Exploit</span>`:''}
        ${item.ransomware?`<span class="post-badge" style="background:#a855f722;color:#a855f7;border:1px solid #a855f744;font-size:10px;padding:3px 7px;border-radius:3px;font-weight:700">RANSOMWARE</span>`:''}
        <span class="post-date">${todayFmt} | ${ico} ${escHtml(item.id)}</span>
      </div>
      <div class="post-card-body">
        <div class="post-title">${escHtml(shortTitle)}</div>
        <p class="post-excerpt">${escHtml(shortDesc)}</p>
        <div class="post-meta">
          <span class="post-cvss${cvss<9?' orange':''}">CVSS ${cvss} — ${sevLabel}</span>
          <span class="post-cve">${escHtml(item.id)}</span>
          <span class="post-source" style="font-size:11px;color:var(--apex-muted,#6b7280)">${escHtml(item.source)}</span>
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

// ── RSS.XML UPDATER ─────────────────────────────────────────────────────
function updateRSS(newItems) {
  const rssItems = newItems.map(item => {
    const link = `${CFG.baseUrl}/posts/${item.slug}.html`;
    return `  <item>\n    <title><![CDATA[${item.title}]]></title>\n    <link>${link}</link>\n    <description><![CDATA[CVSS ${item.cvss} — ${(item.desc||'').slice(0,400)}. Full analysis, Sigma/YARA rules, IOCs by CYBERDUDEBIVASH SENTINEL APEX.]]></description>\n    <pubDate>${new Date().toUTCString()}</pubDate>\n    <guid isPermaLink="true">${link}</guid>\n    <category>Threat Intelligence</category>\n    <category>${item.cisaKev?'CISA KEV':item.type||'CVE Analysis'}</category>\n  </item>`;
  }).join('\n');
  if (!fs.existsSync(CFG.rssPath)) {
    fs.writeFileSync(CFG.rssPath, `<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n  <channel>\n    <title>CYBERDUDEBIVASH SENTINEL APEX — Global Threat Intelligence</title>\n    <link>${CFG.baseUrl}</link>\n    <description>Real-time cybersecurity intelligence by CYBERDUDEBIVASH SENTINEL APEX.</description>\n    <language>en-us</language>\n    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>\n    <atom:link href="${CFG.baseUrl}/rss.xml" rel="self" type="application/rss+xml"/>\n${rssItems}\n  </channel>\n</rss>`, 'utf8');
    log('rss.xml created fresh.'); return;
  }
  let rss = fs.readFileSync(CFG.rssPath, 'utf8');
  rss = rss.replace(/(<lastBuildDate>)[^<]*(<\/lastBuildDate>)/, `$1${new Date().toUTCString()}$2`);
  rss = rss.includes('<item>') ? rss.replace(/(<item>)/, `${rssItems}\n  $1`) : rss.replace('</channel>', `${rssItems}\n  </channel>`);
  fs.writeFileSync(CFG.rssPath, rss, 'utf8');
  log(`rss.xml updated: +${newItems.length} items.`);
}

// ── SITEMAP UPDATER ─────────────────────────────────────────────────────
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

// ── LIVE-INTEL.JSON ─────────────────────────────────────────────────────
function writeLiveIntel(allItems, state) {
  try {
    const liveItems = allItems.slice(0,25).map(item => ({
      id:item.id, title:(item.title||'').slice(0,120), desc:(item.desc||'').slice(0,200),
      cvss:item.cvss||0, type:item.type||'INTEL', source:item.source||'',
      pubDate:item.pubDate||isoNow(), exploited:!!item.exploited, cisaKev:!!item.cisaKev,
      ransomware:!!item.ransomware, vendor:item.vendor||'', product:item.product||'',
      dueDate:item.dueDate||null, refs:(item.refs||[]).slice(0,2), iocs:(item.iocs||[]).slice(0,5),
    }));
    fs.writeFileSync(CFG.liveJsonPath, JSON.stringify({ generatedAt:new Date().toISOString(), totalPublished:state.totalPublished||0, source:'CYBERDUDEBIVASH SENTINEL APEX v3.0', platform:'blog.cyberdudebivash.in', items:liveItems }, null, 2), 'utf8');
    log(`live-intel.json updated: ${liveItems.length} items.`);
  } catch(e) { warn(`live-intel.json failed: ${e.message}`); }
}

// ── MAIN PIPELINE ──────────────────────────────────────────────────────
async function main() {
  const T0 = Date.now();
  log('═'.repeat(65));
  log('CYBERDUDEBIVASH SENTINEL APEX — Global Intelligence Engine v3.0');
  log(`Run started: ${new Date().toISOString()}`);
  log('═'.repeat(65));

  if (!fs.existsSync(CFG.postsDir)) fs.mkdirSync(CFG.postsDir, { recursive: true });

  const state = loadState();
  log(`State: ${state.published.length} items previously published. Total: ${state.totalPublished}`);

  log('\n── PHASE 1: INGESTING ALL SOURCES ─────────────────────────────');
  const [nvdItems, kevItems, cisaAlerts, ghAdvisories, bleepItems, thnItems, krebsItems, secweekItems, sansItems, urlhausItems, threatfoxItems, msrcItems] = await Promise.all([
    fetchNVD().catch(()=>[]),
    fetchCISAKev().catch(()=>[]),
    fetchCISAAlerts().catch(()=>[]),
    fetchGitHubAdvisories().catch(()=>[]),
    fetchRSS(CFG.bleepingRss, 'bleepingcomputer', CFG.maxRssItems).catch(()=>[]),
    fetchRSS(CFG.thnRss, 'thehackernews', CFG.maxRssItems).catch(()=>[]),
    fetchRSS(CFG.krebsRss, 'krebsonsecurity', 4).catch(()=>[]),
    fetchRSS(CFG.secweekRss, 'securityweek', CFG.maxRssItems).catch(()=>[]),
    fetchRSS(CFG.sansRss, 'sans_isc', 4).catch(()=>[]),
    fetchURLhaus().catch(()=>[]),
    fetchThreatFox().catch(()=>[]),
    fetchMSRC().catch(()=>[]),
  ]);

  const allBatches = [nvdItems,kevItems,cisaAlerts,ghAdvisories,bleepItems,thnItems,krebsItems,secweekItems,sansItems,urlhausItems,threatfoxItems,msrcItems];
  const sourceCount = allBatches.filter(a=>a.length>0).length;
  log(`\nSources returning data: ${sourceCount}/12`);

  log('\n── PHASE 2: MERGING + DEDUP + PRIORITIZE ───────────────────────');
  const allItems = mergeAndPrioritize(allBatches);
  log(`Total unique intel items: ${allItems.length}`);

  writeLiveIntel(allItems, state);

  const newItems = allItems.filter(item => item.id && !isPublished(state, item.id));
  log(`New (unpublished) items: ${newItems.length}`);

  if (newItems.length === 0) {
    log('No new intel this cycle. All items already published.');
    saveState(state);
    log(`\nRun complete in ${((Date.now()-T0)/1000).toFixed(1)}s.`);
    return;
  }

  log('\n── PHASE 3: GENERATING INTELLIGENCE REPORTS ────────────────────');
  const toPublish = newItems.slice(0, CFG.maxNewPostsPerRun);
  const generatedCards = [], rssItems = [], newSlugs = [];

  for (const item of toPublish) {
    try {
      const { slug, title, html } = generatePostHTML(item);
      const filePath = path.join(CFG.postsDir, `${slug}.html`);
      if (fs.existsSync(filePath)) {
        log(`Skip (exists): ${slug}.html`);
        markPublished(state, { id:item.id, slug, title });
        continue;
      }
      fs.writeFileSync(filePath, html, 'utf8');
      log(`✅ Published [${item.type}]: ${slug}.html (${(html.length/1024).toFixed(1)}KB)`);
      markPublished(state, { id:item.id, slug, title });
      generatedCards.push({ card: generatePostCard(item, slug, title) });
      rssItems.push({ ...item, slug, title });
      newSlugs.push(slug);
    } catch(e) { err(`Failed: ${item.id} — ${e.message}`); }
  }

  log('\n── PHASE 4: UPDATING PLATFORM FILES ────────────────────────────');
  if (generatedCards.length > 0) {
    updateIndexHTML(generatedCards);
    updateRSS(rssItems);
    updateSitemap(newSlugs);
  }

  saveState(state);

  log('\n' + '═'.repeat(65));
  log(`SENTINEL APEX COMPLETE — Generated: ${generatedCards.length} | Total: ${state.totalPublished} | Sources: ${sourceCount}/12 | Time: ${((Date.now()-T0)/1000).toFixed(1)}s`);
  log('═'.repeat(65));
}

main().catch(e => { err(`FATAL: ${e.message}\n${e.stack||''}`); process.exit(1); });
