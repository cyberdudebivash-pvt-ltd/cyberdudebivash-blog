#!/usr/bin/env node
/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH® SENTINEL APEX™ — AI SECURITY INTELLIGENCE ENGINE
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * A DEDICATED AI security intelligence pipeline, run alongside — never merged
 * with — the general cyber intel pipeline (fetch-live-intel.js). AI security
 * uses different frameworks (MITRE ATLAS, OWASP LLM Top 10) than endpoint /
 * network security, so it gets its own collection, classification, mapping,
 * and quality gates. See Sentinel-APEX/pipeline/AI-SECURITY-PIPELINE.md.
 *
 * Doctrine: Sentinel-APEX/prompts/ai-security-master-prompt.md
 *   Evidence First · Verification First · Never invent · Always assign confidence
 *
 * Stages: Collection → Source Verification → AI Classification → Evidence
 *   Correlation → MITRE ATLAS → OWASP LLM Top 10 → Agent Risk → Enterprise
 *   Impact → Detection Engineering → Threat Hunting → (Executive Review) →
 *   Quality Gates → Publishing → API/Dashboard/Alerts
 *
 * Dependency-free. Node >= 18 (global fetch). Atomic writes. No secrets.
 *
 * Usage:
 *   node ai-security-intel-engine.js            # full run: collect → publish
 *   node ai-security-intel-engine.js --dry-run  # no writes; print decisions
 *   ANTHROPIC_API_KEY=... node ai-security-intel-engine.js --analyst
 * ═══════════════════════════════════════════════════════════════════════════
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const ARGS = process.argv.slice(2);
const DRY_RUN = ARGS.includes('--dry-run');
const RUN_ANALYST = ARGS.includes('--analyst') || !!process.env.AISEC_ANALYST;

const CFG = {
  // Output products
  feedPath:      path.join(ROOT, 'api', 'intel', 'ai-security.json'),
  listingPath:   path.join(ROOT, 'ai-security', 'intel', 'index.html'),
  reportsDir:    path.join(ROOT, 'ai-security', 'reports'),
  statePath:     path.join(ROOT, 'ai-security-intel-state.json'),
  memoryPath:    path.join(ROOT, 'ai-security-intel-memory.json'),
  lockPath:      path.join(ROOT, 'ai-security-intel.lock'),

  // Collection
  sourceTimeoutMs: 15000,
  maxFeedItems:    120,      // machine-readable feed cap
  maxLeadsRetained: 400,     // held (unpublished) leads cap in state
  lookbackDays:    45,       // ignore items older than this

  // Analyst (LLM) stage
  anthropicModel:  'claude-opus-4-8',
  anthropicKey:    process.env.ANTHROPIC_API_KEY || '',
  analystMaxReports: 3,      // cap LLM calls per run (cost control)

  userAgent: 'CYBERDUDEBIVASH-SENTINEL-APEX-AISEC/1.0 (+https://blog.cyberdudebivash.in)',
};

// ── SOURCES (dedicated to AI security) ──────────────────────────────────────
// Tiering drives the evidence bar (see Quality Gates). Tier 1 = authoritative,
// Tier 2 = research, Tier 3 = community lead.
const SOURCES = [
  // TIER 1 — authoritative advisories / vuln databases
  { key: 'ghsa',      tier: 1, type: 'ghsa',  name: 'GitHub Security Advisories',
    url: 'https://api.github.com/advisories?per_page=60&sort=published' },
  { key: 'nvd_ai',    tier: 1, type: 'nvd',   name: 'NVD (AI/LLM keyword)',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=LLM&resultsPerPage=40' },
  { key: 'nvd_pi',    tier: 1, type: 'nvd',   name: 'NVD (prompt injection)',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=prompt%20injection&resultsPerPage=40' },

  // TIER 2 — research
  { key: 'arxiv_sec', tier: 2, type: 'arxiv', name: 'arXiv cs.CR (LLM security)',
    url: 'http://export.arxiv.org/api/query?search_query=cat:cs.CR+AND+abs:%22large+language+model%22&sortBy=submittedDate&sortOrder=descending&max_results=30' },

  // TIER 3 — community leads (corroboration required before publish)
  { key: 'reddit_ml', tier: 3, type: 'rss',   name: 'r/MachineLearning',
    url: 'https://www.reddit.com/r/MachineLearning/.rss?limit=25' },
  { key: 'reddit_ns', tier: 3, type: 'rss',   name: 'r/netsec',
    url: 'https://www.reddit.com/r/netsec/.rss?limit=25' },
];

// ── AI-SECURITY TAXONOMY (from the Constitution collection targets) ─────────
// Each category: matchers (lowercase substrings), OWASP LLM id, ATLAS id.
const TAXONOMY = [
  { id: 'prompt_injection', label: 'Prompt Injection',
    match: ['prompt injection', 'indirect prompt', 'jailbreak', 'prompt leak', 'system prompt leak'],
    owasp: 'LLM01', atlas: 'AML.T0051' },
  { id: 'insecure_output', label: 'Insecure Output Handling',
    match: ['insecure output', 'output handling', 'xss via llm', 'llm output injection'],
    owasp: 'LLM02', atlas: 'AML.T0050' },
  { id: 'data_poisoning', label: 'Training / Data Poisoning',
    match: ['data poisoning', 'training data poison', 'fine-tuning poison', 'rlhf attack', 'backdoor model', 'model backdoor'],
    owasp: 'LLM04', atlas: 'AML.T0020' },
  { id: 'supply_chain', label: 'AI Supply Chain',
    match: ['ai supply chain', 'model supply chain', 'poisoned model', 'malicious model', 'huggingface', 'hugging face', 'pickle model', 'safetensors'],
    owasp: 'LLM05', atlas: 'AML.T0010' },
  { id: 'sensitive_disclosure', label: 'Sensitive Information Disclosure',
    match: ['data leakage', 'training data extraction', 'membership inference', 'model inversion', 'pii leak', 'sensitive disclosure'],
    owasp: 'LLM06', atlas: 'AML.T0057' },
  { id: 'model_theft', label: 'Model Theft / Extraction',
    match: ['model stealing', 'model extraction', 'model theft', 'weight extraction'],
    owasp: 'LLM10', atlas: 'AML.T0044' },
  { id: 'rag_vector', label: 'RAG / Vector DB Attack',
    match: ['rag attack', 'vector database', 'embedding poison', 'retrieval augmented', 'vector store'],
    owasp: 'LLM08', atlas: 'AML.T0051' },
  { id: 'agent_tool', label: 'Agentic / Tool / MCP Exploitation',
    match: ['agentic', 'ai agent', 'autonomous agent', 'tool poisoning', 'tool injection', 'mcp server', 'model context protocol', 'agent-to-agent', 'excessive agency'],
    owasp: 'LLM06', atlas: 'AML.T0053' },
  { id: 'excessive_agency', label: 'Excessive Agency',
    match: ['excessive agency', 'overprivileged agent', 'unbounded consumption', 'denial of wallet'],
    owasp: 'LLM06', atlas: 'AML.T0053' },
  { id: 'infra', label: 'AI Infrastructure / Inference Server',
    match: ['inference server', 'triton', 'vllm', 'ollama', 'llama.cpp', 'inference gateway', 'gpu', 'ml pipeline', 'mlflow', 'ray dashboard', 'kubeflow'],
    owasp: 'LLM05', atlas: 'AML.T0010' },
  { id: 'adversarial_ml', label: 'Adversarial ML / Evasion',
    match: ['adversarial example', 'adversarial ml', 'evasion attack', 'model evasion', 'perturbation attack'],
    owasp: 'LLM09', atlas: 'AML.T0043' },
  { id: 'ai_malware', label: 'AI-Enabled Threats',
    match: ['ai malware', 'ai-generated malware', 'ai phishing', 'deepfake', 'voice cloning', 'wormgpt', 'fraudgpt', 'ai botnet', 'ai-enabled ransomware'],
    owasp: 'LLM05', atlas: 'AML.T0048' },
];

// Broad AI-relevance gate — an item must hit at least one of these to enter the
// pipeline at all (keeps general CVEs out of the AI-specific lane).
const AI_RELEVANCE = [
  'llm', 'large language model', 'genai', 'generative ai', 'gpt', 'chatgpt', 'claude',
  'gemini', 'copilot', 'prompt', 'ai agent', 'agentic', 'mcp', 'model context protocol',
  'rag', 'embedding', 'vector database', 'hugging face', 'huggingface', 'transformers',
  'pytorch', 'tensorflow', 'ollama', 'vllm', 'langchain', 'llamaindex', 'openai',
  'anthropic', 'machine learning model', 'neural network', 'foundation model',
  'inference server', 'ai security', 'ml security', 'adversarial', 'deepfake', 'owasp llm',
];

const OWASP_NAMES = {
  LLM01: 'Prompt Injection', LLM02: 'Insecure Output Handling',
  LLM03: 'Training Data Poisoning', LLM04: 'Model Denial of Service / Data & Model Poisoning',
  LLM05: 'Supply Chain Vulnerabilities', LLM06: 'Sensitive Information Disclosure / Excessive Agency',
  LLM07: 'Insecure Plugin / System Prompt Leakage', LLM08: 'Vector and Embedding Weaknesses',
  LLM09: 'Misinformation', LLM10: 'Unbounded Consumption / Model Theft',
};
const ATLAS_NAMES = {
  'AML.T0010': 'ML Supply Chain Compromise', 'AML.T0020': 'Poison Training Data',
  'AML.T0043': 'Craft Adversarial Data', 'AML.T0044': 'Full ML Model Access / Extraction',
  'AML.T0048': 'External Harms', 'AML.T0050': 'Command and Scripting Interpreter',
  'AML.T0051': 'LLM Prompt Injection', 'AML.T0053': 'LLM Plugin Compromise',
  'AML.T0057': 'LLM Data Leakage',
};

// ── UTILITIES ───────────────────────────────────────────────────────────────
const log  = m => console.log(`[AISEC] ${m}`);
const warn = m => console.warn(`[WARN]  ${m}`);
const errl = m => console.error(`[ERR]   ${m}`);
const isoNow = () => new Date().toISOString();
const idOf = s => crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 16);
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const lc = s => String(s || '').toLowerCase();
const clip = (s, n) => { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };

function safeWriteSync(filePath, data) {
  if (DRY_RUN) { log(`[dry-run] would write ${path.relative(ROOT, filePath)} (${data.length} bytes)`); return; }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = filePath + '.tmp';
  try { fs.writeFileSync(tmp, data, 'utf8'); fs.renameSync(tmp, filePath); }
  catch (e) { try { fs.unlinkSync(tmp); } catch (_) {} throw e; }
}

function readJSON(filePath, fallback) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch (_) { return fallback; }
}

function acquireLock() {
  try {
    if (fs.existsSync(CFG.lockPath)) {
      const l = readJSON(CFG.lockPath, {});
      if (Date.now() - (l.acquired || 0) < 10 * 60000) {
        warn('Another run holds the lock. Aborting.'); return false;
      }
      warn('Stale lock overridden.');
    }
    if (!DRY_RUN) fs.writeFileSync(CFG.lockPath, JSON.stringify({ acquired: Date.now(), pid: process.pid }));
    return true;
  } catch (e) { warn(`Lock failed (fail-open): ${e.message}`); return true; }
}
function releaseLock() { try { if (fs.existsSync(CFG.lockPath)) fs.unlinkSync(CFG.lockPath); } catch (_) {} }

async function httpGet(url, headers, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs || CFG.sourceTimeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: Object.assign({ 'User-Agent': CFG.userAgent, 'Accept': '*/*' }, headers || {}),
    });
    const body = await res.text();
    return { ok: res.ok, status: res.status, body };
  } finally { clearTimeout(t); }
}

// Minimal, dependency-free XML/RSS/Atom field extraction.
function extractTags(xml, tag) {
  const out = [];
  const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'gi');
  let m; while ((m = re.exec(xml)) !== null) out.push(m[1]);
  return out;
}
function stripCdata(s) {
  return String(s || '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/\s+/g, ' ').trim();
}
function firstAttr(block, tag, attr) {
  const re = new RegExp(`<${tag}[^>]*${attr}=["']([^"']+)["']`, 'i');
  const m = re.exec(block); return m ? m[1] : '';
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 1 — COLLECTION (per-source parsers → normalized raw items)
// ═══════════════════════════════════════════════════════════════════════════
function parseGHSA(body, src) {
  let arr; try { arr = JSON.parse(body); } catch (_) { return []; }
  if (!Array.isArray(arr)) return [];
  return arr.map(a => ({
    title: a.summary || a.ghsa_id,
    summary: a.description || a.summary || '',
    url: a.html_url || `https://github.com/advisories/${a.ghsa_id}`,
    published: a.published_at || a.updated_at,
    cve: a.cve_id || null,
    severity: (a.severity || '').toLowerCase() || null,
    vendors: (a.vulnerabilities || []).map(v => v && v.package && v.package.name).filter(Boolean),
    source: src.name, sourceKey: src.key, tier: src.tier,
  }));
}
function parseNVD(body, src) {
  let obj; try { obj = JSON.parse(body); } catch (_) { return []; }
  const vulns = (obj && obj.vulnerabilities) || [];
  return vulns.map(v => {
    const c = v.cve || {};
    const desc = ((c.descriptions || []).find(d => d.lang === 'en') || {}).value || '';
    const metrics = c.metrics || {};
    const cvss = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || [])[0];
    const score = cvss && cvss.cvssData ? cvss.cvssData.baseScore : null;
    return {
      title: `${c.id} — ${clip(desc, 90)}`,
      summary: desc, url: `https://nvd.nist.gov/vuln/detail/${c.id}`,
      published: c.published || c.lastModified, cve: c.id,
      severity: score != null ? (score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low') : null,
      cvss: score, vendors: [],
      source: src.name, sourceKey: src.key, tier: src.tier,
    };
  });
}
function parseArxiv(body, src) {
  const entries = extractTags(body, 'entry');
  return entries.map(e => ({
    title: stripCdata(extractTags(e, 'title')[0]),
    summary: stripCdata(extractTags(e, 'summary')[0]),
    url: (firstAttr(e, 'link', 'href') || stripCdata(extractTags(e, 'id')[0])),
    published: stripCdata(extractTags(e, 'published')[0]),
    cve: null, severity: null, vendors: [],
    source: src.name, sourceKey: src.key, tier: src.tier,
  }));
}
function parseRSS(body, src) {
  let items = extractTags(body, 'item');
  if (!items.length) items = extractTags(body, 'entry'); // Atom
  return items.map(it => {
    const link = firstAttr(it, 'link', 'href') || stripCdata(extractTags(it, 'link')[0]);
    return {
      title: stripCdata(extractTags(it, 'title')[0]),
      summary: stripCdata(extractTags(it, 'description')[0] || extractTags(it, 'summary')[0] || extractTags(it, 'content')[0]),
      url: link,
      published: stripCdata(extractTags(it, 'pubDate')[0] || extractTags(it, 'published')[0] || extractTags(it, 'updated')[0]),
      cve: null, severity: null, vendors: [],
      source: src.name, sourceKey: src.key, tier: src.tier,
    };
  });
}

async function collect(health) {
  const parsers = { ghsa: parseGHSA, nvd: parseNVD, arxiv: parseArxiv, rss: parseRSS };
  const results = await Promise.all(SOURCES.map(async src => {
    const h = { name: src.name, key: src.key, tier: src.tier, status: 'ok', items: 0, error: null };
    try {
      const headers = src.type === 'ghsa'
        ? { 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }
        : {};
      const r = await httpGet(src.url, headers);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const items = (parsers[src.type] || parseRSS)(r.body, src).filter(x => x.title && x.url);
      h.items = items.length;
      health.push(h);
      return items;
    } catch (e) {
      h.status = 'degraded'; h.error = e.message; health.push(h);
      warn(`source ${src.key}: ${e.message}`);
      return [];
    }
  }));
  return results.flat();
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 2 — SOURCE VERIFICATION (relevance gate + freshness + normalization)
// ═══════════════════════════════════════════════════════════════════════════
function isAiRelevant(item) {
  const hay = lc(item.title + ' ' + item.summary);
  return AI_RELEVANCE.some(k => hay.includes(k));
}
function isFresh(item) {
  const t = Date.parse(item.published);
  if (isNaN(t)) return true; // undated → keep (research often lacks a clean date)
  return (Date.now() - t) <= CFG.lookbackDays * 86400000;
}
function verify(rawItems) {
  const seen = new Set();
  const out = [];
  for (const it of rawItems) {
    if (!isAiRelevant(it) || !isFresh(it)) continue;
    const id = idOf(it.url || it.title);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(Object.assign({ id }, it));
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 3 — AI-SPECIFIC CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════════
function classify(item) {
  const hay = lc(item.title + ' ' + item.summary);
  const cats = TAXONOMY.filter(c => c.match.some(m => hay.includes(m)));
  return cats.length ? cats : null; // null → not AI-security-specific enough
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 5/6 — MITRE ATLAS + OWASP LLM Top 10 MAPPING
// ═══════════════════════════════════════════════════════════════════════════
function mapFrameworks(cats) {
  const owasp = [...new Set(cats.map(c => c.owasp))].map(id => ({ id, name: OWASP_NAMES[id] || id }));
  const atlas = [...new Set(cats.map(c => c.atlas))].map(id => ({ id, name: ATLAS_NAMES[id] || id }));
  return { owasp, atlas };
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 7 — AI AGENT RISK ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════
function agentRisk(item, cats) {
  const hay = lc(item.title + ' ' + item.summary);
  const flags = {
    agentic: /agentic|ai agent|autonomous agent|agent-to-agent/.test(hay),
    mcp: /mcp|model context protocol/.test(hay),
    rag: /rag|retrieval augmented|vector (db|database|store)|embedding/.test(hay),
    tool_use: /tool (use|poison|inject)|function calling|plugin/.test(hay),
    supply_chain: cats.some(c => c.id === 'supply_chain'),
  };
  const score = Object.values(flags).filter(Boolean).length;
  return { flags, level: score >= 3 ? 'high' : score >= 1 ? 'elevated' : 'standard' };
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 8 — ENTERPRISE IMPACT ASSESSMENT
// ═══════════════════════════════════════════════════════════════════════════
function enterpriseImpact(item, cats, risk) {
  let score = 0;
  if (item.severity === 'critical') score += 40;
  else if (item.severity === 'high') score += 28;
  else if (item.severity === 'medium') score += 15;
  if (item.cve) score += 15;
  if (risk.level === 'high') score += 20; else if (risk.level === 'elevated') score += 10;
  if (cats.some(c => ['supply_chain', 'agent_tool', 'prompt_injection'].includes(c.id))) score += 10;
  score = Math.min(100, score);
  return { score, priority: score >= 65 ? 'P1' : score >= 40 ? 'P2' : 'P3' };
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 9/10 — DETECTION ENGINEERING + THREAT HUNTING GUIDANCE
// ═══════════════════════════════════════════════════════════════════════════
const DETECTION_PLAYBOOK = {
  prompt_injection: {
    detect: 'Monitor LLM gateway logs for delimiter-breaking tokens, role-swap phrases ("ignore previous", "you are now"), and base64/hex blobs in user or retrieved content.',
    hunt: 'Correlate anomalous tool-invocation sequences that immediately follow untrusted content ingestion (email, web, RAG chunks).',
  },
  supply_chain: {
    detect: 'Alert on model artifact downloads from non-allowlisted registries; scan pickled/`.pt` model files for arbitrary code (Fickling, ModelScan).',
    hunt: 'Review CI/CD and notebook hosts for outbound connections initiated during model load.',
  },
  agent_tool: {
    detect: 'Log every agent tool call with arguments; alert on tools reaching unexpected hosts, filesystem paths, or privileged actions.',
    hunt: 'Trace agent action chains for excessive-agency patterns (self-granted scope, unbounded loops, denial-of-wallet spend).',
  },
  data_poisoning: {
    detect: 'Track training/fine-tune dataset provenance and hash drift; flag label anomalies and out-of-distribution samples.',
    hunt: 'Audit dataset contribution history for low-reputation or newly-added sources preceding a behavior change.',
  },
  rag_vector: {
    detect: 'Monitor vector-store writes for unusual ingestion volume and content that scores high on injection heuristics.',
    hunt: 'Sample retrieved chunks that led to unexpected model actions; check for embedded instructions.',
  },
  sensitive_disclosure: {
    detect: 'DLP on LLM responses for secrets/PII patterns; alert on repeated boundary-probing queries.',
    hunt: 'Look for membership-inference / extraction query cadences against model or embedding APIs.',
  },
  infra: {
    detect: 'Expose-check inference servers (Triton/vLLM/Ollama/MLflow/Ray) for unauthenticated management endpoints.',
    hunt: 'Shodan/asset-inventory sweep for AI infra bound to 0.0.0.0 without auth.',
  },
};
const DEFAULT_DETECTION = {
  detect: 'Instrument the AI application boundary (gateway, tool layer, model API) with structured logging and anomaly alerting.',
  hunt: 'Baseline normal model/agent behavior, then hunt for deviations tied to untrusted input.',
};
function detectionGuidance(cats) {
  const primary = cats[0] && (DETECTION_PLAYBOOK[cats[0].id] || null);
  return primary || DEFAULT_DETECTION;
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 4 — EVIDENCE CORRELATION + CONFIDENCE
// ═══════════════════════════════════════════════════════════════════════════
function correlate(item, memory) {
  // corroboration = how many distinct sources reference the same CVE or URL host
  const key = item.cve || item.url;
  const priorSources = (memory.corroboration && memory.corroboration[key]) || [];
  const sourceSet = new Set(priorSources.concat(item.sourceKey));
  return { key, corroborations: sourceSet.size, sources: [...sourceSet] };
}
function confidence(item, corr) {
  // Constitution confidence model (subset, with rationale)
  let source, evidence, overall, rationale;
  if (item.tier === 1) {
    source = 'HIGH'; evidence = item.cve ? 'HIGH' : 'MODERATE';
    overall = 'HIGH';
    rationale = `Authoritative source (${item.source})${item.cve ? ' with assigned CVE' : ''}.`;
  } else if (item.tier === 2) {
    source = 'MODERATE'; evidence = corr.corroborations >= 2 ? 'MODERATE' : 'LOW';
    overall = corr.corroborations >= 2 ? 'MODERATE' : 'LOW';
    rationale = `Research source; ${corr.corroborations} corroborating source(s).`;
  } else {
    source = 'LOW'; evidence = corr.corroborations >= 2 ? 'MODERATE' : 'LOW';
    overall = corr.corroborations >= 3 ? 'MODERATE' : 'LOW';
    rationale = `Community lead; ${corr.corroborations} corroborating source(s). Treated as a lead until corroborated.`;
  }
  return { source, evidence, overall, rationale };
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 12 — QUALITY GATES (Constitution publication rules)
// ═══════════════════════════════════════════════════════════════════════════
function publicationGate(item, corr) {
  // Structural completeness
  if (!item.title || !item.url || !item.published) {
    return { publish: false, reason: 'incomplete (missing title/url/date)' };
  }
  // Evidence bar by tier
  if (item.tier === 1) return { publish: true, label: 'VERIFIED_ADVISORY' };
  if (item.tier === 2) {
    return corr.corroborations >= 1
      ? { publish: true, label: 'PUBLISHED_RESEARCH' }
      : { publish: false, reason: 'research awaiting corroboration', hold: true };
  }
  // tier 3
  return corr.corroborations >= 2
    ? { publish: true, label: 'CORROBORATED_LEAD' }
    : { publish: false, reason: 'community lead below corroboration threshold', hold: true };
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 11 — EXECUTIVE REVIEW (optional LLM analyst stage)
// ═══════════════════════════════════════════════════════════════════════════
async function runAnalyst(items) {
  if (!CFG.anthropicKey) { log('Analyst stage skipped (no ANTHROPIC_API_KEY).'); return; }
  const promptPath = path.join(ROOT, 'Sentinel-APEX', 'prompts', 'ai-security-master-prompt.md');
  const systemPrompt = fs.existsSync(promptPath)
    ? fs.readFileSync(promptPath, 'utf8')
    : 'You are the Sentinel APEX AI Security Intelligence Division. Evidence first; never invent; always assign confidence.';

  const targets = items
    .filter(i => i.enterpriseImpact.priority === 'P1')
    .slice(0, CFG.analystMaxReports);
  if (!targets.length) { log('Analyst stage: no P1 items this run.'); return; }

  for (const item of targets) {
    try {
      const userMsg = `Produce an enterprise-grade AI security intelligence report for the following verified item. `
        + `Separate Verified Facts, Correlated Observations, Analyst Assessment, Intelligence Gaps, and Future Outlook. `
        + `Map to OWASP LLM Top 10 and MITRE ATLAS where applicable. Assign confidence with rationale.\n\n`
        + `TITLE: ${item.title}\nSOURCE: ${item.source} (tier ${item.tier})\nURL: ${item.url}\n`
        + `CVE: ${item.cve || 'n/a'}\nCATEGORIES: ${item.categories.map(c => c.label).join(', ')}\n`
        + `OWASP: ${item.frameworks.owasp.map(o => o.id).join(', ')}\nATLAS: ${item.frameworks.atlas.map(a => a.id).join(', ')}\n`
        + `SUMMARY: ${clip(item.summary, 1200)}`;

      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': CFG.anthropicKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: CFG.anthropicModel,
          max_tokens: 4000,
          system: systemPrompt,
          messages: [{ role: 'user', content: userMsg }],
        }),
      });
      const data = await res.json();
      if (data && data.stop_reason === 'refusal') { warn(`Analyst refused: ${item.id}`); continue; }
      const text = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n');
      if (!text) { warn(`Analyst empty response: ${item.id}`); continue; }
      item.analystReport = text;
      log(`Analyst report generated: ${clip(item.title, 60)}`);
    } catch (e) { warn(`Analyst error for ${item.id}: ${e.message}`); }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 13 — PUBLISHING (feed JSON + listing HTML)
// ═══════════════════════════════════════════════════════════════════════════
function buildFeed(published, stats) {
  return JSON.stringify({
    platform: 'CYBERDUDEBIVASH SENTINEL APEX — AI Security Intelligence Division',
    endpoint: '/api/intel/ai-security.json',
    doctrine: 'Sentinel-APEX/prompts/ai-security-master-prompt.md',
    generated: isoNow(),
    disclaimer: 'Evidence-graded AI security intelligence. Confidence and evidence labels attached per item. Community leads are corroborated before publication.',
    stats,
    frameworks: { owasp_llm_top10: OWASP_NAMES, mitre_atlas: ATLAS_NAMES },
    count: published.length,
    items: published.map(i => ({
      id: i.id, title: i.title, url: i.url, source: i.source, tier: i.tier,
      published: i.published, cve: i.cve || null, severity: i.severity || null,
      cvss: i.cvss || null,
      evidence_label: i.gate.label,
      categories: i.categories.map(c => ({ id: c.id, label: c.label })),
      owasp_llm: i.frameworks.owasp, mitre_atlas: i.frameworks.atlas,
      agent_risk: i.agentRisk, enterprise_impact: i.enterpriseImpact,
      confidence: i.confidence, corroboration: i.correlation.corroborations,
      detection: i.detection,
      has_analyst_report: !!i.analystReport,
    })),
  }, null, 2);
}

function buildListing(published, stats) {
  const rows = published.map(i => {
    const owasp = i.frameworks.owasp.map(o => `<span class="tag owasp">${esc(o.id)}</span>`).join('');
    const atlas = i.frameworks.atlas.map(a => `<span class="tag atlas">${esc(a.id)}</span>`).join('');
    const pri = esc(i.enterpriseImpact.priority);
    return `      <a class="card" href="${esc(i.url)}" target="_blank" rel="noopener">
        <div class="card-top">
          <span class="pri pri-${pri}">${pri}</span>
          <span class="label">${esc(i.gate.label.replace(/_/g, ' '))}</span>
          <span class="conf conf-${esc(i.confidence.overall.toLowerCase())}">${esc(i.confidence.overall)} confidence</span>
        </div>
        <div class="card-title">${esc(clip(i.title, 140))}</div>
        <div class="card-meta">${esc(i.source)} · ${esc(i.cve || 'no CVE')} · impact ${i.enterpriseImpact.score}/100</div>
        <div class="tags">${owasp}${atlas}${i.categories.map(c => `<span class="tag cat">${esc(c.label)}</span>`).join('')}</div>
      </a>`;
  }).join('\n');

  const owaspGrid = Object.entries(OWASP_NAMES).map(([id, n]) =>
    `<div class="owasp-item"><span class="owasp-id">${esc(id)}</span><span class="owasp-name">${esc(n)}</span></div>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Security Intelligence — CYBERDUDEBIVASH SENTINEL APEX</title>
<meta name="description" content="Evidence-graded AI security intelligence: prompt injection, AI supply chain, agentic/MCP exploitation, RAG attacks, model theft — mapped to OWASP LLM Top 10 and MITRE ATLAS by the CYBERDUDEBIVASH SENTINEL APEX AI Security Intelligence Division.">
<meta name="keywords" content="AI security intelligence, OWASP LLM Top 10, MITRE ATLAS, prompt injection, AI supply chain, agentic AI security, MCP security, RAG attacks, LLM CVE">
<link rel="canonical" href="https://blog.cyberdudebivash.in/ai-security/intel/">
<meta property="og:title" content="AI Security Intelligence — SENTINEL APEX">
<meta property="og:description" content="Evidence-graded AI security intelligence mapped to OWASP LLM Top 10 and MITRE ATLAS.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://blog.cyberdudebivash.in/ai-security/intel/">
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"CollectionPage","name":"AI Security Intelligence — CYBERDUDEBIVASH SENTINEL APEX","description":"Evidence-graded AI security intelligence mapped to OWASP LLM Top 10 and MITRE ATLAS.","url":"https://blog.cyberdudebivash.in/ai-security/intel/","isPartOf":{"@type":"WebSite","name":"CYBERDUDEBIVASH SENTINEL APEX","url":"https://blog.cyberdudebivash.in/"}}
</script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#07090f;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.6}
a{color:inherit;text-decoration:none}
.wrap{max-width:1200px;margin:0 auto;padding:28px 20px 80px}
.head{border:1px solid rgba(168,85,247,.28);border-radius:14px;padding:28px;background:linear-gradient(135deg,#0d1117,#150920)}
.eyebrow{color:#a855f7;font-size:12px;font-weight:800;letter-spacing:2px;text-transform:uppercase}
h1{font-size:clamp(24px,4vw,38px);margin:6px 0 8px;color:#fff}
.sub{color:#94a3b8;max-width:760px}
.doctrine{margin-top:14px;font-size:13px;color:#64748b}
.stats{display:flex;flex-wrap:wrap;gap:14px;margin:22px 0}
.stat{background:#0d1117;border:1px solid #1f2937;border-radius:10px;padding:12px 18px;min-width:120px}
.stat-n{font-size:24px;font-weight:800;color:#a855f7}
.stat-l{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px}
.owasp-strip{margin:22px 0}
.owasp-strip h2{font-size:14px;color:#c084fc;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
.owasp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px}
.owasp-item{background:#0a0e1a;border:1px solid #1a2535;border-radius:6px;padding:9px 11px;font-size:12px}
.owasp-id{color:#a855f7;font-weight:800;display:block}
.owasp-name{color:#8892a4;font-size:11px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px;margin-top:8px}
.card{background:#0d1117;border:1px solid #1f2937;border-radius:12px;padding:16px;transition:.2s;display:block}
.card:hover{border-color:rgba(168,85,247,.5);transform:translateY(-2px)}
.card-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.pri{font-size:10px;font-weight:900;padding:2px 7px;border-radius:4px;color:#000}
.pri-P1{background:#ff4d6d}.pri-P2{background:#fb923c}.pri-P3{background:#38bdf8}
.label{font-size:10px;font-weight:700;color:#a855f7;text-transform:uppercase;letter-spacing:.5px}
.conf{font-size:10px;margin-left:auto;padding:2px 6px;border-radius:4px;border:1px solid}
.conf-high{color:#34d399;border-color:#34d39944}.conf-moderate{color:#fbbf24;border-color:#fbbf2444}.conf-low{color:#94a3b8;border-color:#94a3b844}
.card-title{font-weight:700;color:#f1f5f9;margin-bottom:6px}
.card-meta{font-size:12px;color:#64748b;margin-bottom:10px}
.tags{display:flex;flex-wrap:wrap;gap:5px}
.tag{font-size:10px;padding:2px 7px;border-radius:4px;font-weight:600}
.tag.owasp{background:rgba(168,85,247,.14);color:#c084fc;border:1px solid rgba(168,85,247,.3)}
.tag.atlas{background:rgba(56,189,248,.12);color:#38bdf8;border:1px solid rgba(56,189,248,.3)}
.tag.cat{background:rgba(148,163,184,.1);color:#94a3b8;border:1px solid rgba(148,163,184,.22)}
.empty{padding:40px;text-align:center;color:#64748b;border:1px dashed #1f2937;border-radius:12px;margin-top:14px}
.foot{margin-top:30px;font-size:12px;color:#475569;border-top:1px solid #1f2937;padding-top:16px}
.api{color:#a855f7}
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <div class="eyebrow">◆ AI Security Intelligence Division</div>
    <h1>AI Security Intelligence</h1>
    <p class="sub">Evidence-graded AI security intelligence — prompt injection, AI supply chain, agentic &amp; MCP exploitation, RAG attacks, model theft — collected on a dedicated pipeline and mapped to <strong>OWASP LLM Top 10</strong> and <strong>MITRE ATLAS</strong>. Community leads are corroborated before publication; every item carries a confidence and evidence label.</p>
    <div class="doctrine">Doctrine: Evidence First · Verification First · Never invent · Always assign confidence</div>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-n">${stats.published}</div><div class="stat-l">Published</div></div>
    <div class="stat"><div class="stat-n">${stats.p1}</div><div class="stat-l">P1 Priority</div></div>
    <div class="stat"><div class="stat-n">${stats.leadsHeld}</div><div class="stat-l">Leads Held</div></div>
    <div class="stat"><div class="stat-n">${stats.sourcesOk}/${stats.sourcesTotal}</div><div class="stat-l">Sources Live</div></div>
  </div>

  <div class="owasp-strip">
    <h2>OWASP LLM Top 10 Coverage</h2>
    <div class="owasp-grid">${owaspGrid}</div>
  </div>

  ${published.length ? `<div class="grid">\n${rows}\n  </div>` : `<div class="empty">No items cleared the publication gate this cycle. Held leads are re-evaluated as corroboration arrives. Machine-readable feed: <span class="api">/api/intel/ai-security.json</span></div>`}

  <div class="foot">
    Machine-readable feed: <a class="api" href="/api/intel/ai-security.json">/api/intel/ai-security.json</a>
    &nbsp;·&nbsp; Generated ${esc(isoNow())} &nbsp;·&nbsp; CYBERDUDEBIVASH® SENTINEL APEX™ AI Security Intelligence Division
  </div>
</div>
</body>
</html>`;
}

function buildReport(item) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(clip(item.title, 70))} — SENTINEL APEX AI Security Report</title>
<meta name="description" content="${esc(clip(item.summary, 160))}">
<link rel="canonical" href="https://blog.cyberdudebivash.in/ai-security/reports/${esc(item.id)}.html">
<style>
body{background:#07090f;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.7;max-width:820px;margin:0 auto;padding:28px 20px 80px}
a{color:#a855f7}h1{color:#fff;font-size:26px;line-height:1.3}
.meta{color:#64748b;font-size:13px;margin:8px 0 20px}
.badge{display:inline-block;background:rgba(168,85,247,.14);color:#c084fc;border:1px solid rgba(168,85,247,.3);border-radius:4px;font-size:11px;font-weight:700;padding:2px 8px;margin-right:6px}
pre{white-space:pre-wrap;background:#0d1117;border:1px solid #1f2937;border-radius:10px;padding:20px;font-family:inherit;font-size:15px}
.foot{margin-top:24px;font-size:12px;color:#475569;border-top:1px solid #1f2937;padding-top:14px}
</style></head><body>
<div class="badge">${esc(item.gate.label.replace(/_/g, ' '))}</div>
<div class="badge">${esc(item.confidence.overall)} confidence</div>
<div class="badge">${esc(item.enterpriseImpact.priority)}</div>
<h1>${esc(item.title)}</h1>
<div class="meta">${esc(item.source)} · <a href="${esc(item.url)}" target="_blank" rel="noopener">source</a> · ${esc(item.published)} · ${esc(item.cve || 'no CVE')}</div>
<pre>${esc(item.analystReport)}</pre>
<div class="foot">Generated by the CYBERDUDEBIVASH® SENTINEL APEX™ AI Security Intelligence Division. Evidence-graded; confidence assigned. Doctrine: Evidence First · Never invent.</div>
</body></html>`;
}

// ═══════════════════════════════════════════════════════════════════════════
// PIPELINE ORCHESTRATION
// ═══════════════════════════════════════════════════════════════════════════
async function main() {
  const started = Date.now();
  log(`AI Security Intelligence pipeline starting${DRY_RUN ? ' (dry-run)' : ''}.`);
  if (!acquireLock()) process.exit(0);

  const state = readJSON(CFG.statePath, { published: [], leads: [], totalPublished: 0, lastRun: null });
  const memory = readJSON(CFG.memoryPath, { corroboration: {} });
  const publishedIds = new Set(state.published || []);

  try {
    // Stage 1 — Collection
    const health = [];
    const raw = await collect(health);
    log(`Collected ${raw.length} raw items from ${SOURCES.length} sources.`);

    // Stage 2 — Verification
    const verified = verify(raw);
    log(`${verified.length} AI-relevant, fresh, deduplicated items.`);

    // Update correlation memory (Stage 4 groundwork) BEFORE gating so this run
    // benefits from cross-source corroboration seen this cycle.
    for (const it of verified) {
      const key = it.cve || it.url;
      memory.corroboration[key] = [...new Set((memory.corroboration[key] || []).concat(it.sourceKey))];
    }

    // Stages 3,5,6,7,8,9,4,12 — enrich + gate
    const enriched = [];
    const heldLeads = [];
    for (const it of verified) {
      const cats = classify(it);
      if (!cats) continue; // not AI-security-specific enough for this lane
      it.categories = cats;
      it.frameworks = mapFrameworks(cats);
      it.agentRisk = agentRisk(it, cats);
      it.enterpriseImpact = enterpriseImpact(it, cats, it.agentRisk);
      it.detection = detectionGuidance(cats);
      it.correlation = correlate(it, memory);
      it.confidence = confidence(it, it.correlation);
      it.gate = publicationGate(it, it.correlation);
      if (it.gate.publish) enriched.push(it);
      else if (it.gate.hold) heldLeads.push({ id: it.id, title: it.title, url: it.url, cve: it.cve,
        tier: it.tier, reason: it.gate.reason, corroborations: it.correlation.corroborations, seen: isoNow() });
    }
    log(`${enriched.length} items passed the publication gate; ${heldLeads.length} held as leads.`);

    // Rank by enterprise impact
    enriched.sort((a, b) => b.enterpriseImpact.score - a.enterpriseImpact.score);
    const publishSet = enriched.slice(0, CFG.maxFeedItems);

    // Stage 11 — Executive review (optional LLM)
    if (RUN_ANALYST) await runAnalyst(publishSet);

    // Stage 13 — Publish reports (only items that got an analyst report)
    let reportCount = 0;
    for (const it of publishSet) {
      if (it.analystReport) {
        safeWriteSync(path.join(CFG.reportsDir, `${it.id}.html`), buildReport(it));
        safeWriteSync(path.join(CFG.reportsDir, `${it.id}.json`), JSON.stringify({
          id: it.id, title: it.title, url: it.url, cve: it.cve,
          categories: it.categories, frameworks: it.frameworks,
          confidence: it.confidence, report: it.analystReport, generated: isoNow(),
        }, null, 2));
        reportCount++;
      }
    }

    const sourcesOk = health.filter(h => h.status === 'ok').length;
    const stats = {
      published: publishSet.length,
      p1: publishSet.filter(i => i.enterpriseImpact.priority === 'P1').length,
      leadsHeld: heldLeads.length,
      analystReports: reportCount,
      sourcesOk, sourcesTotal: SOURCES.length,
      sourceHealth: health,
      runtimeMs: Date.now() - started,
    };

    // Stage 13/14 — Feed + listing
    safeWriteSync(CFG.feedPath, buildFeed(publishSet, stats));
    safeWriteSync(CFG.listingPath, buildListing(publishSet, stats));

    // Persist state + memory
    const newlyPublished = publishSet.map(i => i.id).filter(id => !publishedIds.has(id));
    state.published = [...new Set((state.published || []).concat(publishSet.map(i => i.id)))].slice(-2000);
    state.leads = heldLeads.slice(0, CFG.maxLeadsRetained);
    state.totalPublished = (state.totalPublished || 0) + newlyPublished.length;
    state.lastRun = isoNow();
    state.lastStats = { published: stats.published, p1: stats.p1, leadsHeld: stats.leadsHeld, analystReports: reportCount };
    safeWriteSync(CFG.statePath, JSON.stringify(state, null, 2));
    // trim memory to avoid unbounded growth
    const memKeys = Object.keys(memory.corroboration);
    if (memKeys.length > 5000) {
      const trimmed = {}; memKeys.slice(-5000).forEach(k => trimmed[k] = memory.corroboration[k]);
      memory.corroboration = trimmed;
    }
    safeWriteSync(CFG.memoryPath, JSON.stringify(memory, null, 2));

    log(`Done. published=${stats.published} p1=${stats.p1} leadsHeld=${stats.leadsHeld} reports=${reportCount} sources=${sourcesOk}/${SOURCES.length} in ${stats.runtimeMs}ms`);
  } catch (e) {
    errl(`Pipeline error: ${e.stack || e.message}`);
    process.exitCode = 1;
  } finally {
    releaseLock();
  }
}

if (require.main === module) main();

module.exports = {
  // exported for fixture-based testing
  verify, classify, mapFrameworks, agentRisk, enterpriseImpact,
  correlate, confidence, publicationGate, detectionGuidance,
  parseGHSA, parseNVD, parseArxiv, parseRSS, isAiRelevant, buildFeed, buildListing,
  TAXONOMY, OWASP_NAMES, ATLAS_NAMES, SOURCES,
};
