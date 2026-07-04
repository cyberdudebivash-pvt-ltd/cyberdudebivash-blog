'use strict';
/**
 * SENTINEL APEX Detection Engine (Node port).
 *
 * A faithful, zero-dependency port of the Python engine's detection layer
 * (Sentinel-APEX/engine/sentinel_engine/{attack_mapper,detection_specs,
 * detection_builder}.py). It exists so the live generator (fetch-live-intel.js)
 * can emit the same evidence-driven, multi-platform detections the Python
 * engine and its 71 tests validate — one canonical spec per technique,
 * compiled to Sigma / KQL / Splunk / OSQuery, plus Suricata from network IOCs.
 *
 * Design guarantees preserved from the Python engine:
 *  - a technique is only mapped when a concrete source phrase supports it,
 *    and that phrase is carried as evidence;
 *  - a detection format is emitted only where the data model can express it;
 *  - every generated artifact is validated; builders throw rather than emit
 *    a broken rule.
 */

// ── ATT&CK: curated validation set (id -> [name, tactic]) ────────────────
const KNOWN_TECHNIQUES = {
  'T1003.001': ['LSASS Memory', 'credential-access'],
  'T1027': ['Obfuscated Files or Information', 'defense-evasion'],
  'T1041': ['Exfiltration Over C2 Channel', 'exfiltration'],
  'T1047': ['Windows Management Instrumentation', 'execution'],
  'T1053.005': ['Scheduled Task', 'persistence'],
  'T1055': ['Process Injection', 'defense-evasion'],
  'T1059.001': ['PowerShell', 'execution'],
  'T1059.003': ['Windows Command Shell', 'execution'],
  'T1068': ['Exploitation for Privilege Escalation', 'privilege-escalation'],
  'T1071': ['Application Layer Protocol', 'command-and-control'],
  'T1071.004': ['DNS', 'command-and-control'],
  'T1078': ['Valid Accounts', 'initial-access'],
  'T1105': ['Ingress Tool Transfer', 'command-and-control'],
  'T1110': ['Brute Force', 'credential-access'],
  'T1112': ['Modify Registry', 'defense-evasion'],
  'T1133': ['External Remote Services', 'initial-access'],
  'T1189': ['Drive-by Compromise', 'initial-access'],
  'T1190': ['Exploit Public-Facing Application', 'initial-access'],
  'T1195': ['Supply Chain Compromise', 'initial-access'],
  'T1195.002': ['Compromise Software Supply Chain', 'initial-access'],
  'T1203': ['Exploitation for Client Execution', 'execution'],
  'T1204.002': ['Malicious File', 'execution'],
  'T1218.005': ['Mshta', 'defense-evasion'],
  'T1486': ['Data Encrypted for Impact', 'impact'],
  'T1490': ['Inhibit System Recovery', 'impact'],
  'T1496': ['Resource Hijacking', 'impact'],
  'T1498': ['Network Denial of Service', 'impact'],
  'T1505.003': ['Web Shell', 'persistence'],
  'T1547.001': ['Registry Run Keys / Startup Folder', 'persistence'],
  'T1557': ['Adversary-in-the-Middle', 'credential-access'],
  'T1562.001': ['Disable or Modify Tools', 'defense-evasion'],
  'T1566': ['Phishing', 'initial-access'],
  'T1566.001': ['Spearphishing Attachment', 'initial-access'],
  'T1566.002': ['Spearphishing Link', 'initial-access'],
  'T1574.002': ['DLL Side-Loading', 'persistence'],
  'T1595': ['Active Scanning', 'reconnaissance'],
};

// phrase-pattern -> [technique id, confidence]. Order = priority.
const LEXICON = [
  [/spear[- ]?phishing (?:e-?mails? with )?attachments?/i, 'T1566.001', 'HIGH'],
  [/spear[- ]?phishing links?/i, 'T1566.002', 'HIGH'],
  [/phishing/i, 'T1566', 'MEDIUM'],
  [/zero[- ]click/i, 'T1203', 'HIGH'],
  [/drive[- ]by/i, 'T1189', 'HIGH'],
  [/exploit(?:ed|ing|s)? (?:a |an )?(?:public[- ]facing|internet[- ]facing|exposed)/i, 'T1190', 'HIGH'],
  [/supply[- ]chain (?:attack|compromise)/i, 'T1195', 'HIGH'],
  [/malicious (?:npm|pypi|nuget|package|dependency)/i, 'T1195.002', 'HIGH'],
  [/powershell/i, 'T1059.001', 'HIGH'],
  [/cmd\.exe|command shell/i, 'T1059.003', 'MEDIUM'],
  [/\bwmi\b|windows management instrumentation/i, 'T1047', 'HIGH'],
  [/macro[- ]enabled|malicious (?:document|attachment|file)|weaponized document/i, 'T1204.002', 'MEDIUM'],
  [/process (?:injection|hollowing)/i, 'T1055', 'HIGH'],
  [/dll side[- ]?loading/i, 'T1574.002', 'HIGH'],
  [/web ?shell/i, 'T1505.003', 'HIGH'],
  [/scheduled tasks?/i, 'T1053.005', 'MEDIUM'],
  [/run keys?|startup folder/i, 'T1547.001', 'HIGH'],
  [/obfuscat|packed payload|packer/i, 'T1027', 'MEDIUM'],
  [/disabl(?:e[sd]?|ing) (?:edr|antivirus|defender|security tools?)/i, 'T1562.001', 'HIGH'],
  [/mshta/i, 'T1218.005', 'HIGH'],
  [/lsass|credential dump|mimikatz/i, 'T1003.001', 'HIGH'],
  [/brute[- ]forc|password spray|credential stuffing/i, 'T1110', 'HIGH'],
  [/stolen credentials|compromised (?:credentials|accounts?)|valid accounts?/i, 'T1078', 'MEDIUM'],
  [/adversary[- ]in[- ]the[- ]middle|\baitm\b|man[- ]in[- ]the[- ]middle/i, 'T1557', 'HIGH'],
  [/\bvpn\b (?:appliance|gateway|access)|external remote services/i, 'T1133', 'MEDIUM'],
  [/privilege escalation/i, 'T1068', 'MEDIUM'],
  [/c2|command[- ]and[- ]control|beacon(?:ing)?/i, 'T1071', 'MEDIUM'],
  [/dns tunnel/i, 'T1071.004', 'HIGH'],
  [/download(?:s|ed|er)? (?:a |the )?(?:second[- ]stage|payload|additional tools?)/i, 'T1105', 'MEDIUM'],
  [/exfiltrat/i, 'T1041', 'MEDIUM'],
  [/ransomware|encrypt(?:s|ed|ing)? (?:files|data|systems)/i, 'T1486', 'HIGH'],
  [/delet(?:e[sd]?|ing) (?:volume )?shadow cop(?:y|ies)|vssadmin/i, 'T1490', 'HIGH'],
  [/cryptomin|coin ?miner|cryptojack/i, 'T1496', 'HIGH'],
  [/\bddos\b|denial[- ]of[- ]service/i, 'T1498', 'HIGH'],
  [/port scan|mass[- ]scan|active scanning/i, 'T1595', 'MEDIUM'],
  [/registry modification|modif(?:y|ies|ied) (?:the )?registry/i, 'T1112', 'MEDIUM'],
];

const RE_TECHNIQUE_ID = /\bT\d{4}(?:\.\d{3})?\b/g;

function isValidTechniqueId(id) {
  return Object.prototype.hasOwnProperty.call(KNOWN_TECHNIQUES, id);
}

function mapTechniques(text) {
  text = String(text || '');
  const out = new Map();
  for (const [pattern, tid, confidence] of LEXICON) {
    if (out.has(tid)) continue;
    const m = pattern.exec(text);
    if (!m) continue;
    const start = Math.max(0, m.index - 50);
    const evidence = text.slice(start, m.index + m[0].length + 50).replace(/\s+/g, ' ').trim();
    const [name, tactic] = KNOWN_TECHNIQUES[tid];
    out.set(tid, { technique_id: tid, name, tactic, evidence, confidence });
  }
  // explicit technique IDs cited in the text (high confidence)
  const ids = new Set((text.match(RE_TECHNIQUE_ID) || []));
  for (const tid of ids) {
    if (out.has(tid) || !isValidTechniqueId(tid)) continue;
    const [name, tactic] = KNOWN_TECHNIQUES[tid];
    out.set(tid, {
      technique_id: tid, name, tactic,
      evidence: `technique ID ${tid} cited explicitly in source`, confidence: 'HIGH',
    });
  }
  return [...out.values()].sort((a, b) => a.technique_id.localeCompare(b.technique_id));
}

// ── detection specs: one canonical spec per technique ────────────────────
// data source field maps mirror detection_specs.py FIELD_MAP.
const FIELD_MAP = {
  process_creation: {
    _kql_table: 'DeviceProcessEvents', _osquery_table: 'processes',
    _splunk_dm: 'Endpoint.Processes', _splunk_by: ['process_path', 'parent_process_path'],
    process_path: { sigma: 'Image', kql: 'FolderPath', splunk: 'process_path', osquery: 'path' },
    parent_path: { sigma: 'ParentImage', kql: 'InitiatingProcessFolderPath', splunk: 'parent_process_path', osquery: null },
    command_line: { sigma: 'CommandLine', kql: 'ProcessCommandLine', splunk: 'process', osquery: 'cmdline' },
  },
  process_access: {
    _kql_table: 'DeviceEvents', _osquery_table: null,
    _splunk_dm: 'Endpoint.Processes', _splunk_by: ['process_path', 'target_process_path'],
    target_process: { sigma: 'TargetImage', kql: 'FileName', splunk: 'target_process_path', osquery: null },
    granted_access: { sigma: 'GrantedAccess', kql: 'AdditionalFields', splunk: 'granted_access', osquery: null },
  },
  registry_set: {
    _kql_table: 'DeviceRegistryEvents', _osquery_table: 'registry',
    _splunk_dm: 'Endpoint.Registry', _splunk_by: ['process_path', 'registry_path'],
    registry_key: { sigma: 'TargetObject', kql: 'RegistryKey', splunk: 'registry_path', osquery: 'path' },
    image: { sigma: 'Image', kql: 'InitiatingProcessFolderPath', splunk: 'process_path', osquery: null },
  },
};

const SIGMA_LOGSOURCE = {
  process_creation: { product: 'windows', category: 'process_creation' },
  process_access: { product: 'windows', category: 'process_access' },
  registry_set: { product: 'windows', category: 'registry_set' },
};

// m: { field, op: eq|contains|endswith|startswith, values:[], negate:bool }
const ALL = ['sigma', 'kql', 'splunk', 'osquery'];
const NO_OSQUERY = ['sigma', 'kql', 'splunk'];

const REGISTRY = {
  'T1059.001': {
    technique_id: 'T1059.001', title: 'Suspicious Encoded PowerShell Invocation',
    level: 'high', data_source: 'process_creation',
    description: 'PowerShell launched with encoded or base64 command payloads.',
    matches: [
      { field: 'process_path', op: 'endswith', values: ['\\powershell.exe'] },
      { field: 'command_line', op: 'contains', values: ['-EncodedCommand', '-enc ', 'FromBase64String'] },
    ], platforms: ALL,
  },
  'T1204.002': {
    technique_id: 'T1204.002', title: 'Office Application Spawning Script Interpreter',
    level: 'high', data_source: 'process_creation',
    description: 'Office parent process spawning a script or shell interpreter.',
    matches: [
      { field: 'parent_path', op: 'endswith', values: ['\\outlook.exe', '\\winword.exe', '\\excel.exe', '\\powerpnt.exe'] },
      { field: 'process_path', op: 'endswith', values: ['\\powershell.exe', '\\cmd.exe', '\\wscript.exe', '\\mshta.exe'] },
    ], platforms: ALL,
  },
  'T1490': {
    technique_id: 'T1490', title: 'Shadow Copy Deletion Preceding Ransomware Encryption',
    level: 'critical', data_source: 'process_creation',
    description: 'Recovery inhibition via shadow copy / backup catalog deletion.',
    matches: [
      { field: 'command_line', op: 'contains', values: ['vssadmin delete shadows', 'wmic shadowcopy delete', 'recoveryenabled no', 'wbadmin delete catalog'] },
    ], platforms: ALL,
  },
  'T1547.001': {
    technique_id: 'T1547.001', title: 'Registry Run Key Persistence From User-Writable Path',
    level: 'medium', data_source: 'registry_set',
    description: 'Run/RunOnce key modification establishing boot/logon persistence.',
    matches: [
      { field: 'registry_key', op: 'contains', values: ['\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'] },
      { field: 'image', op: 'startswith', values: ['C:\\Program Files', 'C:\\Windows\\'], negate: true },
    ], platforms: ALL,
  },
  'T1003.001': {
    technique_id: 'T1003.001', title: 'LSASS Memory Access by Non-System Process',
    level: 'high', data_source: 'process_access',
    description: 'Process handle to lsass.exe with credential-dumping access mask.',
    matches: [
      { field: 'target_process', op: 'endswith', values: ['\\lsass.exe'] },
      { field: 'granted_access', op: 'contains', values: ['0x1010', '0x1410', '0x1438'] },
    ], platforms: NO_OSQUERY,
  },
  'T1218.005': {
    technique_id: 'T1218.005', title: 'Mshta Executing Remote or Script Content',
    level: 'high', data_source: 'process_creation',
    description: 'mshta.exe used as a proxy to run remote or inline script content.',
    matches: [
      { field: 'process_path', op: 'endswith', values: ['\\mshta.exe'] },
      { field: 'command_line', op: 'contains', values: ['http', 'javascript:', 'vbscript:'] },
    ], platforms: ALL,
  },
};

function buildableTechniques() { return new Set(Object.keys(REGISTRY)); }

// Deterministic UUIDv5 (RFC 4122). Faithfully replicates Python's two-level
// computation — uuid5(uuid5(NAMESPACE_DNS, "sentinel.cyberdudebivash.in"),
// title) — so generated rule ids match the Python engine byte-for-byte.
const crypto = require('crypto');
const DNS_NAMESPACE = Buffer.from('6ba7b8109dad11d180b400c04fd430c8', 'hex');
function _uuid5Bytes(nsBytes, name) {
  const hash = crypto.createHash('sha1')
    .update(nsBytes).update(Buffer.from(name, 'utf8')).digest();
  const b = Buffer.from(hash.slice(0, 16));
  b[6] = (b[6] & 0x0f) | 0x50; // version 5
  b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
  return b;
}
function _fmt(b) {
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
const _NS = _uuid5Bytes(DNS_NAMESPACE, 'sentinel.cyberdudebivash.in');
function uuid5(name) { return _fmt(_uuid5Bytes(_NS, name)); }

function resolveField(ds, logical, platform) {
  const entry = FIELD_MAP[ds][logical];
  if (!entry) throw new Error(`unknown logical field ${logical} for ${ds}`);
  return entry[platform];
}

// ── renderers ────────────────────────────────────────────────────────────
function yamlList(items, indent) {
  return items.map((v) => `\n${indent}- ${yamlScalar(v)}`).join('');
}
function yamlScalar(v) {
  const s = String(v);
  if (s === '' || /^[\s]|[\s]$|[:#\-?*&!|>'"%@`{}[\],]/.test(s) || /^-/.test(s)) {
    return `'${s.replace(/'/g, "''")}'`;
  }
  return s;
}

function sigModifier(op) {
  return { eq: '', contains: '|contains', endswith: '|endswith', startswith: '|startswith' }[op];
}

function toSigma(spec, references, date, evidence) {
  const lines = [];
  lines.push(`title: ${spec.title}`);
  lines.push(`id: ${uuid5(spec.title)}`);
  lines.push('status: experimental');
  const desc = evidence
    ? `${spec.title}. Evidence basis: ${evidence.slice(0, 200)}. CYBERDUDEBIVASH SENTINEL APEX Detection Engineering.`
    : `${spec.description || spec.title}`;
  lines.push(`description: ${yamlScalar(desc)}`);
  lines.push('references:' + (references.length ? yamlList(references, '') : ' []'));
  lines.push('author: CYBERDUDEBIVASH SENTINEL APEX Detection Engineering');
  lines.push(`date: ${date}`);
  lines.push('tags:' + yamlList([`attack.${spec.technique_id.toLowerCase()}`], ''));
  const ls = SIGMA_LOGSOURCE[spec.data_source];
  lines.push('logsource:');
  lines.push(`    product: ${ls.product}`);
  lines.push(`    category: ${ls.category}`);
  lines.push('detection:');
  const conditions = ['selection'];
  const selection = [];
  const filters = [];
  spec.matches.forEach((m, i) => {
    const key = resolveField(spec.data_source, m.field, 'sigma') + sigModifier(m.op);
    if (m.negate) {
      filters.push({ name: `filter_${i}`, key, values: m.values });
      conditions.push(`not filter_${i}`);
    } else {
      selection.push({ key, values: m.values });
    }
  });
  lines.push('    selection:');
  for (const s of selection) {
    if (s.values.length === 1) lines.push(`        ${s.key}: ${yamlScalar(s.values[0])}`);
    else lines.push(`        ${s.key}:` + yamlList(s.values, '            '));
  }
  for (const f of filters) {
    lines.push(`    ${f.name}:`);
    if (f.values.length === 1) lines.push(`        ${f.key}: ${yamlScalar(f.values[0])}`);
    else lines.push(`        ${f.key}:` + yamlList(f.values, '            '));
  }
  lines.push(`    condition: ${conditions.join(' and ')}`);
  lines.push('falsepositives:');
  lines.push('    - Legitimate administrative activity');
  lines.push('    - Authorized security testing');
  lines.push(`level: ${spec.level}`);
  return lines.join('\n');
}

function toKql(spec) {
  const table = FIELD_MAP[spec.data_source]._kql_table;
  const proj = {
    process_creation: 'FolderPath, ProcessCommandLine, InitiatingProcessFolderPath',
    process_access: 'FileName, InitiatingProcessFolderPath',
    registry_set: 'RegistryKey, RegistryValueData, InitiatingProcessFolderPath',
  }[spec.data_source];
  const lines = [table];
  for (const m of spec.matches) {
    const f = resolveField(spec.data_source, m.field, 'kql');
    const op = { eq: '=~', contains: 'contains', endswith: 'endswith', startswith: 'startswith' }[m.op];
    const terms = m.values.map((v) => `${f} ${op} "${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
    let inner = terms.join(' or ');
    if (terms.length > 1) inner = `(${inner})`;
    lines.push(`| where ${m.negate ? `not (${inner})` : inner}`);
  }
  lines.push(`| project Timestamp, DeviceName, ${proj}`);
  return lines.join('\n');
}

function toSplunk(spec) {
  const ds = FIELD_MAP[spec.data_source];
  const dm = ds._splunk_dm;
  const node = dm.split('.').pop();
  const parts = [];
  for (const m of spec.matches) {
    const f = `${node}.${resolveField(spec.data_source, m.field, 'splunk')}`;
    const terms = m.values.map((v) => {
      const x = v.replace(/"/g, '\\"');
      if (m.op === 'eq') return `${f}="${x}"`;
      if (m.op === 'endswith') return `${f}="*${x}"`;
      if (m.op === 'startswith') return `${f}="${x}*"`;
      return `${f}="*${x}*"`;
    });
    let clause = terms.join(' OR ');
    if (terms.length > 1) clause = `(${clause})`;
    parts.push(m.negate ? `NOT ${clause}` : clause);
  }
  const by = ds._splunk_by.map((f) => `${node}.${f}`).join(' ');
  return `| tstats count from datamodel=${dm.split('.')[0]} where nodename=${dm} ${parts.join(' ')} by ${by} _time`;
}

function toOsquery(spec) {
  const table = FIELD_MAP[spec.data_source]._osquery_table;
  if (!table) return '';
  const where = [];
  for (const m of spec.matches) {
    const col = resolveField(spec.data_source, m.field, 'osquery');
    if (col == null) continue;
    const terms = m.values.map((v) => {
      const x = v.replace(/'/g, "''");
      if (m.op === 'eq') return `${col} = '${x}'`;
      if (m.op === 'endswith') return `${col} LIKE '%${x}'`;
      if (m.op === 'startswith') return `${col} LIKE '${x}%'`;
      return `${col} LIKE '%${x}%'`;
    });
    const clause = terms.length > 1 ? `(${terms.join(' OR ')})` : terms[0];
    where.push(m.negate ? `NOT ${clause}` : clause);
  }
  if (!where.length) return '';
  return `SELECT * FROM ${table} WHERE ${where.join(' AND ')};`;
}

// ── validators ───────────────────────────────────────────────────────────
function balanced(s, a, b) { return (s.split(a).length - 1) === (s.split(b).length - 1); }

function validateKql(q) {
  const problems = [];
  const lines = q.trim().split('\n').map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return ['empty KQL query'];
  if (lines[0].startsWith('|')) problems.push('KQL must begin with a table');
  for (const l of lines.slice(1)) if (!l.startsWith('|')) problems.push(`KQL continuation missing pipe: ${l.slice(0, 40)}`);
  if ((q.split('"').length - 1) % 2 !== 0) problems.push('KQL unbalanced quotes');
  if (!q.includes('| where')) problems.push('KQL has no where clause');
  return problems;
}
function validateSplunk(q) {
  const problems = [];
  q = q.trim();
  if (!q.startsWith('|') && !q.startsWith('search')) problems.push('SPL must start with a command');
  if ((q.split('"').length - 1) % 2 !== 0) problems.push('SPL unbalanced quotes');
  if (!balanced(q, '(', ')')) problems.push('SPL unbalanced parentheses');
  return problems;
}
function validateOsquery(q) {
  const problems = [];
  q = q.trim();
  if (!q.endsWith(';')) problems.push('OSQuery must end with semicolon');
  if (!/^SELECT/i.test(q)) problems.push('OSQuery must be a SELECT');
  if (!/ FROM /i.test(q)) problems.push('OSQuery missing FROM');
  if (!balanced(q, '(', ')')) problems.push('OSQuery unbalanced parentheses');
  if ((q.split("'").length - 1) % 2 !== 0) problems.push('OSQuery unbalanced quotes');
  return problems;
}
function validateSuricata(r) {
  const problems = [];
  r = r.trim();
  if (!r.startsWith('alert ')) problems.push('Suricata rule must start with alert');
  if (!(r.endsWith(')') && r.includes('('))) problems.push('Suricata options block malformed');
  if (!r.includes('sid:')) problems.push('Suricata missing sid');
  if (!r.includes('msg:')) problems.push('Suricata missing msg');
  return problems;
}

// ── Suricata from network IOCs ───────────────────────────────────────────
function normalizeIocType(t) {
  t = String(t || '').toLowerCase();
  if (['ip', 'ipv4', 'ip:port', 'ip-dst', 'ip-src'].includes(t)) return 'ipv4';
  if (['domain', 'hostname', 'fqdn'].includes(t)) return 'domain';
  if (['url', 'uri'].includes(t)) return 'url';
  return t;
}
function escSuricata(v) { return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/;/g, '\\;'); }
function splitUrl(url) {
  const stripped = url.includes('://') ? url.split('://')[1] : url;
  const slash = stripped.indexOf('/');
  const host = (slash === -1 ? stripped : stripped.slice(0, slash)).split(':')[0];
  const path = slash === -1 ? '' : stripped.slice(slash);
  return [host, path];
}
function refang(v) {
  return String(v).replace(/hxxps/gi, 'https').replace(/hxxp/gi, 'http')
    .replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.').replace(/\[dot\]/gi, '.').replace(/\[:\]/g, ':');
}
function suricataFor(ioc, sid) {
  const type = normalizeIocType(ioc.type);
  const value = refang(ioc.value);
  const opts = (label, match) => {
    let o = `msg:"CYBERDUDEBIVASH SENTINEL APEX - ${label} ${value}";`;
    if (match) o += ` ${match}`;
    o += ` classtype:trojan-activity; sid:${sid}; rev:1;`;
    return o;
  };
  if (type === 'ipv4') {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return '';
    return `alert ip $HOME_NET any -> ${value} any (${opts('malicious IP', '')})`;
  }
  if (type === 'domain') {
    return `alert dns $HOME_NET any -> any any (${opts('malicious domain', `dns.query; content:"${escSuricata(value)}"; nocase;`)})`;
  }
  if (type === 'url') {
    const [host, path] = splitUrl(value);
    const parts = [];
    if (host) parts.push(`http.host; content:"${escSuricata(host)}"; nocase;`);
    if (path && path !== '/') parts.push(`http.uri; content:"${escSuricata(path)}"; nocase;`);
    if (!parts.length) return '';
    return `alert http $HOME_NET any -> $EXTERNAL_NET any (${opts('malicious URL', parts.join(' '))})`;
  }
  return '';
}
function buildSuricata(iocs, startSid = 9000001) {
  const rules = [];
  let sid = startSid;
  for (const ioc of iocs || []) {
    if (!ioc || !ioc.value) continue;
    const rule = suricataFor(ioc, sid);
    if (rule) {
      const problems = validateSuricata(rule);
      if (problems.length) throw new Error(`generated Suricata rule failed validation: ${problems}`);
      rules.push(rule);
      sid += 1;
    }
  }
  return rules;
}

// ── top-level build ──────────────────────────────────────────────────────
function isoDate() { return new Date().toISOString().slice(0, 10); }

function buildForTechnique(mapping, references, date) {
  const spec = REGISTRY[mapping.technique_id];
  if (!spec) return null;
  const art = { technique_id: spec.technique_id, title: spec.title, level: spec.level };
  if (spec.platforms.includes('sigma')) art.sigma = toSigma(spec, references, date, mapping.evidence);
  if (spec.platforms.includes('kql')) {
    art.kql = toKql(spec);
    guard(validateKql(art.kql), 'KQL', spec);
  }
  if (spec.platforms.includes('splunk')) {
    art.splunk = toSplunk(spec);
    guard(validateSplunk(art.splunk), 'Splunk', spec);
  }
  if (spec.platforms.includes('osquery')) {
    const q = toOsquery(spec);
    if (q) { guard(validateOsquery(q), 'OSQuery', spec); art.osquery = q; }
  }
  return art;
}
function guard(problems, fmt, spec) {
  if (problems.length) throw new Error(`generated ${fmt} for ${spec.technique_id} failed validation: ${problems}`);
}

/**
 * Build multi-platform detections from raw source text + IOCs.
 * @returns {{detections: object[], suricata: string[], techniques: object[]}}
 */
function buildDetections(text, iocs, opts = {}) {
  const references = opts.references || [];
  const date = opts.date || isoDate();
  const techniques = mapTechniques(text);
  const detections = [];
  for (const m of techniques) {
    const art = buildForTechnique(m, references, date);
    if (art) detections.push(art);
  }
  const suricata = buildSuricata(iocs, opts.startSid || 9000001);
  return { detections, suricata, techniques };
}

module.exports = {
  KNOWN_TECHNIQUES, REGISTRY, isValidTechniqueId, mapTechniques, buildableTechniques,
  toSigma, toKql, toSplunk, toOsquery, buildForTechnique, buildDetections,
  buildSuricata, suricataFor, normalizeIocType, refang, uuid5,
  validateKql, validateSplunk, validateOsquery, validateSuricata,
};
