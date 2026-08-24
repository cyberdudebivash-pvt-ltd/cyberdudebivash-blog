/**
 * SENTINEL APEX — Dynamic Social Card Generator (Intelligence Card v2)
 *
 * Renders a per-post branded social preview image — severity, intelligence
 * classification, report identity, and threat-specific metadata — instead
 * of the single static og-image.png every post previously shared. Used as
 * the og:image/twitter:image target from generatePostHTML() in
 * fetch-live-intel.js (blog.cyberdudebivash.in) and from
 * automation.authority_transformer._build_dynamic_og_image_url() (the
 * Blogger/cti.cyberdudebivash.in pipeline, via the post's lead <img>).
 *
 * Query params (all optional, all sanitized and length-bounded — this is a
 * public GET endpoint reachable by anyone, including crawlers and callers
 * that don't know this project's conventions):
 *   title    - post headline
 *   severity - CRITICAL | HIGH | MEDIUM | LOW (default HIGH)
 *   cve      - e.g. CVE-2026-50522
 *   cvss     - e.g. 9.8
 *   type     - short category label, e.g. "Ransomware", "Vulnerabilities"
 *              (rendered as "<TYPE> INTELLIGENCE")
 *   reportId - the platform's one canonical report-identity string, e.g.
 *              "CDB-CTI-2026-AB8646B9A383" (report_integrity.py's
 *              build_report_context() — never a second ID scheme)
 *   date     - short pre-formatted display date, e.g. "24 AUG 2026"
 *   actor    - threat actor / ransomware group name, when the source
 *              record actually supplied one — never fabricated by this
 *              endpoint, which only renders what it's given
 *   sector   - victim sector/context, same rule as actor
 *
 * Trust/design constraints (Sentinel Apex social-preview contract): no
 * emoji, no clickbait, no fabricated rankings, counts, or endorsements —
 * this card is a trust artifact representing real report metadata, not an
 * ad banner. Deterministic, escaped/bounded, no client-side execution.
 *
 * Reliability contract: this endpoint is hit automatically and unattended
 * by social crawlers for every future post. Any rendering failure falls
 * back to a 302 redirect to the pre-existing static /og-image.png rather
 * than a 500 — a slightly generic image beats a broken share card.
 */
'use strict';

const { getResvg } = require('../workers/lib/resvg-wasm-init');
const { loadFontsForRuntime } = require('../workers/lib/og-fonts-init');

const SEVERITY_COLORS = {
  CRITICAL: '#ff3b3b',
  HIGH: '#ff8c00',
  MEDIUM: '#ffe000',
  LOW: '#00ff88',
};

const BRAND_CYAN = '#00ffe0';
const INK = '#07090f';

// Strip control characters and emoji/pictographs (satori has no color-emoji
// font loaded — an unrendered glyph shows as a tofu box). Plain ASCII/Latin
// punctuation, hyphens, and accented characters pass through untouched.
function sanitizeText(value, maxLen) {
  const s = String(value == null ? '' : value)
    .replace(/[\x00-\x1F\x7F]/g, ' ')
    .replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/gu, '')
    .replace(/\s+/g, ' ')
    .trim();
  return maxLen && s.length > maxLen ? s.slice(0, maxLen - 1).trimEnd() + '…' : s;
}

function truncateAtWord(s, n) {
  return s.length <= n ? s : s.slice(0, n + 1).replace(/\s+\S*$/, '').slice(0, n);
}

// flex:true on every node satori renders (including single-text leaves) —
// satori has no default block/inline layout, so this must be explicit on
// every node the same way the rest of this file already does it.
function row(children, style = {}) {
  return { type: 'div', props: { style: { display: 'flex', ...style }, children } };
}

function text(value, style) {
  return row(value, style);
}

function buildTree({ title, severity, cve, cvss, type, reportId, date, actor, sector }) {
  const sevColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.HIGH;
  const typeLabel = type ? `${type.toUpperCase()} INTELLIGENCE` : 'THREAT INTELLIGENCE';

  // Threat-specific metadata row — CVE/CVSS for vulnerability reports,
  // actor/sector for ransomware-style attribution. Every item here comes
  // from a real, source-backed field; absent fields are simply omitted,
  // never guessed or padded to fill the row (Sentinel Apex governance:
  // never fabricate attribution, victims, or scores).
  const metaItems = [];
  if (cve) metaItems.push(text(cve, { color: BRAND_CYAN, fontSize: 27, fontWeight: 700, fontFamily: 'monospace' }));
  if (cvss) metaItems.push(text(`CVSS ${cvss}`, { color: '#ff8c00', fontSize: 27, fontWeight: 700, marginLeft: cve ? 28 : 0 }));
  if (actor) metaItems.push(text(actor, { color: '#e2e8f0', fontSize: 27, fontWeight: 700, marginLeft: (cve || cvss) ? 28 : 0, maxWidth: 420, wordBreak: 'break-word' }));
  if (sector) metaItems.push(text(sector, { color: '#94a3b8', fontSize: 24, fontWeight: 500, marginLeft: (cve || cvss || actor) ? 20 : 0, maxWidth: 420, wordBreak: 'break-word' }));

  return row(
    [
      // Header: brand lockup (left) + severity badge (right)
      row(
        [
          row(
            [
              text('CYBERDUDEBIVASH®', { color: BRAND_CYAN, fontSize: 26, fontWeight: 800, letterSpacing: '-0.3px' }),
              text('SENTINEL APEX™ // GLOBAL CYBER THREAT INTELLIGENCE',
                { color: '#6b7280', fontSize: 14, fontWeight: 700, letterSpacing: '1.5px', marginTop: 6 }),
            ],
            { flexDirection: 'column' },
          ),
          text(severity, {
            color: INK, backgroundColor: sevColor, fontSize: 22, fontWeight: 800,
            padding: '7px 22px', borderRadius: 6, letterSpacing: '1px',
          }),
        ],
        { alignItems: 'center', justifyContent: 'space-between' },
      ),
      // Intelligence type classification
      text(typeLabel, { color: '#94a3b8', fontSize: 20, fontWeight: 700, letterSpacing: '1px', marginTop: 36 }),
      // Headline
      text(title, {
        color: '#f8fafc', fontSize: 44, fontWeight: 800, lineHeight: 1.22,
        letterSpacing: '-1px', wordBreak: 'break-word', marginTop: 16,
      }),
      // Threat-specific metadata row (omitted entirely when nothing is known).
      // flexWrap + a hard maxWidth keep unusually long field combinations
      // (a long actor + a long sector, say) wrapping onto a second line
      // instead of running off the 1200px canvas.
      metaItems.length
        ? row(metaItems, { alignItems: 'center', flexWrap: 'wrap', maxWidth: '100%', marginTop: 26, rowGap: '8px' })
        : row([], { height: 0 }),
      // Footer: report identity (left) — advisory branding + domain/date (right)
      row(
        [
          reportId
            ? text(reportId, { color: '#4b5563', fontSize: 16, fontFamily: 'monospace' })
            : row([], { height: 0 }),
          row(
            [
              text('INTELLIGENCE ADVISORY', { color: BRAND_CYAN, fontSize: 15, fontWeight: 700, letterSpacing: '1.5px' }),
              text(date ? `cti.cyberdudebivash.in  ·  ${date}` : 'cti.cyberdudebivash.in',
                { color: '#6b7280', fontSize: 15, marginTop: 5 }),
            ],
            { flexDirection: 'column', alignItems: 'flex-end' },
          ),
        ],
        { alignItems: 'flex-end', justifyContent: 'space-between', marginTop: 'auto' },
      ),
    ],
    {
      height: '100%', width: '100%', flexDirection: 'column', overflow: 'hidden',
      backgroundColor: INK,
      backgroundImage: 'linear-gradient(135deg, #07090f 0%, #0d1117 100%)',
      padding: '56px 70px', fontFamily: 'Inter',
    },
  );
}

module.exports = async (req, res) => {
  try {
    const url = new URL(req.url, 'https://placeholder.invalid');
    const q = url.searchParams;

    const severityRaw = sanitizeText(q.get('severity'), 20).toUpperCase();
    const severity = SEVERITY_COLORS[severityRaw] ? severityRaw : 'HIGH';
    const title = truncateAtWord(sanitizeText(q.get('title'), 220) || 'CyberDudeBivash Sentinel APEX Intelligence Report', 140);
    const cveCandidate = sanitizeText(q.get('cve'), 30);
    const cve = /^CVE-\d{4}-\d{4,}$/i.test(cveCandidate) ? cveCandidate.toUpperCase() : '';
    const cvssRaw = parseFloat(q.get('cvss'));
    const cvss = Number.isFinite(cvssRaw) && cvssRaw >= 0 && cvssRaw <= 10 ? cvssRaw.toFixed(1) : '';
    const type = sanitizeText(q.get('type'), 40);
    const reportIdCandidate = sanitizeText(q.get('reportId'), 40);
    const reportId = /^[A-Za-z0-9-]+$/.test(reportIdCandidate) ? reportIdCandidate.toUpperCase() : '';
    const date = sanitizeText(q.get('date'), 20);
    const actor = sanitizeText(q.get('actor'), 60);
    const sector = sanitizeText(q.get('sector'), 60);

    const satoriMod = require('satori');
    const satori = satoriMod.default || satoriMod;
    const Resvg = await getResvg();

    const svg = await satori(buildTree({ title, severity, cve, cvss, type, reportId, date, actor, sector }), {
      width: 1200,
      height: 630,
      fonts: await loadFontsForRuntime(),
    });

    const resvg = new Resvg(svg, { fitTo: { mode: 'width', value: 1200 } });
    const png = resvg.render().asPng();

    res.statusCode = 200;
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=86400, s-maxage=31536000, stale-while-revalidate=86400');
    res.end(png);
  } catch (e) {
    // Never let a render failure surface as a broken share card — fall back
    // to the pre-existing static image every post used before this endpoint
    // existed.
    console.error('api/og render failure:', e && e.message);
    res.statusCode = 302;
    res.setHeader('Location', '/og-image.png');
    res.setHeader('Cache-Control', 'no-store');
    res.end();
  }
};
