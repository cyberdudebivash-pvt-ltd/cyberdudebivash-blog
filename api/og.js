/**
 * SENTINEL APEX — Dynamic Social Card Generator (Intelligence Card v3)
 *
 * Renders a per-post branded social preview image — severity, intelligence
 * classification, report identity, and threat-specific metadata — instead
 * of the single static og-image.png every post previously shared. Used as
 * the og:image/twitter:image target from generatePostHTML() in
 * fetch-live-intel.js (blog.cyberdudebivash.in), from
 * automation.authority_transformer._build_dynamic_og_image_url() (the
 * Blogger/cti.cyberdudebivash.in pipeline, via the post's lead <img>), and
 * from Sentinel-APEX/renderer/metadata-engine.js's buildDynamicOgImageUrl().
 *
 * v3 is a visual redesign only — every v2 query param keeps its exact
 * meaning and every v2 caller keeps working unmodified (kev/epss below are
 * additive and optional). See docs/audits/
 * SENTINEL-APEX-CTI-SOCIAL-PREVIEW-CARD-V3-CERTIFICATION.md for the full
 * before/after rationale.
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
 *   kev      - literal "true" only, when the source record confirms real
 *              CISA KEV catalog listing (article.kev_listed is True in the
 *              Python pipeline) — renders a KEV ribbon. Any other value is
 *              treated as absent; this endpoint never prints a "Not
 *              Listed"/negative claim itself (same no-negative-claim
 *              discipline as _build_risk_command_center's KEV tile) —
 *              omission, not a false-negative badge, is the correct
 *              rendering when KEV status is false or unknown.
 *   epss     - EPSS exploit-probability percentage, 0-100 (e.g. "42.3") —
 *              renders a small EPSS chip. Omitted when absent/invalid.
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

// hex -> rgba() string, for glow/halo backgrounds and translucent borders
// where a plain hex color would be fully opaque. Inputs are always our own
// constants above, never user input.
function hexToRgba(hex, alpha) {
  const h = hex.replace('#', '');
  const r = parseInt(h.substring(0, 2), 16);
  const g = parseInt(h.substring(2, 4), 16);
  const b = parseInt(h.substring(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

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

// A labeled "readout tile" — small uppercase caption above a bold value —
// the unit the data row is built from (CVE/CVSS/EPSS, or actor/sector).
// `extra` appends sibling nodes after the value on the same line (used for
// the CVSS meter bar). maxWidth+wordBreak on the value mirrors the
// overflow-safety fix already proven for the v2 metadata row (see this
// file's git history / the v2 certification doc's Security Analysis
// section) — long adversarial field values wrap instead of clipping.
function statTile(label, value, valueColor, extra) {
  return row(
    [
      text(label, { color: '#64748b', fontSize: 13, fontWeight: 700, letterSpacing: '1.1px' }),
      row(
        [text(value, { color: valueColor, fontSize: 26, fontWeight: 800, maxWidth: 340, wordBreak: 'break-word' })].concat(extra || []),
        { alignItems: 'center', marginTop: 6 },
      ),
    ],
    { flexDirection: 'column' },
  );
}

function tileDivider() {
  return row([], { width: 1, height: 44, backgroundColor: 'rgba(255,255,255,0.14)', marginLeft: 30, marginRight: 30 });
}

// 0-10 severity meter — fill width scales linearly with score.
function cvssMeter(score, color) {
  const pct = Math.max(0, Math.min(10, score)) / 10;
  return row(
    [row([], { width: `${Math.round(pct * 170)}px`, height: '100%', backgroundColor: color, borderRadius: 3 })],
    { width: 170, height: 6, backgroundColor: 'rgba(255,255,255,0.1)', borderRadius: 3, marginLeft: 14 },
  );
}

// One "targeting bracket" corner mark — a purely decorative frame accent,
// four of these are placed at the card's outer corners.
function cornerBracket(pos) {
  const size = 26, inset = 24, line = `2px solid ${hexToRgba(BRAND_CYAN, 0.38)}`;
  const base = { position: 'absolute', width: size, height: size };
  if (pos === 'tl') return row([], { ...base, top: inset, left: inset, borderTop: line, borderLeft: line });
  if (pos === 'tr') return row([], { ...base, top: inset, right: inset, borderTop: line, borderRight: line });
  if (pos === 'bl') return row([], { ...base, bottom: inset, left: inset, borderBottom: line, borderLeft: line });
  return row([], { ...base, bottom: inset, right: inset, borderBottom: line, borderRight: line });
}

function kevRibbon() {
  return text('CISA KEV CATALOG — LISTED', {
    color: '#fff', backgroundColor: SEVERITY_COLORS.CRITICAL, fontSize: 15, fontWeight: 800,
    padding: '6px 14px', borderRadius: 5, letterSpacing: '0.5px',
    boxShadow: `0 0 20px 1px ${hexToRgba(SEVERITY_COLORS.CRITICAL, 0.45)}`,
  });
}

function buildTree({ title, severity, cve, cvss, type, reportId, date, actor, sector, kev, epss }) {
  const sevColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.HIGH;
  const typeLabel = type ? `${type.toUpperCase()} INTELLIGENCE` : 'THREAT INTELLIGENCE';

  // Data readout tiles — CVE/CVSS/EPSS for vulnerability reports, actor/
  // sector for ransomware-style attribution (mutually exclusive: a report
  // never has both in practice, and CVE/CVSS takes precedence if it
  // somehow did). Every tile comes from a real, source-backed field;
  // absent fields are simply omitted, never guessed or padded to fill the
  // row (Sentinel Apex governance: never fabricate attribution, victims,
  // or scores).
  const tiles = [];
  if (cve) tiles.push(statTile('VULNERABILITY ID', cve, BRAND_CYAN));
  if (cvss) {
    const score = parseFloat(cvss);
    tiles.push(statTile('CVSS SEVERITY SCORE', cvss, sevColor, [
      text('/10', { color: '#64748b', fontSize: 15, fontWeight: 700, marginLeft: 4 }),
      Number.isFinite(score) ? cvssMeter(score, sevColor) : row([], { height: 0 }),
    ]));
  }
  if (epss) {
    // Mirrors _build_risk_command_center's EPSS threshold semantics
    // (>=50% red, >=10% amber, else green) but reuses THIS card's own
    // SEVERITY_COLORS rather than the article body's separate risk-tile
    // palette — the two rendering surfaces already use different hex
    // systems for the same concept; this keeps one image internally
    // consistent instead of introducing a third color set for one chip.
    const epssNum = parseFloat(epss);
    const epssColor = epssNum >= 50 ? SEVERITY_COLORS.CRITICAL : epssNum >= 10 ? SEVERITY_COLORS.HIGH : SEVERITY_COLORS.LOW;
    tiles.push(statTile('EPSS EXPLOIT PROBABILITY', `${epss}%`, epssColor));
  }
  if (!cve && !cvss) {
    if (actor) tiles.push(statTile('THREAT ACTOR', actor, '#ff6b6b'));
    if (sector) tiles.push(statTile('TARGET SECTOR', sector, '#c084fc'));
  }
  const tileRow = [];
  tiles.forEach((tile, i) => {
    if (i > 0) tileRow.push(tileDivider());
    tileRow.push(tile);
  });

  return row(
    [
      // Full-width classification accent bar — brand cyan fading into the
      // report's own severity color.
      row([], { width: '100%', height: 6, backgroundImage: `linear-gradient(90deg, ${BRAND_CYAN} 0%, ${sevColor} 100%)` }),
      // Body: decorative corner brackets + glows sit behind the padded
      // content as siblings, never nested inside it, so they can never
      // collide with or constrain real text layout.
      row(
        [
          row([], {
            position: 'absolute', top: -140, right: -140, width: 520, height: 520, borderRadius: '50%',
            backgroundImage: `radial-gradient(circle, ${hexToRgba(sevColor, 0.16)} 0%, rgba(0,0,0,0) 70%)`,
          }),
          row([], {
            position: 'absolute', bottom: -160, left: -120, width: 480, height: 480, borderRadius: '50%',
            backgroundImage: `radial-gradient(circle, ${hexToRgba(BRAND_CYAN, 0.07)} 0%, rgba(0,0,0,0) 70%)`,
          }),
          cornerBracket('tl'), cornerBracket('tr'), cornerBracket('bl'), cornerBracket('br'),
          row(
            [
              // Header: brand lockup (left) + severity module (right)
              row(
                [
                  row(
                    [
                      row(
                        [
                          row([], { width: 13, height: 13, backgroundColor: BRAND_CYAN, borderRadius: 3, transform: 'rotate(45deg)', marginRight: 14, marginTop: 4 }),
                          text('CYBERDUDEBIVASH®', { color: BRAND_CYAN, fontSize: 27, fontWeight: 800, letterSpacing: '-0.3px' }),
                        ],
                        { alignItems: 'center' },
                      ),
                      text('SENTINEL APEX™ // GLOBAL CYBER THREAT INTELLIGENCE',
                        { color: '#6b7280', fontSize: 14, fontWeight: 700, letterSpacing: '1.5px', marginTop: 8, marginLeft: 27 }),
                    ],
                    { flexDirection: 'column' },
                  ),
                  text(severity, {
                    color: INK, backgroundColor: sevColor, fontSize: 22, fontWeight: 800,
                    padding: '7px 22px', borderRadius: 6, letterSpacing: '1px',
                    boxShadow: `0 0 26px 2px ${hexToRgba(sevColor, 0.4)}`,
                  }),
                ],
                { alignItems: 'flex-start', justifyContent: 'space-between' },
              ),
              // Classification row: type label (left) + KEV ribbon (right, if listed)
              row(
                [
                  text(typeLabel, { color: '#94a3b8', fontSize: 20, fontWeight: 700, letterSpacing: '1px' }),
                  kev ? kevRibbon() : row([], { height: 0 }),
                ],
                { alignItems: 'center', justifyContent: 'space-between', marginTop: 34 },
              ),
              // Headline. maxHeight+overflow:'hidden' is a hard clip, not
              // just a style nicety: satori/Yoga's text measurement for an
              // extreme pathological input (a single very long run with no
              // whitespace at all, e.g. an adversarial title with no word
              // boundaries) was found, via actual rendered-output
              // inspection, to under-report its own height to the flex
              // parent while still painting every wrapped line — silently
              // pushing the tile row below UP into the headline instead of
              // being pushed down by it. A fixed maxHeight makes the
              // reserved box exact regardless of any such measurement
              // quirk, so this can't recur for any future input shape.
              // 165px = ~3 lines at this font-size/line-height, matching
              // how many lines a realistic (space-containing) long title
              // already wraps to safely.
              text(title, {
                color: '#f8fafc', fontSize: 44, fontWeight: 800, lineHeight: 1.22,
                letterSpacing: '-1px', wordBreak: 'break-word', marginTop: 16,
                maxHeight: 165, overflow: 'hidden',
              }),
              // Data readout tiles (omitted entirely when nothing is known).
              // flexWrap + a hard maxWidth on each tile's value keep
              // unusually long field combinations wrapping onto a second
              // line instead of running off the 1200px canvas.
              tileRow.length
                ? row(tileRow, { alignItems: 'center', flexWrap: 'wrap', maxWidth: '100%', marginTop: 28, rowGap: '14px' })
                : row([], { height: 0 }),
              // Footer: divider, then report identity (left) — advisory
              // branding + domain/date (right)
              row(
                [
                  row([], { width: '100%', height: 1, backgroundColor: 'rgba(255,255,255,0.09)' }),
                  row(
                    [
                      reportId
                        ? text(reportId, {
                            color: '#94a3b8', fontSize: 15, letterSpacing: '0.5px',
                            border: `1px solid ${hexToRgba(BRAND_CYAN, 0.25)}`, borderRadius: 4, padding: '4px 10px',
                          })
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
                    { alignItems: 'center', justifyContent: 'space-between', marginTop: 14 },
                  ),
                ],
                { flexDirection: 'column', marginTop: 'auto' },
              ),
            ],
            { flexDirection: 'column', height: '100%', width: '100%', padding: '44px 68px 36px', position: 'relative' },
          ),
        ],
        { flexGrow: 1, flexShrink: 1, flexBasis: 0, width: '100%', position: 'relative', overflow: 'hidden' },
      ),
    ],
    {
      height: '100%', width: '100%', flexDirection: 'column', overflow: 'hidden',
      backgroundColor: INK,
      backgroundImage: 'linear-gradient(160deg, #05070c 0%, #0a0e16 55%, #05070c 100%)',
      fontFamily: 'Inter', position: 'relative',
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
    // Strict literal match, not a general truthy-string parse — an absent
    // or malformed value must render as "omitted", never as a guessed
    // negative claim (see this file's module docstring).
    const kev = sanitizeText(q.get('kev'), 10).toLowerCase() === 'true';
    const epssRaw = parseFloat(q.get('epss'));
    const epss = Number.isFinite(epssRaw) && epssRaw >= 0 && epssRaw <= 100 ? epssRaw.toFixed(1) : '';

    const satoriMod = require('satori');
    const satori = satoriMod.default || satoriMod;
    const Resvg = await getResvg();

    const svg = await satori(buildTree({ title, severity, cve, cvss, type, reportId, date, actor, sector, kev, epss }), {
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
