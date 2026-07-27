/**
 * SENTINEL APEX — Dynamic Social Card Generator
 *
 * Renders a per-post branded social preview image (severity badge, CVE ID,
 * CVSS score, headline) instead of the single static og-image.png every
 * post previously shared. Used as the og:image/twitter:image target from
 * generatePostHTML() in fetch-live-intel.js.
 *
 * Query params (all optional, all sanitized — this is a public GET
 * endpoint reachable by anyone, including crawlers that don't know this
 * project's conventions):
 *   title    - post headline
 *   severity - CRITICAL | HIGH | MEDIUM | LOW (default HIGH)
 *   cve      - e.g. CVE-2026-50522
 *   cvss     - e.g. 9.8
 *   type     - short label, e.g. "CVE ANALYSIS", "ZERO-DAY", "RANSOMWARE"
 *
 * Reliability contract: this endpoint is hit automatically and unattended
 * by social crawlers for every future post. Any rendering failure falls
 * back to a 302 redirect to the pre-existing static /og-image.png rather
 * than a 500 — a slightly generic image beats a broken share card.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const FONT_DIR = path.join(__dirname, '_lib', 'fonts');
const SEVERITY_COLORS = {
  CRITICAL: '#ff3b3b',
  HIGH: '#ff8c00',
  MEDIUM: '#ffe000',
  LOW: '#00ff88',
};

// Strip control characters and emoji/pictographs (satori has no color-emoji
// font loaded — an unrendered glyph shows as a tofu box). Plain ASCII/Latin
// punctuation, hyphens, and accented characters pass through untouched.
function sanitizeText(value, maxLen) {
  const s = String(value == null ? '' : value)
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/gu, '')
    .replace(/\s+/g, ' ')
    .trim();
  return maxLen && s.length > maxLen ? s.slice(0, maxLen - 1).trimEnd() + '…' : s;
}

function truncateAtWord(s, n) {
  return s.length <= n ? s : s.slice(0, n + 1).replace(/\s+\S*$/, '').slice(0, n);
}

let fontCache = null;
function loadFonts() {
  if (fontCache) return fontCache;
  fontCache = [
    { name: 'Inter', data: fs.readFileSync(path.join(FONT_DIR, 'Inter-Regular.woff')), weight: 400, style: 'normal' },
    { name: 'Inter', data: fs.readFileSync(path.join(FONT_DIR, 'Inter-Bold.woff')), weight: 700, style: 'normal' },
    { name: 'Inter', data: fs.readFileSync(path.join(FONT_DIR, 'Inter-ExtraBold.woff')), weight: 800, style: 'normal' },
  ];
  return fontCache;
}

function buildTree({ title, severity, cve, cvss, type }) {
  const sevColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.HIGH;
  const footer = [cve, cvss ? `CVSS ${cvss}` : ''].filter(Boolean);

  return {
    type: 'div',
    props: {
      style: {
        height: '100%', width: '100%', display: 'flex', flexDirection: 'column',
        backgroundColor: '#07090f',
        backgroundImage: 'linear-gradient(135deg, #07090f 0%, #0d1117 100%)',
        padding: '60px 70px', fontFamily: 'Inter',
      },
      children: [
        {
          type: 'div',
          props: {
            style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
            children: [
              {
                type: 'div',
                props: {
                  style: { display: 'flex', alignItems: 'center', color: '#00ffe0', fontSize: 28, fontWeight: 800, letterSpacing: '-0.5px' },
                  children: 'CYBERDUDEBIVASH SENTINEL APEX',
                },
              },
              {
                type: 'div',
                props: {
                  style: {
                    display: 'flex', backgroundColor: sevColor, color: '#07090f', fontSize: 24,
                    fontWeight: 800, padding: '8px 24px', borderRadius: 6, letterSpacing: '1px',
                  },
                  children: severity,
                },
              },
            ],
          },
        },
        type ? {
          type: 'div',
          props: { style: { display: 'flex', marginTop: 40, color: '#6b7280', fontSize: 22, fontWeight: 700, wordBreak: 'break-word' }, children: type },
        } : { type: 'div', props: { style: { display: 'flex', marginTop: 40, height: 22 } } },
        {
          type: 'div',
          props: {
            style: {
              display: 'flex', marginTop: 20, color: '#e2e8f0', fontSize: 46, fontWeight: 800,
              lineHeight: 1.25, letterSpacing: '-1px', wordBreak: 'break-word',
            },
            children: title,
          },
        },
        {
          type: 'div',
          props: {
            style: { display: 'flex', marginTop: 'auto', alignItems: 'center' },
            children: footer.map((text, i) => ({
              type: 'div',
              props: {
                style: {
                  display: 'flex',
                  color: i === 0 ? '#00ffe0' : '#ff8c00',
                  fontSize: 30, fontWeight: 700,
                  fontFamily: i === 0 ? 'monospace' : 'Inter',
                  marginLeft: i === 0 ? 0 : 30,
                },
                children: text,
              },
            })),
          },
        },
      ],
    },
  };
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

    const satoriMod = require('satori');
    const satori = satoriMod.default || satoriMod;
    const { Resvg } = require('@resvg/resvg-js');

    const svg = await satori(buildTree({ title, severity, cve, cvss, type }), {
      width: 1200,
      height: 630,
      fonts: loadFonts(),
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
