'use strict';
// Regression coverage for ESPMP v1: platform/social-preview-metadata-audit.md
// found all 7 intelligence-hub page types (vendor/timeline/collections/
// detections/threat, plus per-vendor and per-collection detail pages) shared
// the single static /og-image.png via one common renderShell() — meaning
// none of them ever showed a branded, section-specific share card.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const { renderShell } = require(path.join(__dirname, '..', 'generate-intelligence-hub.js'));

function renderVendorHubPage() {
  return renderShell({
    path: '/vendor/',
    title: 'Vendor & Ecosystem Intelligence Centers | CYBERDUDEBIVASH SENTINEL APEX',
    description: 'Real, vendor-attributed CVE intelligence.',
    eyebrow: 'Vendor Intelligence',
    h1: 'Vendor & Ecosystem Intelligence Centers',
    lede: 'lede text',
    bodyHtml: '<p>body</p>',
    jsonLd: { '@type': 'CollectionPage' },
    activeHref: '/vendor/',
  });
}

test('renderShell() uses the dynamic api/og.js card, not the static og-image.png', () => {
  const html = renderVendorHubPage();
  assert.ok(html.includes('property="og:image" content="https://blog.cyberdudebivash.in/api/og?'));
  assert.ok(!html.includes('/og-image.png'));
});

test('renderShell() passes eyebrow through as the image "type" label, so different sections get different cards', () => {
  const vendorHtml = renderVendorHubPage();
  const timelineHtml = renderShell({
    path: '/timeline/', title: 'Threat Intelligence Timeline | CYBERDUDEBIVASH SENTINEL APEX',
    description: 'd', eyebrow: 'Timeline', h1: 'h1', lede: 'l', bodyHtml: 'b', jsonLd: {}, activeHref: '/timeline/',
  });

  const vendorImg = new URL(vendorHtml.match(/property="og:image" content="([^"]+)"/)[1]);
  const timelineImg = new URL(timelineHtml.match(/property="og:image" content="([^"]+)"/)[1]);
  assert.strictEqual(vendorImg.searchParams.get('type'), 'Vendor Intelligence');
  assert.strictEqual(timelineImg.searchParams.get('type'), 'Timeline');
  assert.notStrictEqual(vendorImg.toString(), timelineImg.toString());
});

test('renderShell() includes og:image width/height/alt and a full Twitter Card block', () => {
  const html = renderVendorHubPage();
  assert.ok(html.includes('<meta property="og:image:width" content="1200">'));
  assert.ok(html.includes('<meta property="og:image:height" content="630">'));
  assert.ok(html.includes('<meta name="twitter:card" content="summary_large_image">'));
  assert.ok(html.includes('<meta name="twitter:image" content="https://blog.cyberdudebivash.in/api/og?'));
  assert.ok(html.includes('<meta name="twitter:site" content="@cyberdudebivash">'));
  assert.ok(html.includes('<meta name="twitter:creator" content="@cyberdudebivash">'));
});
