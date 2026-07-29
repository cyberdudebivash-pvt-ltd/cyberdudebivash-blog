'use strict';
/**
 * SENTINEL APEX — Canonical Metadata Engine (ESPMP v1 Phase 2)
 *
 * Single source of truth for title/description/OpenGraph/Twitter Card/
 * JSON-LD generation. Exists because platform/social-preview-metadata-audit.md
 * found four independent title builders and four independent description
 * builders across fetch-live-intel.js, Sentinel-APEX/renderer/publish-report.js,
 * generate-cve-pages.js, and automation/seo_optimizer.py — each correct in
 * isolation, each producing slightly different output for the same
 * underlying report. This module extracts and generalizes the most complete
 * of those (fetch-live-intel.js's CVE-aware description branching,
 * publish-report.js's OG/Twitter tag set) rather than inventing new rules.
 *
 * Deliberately a pure, dependency-free, platform-independent module: given a
 * normalized input object describing one report/article, buildMetadata()
 * returns a plain metadata object — no file I/O, no HTML page assembly, no
 * knowledge of Blogger/WordPress/Vercel. Existing generators keep owning
 * their own page templates; they call this for the data that goes in the
 * <head>. Matches the spec's "reusable by future publishing targets" and
 * report-renderer.js's own precedent (parseReport() returns a model,
 * toHTMLDocument() is a separate, optional consumer of it).
 *
 * NOT migrated in this sprint (see the audit's staged plan): the existing
 * live callers (fetch-live-intel.js, publish-report.js, generate-cve-pages.js)
 * keep their current inline logic for now — this module is the new SSOT for
 * *new* and *fixed* call sites; migrating proven, revenue-adjacent live
 * generators onto it is follow-on work with its own blast-radius review.
 */

const DEFAULT_BRAND_SUFFIX = 'CYBERDUDEBIVASH SENTINEL APEX';
const DEFAULT_SITE_NAME = 'CYBERDUDEBIVASH SENTINEL APEX';
const DEFAULT_ARTICLE_AUTHOR = 'CYBERDUDEBIVASH SENTINEL APEX';
const DEFAULT_PUBLISHER_NAME = 'CYBERDUDEBIVASH';
const DEFAULT_PUBLISHER_LOGO = 'https://blog.cyberdudebivash.in/icon-512.png';
const DEFAULT_LOCALE = 'en_US';
const DEFAULT_LANGUAGE = 'en';
// Matches the one existing precedent for these two specific tags
// (index.html:41-42) — note the Organization JSON-LD's own sameAs array
// points at a different handle (@cdbsentinelapex on x.com); that
// pre-existing inconsistency is out of scope here (see open-issues.md).
const DEFAULT_TWITTER_SITE = '@cyberdudebivash';
const DEFAULT_TWITTER_CREATOR = '@cyberdudebivash';
const DEFAULT_DESCRIPTION_SUFFIX = `Analysis, IOCs, and detection guidance by ${DEFAULT_BRAND_SUFFIX}.`;

// Control chars in titles break JSON-LD parsing (raw newlines are illegal
// in JSON strings) — same guard as fetch-live-intel.js:2214 and
// api/og.js's sanitizeText(), expressed with \x hex escapes rather than
// \u so the low code points (NUL..US, DEL) are unambiguous byte values.
const CONTROL_CHARS_RE = /[\x00-\x1F\x7F]/g;

function escHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Same algorithm as the two independently-typed copies this replaces
// (fetch-live-intel.js:217-219, publish-report.js:53-56) — centralized,
// not redesigned, so existing slugs keep resolving identically if/when a
// caller migrates.
function slugify(str, maxLen = 90) {
  return String(str == null ? '' : str)
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .replace(/\s+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, maxLen);
}

function truncateAtWord(str, maxLen) {
  const s = String(str == null ? '' : str);
  return s.length <= maxLen ? s : s.slice(0, maxLen + 1).replace(/\s+\S*$/, '').slice(0, maxLen);
}

// Generalizes fetch-live-intel.js's cleanDescText pipeline (2225-2231):
// strips markdown fences/emphasis/links/headings down to plain prose
// suitable for a meta description, without pulling in a Markdown library.
function stripToPlainText(raw) {
  return String(raw == null ? '' : raw)
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`+/g, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/(^|\s)#{1,6}\s+/g, ' ')
    .replace(/[*_]{2,}/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// 225 wpm is the commonly-cited average adult reading speed for technical
// prose; matches neither app in this repo today because neither computes
// reading time at all (spec Phase 2 field, genuinely new).
function computeReadingTime(text, wordsPerMinute = 225) {
  const words = stripToPlainText(text).split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.ceil(words / wordsPerMinute));
}

function buildKeywords({ cveIds = [], threatCategory, threatActor, malwareFamily, vendor, product, extra = [] } = {}) {
  const candidates = [
    ...cveIds,
    threatCategory,
    threatActor,
    malwareFamily,
    vendor,
    product,
    ...extra,
    'threat intelligence',
    'cybersecurity',
  ].filter(Boolean).map(String);
  const seen = new Set();
  const out = [];
  for (const k of candidates) {
    const key = k.toLowerCase();
    if (!seen.has(key)) { seen.add(key); out.push(k); }
    if (out.length >= 12) break;
  }
  return out;
}

function buildTitles({ title, brandSuffix = DEFAULT_BRAND_SUFFIX }) {
  const safeTitle = String(title || '').replace(CONTROL_CHARS_RE, ' ').replace(/\s+/g, ' ').trim();
  return {
    title: safeTitle,
    seoTitle: `${safeTitle} | ${brandSuffix}`,
    shortTitle: truncateAtWord(safeTitle, 60),
  };
}

// CVE-aware branching generalized from fetch-live-intel.js:2234-2236 (the
// most complete of the three existing implementations). LinkedIn gets a
// longer budget deliberately: neither LinkedIn nor Telegram nor Facebook
// defines its own meta-tag namespace (all three read standard og:* tags —
// see renderHeadTagsHTML below), so these three fields are not new HTML
// tags, they're pre-tuned copy for future manual/API social posting.
function buildDescriptions({
  summary, cveIds = [], cvss, descriptionSuffix = DEFAULT_DESCRIPTION_SUFFIX, fallbackTitle,
} = {}) {
  const plain = stripToPlainText(summary) || String(fallbackTitle || '');
  const primaryCve = cveIds[0];
  const lead = primaryCve
    ? `${primaryCve}${cvss ? ` (CVSS ${cvss})` : ''} — ${truncateAtWord(plain, 130)}`
    : truncateAtWord(plain, 155);
  const core = `${lead}. ${descriptionSuffix}`;
  const linkedin = `${primaryCve ? `${primaryCve}${cvss ? ` (CVSS ${cvss})` : ''} — ` : ''}${truncateAtWord(plain, 260)}. ${descriptionSuffix}`;
  return {
    metaDescription: core,
    seoDescription: core,
    ogDescription: core,
    twitterDescription: core,
    linkedinDescription: linkedin,
    telegramDescription: core,
    facebookDescription: core,
  };
}

// Matches api/og.js's documented query contract exactly (api/og.js:9-16):
// title, severity, cve, cvss, type — verified against the two live callers
// (fetch-live-intel.js:2223, publish-report.js:77) as well as the
// endpoint's own docstring, not assumed.
function buildDynamicOgImageUrl({ baseUrl, title, severity = 'HIGH', cveId = '', cvss, type = 'THREAT INTEL' }) {
  const params = new URLSearchParams();
  params.set('title', title || '');
  params.set('severity', severity || 'HIGH');
  if (cveId) params.set('cve', cveId);
  if (cvss !== undefined && cvss !== null && cvss !== '') params.set('cvss', String(cvss));
  params.set('type', type || 'THREAT INTEL');
  return `${baseUrl}/api/og?${params.toString()}`;
}

function buildImages({ baseUrl, title, severity, cveId, cvss, type, imageUrl, staticFallback = '/og-image.png' }) {
  const dynamic = imageUrl || buildDynamicOgImageUrl({ baseUrl, title, severity, cveId, cvss, type });
  return {
    primaryImage: dynamic,
    thumbnail: dynamic,
    socialBanner: dynamic,
    staticFallback: `${baseUrl}${staticFallback}`,
  };
}

function buildJsonLd({
  title, description, image, canonicalUrl, publishedTime, modifiedTime,
  breadcrumbSectionName = 'Intelligence', breadcrumbSectionUrl, baseUrl,
  author = DEFAULT_ARTICLE_AUTHOR, publisherName = DEFAULT_PUBLISHER_NAME, publisherLogo = DEFAULT_PUBLISHER_LOGO,
}) {
  const article = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: title,
    description,
    image,
    url: canonicalUrl,
    datePublished: publishedTime,
    dateModified: modifiedTime || publishedTime,
    author: { '@type': 'Organization', name: author, url: baseUrl },
    publisher: {
      '@type': 'Organization',
      name: publisherName,
      logo: { '@type': 'ImageObject', url: publisherLogo, width: 512, height: 512 },
    },
    mainEntityOfPage: { '@type': 'WebPage', '@id': canonicalUrl },
  };
  const breadcrumb = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: DEFAULT_SITE_NAME, item: `${baseUrl}/` },
      { '@type': 'ListItem', position: 2, name: breadcrumbSectionName, item: breadcrumbSectionUrl || `${baseUrl}/` },
      { '@type': 'ListItem', position: 3, name: truncateAtWord(title, 120), item: canonicalUrl },
    ],
  };
  return { article, breadcrumb };
}

/**
 * @param {object} input
 * @param {string} input.title
 * @param {string} input.baseUrl - e.g. 'https://blog.cyberdudebivash.in'
 * @param {string} input.pathPrefix - e.g. 'posts' | 'intelligence' | 'cve'
 * @param {string} [input.slug] - pre-computed slug; derived from slugSource if omitted
 * @param {string} [input.slugSource] - text to slugify when slug is not given
 * @param {string} [input.summary] - source text used for description + reading time
 * @param {string[]} [input.cveIds]
 * @param {number|string} [input.cvss]
 * @param {string} [input.severity]
 * @param {string} [input.threatCategory]
 * @param {string} [input.threatLevel]
 * @param {string} [input.threatActor]
 * @param {string} [input.malwareFamily]
 * @param {string[]} [input.mitreTechniques]
 * @param {number} [input.iocCount]
 * @param {number|string} [input.confidenceScore]
 * @param {string} [input.industry]
 * @param {string} [input.publishedTime] - ISO 8601
 * @param {string} [input.modifiedTime] - ISO 8601
 * @param {string} [input.version]
 * @param {string[]} [input.sourceReferences]
 * @param {Array<{title:string,url:string}>} [input.internalLinks]
 * @param {Array<{title:string,url:string}>} [input.relatedReports]
 * @param {string} [input.type] - label passed to api/og.js, e.g. 'CVE ANALYSIS'
 * @param {string} [input.imageUrl] - override the dynamic api/og.js URL
 * @param {string} [input.geo]
 * @returns {object} full ESPMP v1 Phase 2 metadata object
 */
function buildMetadata(input) {
  const {
    title, baseUrl, pathPrefix, slug: slugIn, slugSource,
    summary = '', cveIds = [], cvss, severity, threatCategory, threatLevel,
    threatActor, malwareFamily, mitreTechniques = [], iocCount, confidenceScore,
    industry, publishedTime, modifiedTime, version, sourceReferences = [],
    internalLinks = [], relatedReports = [], type, imageUrl, geo,
    author = DEFAULT_ARTICLE_AUTHOR, brandSuffix = DEFAULT_BRAND_SUFFIX,
    descriptionSuffix, breadcrumbSectionName, breadcrumbSectionUrl,
  } = input;

  if (!title) throw new Error('metadata-engine.buildMetadata: title is required');
  if (!baseUrl) throw new Error('metadata-engine.buildMetadata: baseUrl is required');
  if (!pathPrefix) throw new Error('metadata-engine.buildMetadata: pathPrefix is required');

  const slug = slugIn || slugify(slugSource || title);
  const canonicalUrl = `${baseUrl}/${pathPrefix}/${slug}.html`;

  const titles = buildTitles({ title, brandSuffix });
  const descriptions = buildDescriptions({
    summary, cveIds, cvss, descriptionSuffix, fallbackTitle: title,
  });
  const images = buildImages({
    baseUrl, title: titles.title, severity: severity || threatLevel, cveId: cveIds[0], cvss, type, imageUrl,
  });
  const jsonLd = buildJsonLd({
    title: titles.title,
    description: descriptions.seoDescription,
    image: images.primaryImage,
    canonicalUrl,
    publishedTime: publishedTime || new Date().toISOString(),
    modifiedTime,
    breadcrumbSectionName,
    breadcrumbSectionUrl,
    baseUrl,
    author,
  });

  return {
    ...titles,
    executiveSummary: summary || '',
    metaDescription: descriptions.metaDescription,
    seoDescription: descriptions.seoDescription,
    keywords: buildKeywords({ cveIds, threatCategory, threatActor, malwareFamily, extra: mitreTechniques }),
    threatCategory: threatCategory || null,
    threatLevel: threatLevel || severity || null,
    industry: industry || null,
    threatActor: threatActor || null,
    malwareFamily: malwareFamily || null,
    cveIds,
    mitreTechniques,
    iocCount: iocCount != null ? iocCount : null,
    confidenceScore: confidenceScore != null ? confidenceScore : null,
    author,
    publishedTime: publishedTime || null,
    modifiedTime: modifiedTime || publishedTime || null,
    readingTimeMinutes: computeReadingTime(summary),
    canonicalUrl,
    slug,
    primaryImage: images.primaryImage,
    thumbnail: images.thumbnail,
    socialBanner: images.socialBanner,
    og: {
      title: titles.seoTitle,
      type: 'article',
      url: canonicalUrl,
      image: images.primaryImage,
      imageWidth: 1200,
      imageHeight: 630,
      imageAlt: titles.seoTitle,
      description: descriptions.ogDescription,
      siteName: DEFAULT_SITE_NAME,
      locale: DEFAULT_LOCALE,
      articlePublishedTime: publishedTime || null,
      articleModifiedTime: modifiedTime || publishedTime || null,
      articleAuthor: author,
      articleSection: threatCategory || null,
      articleTags: [...cveIds, threatActor, malwareFamily].filter(Boolean),
    },
    twitter: {
      card: 'summary_large_image',
      title: titles.seoTitle,
      description: descriptions.twitterDescription,
      image: images.primaryImage,
      imageAlt: titles.seoTitle,
      site: DEFAULT_TWITTER_SITE,
      creator: DEFAULT_TWITTER_CREATOR,
    },
    linkedinDescription: descriptions.linkedinDescription,
    telegramDescription: descriptions.telegramDescription,
    facebookDescription: descriptions.facebookDescription,
    jsonLd,
    language: DEFAULT_LANGUAGE,
    geo: geo || null,
    copyright: `© ${new Date().getUTCFullYear()} CyberDudeBivash. All rights reserved.`,
    license: 'All Rights Reserved',
    version: version || null,
    sourceReferences,
    internalLinks,
    relatedReports,
  };
}

// Drop-in <head> block: every tag existing live generators already prove
// out (og:*, twitter:*, canonical, JSON-LD), plus article:section/
// article:tag/article:author, which the spec's Phase 4 asks for and no
// current generator emits at all.
function renderHeadTagsHTML(metadata) {
  const m = metadata;
  const lines = [
    `<meta name="description" content="${escHtml(m.metaDescription)}">`,
    `<meta name="keywords" content="${escHtml(m.keywords.join(', '))}">`,
    `<meta property="og:title" content="${escHtml(m.og.title)}">`,
    `<meta property="og:type" content="${escHtml(m.og.type)}">`,
    `<meta property="og:url" content="${escHtml(m.og.url)}">`,
    `<meta property="og:description" content="${escHtml(m.og.description)}">`,
    `<meta property="og:site_name" content="${escHtml(m.og.siteName)}">`,
    `<meta property="og:locale" content="${escHtml(m.og.locale)}">`,
    `<meta property="og:image" content="${escHtml(m.og.image)}">`,
    `<meta property="og:image:secure_url" content="${escHtml(m.og.image)}">`,
    `<meta property="og:image:type" content="image/png">`,
    `<meta property="og:image:width" content="${m.og.imageWidth}">`,
    `<meta property="og:image:height" content="${m.og.imageHeight}">`,
    `<meta property="og:image:alt" content="${escHtml(m.og.imageAlt)}">`,
  ];
  if (m.og.articlePublishedTime) lines.push(`<meta property="article:published_time" content="${escHtml(m.og.articlePublishedTime)}">`);
  if (m.og.articleModifiedTime) lines.push(`<meta property="article:modified_time" content="${escHtml(m.og.articleModifiedTime)}">`);
  if (m.og.articleAuthor) lines.push(`<meta property="article:author" content="${escHtml(m.og.articleAuthor)}">`);
  if (m.og.articleSection) lines.push(`<meta property="article:section" content="${escHtml(m.og.articleSection)}">`);
  for (const tag of m.og.articleTags) lines.push(`<meta property="article:tag" content="${escHtml(tag)}">`);
  lines.push(
    `<meta name="twitter:card" content="${escHtml(m.twitter.card)}">`,
    `<meta name="twitter:title" content="${escHtml(m.twitter.title)}">`,
    `<meta name="twitter:description" content="${escHtml(m.twitter.description)}">`,
    `<meta name="twitter:image" content="${escHtml(m.twitter.image)}">`,
    `<meta name="twitter:image:alt" content="${escHtml(m.twitter.imageAlt)}">`,
    `<meta name="twitter:site" content="${escHtml(m.twitter.site)}">`,
    `<meta name="twitter:creator" content="${escHtml(m.twitter.creator)}">`,
    `<link rel="canonical" href="${escHtml(m.canonicalUrl)}">`,
    `<title>${escHtml(m.seoTitle)}</title>`,
    `<script type="application/ld+json">${JSON.stringify(m.jsonLd.article)}</script>`,
    `<script type="application/ld+json">${JSON.stringify(m.jsonLd.breadcrumb)}</script>`,
  );
  return lines.join('\n');
}

module.exports = {
  buildMetadata,
  renderHeadTagsHTML,
  slugify,
  truncateAtWord,
  stripToPlainText,
  computeReadingTime,
  buildKeywords,
  buildTitles,
  buildDescriptions,
  buildDynamicOgImageUrl,
  buildImages,
  buildJsonLd,
};
