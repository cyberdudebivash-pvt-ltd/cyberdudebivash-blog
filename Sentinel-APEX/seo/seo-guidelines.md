# SENTINEL APEX — SEO & INTERNAL LINKING GUIDELINES

Applied at pipeline Stage 7, after the quality gate. SEO never overrides
analyst quality — a report that reads as filler fails the quality gate
regardless of its keyword profile.

## Metadata (per published report)
- **Title (`<title>` / `og:title`):** specific and non-clickbait. Lead with the
  concrete subject (CVE, actor, family) + the value ("detection", "analysis").
- **Meta description:** 150–160 chars, states the "so what", includes the
  primary keyword naturally.
- **Canonical URL:** always set; one canonical per report.

## Structured Data (schema.org)
- `Article` / `TechArticle` with `datePublished`, `dateModified`, `author`
  (CyberDudeBivash Sentinel APEX), `publisher`.
- `BreadcrumbList` for section hierarchy.
- Where applicable, reference identifiers (CVE IDs) in body text so search
  engines associate the page with the vulnerability.

## OpenGraph / Social
- `og:type=article`, `og:title`, `og:description`, `og:image` (use
  `Sentinel-APEX/images/`), `og:url`. Twitter card `summary_large_image`.

## Keyword Clustering
Anchor each report to a primary cluster and 2–4 supporting terms:
- CVEs / zero-days / ransomware / threat intelligence
- AI security / OWASP LLM / MITRE ATLAS / NIST AI RMF
- SIEM detections / MITRE ATT&CK / SOC operations / DevSecOps / threat hunting

## Internal Linking
- Link to related `intelligence/cves/`, `intelligence/malware/`, and
  `intelligence/apt/` entities to build topical authority.
- Link detection sections to the relevant Sentinel APEX product/portal pages
  (detection packs, threat-intel API, consulting) as the monetization path.
- Every report links to at least 2 prior related reports and 1 product CTA.

## Core Web Vitals
- Compress and lazy-load images; provide dimensions to prevent CLS.
- Keep report pages fast (LCP < 2.5s, CLS < 0.1) per the Governance Constitution.

## Crawlability
- Ensure new published reports are added to `sitemap.xml`.
- Confirm `robots.txt` does not block report paths.
