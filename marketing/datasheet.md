# CYBERDUDEBIVASH SENTINEL APEX — Product Datasheet

Internal sales-enablement reference. Every claim below is sourced to a
verified, real platform capability (checked directly against this
codebase) or a specifically-cited external source — nothing here is
invented for the purpose of this document. Update this file if any
underlying fact changes; do not let it drift stale (mirrors the discipline
`docs/PRICING.md` already enforces for pricing specifically).

## What Sentinel APEX is

A threat intelligence platform combining (1) a continuously-updated,
automated live intelligence feed (13+ ingestion sources, ~30-minute cycle)
and (2) hand-authored, evidence-tagged analyst intelligence reports that
pass an internal quality gate and certification process before publication.

## Core capabilities (verified)

| Capability | Detail |
|---|---|
| Live threat graph | Actor → Campaign → CVE → IOC relationships, plus `co_occurs_with` correlation edges between campaigns sharing a CVE and between CVEs sharing a campaign |
| Actor attribution | Evidence-scored (IOC overlap, keyword match, source mentions, campaign overlap), explicitly labeled "Unknown" below a 0.50 confidence threshold rather than forced |
| Detection engineering | Sigma, SIEM query, and hunting-query generation; multi-format detection output |
| Analyst reports | Hand-authored, MITRE ATT&CK-mapped with cited evidence per technique (not template-stamped), quality-gated and certified before publication |
| API access | Tiered (Free/Starter/Pro/Enterprise), self-serve registration, no card required for Free tier |
| Export formats | STIX 2.1 bundle export (Enterprise tier) |
| Explainability | Every enriched intelligence item carries a structured `_explanation` block (actor, campaign, score, data confidence reasoning) |

## Pricing (self-serve, transparent — verified current as of this document)

| Tier | Price | Key limits |
|---|---|---|
| Free | $0 | Rate-limited API, public CVE/threat pages |
| API Starter | ₹999 / ~$12 per month | 5,000 API calls/day, weekly intel digest |
| SOC Pro | ₹1,499 / ~$18 per month | 25,000 API calls/day, full IOC feed, Sigma/Yara rules |
| Enterprise | ₹4,999 / ~$60 per month | Unlimited API calls, STIX 2.1 export, bulk data, priority support |

All four tiers are publicly priced and self-serve — no sales call required
to see cost or start using the product.

## What we do not claim

No SOC 2 / ISO 27001 / GDPR / HIPAA / PCI-DSS certification is claimed
anywhere in this platform's marketing today — do not represent otherwise in
a sales conversation. No specific uptime SLA number is verified for
external use in this document; do not quote one unless and until it is
independently confirmed. No customer count, logo, or market-share figure is
claimed — enterprise case studies on `enterprise.html` are explicitly
labeled illustrative scenarios, not real customer testimonials.

See `marketing/competitive-battlecard.md` for positioning against Recorded
Future and GreyNoise, and `platform/open-issues.md` for current known
product gaps — read both before an enterprise sales conversation.
