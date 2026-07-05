# SENTINEL APEX™ — Intelligence Prompt Architecture

A **layered, versioned** prompt system for producing premium enterprise threat
intelligence. This replaces the idea of one monolithic prompt with composable
layers, so every report inherits the same standards while each intelligence
product is tuned for its audience.

> Design principle: **the intelligence is the product.** Optimize for decision
> value and customer trust, never for word count or clicks.

---

## The layers (compose top-to-bottom)

| # | Layer | File | Changes |
|---|---|---|---|
| 1 | **Constitution** | [`00-constitution.md`](00-constitution.md) | Rarely — mission, editorial standards, evidence policy, confidence model, publication rules |
| 2 | **Production Workflow** | [`10-production-workflow.md`](10-production-workflow.md) | Occasionally — COLLECT→PUBLISH analyst workflow, evidence & enrichment rules |
| 3 | **Report-Type Prompt** | [`reports/*.md`](reports/) | Per product — CVE, ransomware, AI security, executive briefing, weekly digest, monthly landscape |
| 4 | **Industry Overlay** *(optional)* | [`industry/industry-intelligence.md`](industry/industry-intelligence.md) | Adds sector framing — finance, healthcare, manufacturing, government, retail, critical infrastructure |
| 5 | **Editorial QA Gate** | [`20-editorial-qa.md`](20-editorial-qa.md) | Rarely — factual-consistency, unsupported-claim detection, SEO, publication scoring |

**Composition for any report:**
```
Constitution  +  Production Workflow  +  Report-Type[+ Industry Overlay]  →  DRAFT
DRAFT  →  Editorial QA Gate  →  PUBLISH (only if score ≥ threshold)
```

The Constitution and QA gate are constant across every product. Report-type and
industry layers change what the analyst emphasizes and how the report is
structured — never the evidence or honesty rules.

---

## How this maps to the running platform

- **`fetch-live-intel.js`** is the deterministic report generator. Its sections
  already implement Constitution requirements: primary-source references,
  Severity Anatomy (decoded CVSS vector), Weakness Anatomy (decoded CWE),
  representative (not asserted) attack paths, honest exploitation status
  (KEV/reported only), and MITRE mapping.
- The **optional LLM analyst stage** (`ai-security-intel.yml`, gated on
  `ANTHROPIC_API_KEY`) is where these prompts are loaded directly: Constitution
  + Workflow + the matching Report-Type prompt as the system context.
- New report products are added by writing a new `reports/*.md` file — the
  Constitution, Workflow, and QA layers are inherited unchanged.

---

## Versioning

- Each file carries a `Version:` and `Status:` header and a changelog at the
  bottom. The Constitution is `v1.0` and is expected to change rarely; bumps to
  it are **major** and require review.
- Report-type and industry prompts version independently so a product can evolve
  without touching the Constitution.
- Never edit a prompt in place for a one-off; add a versioned successor.

## Non-negotiables (enforced by every layer)

1. Never invent CVEs, IOCs, actors, campaigns, advisories, MITRE mappings, or
   detection logic. Missing evidence is stated as an **Intelligence Gap**.
2. Every claim is labeled by evidence class and carries a confidence rationale.
3. No fear marketing, no severity inflation, no unlabeled speculation.
4. Every report must survive scrutiny by a Fortune 500 CISO, a regulator, and a
   competitor.
