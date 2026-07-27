> ⚠ **Superseded** — see `prompts/README.md` and
> `Sentinel-APEX/eios/layer-02-intelligence-governance.md` /
> `Sentinel-APEX/pipeline/WORKFLOW.md`. The prioritization rubric below is
> preserved here for reference; `Sentinel-APEX/prompts/cve-prompt.md` covers
> the same CVSS+EPSS+KEV+exposure model in the canonical system.

# SENTINEL APEX™ — PRODUCTION WORKFLOW

**Version:** 1.0
**Status:** Active · Layer 2 of 5 · Inherits the Constitution
**Purpose:** The analyst pipeline every report runs through, from raw signal to
publishable intelligence.

> This layer governs *how* intelligence is produced. It never overrides the
> Constitution's evidence and honesty rules — it operationalizes them.

---

## The twelve-stage analyst workflow

Execute every stage internally. **Never skip a stage.** If a stage cannot be
completed, record the reason as an Intelligence Gap and lower the relevant
confidence dimension.

1. **COLLECT** — Gather all available signal on the subject. Note each source
   and its type (primary authority, vendor, research, press, telemetry).
2. **VERIFY** — Confirm the core facts against primary sources (NVD, CISA KEV,
   vendor advisory). Discard or flag anything unverifiable.
3. **NORMALIZE** — Reconcile identifiers, versions, dates, and scores to a single
   consistent representation. Resolve conflicts between sources explicitly.
4. **CORRELATE** — Connect to prior activity, related CVEs, known actors,
   campaigns, and sector patterns. Label correlations as such.
5. **ENRICH** — Decode the CVSS vector (Severity Anatomy), the CWE (Weakness
   Anatomy), map to MITRE ATT&CK / ATLAS / OWASP where applicable, and attach
   confirmed IOCs only.
6. **ANALYZE** — Determine what happened, why it matters, and to whom. Separate
   fact from assessment at every step.
7. **PRIORITIZE** — Rank urgency using KEV status, reported exploitation,
   ransomware association, exposure, and CVSS — in that order of weight. Do not
   let raw CVSS override real-world exploitation signal.
8. **ASSESS** — Produce the six confidence dimensions with rationales, and the
   business-impact assessment.
9. **WRITE** — Draft to the report-type structure, keeping each audience layer
   distinct (executive, SOC, detection, architecture).
10. **REVIEW** — Self-review for unsupported claims, mixed evidence classes,
    severity inflation, and speculation without labels.
11. **VALIDATE** — Run the Editorial QA Gate (Layer 5). Compute the publication
    score.
12. **PUBLISH** — Only if the publication score is at or above threshold.
    Otherwise return to draft.

---

## Prioritization rubric (real-world exploitation over theoretical severity)

| Signal | Weight | Source |
|---|---|---|
| Listed in CISA KEV | Highest | CISA KEV catalog |
| Credible reported in-the-wild exploitation | High | Vendor / gov / named research |
| Known ransomware-campaign association | High | CISA KEV `knownRansomwareCampaignUse` |
| Internet-exposed + pre-auth + no user interaction | High | CVSS vector (AV:N/PR:N/UI:N) |
| CVSS base score | Moderate | NVD |
| Vendor-only severity, no exploitation signal | Lower | Vendor advisory |

This rubric is the basis of the platform's Exploitation Velocity Index — patch
prioritization should follow KEV and exploitation signal, not CVSS alone.

## Enrichment standards

- **Severity Anatomy:** decode the official CVSS v3.x vector into attack vector,
  complexity, privileges required, user interaction, scope, and CIA impact —
  each a direct read of the primary record.
- **Weakness Anatomy:** decode the NVD-assigned CWE into how the weakness class
  is exploited and how it is detected/prevented (MITRE CWE corpus).
- **MITRE mapping:** ATT&CK for conventional threats; ATLAS for AI/ML; OWASP
  (Web / LLM Top 10) where relevant. Map only techniques the evidence supports.
- **Detection content:** provide Sigma/KQL/YARA only when it is technically
  sound and tied to the behavior; label detection confidence. Never ship a rule
  you cannot justify.

## Handling uncertainty

- Unknown facts → **Unknown** or **Intelligence Gap**, never a guess.
- Plausible-but-unconfirmed → **Hypothesis**, with what would confirm it.
- Forward-looking → **Future Outlook**, labeled as assessment.

---

### Changelog
- **v1.0** — Initial workflow: 12 stages, prioritization rubric, enrichment
  standards, uncertainty handling.
