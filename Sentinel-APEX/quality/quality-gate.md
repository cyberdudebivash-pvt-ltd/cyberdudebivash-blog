# SENTINEL APEX — QUALITY GATE

Every intelligence product MUST pass this gate before moving from
`reports/drafts/` to `reports/final/`. A single failed item blocks promotion.

> **Executable enforcement:** the machine-checkable subset of this gate
> (structure, ATT&CK validity, IOC defanging, Sigma rule validity, confidence
> labeling, scraper-noise leakage, cross-report duplication) runs as code in
> `../engine/` — `python3 cli.py gate <report...>` exits non-zero on any
> blocking finding. Run it before manual review, not instead of it.

## 1. Evidence Integrity
- [ ] Every statement in **Verified Facts** is directly supported by a cited source
- [ ] No invented CVEs, hashes, IOCs, victim names, or telemetry
- [ ] Every hash matches the source exactly (no truncation/reconstruction)
- [ ] All source URLs appear in **References**

## 2. Analytical Discipline
- [ ] Assessments beyond the source are labeled (ANALYST ASSESSMENT / HYPOTHESIS / ESTIMATED / LIKELY / POSSIBLE / UNCONFIRMED / UNKNOWN)
- [ ] Every assessment carries a confidence level (VERY LOW → VERY HIGH)
- [ ] Confidence ratings are justified with reasoning
- [ ] **Intelligence Gaps** section honestly states what is NOT known

## 3. Framework Accuracy
- [ ] ATT&CK technique IDs are correct and include sub-techniques where determinable
- [ ] Every ATT&CK ID in the body appears in front matter `attack_ids`
- [ ] CVSS scores/vectors match the authoritative source (NVD/vendor)
- [ ] EPSS and CISA KEV status are current-as-of the report date and dated
- [ ] CWE / CAPEC / D3FEND references (where used) are valid
- [ ] If SSVC is used for prioritization, the decision points (Exploitation, Exposure, Utility, Safety/Mission Impact) are stated explicitly, not just the resulting action
- [ ] If a STIX bundle is included, it is valid STIX 2.1 JSON

## 4. IOC Discipline
- [ ] Every IOC is in exactly one category (Confirmed / Observed / Historical / Behavioral / Derived / Hypothetical)
- [ ] All network IOCs are defanged (`hxxp`, `[.]`)
- [ ] First-seen / last-seen context included where the source provides it

## 5. Detection Content Validity
- [ ] Sigma rules are valid YAML with required fields and a UUID `id`
- [ ] KQL / SPL / EQL reference real tables/indexes and field names
- [ ] YARA rules have valid syntax and no invented byte patterns
- [ ] Suricata rules are well-formed
- [ ] Each rule states expected false positives and required telemetry
- [ ] Low-confidence rules are marked `experimental` with a note

## 6. Business & Operational Value
- [ ] Business impact is evidence-based; estimates are labeled
- [ ] Remediation / patch prioritization is concrete (SLA, not "patch promptly")
- [ ] Compensating controls provided for un-patchable scenarios (CVE reports)
- [ ] IR guidance covers containment, eradication, and credential rotation

## 7. Audience Test
- [ ] A Fortune 500 CISO would find the executive sections useful
- [ ] A SOC analyst could begin hunting within 15 minutes
- [ ] An incident responder gains operational value
- [ ] The report delivers substantially more value than the original source

## 8. Publication Readiness
- [ ] Front matter is complete and machine-parseable
- [ ] Executive Summary ≤ 250 words and self-contained
- [ ] Writing is professional, non-sensational, non-clickbait
- [ ] SEO metadata / schema / internal links applied (pre-publish)
- [ ] TLP marking present

---
**Decision:** PASS → promote to `reports/final/`. FAIL → return to draft with
noted deficiencies. No exceptions.
