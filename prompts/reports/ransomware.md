> ⚠ **Superseded** — see `prompts/README.md`. Canonical equivalent:
> `Sentinel-APEX/prompts/malware-prompt.md` (explicitly covers ransomware
> strains).

# REPORT TYPE — RANSOMWARE INTELLIGENCE

**Version:** 1.0 · **Layer 3** · Inherits Constitution + Production Workflow
**Use when:** a ransomware group, campaign, or incident is the subject.

---

## Objective
Give defenders and executives an evidence-based read on a ransomware threat: who,
how, who is exposed, and what to do — without sensationalism. Ransomware coverage
is where fear marketing is most tempting and most damaging to trust. Resist it.

## Required inputs (never invent)
- Group/affiliate name as reported; avoid attribution beyond the evidence.
- Initial-access vectors and CVEs actually cited (with KEV status).
- TTPs mapped to MITRE ATT&CK, supported by named research/vendor/gov reporting.
- Confirmed IOCs only, with source and first-seen.
- Victimology claims: label as **Vendor/Research Statement** or leak-site claim,
  never as Verified Fact unless independently confirmed. Do not repeat unverified
  victim counts or ransom figures as fact.

## Section structure
1. **Executive Risk Snapshot** — is your sector/stack in scope, and the one
   action that most reduces risk.
2. **Threat Overview** — group, activity level, double-extortion model, as
   reported (labeled).
3. **Verified Facts vs Claims** — separate confirmed technical facts from
   leak-site/marketing claims by the actor.
4. **Initial Access & Exploited CVEs** — the vulnerabilities actually used, with
   KEV status and Severity Anatomy for the key ones.
5. **Attack Narrative (Representative)** — access → escalation → lateral movement
   → exfiltration → encryption, MITRE-mapped; labeled as a representative model
   informed by reporting.
6. **Behavioral Indicators & Confirmed IOCs** — prioritize behavior (vssadmin,
   shadow-copy deletion, mass file rename) over ephemeral IOCs.
7. **Detection & Threat Hunting** — Sigma/KQL for the behaviors; hunt hypotheses.
8. **Containment / Mitigation / Recovery** — including offline-backup validation
   and isolation-before-spread guidance.
9. **Business Impact** — operational downtime, extortion/regulatory exposure,
   supply-chain and identity risk.
10. **Confidence Block** — six dimensions with rationales (attribution confidence
    called out explicitly).
11. **References** · 12. **Analyst Conclusion.**

## Do not
- State victim counts or ransom amounts as fact without corroboration.
- Over-attribute. · Sensationalize. · Imply an org is breached without evidence.
