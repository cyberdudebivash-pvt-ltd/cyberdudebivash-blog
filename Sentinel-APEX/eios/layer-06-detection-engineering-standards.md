# EIOS LAYER 6 — DETECTION ENGINEERING STANDARDS

Specifies which detection formats are supported and, new in this revision,
the maturity of each artifact — so a consumer never mistakes an untested
reference rule for something that has been validated in production.

## Supported formats

The full named-platform coverage table already lives in
`prompts/master-prompt.md` § Named Detection Platform Coverage (added in the
prior EIOS revision) — this layer does not restate it, only adds maturity.
Summary of what's covered: Sigma, YARA, Splunk SPL, Microsoft Sentinel /
Defender XDR / Defender for Endpoint / Defender for Identity KQL, Elastic
EQL and ES\|QL, Google Chronicle YARA-L 2.0, IBM QRadar AQL, CrowdStrike
Falcon (FQL), SentinelOne Deep Visibility, Palo Alto Cortex XDR / XSIAM,
Suricata, Snort.

**Snort** was named in the v2 specification and is not yet in the platform
coverage table — added here: Snort 3 rule syntax, for environments running
Snort rather than (or alongside) Suricata. Sigma/YARA validity is
machine-checked (Layer 4); Snort and Suricata rule syntax are not — flag
them `experimental` if the author cannot verify syntax against a running
sensor.

## Maturity model

Every detection artifact declares one of four maturity levels. This is new
in EIOS v2 — v1 had no maturity concept beyond Sigma's own `status` field
(`experimental`/`test`/`stable`, a Sigma-specific convention). The EIOS
maturity model applies uniformly across every format, including ones with no
native status field of their own (YARA, KQL, SPL):

| Maturity | Meaning | Evidence required |
|---|---|---|
| **Reference** | Illustrates the technique; not validated against real telemetry | None beyond syntactic validity (Layer 4 gate) |
| **Reviewed** | A second analyst confirmed the logic is sound | Reviewer identified (Layer 8 `reviewer` field) |
| **Tested** | Fired correctly against real or synthetic telemetry in a lab | Test telemetry source and result documented |
| **Production Validated** | Running in a live environment with a known false-positive rate | Deployment context + measured FP rate documented |

**Never claim a maturity level the evidence doesn't support.** A Sigma rule
authored from a source advisory's prose description, with no telemetry to
test against, is `Reference` — not `Tested` — regardless of how confident
the analyst is in the logic. This mirrors the platform's core no-fabrication
rule applied to detection content specifically: claiming untested
compatibility is its own form of fabrication.

## Where maturity is recorded

- Per-artifact, in the Detection Engineering Brief template
  (`templates/detection-engineer/detection-engineer-brief.md`, added in
  Layer 5).
- In Sigma's own `status` field where a natural mapping exists
  (`experimental` → Reference/Reviewed, `test` → Tested, `stable` →
  Production Validated) — this is a convention, not a forced rename; Sigma's
  field stays exactly as CONVENTIONS.md already defines it.
- YARA, KQL, SPL, and other formats without a native status field record
  maturity in the surrounding report prose (the Detection Opportunities /
  format-specific section) until Layer 3's `DetectionRule` object is
  implemented in code, at which point `maturity` becomes a structured field.

## Relationship to Layer 4

Maturity is a **quality/trust** signal, not a **correctness** gate. A
`Reference`-maturity Sigma rule can still be syntactically perfect and pass
every Layer 4 gate — maturity tells the consumer how much to trust it in
production, which the correctness gate cannot measure.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 6*
