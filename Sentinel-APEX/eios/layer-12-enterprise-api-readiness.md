# EIOS LAYER 12 — ENTERPRISE API READINESS

Structured data alongside prose, so a dashboard or API never has to re-parse
narrative markdown. **Scope note before anything else:** this layer defines
a schema. It does not modify the live, paid `api/v1/*` product surface
(`auth.js`, `billing.js`, `admin.js`, the intel endpoints defined in
`vercel.json`) — that is a separate, higher-risk change with real customer
and billing-webhook impact, out of scope here, and flagged as a future
integration task, not attempted silently.

## What already produces structured output

Three things exist today, none of which this layer replaces:

1. **Front matter** (`prompts/report-prompt.md` § Output Contract, extended
   by Layer 8) — every report already carries a machine-parseable YAML
   header. This is the source of truth for a report's own metadata.
2. **`IntelligenceScore.to_dict()`** and **`GateResult.to_dict()`**
   (`engine/sentinel_engine/models.py`, `scoring.py`) — the score and gate
   result are already dataclasses with a `to_dict()` method producing exactly
   the kind of JSON the v2 spec's example illustrates, computed, not
   hand-written.
3. **`api/intel/*.json`** siblings to every published `posts/*.html` (e.g.
   `api/intel/cve/CVE-2026-0257.json` alongside the corresponding post) —
   this is the live production pattern already serving real traffic. Any
   new schema here should follow its conventions, not invent new ones.

## The report-level JSON schema

Formalizes the front matter (Layer 8) plus the score/gate objects into one
sibling artifact per report — extending pattern 3 above to intelligence
reports specifically, the same way it already exists for CVE/vendor pages:

```json
{
  "report_id": "SA-2026-0042",
  "report_type": "incident",
  "subject_taxonomy": "zero-day-intelligence",
  "version": "1.0",
  "severity": "Critical",
  "confidence": {
    "source": "High",
    "evidence": "High",
    "technical": "High",
    "attribution": "Medium",
    "detection": "High",
    "operational": "High",
    "business_impact": "Medium"
  },
  "score": {
    "overall": 78,
    "tier": "PRO",
    "eligible": true
  },
  "mitre_attack": ["T1190", "T1059"],
  "cves": ["CVE-2026-0257"],
  "iocs": [],
  "detections": [
    {"format": "sigma", "maturity": "reviewed"}
  ],
  "references": [],
  "review_status": "published",
  "last_updated": "2026-07-27"
}
```

Field-by-field provenance: `report_id`/`report_type`/`version`/
`review_status`/`last_updated` come straight from Layer 8's front matter.
`subject_taxonomy` comes from Layer 3's classification table. `confidence`
comes from Layer 7's seven-dimension model. `score` comes directly from
`IntelligenceScore.to_dict()` (Layer 10) — do not hand-compute it a second
time. `detections[].maturity` comes from Layer 6.

## Defensive-consumption convention

If and when this schema is consumed by another system (a dashboard, the
Sentinel APEX product portal), follow the schema-tolerance pattern this
codebase already established for the reverse direction — ingesting
`intel.cyberdudebivash.com` into `fetch-live-intel.js`
(`docs/SENTINEL-APEX-PROVIDER.md`): read fields defensively through
candidate-key lookups, skip malformed/unrecognized records rather than
fabricate values for them, and track how many records didn't match any
known shape. A consumer that fails hard on an unexpected field is a defect
in the consumer, not license to freeze the producer's schema forever.

---
*CyberDudeBivash® Sentinel APEX — EIOS Layer 12*
