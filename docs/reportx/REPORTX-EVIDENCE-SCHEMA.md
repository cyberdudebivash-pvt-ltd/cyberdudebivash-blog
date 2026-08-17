# ReportX Evidence Schema

Reference for the canonical claim/evidence/source model implemented in
`Sentinel-APEX/engine/sentinel_engine/reportx/`. Every type described here
has a corresponding dataclass in the codebase — this document explains the
design intent behind each field; it is not a substitute for reading the
source, which is the authoritative definition.

---

## Layering

```
SOURCE RECORDS -> EVIDENCE RECORDS -> CLAIMS
    -> ANALYTIC JUDGMENTS (forecasts, hypotheses)
    -> RECOMMENDATIONS
    -> REPORT PRODUCT
```

`claim_model.py` implements the first three layers. `forecast.py` and
`analytic_scaffolding.py` implement the analytic-judgment layer.
`commercial_readiness.py` assembles everything into the final gate.

## `SourceRecord` (`claim_model.py`)

One retrieved source. Fields: `source_id`, `url`, `publisher`, `source_type`
(`SourceType` enum — `VENDOR_CNA`, `CISA`, `NVD`, `MITRE`,
`PRIMARY_TECHNICAL_ADVISORY`, `LEAK_SITE_AGGREGATOR`, `VICTIM_STATEMENT`,
`REGULATOR_FILING`, `JOURNALISM`, `CTI_VENDOR_RESEARCH`,
`SECURITY_RESEARCHER`, `OTHER`), `source_role` (`SourceRole` enum —
`PRIMARY_EVENT_SOURCE`, `CORROBORATION`, `ACTOR_CONTEXT`,
`VULNERABILITY_SOURCE`, `DETECTION_SOURCE`, `STATISTICAL_SOURCE`,
`REGULATORY_SOURCE`, `METHODOLOGY_SOURCE`), `retrieved_at` (our own
retrieval clock — always exact), `source_date` (verbatim as the source
states it), `temporal_precision`, `content_sha256`, `reliability`,
`independence_group`, `accessibility`, `notes`.

**`temporal_precision`** (`TemporalPrecision` enum: `EXACT_TIMESTAMP` /
`DATE_ONLY` / `MONTH_ONLY` / `YEAR_ONLY` / `UNKNOWN`) is auto-classified
from `source_date` by `infer_temporal_precision()` unless the caller
explicitly overrides it — but the override is never silently accepted
without evidence: `commercial_readiness.py`'s "Temporal integrity" control
(row 14) re-runs the same inference against the stored string and fails
the report if the claimed precision doesn't match what the raw string
actually supports. This is the direct fix for the exact defect class named
in the task: a source giving only `2026-08-18` must never be represented
internally as `2026-08-18T00:00:00Z`.

**`independence_group`**: two sources sharing this string are treated as
NOT independent of each other (e.g. two outlets both syndicating the same
wire story). Corroboration state (below) is computed from these groups,
never set by hand.

## `EvidenceRecord`

A specific excerpt from a source (`evidence_id`, `source_id`, `excerpt`,
`locator`). Sits between raw sources and claims so one source can back
multiple distinct claims without re-quoting the whole source each time.

## `Claim`

The unit of assertion. Fields: `claim_id` (stable, required), `claim_type`
(`ClaimType` enum — see below), `text`, `scope`, `status` (`EpistemicState`
enum), `confidence` (reused from the parent package's existing
`models.Confidence` — `LOW`/`MEDIUM`/`HIGH`, not redefined), `evidence_refs`,
`source_refs`, `corroboration_state`, `source_independence`,
`observed_vs_context`, `temporal_scope`, `applicability`, `contradictions`,
`analyst_notes`.

### `EpistemicState`

Nine explicit states, deliberately not a linear confidence scale — they
represent different *kinds* of standing:

| State | Meaning |
|---|---|
| `CONFIRMED` | Verified against a primary source |
| `REPORTED` | Stated by a source, not independently verified |
| `CORROBORATED` | `REPORTED` + an independent second source agrees |
| `ASSESSED` | An analytic judgment, not a directly observed fact |
| `HYPOTHESIS` | One candidate explanation among several considered |
| `UNKNOWN` | The question is meaningful but unanswered |
| `NOT_ASSESSED` | Not yet evaluated (nobody has looked) |
| `NOT_APPLICABLE` | The question does not apply to this claim/schema |
| `DISPUTED` | Sources directly conflict |

`UNKNOWN` and `NOT_APPLICABLE` are never interchangeable — a test in
`test_claim_model.py` asserts this at the enum-value level, and the
threat-schema isolation tests assert it again at the field-default level
(a bare `RansomwareVictimClaim`'s vulnerability markers are `NOT_APPLICABLE`,
never `UNKNOWN`, because the question genuinely doesn't apply absent a
linked vulnerability — it isn't merely unanswered).

### `ClaimType`

`VICTIM_IDENTITY`, `ACTOR_ATTRIBUTION`, `EXPLOITATION`, `TTP_OBSERVED`,
`TTP_HISTORICAL`, `DATA_THEFT`, `RANSOM_PAYMENT`, `BUSINESS_IMPACT`,
`VULNERABILITY_FACT`, `DETECTION_STATE`, `REGULATORY_APPLICABILITY`,
`STATISTIC`, `FORECAST`, `GENERIC_GUIDANCE`.

`HIGH_IMPACT_CLAIM_TYPES` (`EXPLOITATION`, `ACTOR_ATTRIBUTION`,
`DATA_THEFT`, `RANSOM_PAYMENT`, `BUSINESS_IMPACT`, `TTP_OBSERVED`,
`VICTIM_IDENTITY`) are subject to the stronger corroboration policy
(Section 10): `Claim.requires_downgrade_without_corroboration()` returns
`True` if a high-impact claim is asserted above `REPORTED` on a single,
uncorroborated source.

### `CorroborationState`

`SINGLE_SOURCE`, `MULTI_SOURCE_INDEPENDENT`, `MULTI_SOURCE_DEPENDENT`
(multiple sources exist but share an `independence_group`), `UNCORROBORATED`
(no sources at all). Always computed by `EvidenceGraph.recompute_corroboration()`
from the claim's actual `source_refs`/`evidence_refs`, deduplicated by
physical source — never set directly by a caller, so it cannot drift from
the underlying evidence graph.

### `ObservedVsContext`

`OBSERVED` (incident-specific, this event) / `CONTEXT` (actor-historical or
generic background) / `NOT_SET`. Makes Section 6B/19's "this incident vs.
general knowledge about the actor" distinction a first-class, checkable
field rather than a prose convention — `commercial_readiness.py`'s
"Source-specific facts" control (row 4) fails any `OBSERVED` claim that
carries no evidence of its own.

## `EvidenceGraph`

The per-report container: `sources`, `evidence`, `claims` dicts, each keyed
by id for O(1) lookup. `add_source()`/`add_evidence()`/`add_claim()` all
validate referential integrity at insertion time — an `EvidenceRecord`
citing an unregistered `source_id`, or a `Claim` citing an unregistered
`evidence_id`/`source_id`, raises immediately rather than silently
producing a dangling reference.

---

## Threat-type schemas (`threat_schemas.py`)

`ThreatProduct` is the shared base (`product_id`, `threat_type`,
`linked_vulnerabilities`). Three concrete schemas are implemented:

- **`RansomwareVictimClaim`** — three explicit layers:
  `VictimObservation` (incident-specific), `ActorHistoricalContext`
  (actor-general, every field claim-id-backed), `GenericReadiness`
  (always labeled `GENERIC_DEFENSIVE_READINESS`). Four vulnerability-shaped
  applicability markers (`cisa_kev_state`, `cvss_state`, `patch_state`,
  `exploit_cve_status`) stay `NOT_APPLICABLE` unless a real
  `LinkedVulnerability` is attached — enforced in `__post_init__`, not just
  by convention, so a caller cannot smuggle a positive state past it.
- **`CVERecord`** — the full Section 7 field set (CVSS v3.1/v4, EPSS, KEV
  state, exploit chain, PoC/weaponization status, mitigations, ATT&CK
  technique ids, ...). Has no ransomware-shaped fields at all.
- **`CISAKEVRecord`** — kept distinct from `CVERecord` because a KEV
  listing is CISA's own claim about a CVE, not the CVE's technical record;
  collapsing them would blur "when disclosed" with "when CISA listed it."

`LinkedVulnerability` is the *only* channel through which vulnerability
data may reach a non-CVE schema — it wraps a full, independent `CVERecord`
plus the `Claim` that establishes the attribution, rather than copying
fields into the parent schema's own namespace.

Isolation is proven in both directions by `test_threat_schema_isolation.py`
(11 tests): zero vulnerability-only fields exist on `RansomwareVictimClaim`
at the dataclass level (not just "unused" — genuinely absent), and zero
ransomware-only fields exist on `CVERecord`.
