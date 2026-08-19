# PHASE 1 — Commercial Intelligence Data Model
## Release Certification Record (Slice 1: `related_intelligence[]` relationship typing)

**Scope of this certification.** The full Phase 1 mandate specifies a ~40-field
commercial intelligence object model spanning both `automation/` (the Blogger
syndication pipeline) and `Sentinel-APEX/engine` (the separate ReportX CTI
platform). That full scope is not achievable in one certifiable slice without
either rushing verification or fabricating coverage — both explicitly
prohibited by the governing directive's own Section 37. This record certifies
**one concrete, independently-verifiable slice**: replacing
`internal_linker.py`'s flat CVE-then-label "related intelligence" matching
with the directive's Phase 16 structured relationship model
(`DIRECT_RELATION` / `CAMPAIGN_RELATION` / `TACTICAL_SIMILARITY` /
`SECTOR_RELATION` / `RECENCY_ONLY`), plus the prerequisite state-file
persistence it depends on. Remaining Phase 1 fields (`claims[]`,
`contradictions[]`, `actors[]`, `campaigns[]`, `attack_mappings[]` with
Status, `detections[]` maturity states, `hunting_hypotheses[]`, etc.) are
tracked as open scope below, not silently dropped.

---

## Requirements Traceability

| Directive requirement | Implementation | Verified |
|---|---|---|
| Phase 16: rank relationships (actor > campaign > vuln family > sector > recency), not recency-primary | `_classify_relation()` checks strongest-first: CVE → actor → discriminating label → sector/country → recency | Unit + integration tests |
| Phase 16: mark relationship type explicitly | `RELATION_DIRECT` / `CAMPAIGN` / `TACTICAL` / `SECTOR` / `RECENCY_ONLY` constants, rendered as a human-readable label per `<li>` | Live-verified against real report data |
| Phase 16: "Do not expose RECENCY_ONLY as meaningful intelligence correlation" | `build_correlation_block()` excludes `RELATION_RECENCY_ONLY` candidates entirely before rendering | `test_nothing_shared_is_recency_only`, `test_omits_unrelated_recent_posts_when_no_direct_match` |
| Section 30: source content must never control certification/publication state | New fields (`ransomware_group`/`sector`/`country`) flow only from `threat_feeds.py`'s already-sanitized `_clean_taxonomy()`/`_safe_str()` extraction — no new unsanitized input path introduced | Code inspection; no new external-content ingestion added |
| Section 5 (Phase 1 gate): backward compatibility, null/missing behavior | `build_correlation_block()`'s 3 new params default to `""`; existing callers/tests pass unchanged | `test_a_genuinely_shared_discriminating_label_still_matches` and 18 other pre-existing tests pass unmodified |

---

## Test Environment

Local execution, Python 3.11, `pytest 9.1.1`, repository root, against a
branch freshly rebased on `origin/main` (post-#100 merge).

## Tests Executed

- **Unit tests** (`TestClassifyRelation`, 8 tests): each of the 5 relation
  outcomes individually; strongest-match-wins priority when multiple signals
  are simultaneously true; the adversarial placeholder-collision case (below).
- **Component tests** (`TestBuildCorrelationBlock`, +4 new / 11 pre-existing):
  end-to-end `build_correlation_block()` behavior — campaign match surfaces
  with the correct label, sector-only match surfaces correctly in isolation
  from label overlap, 4-tier ranking holds even when tier order contradicts
  recency order.
  - **One test authoring bug was self-caught, not shipped**: an early version of
    `test_shared_sector_alone_surfaces_as_sector_relation` gave both articles
    the `"Ransomware"` label, which is itself genuinely discriminating — so
    `TACTICAL_SIMILARITY` correctly won ahead of `SECTOR_RELATION` per the
    designed priority order, and the test failed. That is the implementation
    working as designed, not a defect; the test was corrected to isolate the
    sector-only signal, not the implementation.
- **Persistence tests** (`test_mark_published_persists_ransomware_fields`):
  confirms the 3 new fields actually survive into
  `data/published_posts.json`, not just the in-memory `DiscoveredArticle` —
  this was verified as a real, necessary prerequisite gap before writing any
  classification logic (the fields existed on the dataclass since the
  previous PR's dashboard-tile fix, but were never persisted).
- **Regression tests**: full suite, `pytest tests/ automation/tests/` —
  **372/372 pass**, including all pre-existing `internal_linker`/
  `content_discovery` coverage from every prior round this session.
- **Adversarial testing**: attempted to break the new classification logic
  before certifying it (see Adversarial Results below).
- **Live-like verification**: reconstructed the real `SilentRansomGroup`/
  `shinyhunters`/unrelated-CVE data from this session's user-uploaded
  reports, ran it through the actual `InternalLinker.build_correlation_block()`
  end-to-end, and inspected the real rendered HTML output (not just
  assertions) — confirmed the unrelated CVE is excluded, the same-actor
  match is labeled "Same threat actor" and ranks first, and a same-topic
  (different-actor) ransomware match is labeled "Related topic" and ranks
  second.

## Adversarial Results

**Finding (real, fixed before certification):** `threat_feeds.py`'s
`RansomwareIntelSource` falls back to the literal string `"Unknown Group"`
when a source record names no actor (`group = _safe_str(v.get("group")) or
"Unknown Group"`). A naive equality check on `ransomware_group` would
classify two claims from two different, genuinely unidentified actors as
`CAMPAIGN_RELATION` ("Same threat actor") purely because both defaulted to
the same placeholder string — a real false positive, not merely a weak
match. Fixed by excluding known placeholder values
(`_PLACEHOLDER_ACTOR_NAMES`) from the actor-match branch, mirroring the
existing `_AGGREGATING_CONNECTORS` pattern in the same file for the
analogous Round 7 finding. Regression test:
`test_two_unidentified_actors_sharing_the_unknown_group_placeholder_are_not_campaign_related`.

**Checked, no defect found:** the sector/country extraction path
(`_clean_taxonomy()`) already rejects placeholder/malformed values and
returns `""`, which correctly fails the truthy check in
`_classify_relation()` — confirmed by code inspection, no equivalent
placeholder-collision risk exists there. The CVE-match path is a strict
regex extraction (`CVE-\d{4}-\d{4,}`), not free text, so it carries no
analogous risk either.

## Security Validation

No new untrusted-input path is introduced. The 3 new fields are sourced
exclusively from `threat_feeds.py`'s existing sanitization
(`_safe_str`/`_clean_taxonomy`), the same functions every pre-existing field
in this pipeline already goes through. Rendered output continues to pass
through `html.escape()` at the same call sites as before this change.

## Performance

Not separately load-tested at full production scale (thousands of entries
in the real `data/published_posts.json`). The algorithm's complexity class
is unchanged from the prior implementation — still a single O(n) pass over
`posts.items()`, now doing a classification call instead of a set
intersection per entry, both O(1) amortized per entry. No new I/O.

## Blogger Validation

**NOT_EXECUTED — BLOCKED BY scope.** This change alters what
`build_correlation_block()` renders on the *next* real syndication run, but
no live post has been published and post-publication-fetched against this
specific change in this certification pass. The full publish→fetch→
parse→compare cycle described in the directive's Section 26 has not been
run for this slice. This is a genuine, named gap, not an implied pass.

## Open Defects

None found beyond the one adversarial finding above, which was fixed prior
to this certification.

## Residual Risk

- **LOW** — `TACTICAL_SIMILARITY` genuinely can still fire on a merely
  coincidental shared label if a future keyword mapping in
  `content_discovery._infer_labels()` becomes overly broad (the same defect
  class fixed for `"Vulnerabilities"` this session and for the three
  universal labels in Round 4). No new instance of this risk was introduced,
  but it remains a live class of risk in the underlying label-inference
  system this slice depends on.
- **LOW** — `ransomware_group` matching is case-sensitive exact string
  equality; a source providing inconsistent casing for the same real actor
  across different pulls would silently miss a real `CAMPAIGN_RELATION`
  match (false negative, not false positive). Not observed in the two real
  actor names available this session (`SilentRansomGroup`, `shinyhunters`);
  flagged as a residual risk, not fixed speculatively without evidence of it
  actually occurring.

## Rollback Readiness

Fully additive change: 3 new optional dataclass fields (default `None`), 3
new optional function parameters (default `""`), one internal algorithm
change scoped entirely to `build_correlation_block()`'s private bucketing
logic. Reverting the single commit fully restores prior behavior; no schema
migration, no data deletion, no irreversible state change.

## Certification Decision

```
RELEASE_CERTIFIED_WITH_LIMITATIONS
```

Certified for the scope stated above (related-intelligence relationship
typing + its persistence prerequisite). Not a certification of Phase 1 in
its full ~40-field scope — that remains open, tracked below. Blogger
post-publication validation for this specific change is the one explicitly
named gap (`NOT_EXECUTED — BLOCKED BY scope`), not silently assumed passing.

---

## Remaining Phase 1 Scope (not yet attempted)

- `claims[]` with per-claim status (confirmed/corroborated/reported/
  claimed/disputed/unknown) — currently corroboration is report-level, not
  claim-level. Directly named in Phase 3 as a current defect.
- `contradictions[]`, `intelligence_gaps[]`, `collection_requirements[]` —
  not modeled as structured data anywhere in either codebase today.
- `actors[]`, `campaigns[]`, `malware[]`, `infrastructure[]` as normalized
  entity lists (today: only the single `ransomware_group` string this slice
  persists — a real step toward this, not the full entity model).
- `attack_mappings[]` with `Status` (`OBSERVED`/`ASSESSED`/`CONDITIONAL`/
  `NOT_SUPPORTED`) — ATT&CK mappings currently render as prose text, not a
  structured, status-qualified object.
- `detections[]` maturity model beyond the current single `status` field
  (`SYNTAX_STATUS`/`SEMANTIC_RELIABILITY`/`PRODUCT_VALIDATION`/etc. as
  Phase 11 specifies).
- `hunting_hypotheses[]`, `forecasts[]`, `business_impacts[]`,
  `role_decisions[]` as structured lists (role decisions currently render as
  prose per role, not `{Decision, Rationale, Priority, Deadline,
  Evidence Dependency, Escalation Trigger}` records).
- `public_safety_status` as a 4th, distinct certification axis (today:
  `review_status` + `certification_status` exist; Phase 17 specifies 4
  separate axes).
- Any of this slice's work applied to `Sentinel-APEX/engine`'s separate
  ReportX system — out of scope for this slice, since `related_intelligence`
  is exclusively an `automation/`-side, Blogger-publishing concept today.
