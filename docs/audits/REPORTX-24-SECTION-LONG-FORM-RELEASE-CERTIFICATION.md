# ReportX 24-Section Premium Long-Form Standard — Release Certification

## Scope of this certification

The founder mandate's full scope (Phases A–L: a 24-section contract, family
applicability matrices, a completeness engine, an analytical depth gate, an
anti-padding/anti-duplication control, page-length targets, four product
tiers, a Blogger publication rule, a quality-scoring model, and a full
canary/adversarial validation suite) is not achievable as one certified
unit without either rushing verification or overclaiming coverage. This
record certifies what was actually built and verified this round: **Phase
A (canonical 24-section contract + family applicability matrices), Phase C
(section-completeness evaluator), and Phase D/G (analytical depth gate +
product tier verdict)** — `automation/report_contract.py` and
`automation/analytical_depth_gate.py`. Remaining phases are listed as open
scope at the end of this document, not silently dropped.

## The decisive fact this certification is built around

Before writing any schema code, a targeted research pass across this
repository's three parallel report-generation systems (`automation/`,
`Sentinel-APEX/engine/sentinel_engine/reportx/`, and
`Sentinel-APEX/eios/`) confirmed: **no long-form analytical prose generator
exists anywhere in this codebase.** `pipeline_composer.compose_report()`'s
own docstring states it directly: *"The point of this module is not to
write new analytical prose from scratch."* The only place genuine deep
analyst content (Actor Context, Forecast, Historical Correlation) has ever
existed is 5 hand/agent-researched canary fixtures, each built from a
one-off real-incident research session — not a reproducible production
capability. The one mechanism that could generate real prose at scale —
an LLM call — was independently verified as non-functional in production
earlier this same session (Groq 404, DeepSeek/OpenRouter 402 Payment
Required, Anthropic key unset).

Given this, and per the founder mandate's own explicit routing rule
("INSUFFICIENT BUT ENRICHABLE → HOLD_FOR_ENRICHMENT... Never manufacture
intelligence merely to meet a page count"), the correct engineering
response is not to build a prose generator that would necessarily either
fabricate content or never leave the drafting board. It is to build the
**gate** that honestly recognizes today's real evidence density and routes
accordingly — which is exactly what this certification covers, and exactly
why every real report checked below resolves to `TACTICAL`, not
`PREMIUM_LONG_FORM`. That is the correct outcome, not a shortfall.

## Reuse precedent (checked before building anything)

`Sentinel-APEX/eios/sentinel-intelligence-standard.md:296-329` already
documents a "Cross-reference to an external 25-part taxonomy request" — a
nearly identical prior directive, reconciled item-by-item against the
existing tier system with the finding "no requested part names a
genuinely new analytical capability." This certification's section list
and applicability matrices were built using the same discipline: every one
of the 24 sections was checked against what `report_renderer.py` and
`authority_transformer.py` actually render today before being marked
`_IMPLEMENTED_TODAY`, `_IMPLEMENTED_ELSEWHERE`, `_PARTIAL_SIGNAL_ONLY`, or
left to resolve `WITHHELD_INSUFFICIENT_EVIDENCE` by default — not assumed
new or assumed covered.

---

## Requirements Traceability

| Directive requirement | Implementation | Verified |
|---|---|---|
| Phase A: canonical 24-section contract | `report_contract.py`'s `ALL_SECTIONS`, `SECTION_1_...` through `SECTION_24_...` constants | Code review against the founder mandate's own section list, 1:1 |
| Phase A/B: family-specific applicability, "do not invent an intrusion chain" for ransomware | `_FAMILY_APPLICABILITY["ransomware_claim"]` marks Attack Path/ATT&CK/Technical Analysis/Exposure `NOT_APPLICABLE`, not merely unresolved | `test_attack_path_and_technical_analysis_are_not_applicable` |
| Phase C: 5-state section resolution, "a blank heading is forbidden" | `SectionState` enum; every section resolves to a named state, never silently omitted | 15 tests in `test_report_contract.py` |
| Phase C: no generic filler | Sections with no real implementation resolve `WITHHELD_INSUFFICIENT_EVIDENCE`, never a synthesized placeholder | Code review: no string-generation path exists for unimplemented sections |
| Phase D: "a report cannot qualify merely because it contains 24 headings" | `evaluate_product_tier()` requires zero mandatory sections withheld AND analyst authorship AND (for CVEs) independent corroboration — never section-count alone | `TestMechanismCanReachPremiumWhenConditionsAreGenuinelyMet` |
| Phase D adversarial: "certify a sparse report as premium" must fail | All 5 real uploaded reports, all 3 real `content_source` values (9 combinations) verified to resolve `TACTICAL`, never `PREMIUM_LONG_FORM` | Live-like verification, reconstructed real data (below) |
| Phase G: product tiers FLASH/TACTICAL/PREMIUM_LONG_FORM | `FLASH`, `TACTICAL`, `PREMIUM_LONG_FORM` constants in `analytical_depth_gate.py` | — |
| Phase G: "Do not call every raw feed event PREMIUM_LONG_FORM" | Verified directly: no combination tested this round reaches it | Live-like verification (below) |

## Adversarial Testing

**Attempted: force PREMIUM_LONG_FORM from a single sentence / sparse
record.** All 3 real `content_source` values tested against all 3 real
sample articles (CVE-2026-75912 with a CWE, CVE-2026-60698 without one,
SilentRansomGroup's ransomware claim) — 9/9 combinations resolved
`TACTICAL`. Even the hypothetical case of genuine LLM authorship
(`content_source="groq"`) does not reach premium, because `key_judgements`
and `intelligence_gaps` have no implementation anywhere in this pipeline
and always resolve withheld — this is checked explicitly in
`test_llm_authored_cve_report_still_capped_because_key_judgements_are_withheld`.

**Attempted: prove the gate isn't stuck closed by construction.** Using a
mocked all-`COMPLETE` section-resolution set (isolating
`evaluate_product_tier()`'s own logic from today's real content gaps),
confirmed the gate genuinely opens to `PREMIUM_LONG_FORM` when analyst
authorship, complete mandatory sections, and independent corroboration are
all genuinely present — and stays at `TACTICAL` when corroboration is
missing even with otherwise-complete sections. This proves the mechanism
is a real gate, not a permanently-sealed one.

**Attempted: reuse the "Unknown Group" false-positive class of bug.**
`threat_feeds.py`'s literal placeholder fallback was checked against
Section 12 (Actor/Campaign Context)'s resolver — confirmed it correctly
resolves `WITHHELD_INSUFFICIENT_EVIDENCE`, not falsely credited as real
actor context, mirroring the identical adversarial finding fixed in the
Phase 1 slice.

**Attempted: silently guess eligibility for an unreconciled family.**
`breach_notice` (and by the same code path, `ai_security`/
`general_intelligence`) have no applicability matrix entry yet.
`get_applicability()`'s default is `OPTIONAL`, never `MANDATORY` (which
would falsely gate an unanalyzed family) and never `NOT_APPLICABLE` (which
would silently hide a section that might genuinely apply once that family
is reconciled). Confirmed the resulting empty `mandatory` list correctly
caps the family at `TACTICAL` via its own explicit code path, not an
accidental pass-through. Test: `test_family_with_no_matrix_is_capped_at_tactical_even_with_llm_content`.

## Live-Like Verification (real data, not synthetic fixtures)

Reconstructed the exact real `DiscoveredArticle` data from this session's
3 representative uploaded reports (CVE-2026-75912 with CWE-88,
CVE-2026-60698 with no CWE, SilentRansomGroup/Troutman Pepper Locke) and
ran each through the actual `evaluate_product_tier()` function against all
3 real `content_source` values the pipeline can produce
(`reportx_composer`, `template`, `groq`). All 9 verdicts: `TACTICAL`, with
an explicit, correct reason naming exactly which mandatory sections are
withheld. No manual inspection needed beyond confirming the printed
reasons name real, correct section keys — which they do.

## Test Suite

- `tests/test_report_contract.py`: 15 tests — applicability defaults,
  per-section state resolution for both reconciled families (`cve_advisory`,
  `ransomware_claim`), detection-status-driven resolution for Detection
  Engineering and ATT&CK Mapping, the "Unknown Group" adversarial guard.
- `tests/test_analytical_depth_gate.py`: 8 tests — current-reality capping
  (4 tests), mechanism-can-open-when-earned (3 tests), unreconciled-family
  handling (1 test).
- Full suite: **395/395 pass** (`pytest tests/ automation/tests/`),
  including all prior rounds' coverage unmodified.

## Security Validation

No new untrusted-input path. Both new modules consume only
`DiscoveredArticle`/`ReportContext` fields already sanitized upstream, plus
a `detection_status`/`content_source` string the caller already computed.
`analytical_depth_gate.py`'s only I/O is the pre-existing, already-tested
`find_independent_prior_source()` state-file read (Round 7) — no new file
or network access introduced.

## Performance

Both modules are pure, synchronous, in-memory functions over a fixed
24-section list — O(1) relative to article size, no new I/O beyond the
pre-existing corroboration lookup. Not separately load-tested; the
complexity class does not warrant it.

## Blogger Validation

**NOT_EXECUTED — BLOCKED BY scope.** Neither module is wired into
`authority_transformer.py`'s live `transform()` call this round (see "What
this does not do" below) — there is nothing yet to observe on a real
published post. Marked explicitly, not implied passing.

## Open Defects

None found beyond the "Unknown Group" class already covered by Phase 1's
adversarial fix, confirmed to also hold correctly here.

## Residual Risk

- **LOW** — the applicability matrix currently covers 2 of 7 real report
  families (`cve_advisory`/`cisa_kev`/`cisa_advisory` share one matrix;
  `ransomware_claim` has its own). `breach_notice`, `ai_security`, and
  `general_intelligence` fall back to the safe `OPTIONAL` default rather
  than a reconciled matrix — correct and non-fabricating, but means those
  3 families cannot currently distinguish `TACTICAL` from `FLASH`
  meaningfully via the mandatory-section mechanism.
- **LOW** — Section 13 (Historical Correlation) is always `PARTIAL_EVIDENCE`
  by design (the mechanism is real, but confirming an actual match needs
  the state file, which this function deliberately doesn't couple to). A
  report with zero real historical relationships is currently
  indistinguishable from one with several, at this layer.

## Rollback Readiness

Two new, fully standalone files with no modification to any existing
module and no wiring into the live publish path. Deleting both files (or
reverting the single commit) fully restores prior behavior with zero
downstream effect, since nothing currently calls them.

## Certification Decision

```
RELEASE_CERTIFIED_WITH_LIMITATIONS
```

Certified for the scope stated above. The central, load-bearing claim —
that no current report can be dishonestly certified `PREMIUM_LONG_FORM` —
is proven by both adversarial testing and live-like verification against
real data. Named limitations: Blogger validation not executed (nothing
observable yet), only 2 of 7 families have a reconciled applicability
matrix, and — the largest limitation — the gate is not yet wired into the
live pipeline at all (see below).

---

## What this does *not* do

- **Not wired into `authority_transformer.py`'s live `transform()` call.**
  This was a deliberate scope decision, not an oversight: since every real
  report currently resolves to the same tier regardless of input, wiring
  it in this round would have zero observable production effect, and the
  actual integration design (does a tier verdict gate publication outright,
  or only get recorded as observability data in `data/published_posts.json`
  / `logs/run-*.json`? what happens to a report that resolves `FLASH`
  today?) deserves its own scoping decision, not a rushed bolt-on.
- **Not a content generator.** As established above, this round
  deliberately does not attempt to produce real 20-30 page prose — that
  remains blocked on either a working LLM provider or a fundamentally
  different (and separately-scoped) content-acquisition architecture.
- **Not the remaining 5 families' applicability matrices**
  (`breach_notice`, `ai_security`, `general_intelligence`, plus the
  founder mandate's other named families this pipeline doesn't yet
  distinguish at all: malware, threat actor, campaign, phishing/PhaaS,
  cloud threat, identity threat, IOC bulletin, exploitation intelligence,
  strategic intelligence — none of which this pipeline's `report_integrity.
  _classify_family()`-equivalent logic currently produces as a distinct
  family).
- **Not Phase E (anti-padding/anti-duplication)** — genuinely lower
  priority right now, since nothing currently produces long-form content
  for it to detect padding within.
- **Not Phase J (quality scoring)** or **Phase K (regression canary
  matrix)** in the founder mandate's specific new form — `Sentinel-APEX/
  engine`'s existing 20-dimension scorecard (Round 5/6) and 5 real canaries
  remain the closest existing equivalents, not reconciled against this
  specific new spec this round.

## What remains, named plainly

1. **Decide the wiring/integration design** for
   `evaluate_product_tier()`'s output — the single highest-leverage next
   step, since it's what would make this gate load-bearing in production
   rather than a certified-but-dormant module.
2. **Resolve the LLM provider blocker** (owner action, named in the
   previous PRs this session) — the actual precondition for any real
   report ever reaching `PREMIUM_LONG_FORM`.
3. Reconcile the remaining 5 report families against the 24-section
   contract, the same item-by-item way `cve_advisory` and
   `ransomware_claim` were this round.
4. Build Phase C's remaining gap: a real, non-mocked way to confirm
   Section 13's historical-correlation mechanism found an actual match for
   a specific article (today it's correctly conservative but structurally
   blind without the state file).
