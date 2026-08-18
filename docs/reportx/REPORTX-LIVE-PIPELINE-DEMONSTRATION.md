# Live Pipeline Demonstration — Real Data, Real Pipeline, Dry Run

This is the proof the ROLE mandate's VALIDATION section asks for, run the
way the mandate's non-negotiable constraints require: **not a hand-built
bundle.** Both example reports in `docs/reportx/examples/live-pipeline/`
were produced by calling `automation.authority_transformer.AuthorityTransformer.transform()`
— the exact method `automation/main.py`'s `run_pipeline()` calls at its
own `transform(article)` call site — against real `DiscoveredArticle`
records that `automation.content_discovery.ContentDiscoveryEngine.discover()`
fetched live from NVD and CISA on 2026-08-18. No content in either example
was authored, edited, or hand-assembled; both are exactly what the wired
pipeline (`REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md`'s bridge +
composer, wired into `transform()` in this work) produces unattended.

**Not performed:** no publish. `dry_run` semantics only — no call reached
`BloggerPublisher`, `cyberbivash.blogspot.com`, or `blog.cyberdudebivash.in`'s
write path. `state_file`/`logs_dir` were pointed at a scratch directory
outside the repo so the real `data/published_posts.json` tracking file was
never touched. `automation/main.py` itself was not modified or invoked as
a CLI entrypoint; `transform()` was called directly in a script, which is
what `run_pipeline()` itself does internally.

## Method

1. `ContentDiscoveryEngine(config).discover()`, called for real — live GET
   requests to CISA KEV's public JSON catalog, NVD's public CVE API, CISA
   advisories, ransomware-intel and breach-intel feeds, and ~79 global RSS
   sources (most external blog feeds 404/403/timeout over time, same as
   in ordinary production operation; each source is independently
   sandboxed, exactly as `content_discovery.py`'s own design already
   guarantees — a dead feed never blocks the others). Returned 5 real,
   current records, including the same CVE-2025-62593 (Ray) KEV entry
   this session's earlier hand-built flagship covered — still live in
   CISA's catalog — and 4 fresh NVD CRITICAL CVEs.
2. Two of the four fresh NVD records were run through `transform()`, with
   no LLM provider key configured in this environment (so both
   necessarily exercise the LLM-failure fallback chain — the exact path
   this session's composer wiring was built to improve).
3. Full input/output metadata (`llm_attempts`, `content_source`,
   `detection_status`, `report_id`, hashes) saved alongside each rendered
   HTML file for audit.

## Results

| CVE | CVSS | Real vulnerability | `content_source` | `detection_status` | Achieved tier |
|---|---|---|---|---|---|
| [CVE-2026-75094](https://nvd.nist.gov/vuln/detail/CVE-2026-75094) | 9.1 | COMFAST CF-N1-S CGI endpoint — unauthenticated OS command injection via the `ssid` parameter | `reportx_composer` | `syntax_validated_experimental` (real Sigma **and** Sentinel KQL generated) | `TACTICAL_READY` |
| [CVE-2026-75110](https://nvd.nist.gov/vuln/detail/CVE-2026-75110) | 9.8 | MemOS (LLM/AI-agent memory OS) — auth check fails open when `INTERNAL_SERVICE_SECRET` is unset (`None == None` evaluates true) | `reportx_composer` | `withheld_insufficient_evidence` (correctly — no product-specific telemetry for a defensible rule) | `TACTICAL_READY` |

Both are real records neither hand-selected for being easy nor filtered
for a clean run — they are 2 of the 4 fresh NVD CRITICAL CVEs discovery
returned, in the order discovery returned them. Both cleared every
correctness control in the 23-row matrix; both landed at `TACTICAL_READY`
(not `PREMIUM_READY_PENDING_HUMAN`) because neither carries a forecast,
alternative-hypothesis set, regulatory read, or statistics claim — exactly
the honest, expected outcome for unattended FLASH-tier volume content, per
`tier_downgrade.py`'s design and `REPORTX-PRODUCT-QUALITY-GATES.md`.

CVE-2026-75094's report includes real, evidence-conditioned Sigma **and**
Sentinel KQL detection content (`_detection_package()`'s `command_injection`
+ web-context branch), both syntax-validated, both withheld of the words
"production" or "validated" beyond that literal status label. CVE-2026-75110
correctly generates neither — an authentication/authorization-class
vulnerability with no product-specific telemetry in the source record is
exactly the case `_detection_package()` is designed to withhold on, and it
did, on real data, without prompting.

## A real defect found and fixed by this run

CVE-2026-75110 did **not** reach `reportx_composer` on the first attempt —
it fell all the way through to the legacy template, because
`qa_linter.py`'s `grammar_synthesis_qa` control failed with three
`none_value_leak` findings. Investigating (rather than dismissing the
downgrade) found the cause: MemOS's real NVD summary contains the
sentence *"...the comparison `None == None` evaluates true"* — an
accurate technical description of the vulnerable code's own equality
check, not a leaked unset Python field. `qa_linter.py`'s
`_RE_PYTHON_NONE_LEAK` regex matched the `=` inside `==` as if it were an
assignment-style leak (`vendor = None`). This is exactly the class of
defect a synthetic test fixture is unlikely to ever produce — nobody
hand-writing a test CVE summary naturally quotes a real equality
comparison from the vulnerable code — and exactly what running the real
pipeline against real, current, externally-authored text is for.

Fixed in `qa_linter.py`: the `=`-based alternative of
`_RE_PYTHON_NONE_LEAK` now excludes `=` characters that are part of a
`==`/`!=`/`<=`/`>=` comparison operator (`(?<![=!<>])=(?!=)\s*None`),
narrowing to genuine single-`=` assignment-style leaks. 4 new regression
tests added to `tests/reportx/test_qa_linter.py`, including this exact
sentence verbatim, plus `!=`/`<=` cases, plus a confirmation that a
genuine `vendor = None, product = None` leak is still caught. Full
existing suite (809 `Sentinel-APEX/engine` tests + 309 repo-root tests at
the time of this fix) re-ran clean after the change — this is the second
real false positive this exact regex has needed narrowed for (see its own
code comment for the first, the Qilin/Spoonful of Comfort fixture).

After the fix, CVE-2026-75110 re-ran through the unmodified pipeline and
reached `reportx_composer` at `TACTICAL_READY`, per the results table
above.

## A related, honestly-unfixed observation

CVE-2026-75110 classifies as `vulnerability_class = "unclassified"` in
`automation/report_integrity.py`'s `_vulnerability_class()`, not
`authentication_failure` — its CWE (`CWE-697`, Incorrect Comparison) isn't
in `_CWE_CLASS`, and its real phrasing ("fails open", "AUTH_ENABLED",
"is internal request") doesn't match the classifier's
`authentication bypass|missing authentication|auth bypass` regex. The
system's behavior stayed safe regardless — `unclassified` still routes to
`_detection_package()`'s honest `withheld_insufficient_evidence` default,
never a fabricated rule — so this is a coverage gap, not a correctness or
safety one, and is not fixed here: expanding CWE/keyword classifier
coverage is a materially larger, separately-scoped undertaking than this
demonstration, and Principle 4 (build/change only against a demonstrated
need, not speculatively) argues for naming it rather than guessing at a
fix for CWEs this session has not evidenced.

## Files

- `examples/live-pipeline/CVE-2026-75094.html`, `.meta.json`
- `examples/live-pipeline/CVE-2026-75110.html`, `.meta.json`

Both are the literal `result["content"]` / metadata dict `transform()`
returned — unedited.
