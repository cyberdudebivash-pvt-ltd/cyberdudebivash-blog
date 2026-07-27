# EIPS — EXTENSIBILITY FRAMEWORK

Practical steps for the extension points that already exist in code, not a
principle restated from `CLAUDE.md`'s "Additive First Architecture." Each
entry names the actual file to touch.

## Add a new report type / subject-matter category

1. Add a row to `Sentinel-APEX/prompts/master-prompt.md`'s Report Type
   Taxonomy table — which task prompt it loads, which structural
   `report_type` it maps to.
2. If it needs section emphasis beyond `report-prompt.md`'s general
   structure, add a new task prompt file following `cve-prompt.md` /
   `malware-prompt.md`'s pattern (load master first, override specific
   sections).
3. Do not add a fifth structural `report_type` value — the taxonomy table
   exists precisely so new subject matter doesn't require that.

## Add a new detection format or SIEM platform

1. Add it to `master-prompt.md`'s Named Detection Platform Coverage table.
2. Add its section-heading fragment to `quality.py`'s
   `DETECTION_SECTION_FRAGMENTS` if it should be checked for the
   empty-section gate.
3. If the format has real syntax to validate (like Sigma/YARA), add a
   `validate_<format>()` function following `validate_sigma`/`validate_yara`'s
   exact pattern — required-field check, then a targeted structural check —
   and wire it into `gate_report()`.
4. Add its maturity expectations to EIOS Layer 6.

## Add a new live threat-intelligence feed source

Already documented with a real worked example —
`Sentinel-APEX/docs/SENTINEL-APEX-PROVIDER.md` § Future Endpoint Expansion:
add the URL to `fetch-live-intel.js`'s `CFG`, add it to the `endpoints`
array, reuse the existing defensive candidate-key parsing pattern
(`sapexPick()`/`sapexPickArray()`) rather than writing a new parser assuming
one exact schema. This is the platform's best-executed extensibility
pattern — schema-tolerant by design, health-monitored the same way every
other source is, documented with its own failure mode (schema drift) named
explicitly.

## Add a new AI-assisted workflow

Follow `ai-security-intel.yml`'s pattern: gate the LLM call behind an
optional secret (`ANTHROPIC_API_KEY`), keep the rule-based
collection/classification/publication stages functioning without it, and
give the LLM stage its own constitution file
(`Sentinel-APEX/prompts/ai-security-master-prompt.md` is the template) rather
than reusing the general master prompt unmodified — a domain-specific
system prompt outperforms a generic one loaded with an extra paragraph
bolted on.

## Add a customer-specific / industry overlay

Not yet implemented anywhere real (the one prior attempt,
`prompts/industry/industry-intelligence.md`, was deprecated in this session
as part of the `/prompts/` consolidation — see that file's banner). If this
becomes a real need, port its content into a new
`Sentinel-APEX/prompts/industry-overlay.md` layered on top of a task prompt,
following the composition model root `/prompts/README.md` described
correctly even though its implementation was abandoned. Do not reactivate
the deprecated file directly — it was never reconciled against the
canonical evidence/confidence taxonomies.

## Add a new structured intelligence object

`EIOS Layer 3` already specifies the schema for `Campaign`, `Incident`,
`Victim`, `Infrastructure`, `Exploit`, `Mitigation`, `DetectionRule` —
none coded yet. When one is needed: add the dataclass to
`engine/sentinel_engine/models.py` following the existing pattern (frozen
where the object is immutable evidence, like `IOC`; mutable where it
accumulates state, like `NormalizedDoc`), wire it into
`knowledge_graph.py::ingest()` using the same `type:name` key convention
already used for every other entity — do not build a second graph. Add a
dataclass only when a real consumer needs it; an unused dataclass is dead
code the QA pipeline should flag.

---
*CyberDudeBivash® Sentinel APEX — Extensibility Framework*
