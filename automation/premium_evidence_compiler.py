"""P0 Stage-2 premium-yield independence runtime.

The production failure after PR #166 was no longer discovery or Blogger: a
large candidate pool reached the factory, but valid 3k-4k word narratives were
rejected because free-form model HTML omitted References or other structural
sections.  This layer moves structural authority out of model output.

Design invariants:
- the existing ReportX evidence graph, contradiction gate, quantitative-claim
  grounding, exploitation/ransomware claim boundaries, artifact hash and
  Blogger fetch-back remain authoritative;
- the compiler never upgrades thin input: pre-compiler word/paragraph/list
  density is carried into the public premium gate, so deterministic wrappers
  cannot manufacture depth;
- References are rebuilt only from trusted structured provenance;
- Key Judgements are derived from real EvidenceGraph claim IDs, removing the
  mandatory second model call and malformed-JSON failure class;
- model output remains optional analytical enrichment.  The renderer owns the
  public section contract.
"""

from __future__ import annotations

import html
import ipaddress
import re
from collections import Counter
from dataclasses import replace
from statistics import mean
from typing import Callable, Optional
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from . import authority_transformer as _authority
from . import premium_incident_recovery as _recovery
from . import premium_publication as _premium
from .key_judgements import KeyJudgement
from .logger import setup_logger
from .provider_quota_ledger import telemetry_snapshot as quota_telemetry_snapshot

logger = setup_logger("premium_evidence_compiler")

EVIDENCE_COMPILED_SOURCE = "evidence_compiled"
GENERATION_LLM_ENHANCED = "LLM_ENHANCED"
GENERATION_EVIDENCE_COMPILED = "EVIDENCE_COMPILED"
GENERATION_LEGACY_FALLBACK = "LEGACY_FALLBACK"

# The public deterministic section contract requested by the production
# program.  These exact titles intentionally satisfy premium_publication's
# customer-facing core-section names while keeping stable machine IDs.
CANONICAL_SECTION_CONTRACT: tuple[tuple[str, str], ...] = (
    ("executive_summary", "Executive Summary"),
    ("key_judgements", "Key Judgements"),
    ("verified_facts", "Verified Facts"),
    ("threat_classification", "Threat Classification"),
    ("threat_severity_assessment", "Threat Severity Assessment"),
    ("evidence_source_assessment", "Evidence & Source Assessment"),
    ("timeline_chronology", "Timeline & Chronology"),
    ("business_impact", "Business Impact"),
    ("enterprise_exposure", "Enterprise Exposure Assessment"),
    ("technical_analysis", "Technical Analysis"),
    ("report_type_deep_dive", "Report-Type Deep Dive"),
    ("mitre_attack_assessment", "MITRE ATT&CK Assessment"),
    ("indicators_observables", "Indicators & Observables"),
    ("detection_engineering", "Detection Engineering Guidance"),
    ("detection_validation", "Detection Validation & Required Telemetry"),
    ("threat_hunting", "Threat Hunting Queries"),
    ("soc_playbook", "SOC Analyst Playbook"),
    ("incident_response", "Incident Response & Containment Decision Plan"),
    ("remediation_validation", "Remediation & Validation Plan"),
    ("executive_decision_matrix", "Executive Decision Matrix"),
    ("executive_recommendations", "Executive Recommendations"),
    ("intelligence_gaps", "Intelligence Gaps & Collection Requirements"),
    ("analytic_confidence", "Analytic Confidence & Limitations"),
    ("forecast_outlook", "Forecast & Outlook"),
    ("references", "References"),
)

_LLM_PROVIDER_SOURCES = frozenset({"groq", "deepseek", "openrouter", "anthropic"})

_ORIGINAL_ASSEMBLE_HTML: Optional[Callable] = None
_ORIGINAL_BASE_TRANSFORM: Optional[Callable] = None
_ORIGINAL_KEY_JUDGEMENTS: Optional[Callable] = None
_ORIGINAL_ASSESSMENT: Optional[Callable] = None
_ORIGINAL_RAW_CONTRACT_COMPLETE: Optional[Callable] = None
_ORIGINAL_PROMPT_BUILDER: Optional[Callable] = None
_ORIGINAL_RUN_REPORT_WRITER: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "compiled_reports": 0,
    "generation_modes": Counter(),
    "provider_attempts": Counter(),
    "successful_model_calls": Counter(),
    "fallback_attempts": 0,
    "deterministic_key_judgements": 0,
    "compiler_input_words": [],
    "compiler_input_paragraphs": [],
    "compiler_input_list_items": [],
}


def _esc(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def _paragraph(text: str) -> str:
    return f"<p>{_esc(text)}</p>"


def _bullets(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{_esc(item)}</li>" for item in items if item) + "</ul>"


def _gap(needed: str) -> str:
    return _paragraph(
        "Not established in cited evidence. "
        + needed
        + " The factory does not infer the missing fact from absence of evidence."
    )


def _safe_reference_url(value: object) -> Optional[str]:
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_reserved or address.is_unspecified
    ):
        return None
    return raw


def deterministic_references(article) -> list[tuple[str, str]]:
    """Build the only references the compiler is allowed to assert."""
    candidates: list[tuple[str, str]] = []
    primary = _safe_reference_url(getattr(article, "url", ""))
    if primary:
        publisher = str(getattr(article, "source_publisher", "") or getattr(article, "source", "") or "Primary cited source")
        candidates.append((publisher, primary))

    cve_id = str(getattr(article, "cve_id", "") or "").strip().upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        candidates.append(("NIST National Vulnerability Database", f"https://nvd.nist.gov/vuln/detail/{cve_id}"))

    if getattr(article, "kev_listed", None) is True or getattr(article, "source", "") == "cisa_kev":
        candidates.append(("CISA Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))

    if getattr(article, "epss_score", None) is not None or getattr(article, "epss_percentile", None) is not None:
        candidates.append(("FIRST Exploit Prediction Scoring System", "https://www.first.org/epss/"))

    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, url in candidates:
        safe = _safe_reference_url(url)
        if safe and safe not in seen:
            seen.add(safe)
            result.append((label, safe))
    return result


def _render_references(article) -> str:
    refs = deterministic_references(article)
    if not refs:
        return _gap("No independently trusted HTTP(S) provenance URL is available in the normalized record; collection must obtain one before a public artifact can rely on external references.")
    return "<ul>" + "".join(
        f'<li><a href="{_esc(url)}" target="_blank" rel="noopener noreferrer">{_esc(label)}</a> — {_esc(url)}</li>'
        for label, url in refs
    ) + "</ul>"


def _strip_model_structure_and_reference_section(body_content: str) -> str:
    """Preserve analytical content while removing model ownership of structure.

    Model-supplied References sections are discarded completely; all other
    h2/h3 labels become non-heading strong labels.  The deterministic compiler
    then emits the only public h3 contract and the only References section.
    """
    soup = BeautifulSoup(body_content or "", "html.parser")

    headings = list(soup.find_all(["h2", "h3"]))
    for heading in headings:
        normalized = re.sub(r"[^a-z0-9]+", " ", " ".join(heading.stripped_strings).lower()).strip()
        if normalized == "references" or normalized.endswith(" references"):
            sibling = heading.next_sibling
            while sibling is not None:
                nxt = sibling.next_sibling
                if getattr(sibling, "name", None) in {"h2", "h3"}:
                    break
                try:
                    sibling.extract()
                except Exception:
                    pass
                sibling = nxt
            heading.decompose()

    for heading in list(soup.find_all(["h2", "h3"])):
        label = " ".join(heading.stripped_strings).strip()
        replacement = soup.new_tag("strong")
        replacement["data-original-analytical-module"] = "true"
        replacement.string = label
        heading.replace_with(replacement)

    return str(soup)


def _fact_items(article) -> list[str]:
    rows = [
        ("CVE", getattr(article, "cve_id", None)),
        ("Affected vendor", getattr(article, "affected_vendor", None)),
        ("Affected product", getattr(article, "affected_product", None)),
        ("CVSS", getattr(article, "cvss_score", None)),
        ("CWE", ", ".join(str(x) for x in (getattr(article, "cwe_ids", None) or [])) or None),
        ("EPSS", getattr(article, "epss_score", None)),
        ("CISA KEV listed", getattr(article, "kev_listed", None)),
        ("Ransomware actor", getattr(article, "ransomware_group", None)),
        ("Sector", getattr(article, "ransomware_sector", None)),
        ("Country", getattr(article, "ransomware_country", None)),
        ("Source publisher", getattr(article, "source_publisher", None) or getattr(article, "source", None)),
        ("Source published", getattr(article, "published_at", None)),
    ]
    items = [f"{label}: {value}" for label, value in rows if value is not None and str(value).strip()]
    if not items:
        items.append("The normalized record contains source text but no additional structured vulnerability, actor, sector, or scoring fields.")
    return items


def _report_family_label(article, context) -> str:
    return str(getattr(context, "family_label", "") or getattr(context, "family", "") or getattr(article, "source", "") or "Threat intelligence")


def _section_payloads(article, context, analytical_body: str) -> dict[str, str]:
    summary = str(getattr(article, "summary", "") or "").strip()
    family = _report_family_label(article, context)
    cve = str(getattr(article, "cve_id", "") or "").strip()
    product = str(getattr(article, "affected_product", "") or "").strip()
    vendor = str(getattr(article, "affected_vendor", "") or "").strip()
    asset_anchor = " / ".join(x for x in (vendor, product, cve) if x) or "the technology or service named in the cited record"
    exploitation = str(getattr(context, "exploitation_label", "") or "not established")
    patch = str(getattr(context, "patch_label", "") or "not established")
    source_name = str(getattr(article, "source_publisher", "") or getattr(article, "source", "") or "the cited source")
    published_at = str(getattr(article, "published_at", "") or "not supplied")

    return {
        "executive_summary": _paragraph(summary or "The cited record supplies the evidence basis for this automated intelligence assessment."),
        "key_judgements": _paragraph(
            "Key Judgements are derived from validated ReportX claim identifiers rather than a second free-form model request. "
            "They may prioritize validation and collection, but they do not convert source-reported claims into confirmed customer impact."
        ),
        "verified_facts": _bullets(_fact_items(article)),
        "threat_classification": _paragraph(
            f"Report family: {family}. Exploitation state: {exploitation}. Remediation state: {patch}. "
            "These labels come from the normalized report context and remain bounded by cited evidence."
        ),
        "threat_severity_assessment": _paragraph(
            "Severity is interpreted from structured scoring or source evidence when present. No customer-specific risk score, blast radius, or compromise state is inferred by this compiler."
        ),
        "evidence_source_assessment": _paragraph(
            f"Primary provenance is {source_name}. The compiler distinguishes source-reported material from independently structured NVD/CISA/EPSS evidence when those fields are actually present."
        ),
        "timeline_chronology": _paragraph(
            f"The normalized source publication timestamp is {published_at}. Additional intrusion, exploitation, disclosure, or remediation timestamps are not asserted unless they are present in the cited evidence body below."
        ),
        "business_impact": _paragraph(
            "Customer-specific business impact is not established by a public source record alone. Decision value comes from determining whether relevant assets, identities, dependencies, or services are actually present and exposed."
        ),
        "enterprise_exposure": _bullets([
            f"Inventory and ownership teams should determine whether {asset_anchor} exists in the environment before assigning incident status.",
            "A positive exposure determination requires asset, version, identity, dependency, cloud/SaaS, or equivalent internal telemetry that can be tied to the cited condition.",
            "A negative determination should record the inventory evidence and timestamp used so the decision can be revalidated if the source record changes.",
        ]),
        "technical_analysis": analytical_body or _gap("No substantive analytical body survived the evidence-safe renderer; the report must remain below the premium depth floor."),
        "report_type_deep_dive": _paragraph(
            f"This {family} record is analyzed according to the evidence available for its family. Unsupported exploit chains, malware capabilities, breach scope, attribution, encryption, exfiltration, and regulatory consequences are intentionally not synthesized."
        ),
        "mitre_attack_assessment": _gap(
            "ATT&CK technique mapping requires source-backed behavior. Any mappings present in the preserved analytical body are subject to the existing ReportX semantic gate; the compiler adds none of its own."
        ),
        "indicators_observables": _gap(
            "Only source-derived, validated and safely defanged observables may be operationalized. The compiler does not invent domains, IP addresses, hashes, paths, process names, mutexes, or command lines."
        ),
        "detection_engineering": _paragraph(
            "Detection content remains evidence-conditioned. Production rules require source-backed behavior plus the telemetry needed to validate precision; otherwise the correct output is a telemetry specification rather than fabricated executable logic."
        ),
        "detection_validation": _bullets([
            "Identify the telemetry source and fields needed to observe the cited behavior before promoting detection logic.",
            "Replay or safely simulate only evidence-supported behavior, measure expected false positives, and retain test evidence with the rule version.",
            "Do not represent syntax validation as production efficacy; deployment requires environment-specific validation and accountable approval.",
        ]),
        "threat_hunting": _paragraph(
            f"Threat hunting should begin with exposure to {asset_anchor} and then pivot only on observables or behavior established in cited evidence. Absence of a source-backed pivot is an intelligence gap, not permission to invent one."
        ),
        "soc_playbook": _bullets([
            "Validate whether the affected technology, identity, dependency, service, or victim context exists internally.",
            "Preserve relevant logs and timestamps before destructive containment when an internal match is found.",
            "Escalate from intelligence validation to incident response only when internal telemetry or independently cited evidence supports the transition.",
        ]),
        "incident_response": _paragraph(
            "Public threat intelligence alone does not establish an internal incident. If internal evidence confirms relevance, preserve evidence, scope affected assets and identities, contain the validated path, eradicate the supported cause, recover, and verify recurrence controls."
        ),
        "remediation_validation": _bullets([
            f"Remediation state from the normalized record: {patch}.",
            "Apply vendor/CISA remediation only when that action is actually present in trusted evidence; otherwise obtain the authoritative remediation source before changing production systems.",
            "After change, verify asset/version state, exposure path, relevant telemetry, and rollback readiness rather than assuming the change succeeded.",
        ]),
        "executive_decision_matrix": _bullets([
            "No internal exposure evidence: retain as intelligence, document the negative exposure basis, and continue collection.",
            "Exposure confirmed but compromise unconfirmed: prioritize supported remediation and heightened telemetry while avoiding unsupported incident claims.",
            "Internal malicious activity confirmed: activate the organization's incident-response process using the preserved evidence and scoped telemetry.",
        ]),
        "executive_recommendations": _bullets([
            f"Validate enterprise relevance to {asset_anchor} before treating the public record as a customer-specific finding.",
            "Prioritize evidence-backed remediation, telemetry coverage, and verification over severity labels alone.",
            "Keep unresolved exploitation, attribution, breach scope, and impact statements explicitly unresolved until corroborating evidence exists.",
        ]),
        "intelligence_gaps": _bullets([
            "Customer-specific exposure is not established by the public source record.",
            "Customer-specific compromise or impact is not established unless internal telemetry is supplied.",
            "Any source dimension not represented in the normalized evidence graph requires additional authoritative collection before it can drive a material claim.",
        ]),
        "analytic_confidence": _paragraph(
            "Confidence is bounded by source reliability, information credibility, corroboration state, and unresolved contradictions already computed by ReportX. Structural compilation never raises epistemic confidence."
        ),
        "forecast_outlook": _paragraph(
            "No new future event is predicted by the compiler. Forecast statements, when present in the preserved analytical body, must remain tied to ReportX supporting observation claims and explicit confidence rationale."
        ),
        "references": _render_references(article),
    }


def compile_premium_body(article, context, body_content: str) -> str:
    """Return one deterministic 25-heading public body without inventing depth."""
    input_words = _premium._word_count(body_content)
    input_paragraphs, input_list_items = _premium._semantic_counts(body_content)
    analytical_body = _strip_model_structure_and_reference_section(body_content)
    payloads = _section_payloads(article, context, analytical_body)

    parts = ['<div data-cdb-premium-compiler="v1">']
    for section_id, title in CANONICAL_SECTION_CONTRACT:
        parts.append(
            f'<section data-cdb-section="{_esc(section_id)}">'
            f'<h3>{_esc(title)}</h3>{payloads[section_id]}</section>'
        )
    parts.append("</div>")

    _RUNTIME["compiled_reports"] += 1
    _RUNTIME["compiler_input_words"].append(input_words)
    _RUNTIME["compiler_input_paragraphs"].append(input_paragraphs)
    _RUNTIME["compiler_input_list_items"].append(input_list_items)
    return "".join(parts)


def _confidence_label(analytical_confidence: dict) -> str:
    raw = str((analytical_confidence or {}).get("overall_confidence") or "MEDIUM").upper()
    if "HIGH" in raw:
        return "HIGH"
    if "LOW" in raw:
        return "LOW"
    return "MEDIUM"


def _first_existing_claim(claims: dict, preferences: tuple[str, ...]) -> Optional[str]:
    for claim_id in preferences:
        if claim_id in claims:
            return claim_id
    return next(iter(claims), None)


def derive_key_judgements(
    article,
    config,
    evidence_graph: Optional[dict],
    contradictions: tuple,
    analytical_confidence: dict,
    context,
    call_llm_fn=None,
):
    """Derive one bounded, source-scoped judgement without an external call."""
    del config, call_llm_fn
    if not evidence_graph or not evidence_graph.get("claims"):
        return (), ("NO_EVIDENCE_GRAPH",)
    if any(c.get("severity") == "block" for c in (contradictions or ()) if isinstance(c, dict)):
        return (), ("BLOCKING_CONTRADICTION",)

    claims = evidence_graph.get("claims", {})
    family = str(getattr(context, "family", "") or "")
    confidence = _confidence_label(analytical_confidence)

    if family == "ransomware_claim":
        claim_id = _first_existing_claim(claims, ("c-victim-claim", "c-summary"))
        judgement = (
            "The source-scoped ransomware victim claim is a validation trigger, not confirmation of breach, "
            "encryption, exfiltration, or compromise of the named organization."
        )
        relevance = "SOC/IR should seek independent or internal corroboration before activating incident claims or destructive response actions."
    elif getattr(article, "kev_listed", None) is True:
        claim_id = _first_existing_claim(claims, ("c-kev-listed", "c-exploitation-status", "c-cve-id", "c-summary"))
        judgement = (
            "The KEV-backed vulnerability record materially increases remediation urgency for environments that deploy the affected technology, "
            "while still not establishing compromise of any specific customer environment."
        )
        relevance = "Prioritize exposure validation and evidence-backed remediation without converting public exploitation evidence into a customer incident assertion."
    elif family in {"cve_advisory", "cisa_advisory", "cisa_kev"} or getattr(article, "cve_id", None):
        claim_id = _first_existing_claim(claims, ("c-cve-id", "c-summary", "c-exploitation-status"))
        judgement = (
            "The vulnerability record warrants asset and version exposure validation; the public evidence does not by itself establish that any customer environment is exposed or compromised."
        )
        relevance = "Vulnerability management should make the deploy/not-deployed and affected/not-affected determination before escalating to incident response."
    else:
        claim_id = _first_existing_claim(claims, ("c-summary",))
        judgement = (
            "The cited record supports an intelligence-validation task, while customer-specific exposure, compromise, and impact remain separate questions requiring internal telemetry or independent corroboration."
        )
        relevance = "Use the record to drive scoped collection and validation rather than treating a public report as proof of internal impact."

    if not claim_id:
        return (), ("NO_REFERENCABLE_CLAIM",)

    _RUNTIME["deterministic_key_judgements"] += 1
    return (
        KeyJudgement(
            id="kj-1",
            judgement=judgement,
            confidence=confidence,
            claim_refs=(claim_id,),
            reasoning_basis=f"Bound to ReportX evidence claim {claim_id}; no second model synthesis was used.",
            decision_relevance=relevance,
            limitations=("Public-source evidence does not establish customer-specific exposure or compromise without separate supporting telemetry.",),
            what_would_change_the_judgement="Independent corroboration or internal telemetry that materially changes the evidence state.",
            verification_status="SUPPORTED",
        ),
    ), ()


def compiler_semantic_preflight_complete(content: str) -> bool:
    """Failover decision based on real analytical density, never model markup."""
    words = _premium._word_count(content)
    paragraphs, list_items = _premium._semantic_counts(content)
    return (
        words >= _premium.MIN_VISIBLE_WORDS
        and paragraphs >= _premium.MIN_PARAGRAPHS
        and list_items >= _premium.MIN_LIST_ITEMS
    )


def _patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url=None):
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("premium evidence compiler is not installed")
    self._cdb_compiler_input_metrics = {
        "words": _premium._word_count(body_content),
        "paragraphs": _premium._semantic_counts(body_content)[0],
        "list_items": _premium._semantic_counts(body_content)[1],
    }
    compiled = compile_premium_body(article, context, body_content)
    return _ORIGINAL_ASSEMBLE_HTML(self, article, compiled, seo_data, context, image_url=image_url)


def _record_provider_attempts(attempts: list[dict]) -> None:
    successful = 0
    for entry in attempts or []:
        provider = str(entry.get("provider") or "unknown")
        model = str(entry.get("model") or "none")
        key = f"{provider}:{model}"
        _RUNTIME["provider_attempts"][key] += 1
        if entry.get("ok") is True:
            _RUNTIME["successful_model_calls"][key] += 1
            successful += 1
    if len(attempts or []) > successful:
        _RUNTIME["fallback_attempts"] += max(0, len(attempts or []) - 1)


def _patched_base_transform(self, article):
    if _ORIGINAL_BASE_TRANSFORM is None:
        raise RuntimeError("premium evidence compiler is not installed")
    transformed = _ORIGINAL_BASE_TRANSFORM(self, article)
    source = str(transformed.get("content_source") or "")
    if source in _LLM_PROVIDER_SOURCES:
        mode = GENERATION_LLM_ENHANCED
    elif source == "reportx_composer":
        mode = GENERATION_EVIDENCE_COMPILED
        transformed["content_source"] = EVIDENCE_COMPILED_SOURCE
    else:
        mode = GENERATION_LEGACY_FALLBACK

    metrics = getattr(self, "_cdb_compiler_input_metrics", {}) or {}
    transformed["generation_mode"] = mode
    transformed["key_judgement_derivation_mode"] = "DETERMINISTIC_EVIDENCE_GRAPH"
    transformed["compiler_input_visible_words"] = int(metrics.get("words", 0) or 0)
    transformed["compiler_input_substantive_paragraphs"] = int(metrics.get("paragraphs", 0) or 0)
    transformed["compiler_input_substantive_list_items"] = int(metrics.get("list_items", 0) or 0)
    transformed["compiler_contract_sections"] = len(CANONICAL_SECTION_CONTRACT)

    _RUNTIME["generation_modes"][mode] += 1
    _record_provider_attempts(transformed.get("llm_attempts", []))
    return transformed


def _assessment_with_input_floor(article, transformed: dict):
    """Compiler structure may fix shape, but never manufacture analytical depth."""
    if _ORIGINAL_ASSESSMENT is None:
        raise RuntimeError("premium evidence compiler assessment is not installed")
    assessment = _ORIGINAL_ASSESSMENT(article, transformed)
    reasons = list(assessment.reasons)

    input_words = int(transformed.get("compiler_input_visible_words", 0) or 0)
    input_paragraphs = int(transformed.get("compiler_input_substantive_paragraphs", 0) or 0)
    input_list_items = int(transformed.get("compiler_input_substantive_list_items", 0) or 0)
    if input_words and input_words < _premium.MIN_VISIBLE_WORDS:
        reasons.append(
            f"pre-compiler analytical depth {input_words} words is below production floor {_premium.MIN_VISIBLE_WORDS}; deterministic structure cannot manufacture depth"
        )
    if input_paragraphs and input_paragraphs < _premium.MIN_PARAGRAPHS:
        reasons.append(
            f"pre-compiler substantive paragraph density {input_paragraphs} is below production floor {_premium.MIN_PARAGRAPHS}"
        )
    if input_list_items and input_list_items < _premium.MIN_LIST_ITEMS:
        reasons.append(
            f"pre-compiler substantive list density {input_list_items} is below production floor {_premium.MIN_LIST_ITEMS}"
        )

    unique_reasons = tuple(dict.fromkeys(reasons))
    return _premium.EnterpriseQualityAssessment(
        ready=not unique_reasons,
        report_type=assessment.report_type,
        quality_band=assessment.quality_band,
        visible_words=assessment.visible_words,
        distinct_headings=assessment.distinct_headings,
        substantive_paragraphs=assessment.substantive_paragraphs,
        substantive_list_items=assessment.substantive_list_items,
        reasons=unique_reasons,
    )


def _compiler_prompt(article) -> str:
    if _ORIGINAL_PROMPT_BUILDER is None:
        raise RuntimeError("premium evidence compiler prompt builder is not installed")
    base = _ORIGINAL_PROMPT_BUILDER(article)
    return base + """

P0 STAGE-2 STRUCTURE OWNERSHIP OVERRIDE — FINAL INSTRUCTION
The deterministic report compiler, not you, owns all public section headings and References.
Prioritize substantive evidence-specific analysis over reproducing heading boilerplate.
- Do not invent a reference URL. The renderer rebuilds References from normalized provenance.
- Do not spend completion budget repeating 25 section names merely for structure.
- Preserve at least 2,200 useful visible analytical words when evidence supports that depth.
- Produce at least 18 substantive paragraphs and 18 substantive list items using source-specific facts, decisions, validation steps, collection requirements, or explicit evidence gaps.
- If evidence is insufficient for the depth floor, remain concise and truthful; the public gate will hold the artifact rather than padding it.
- HTML headings from your response are treated only as labels and cannot satisfy public structural certification.
"""


def _failure_histogram(report: dict) -> dict:
    counts = Counter()
    for post in report.get("posts", []):
        for issue in post.get("integrity_issues", []) or []:
            text = str(issue).lower()
            if "word" in text and "floor" in text:
                counts["word_floor"] += 1
            if "reference" in text:
                counts["references"] += 1
            if "heading" in text:
                counts["heading_floor"] += 1
            if "paragraph" in text:
                counts["paragraph_density"] += 1
            if "list" in text and ("item" in text or "density" in text):
                counts["list_density"] += 1
            if "evidence" in text or "claim" in text or "corrobor" in text:
                counts["evidence_grounding"] += 1
    return dict(counts)


def _summary(values: list[int]) -> dict:
    if not values:
        return {"count": 0, "min": 0, "max": 0, "avg": 0.0}
    return {"count": len(values), "min": min(values), "max": max(values), "avg": round(mean(values), 2)}


def _stage2_write_run_report(report: dict, logs_dir: str) -> None:
    if _ORIGINAL_RUN_REPORT_WRITER is None:
        raise RuntimeError("premium evidence compiler run-report wrapper is not installed")
    attempted = int(report.get("discovered", 0) or 0)
    published = int(report.get("published", 0) or 0)
    report["premium_yield_stage2"] = {
        "compiler_contract_sections": len(CANONICAL_SECTION_CONTRACT),
        "compiled_reports": int(_RUNTIME["compiled_reports"]),
        "generation_mode_counts": dict(_RUNTIME["generation_modes"]),
        "provider_model_attempts": dict(_RUNTIME["provider_attempts"]),
        "successful_model_calls": dict(_RUNTIME["successful_model_calls"]),
        "fallback_attempts": int(_RUNTIME["fallback_attempts"]),
        "key_judgement_derivation_mode": "DETERMINISTIC_EVIDENCE_GRAPH",
        "deterministic_key_judgements": int(_RUNTIME["deterministic_key_judgements"]),
        "compiler_input_words": _summary(_RUNTIME["compiler_input_words"]),
        "compiler_input_paragraphs": _summary(_RUNTIME["compiler_input_paragraphs"]),
        "compiler_input_list_items": _summary(_RUNTIME["compiler_input_list_items"]),
        "gate_failure_counts": _failure_histogram(report),
        "premium_yield_pct": round((published / attempted) * 100, 2) if attempted else 0.0,
        "published_without_external_llm_count": sum(
            1 for p in report.get("posts", [])
            if p.get("status") == "published" and p.get("content_source") == EVIDENCE_COMPILED_SOURCE
        ),
        "provider_quota": quota_telemetry_snapshot(),
        "fetch_back_discrepancies": int(report.get("fetch_back_discrepancies", 0) or 0),
    }
    _ORIGINAL_RUN_REPORT_WRITER(report, logs_dir)


def install_premium_evidence_compiler_overrides(main_module) -> None:
    """Install last, after premium-publication and factory runtime overrides."""
    global _ORIGINAL_ASSEMBLE_HTML, _ORIGINAL_BASE_TRANSFORM, _ORIGINAL_KEY_JUDGEMENTS
    global _ORIGINAL_ASSESSMENT, _ORIGINAL_RAW_CONTRACT_COMPLETE, _ORIGINAL_PROMPT_BUILDER
    global _ORIGINAL_RUN_REPORT_WRITER, _INSTALLED
    if _INSTALLED:
        return

    _ORIGINAL_ASSEMBLE_HTML = _authority.AuthorityTransformer._assemble_html
    _ORIGINAL_BASE_TRANSFORM = _authority.AuthorityTransformer.transform
    _ORIGINAL_KEY_JUDGEMENTS = _authority.generate_key_judgements
    _ORIGINAL_ASSESSMENT = _premium.assess_enterprise_report
    _ORIGINAL_RAW_CONTRACT_COMPLETE = _recovery._raw_contract_complete
    _ORIGINAL_PROMPT_BUILDER = _authority._build_analyst_prompt
    _ORIGINAL_RUN_REPORT_WRITER = main_module._write_run_report

    _authority.generate_key_judgements = derive_key_judgements
    _authority.AuthorityTransformer._assemble_html = _patched_assemble_html
    _authority.AuthorityTransformer.transform = _patched_base_transform
    _authority._build_analyst_prompt = _compiler_prompt

    # Public premium certification recognizes evidence-compiled generation as
    # a generation mode, not as fake LLM authorship.  Every other premium gate
    # below remains unchanged and the separate ReportX product tier continues
    # to report TACTICAL when analyst authorship/corroboration is absent.
    _premium._LLM_SOURCES = frozenset(set(_premium._LLM_SOURCES) | {EVIDENCE_COMPILED_SOURCE})
    _premium.assess_enterprise_report = _assessment_with_input_floor

    # Structural headings are now renderer-owned.  Model failover is driven by
    # the exact analytical density floors the public gate will still apply to
    # pre-compiler content, so a 4k-word semantically thin response still does
    # not qualify and a 3k-word sound response no longer burns models merely
    # because it used malformed/omitted headings.
    _recovery._raw_contract_complete = compiler_semantic_preflight_complete

    main_module._write_run_report = _stage2_write_run_report
    _INSTALLED = True
    logger.info(
        "P0 Stage-2 premium evidence compiler installed",
        extra={
            "contract_sections": len(CANONICAL_SECTION_CONTRACT),
            "key_judgement_mode": "DETERMINISTIC_EVIDENCE_GRAPH",
            "provider_independent_source": EVIDENCE_COMPILED_SOURCE,
        },
    )
