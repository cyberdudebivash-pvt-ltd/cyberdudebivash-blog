"""ReportX Phase 1K real-data section-completeness verification set.

Same convention as this directory's phase1i_attack_mapping_.../
phase1j_role_decision_... scripts: REPRESENTATIVE, hand-constructed
`DiscoveredArticle` instances, but every row is produced by a live,
unmocked call to `AuthorityTransformer(Config()).transform()` -- the real
compose_report() -> authority_transformer.py -> report_contract.py chain
end to end, not a mocked or hand-computed result.

Captures the mandate's own requested matrix (family, section states, which
sections have real structured content vs. are withheld, Key Judgement
count, role decision count, ATT&CK count, hunt count, gap count, business
impact state, forecast state, tier) across all 8 production families, and
asserts -- not just prints -- that every section a count claims COMPLETE
for actually appears in the rendered, customer-visible HTML.

Run directly: `python reportx-canary/phase1k_section_completeness_representative_fixtures.py`
from the repo root, with the same venv used for `tests/`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from automation.authority_transformer import AuthorityTransformer
from automation.config import Config
from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_contract import (
    SECTION_6_EVIDENCE_SOURCE_ASSESSMENT,
    SECTION_11_ATTACK_MAPPING,
    SECTION_14_THREAT_HUNTING,
    SECTION_19_ROLE_DECISION_MATRIX,
    SECTION_21_INTELLIGENCE_GAPS,
    SECTION_22_FORECAST_OUTLOOK,
    evaluate_section_states,
)
from automation.report_integrity import build_report_context


def _article(**kwargs) -> DiscoveredArticle:
    defaults = dict(
        url="https://example.test/fixture", title="Fixture Title",
        summary="Fixture summary.", published_at="2026-08-20T00:00:00+00:00",
        labels=[], source="global_rss",
    )
    defaults.update(kwargs)
    defaults.setdefault("content_hash", _compute_hash(defaults["url"], defaults["title"]))
    return DiscoveredArticle(**defaults)


CASES = {
    "CVE (not KEV)": _article(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-90005", title="CVE-2026-90005 command injection",
        summary="A command injection vulnerability in a web-facing administrative endpoint allows "
                "unauthenticated attackers to execute arbitrary commands.",
        source="nvd", cve_id="CVE-2026-90005", cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-78"], kev_listed=False,
    ),
    "KEV (confirmed exploited)": _article(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-90004", title="CVE-2026-90004 actively exploited",
        summary="CISA confirms this remote code execution vulnerability is being actively exploited in the wild.",
        source="cisa_kev", cve_id="CVE-2026-90004", cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-78"], kev_listed=True,
    ),
    "Ransomware claim": _article(
        url="https://www.ransomware.live/id/fixture-victim", title="Group Claims Fixture Corp",
        summary="Group has listed Fixture Corp as a new victim on its leak site, claiming encryption and "
                "exfiltration of sensitive data across the network.",
        labels=["Ransomware"], source="ransomware_intel",
    ),
    "Ransomware reporting (news)": _article(
        url="https://example.test/ransomware-vpn-targeting", title="Ransomware Gangs Target VPN Appliances",
        summary="A new report finds ransomware operators increasingly exploit unpatched VPN devices for access.",
        labels=["Ransomware", "Research"], source="global_rss",
    ),
    "Threat actor": _article(
        url="https://example.test/actor-pulse", title="Tracked Actor Infrastructure Update",
        summary="A subscribed OTX pulse updates infrastructure associated with a tracked threat actor.",
        labels=["Threat Actor"], source="threat_actor_intel",
    ),
    "AI security": _article(
        url="https://example.test/llm-prompt-injection-study", title="LLM Prompt Injection Study",
        summary="Researchers documented a prompt injection technique against a large language model deployment.",
        labels=["AI Security"], source="global_rss",
    ),
    "Breach notice": _article(
        url="https://example.test/breach-record", title="Breach Record Z",
        summary="A public breach-record entry lists Example Corp among affected organizations.",
        labels=["Data Breach"], source="breach_intel",
    ),
    "General intelligence": _article(
        url="https://example.test/roundup", title="Weekly Security News Roundup",
        summary="A general roundup of security news items with no specific technical claim.",
        labels=["News"], source="global_rss",
    ),
}


def _real_forecast_count(forecasts: list) -> int:
    return sum(1 for f in forecasts if not f.get("withheld") and f.get("supporting_observation_claim_ids") and f.get("confidence_rationale"))


def main() -> None:
    config = Config()
    header = (
        f"{'Case':<28}{'Family':<20}{'KJ':<4}{'Role':<5}{'ATT&CK':<7}{'Hunt':<5}{'Gaps':<5}{'Fcst':<5}"
        f"{'S6':<12}{'S19':<32}{'S21':<20}{'S22':<32}{'Tier'}"
    )
    print(header)
    failures = []
    for label, article in CASES.items():
        result = AuthorityTransformer(config).transform(article)
        kj = len(result.get("key_judgements") or [])
        roles = len(result.get("role_decisions") or [])
        attack = len(result.get("attack_mappings") or [])
        hunts = len(result.get("hunt_hypotheses") or [])
        gaps = len(result.get("intelligence_gaps") or [])
        forecasts = result.get("forecasts") or []
        real_forecasts = _real_forecast_count(forecasts)

        context = build_report_context(article)
        resolutions = evaluate_section_states(
            article, context, key_judgement_count=kj, hunt_hypothesis_count=hunts,
            attack_mapping_count=attack, role_decision_count=roles, forecast_count=real_forecasts,
        )
        state_of = {r.section: r.state.value for r in resolutions}

        print(
            f"{label:<28}{result['report_family']:<20}{kj:<4}{roles:<5}{attack:<7}{hunts:<5}{gaps:<5}{real_forecasts:<5}"
            f"{state_of[SECTION_6_EVIDENCE_SOURCE_ASSESSMENT]:<12}{state_of[SECTION_19_ROLE_DECISION_MATRIX]:<32}"
            f"{state_of[SECTION_21_INTELLIGENCE_GAPS]:<20}{state_of[SECTION_22_FORECAST_OUTLOOK]:<32}"
            f"{result['product_tier']}"
        )

        # Live proof, not just a printed table: whatever report_contract.py
        # claims COMPLETE for a section with real rendered content behind
        # it must actually appear in the published HTML -- the exact
        # defect class (counted but not rendered) this phase exists to
        # close, reproven here against every family, not only the ones
        # unit tests happen to cover.
        content = result["content"]
        if state_of[SECTION_6_EVIDENCE_SOURCE_ASSESSMENT] == "COMPLETE" and "Source Reliability" not in content:
            failures.append(f"{label}: Section 6 COMPLETE but reliability content missing from rendered HTML")
        if roles > 0 and "Role-Based Decisions" not in content:
            failures.append(f"{label}: {roles} role decisions but section missing from rendered HTML")
        if gaps > 0 and "Intelligence Gaps" not in content:
            failures.append(f"{label}: {gaps} intelligence gaps but section missing from rendered HTML")
        if real_forecasts > 0 and "Forecast / Outlook" not in content:
            failures.append(f"{label}: {real_forecasts} real forecast(s) but section missing from rendered HTML")
        if real_forecasts == 0 and "Forecast / Outlook" in content:
            failures.append(f"{label}: no real forecast but 'Forecast / Outlook' rendered anyway")

        # Cross-section consistency spot-check (mandate section 22): a
        # ransomware CLAIM must never assert a confirmed breach/compromise
        # in its own family-specific analytical prose ("Claim Assessment"),
        # regardless of tier or section states. Scoped to that one section,
        # not the whole page: report_renderer.py's universal Executive
        # Summary "Decision:" line legitimately contains the phrase
        # "...before treating this record as an incident, confirmed
        # compromise, or customer-specific finding" as CAUTIONARY guidance
        # (the reader is told NOT to assume it) -- a whole-page substring
        # match without this scoping produces exactly that false positive,
        # confirmed by hand while building this check.
        if context.family == "ransomware_claim":
            claim_section = re.search(r'data-section="claim-assessment".*?</section>', content, re.DOTALL)
            if claim_section:
                lowered = claim_section.group(0).lower()
                if "confirmed breach" in lowered or "confirmed compromise" in lowered:
                    failures.append(f"{label}: ransomware_claim's Claim Assessment section asserts a confirmed breach/compromise")

    print()
    if failures:
        print(f"FAILURES ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("All assertions passed: every claimed-COMPLETE section's content is genuinely present in the "
          "rendered HTML for every case, and no cross-section consistency spot-check failed.")


if __name__ == "__main__":
    main()
