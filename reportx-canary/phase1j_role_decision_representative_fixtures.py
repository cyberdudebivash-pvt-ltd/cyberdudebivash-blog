"""ReportX Phase 1J role-decision real-data verification set.

Same convention as phase1i_attack_mapping_representative_fixtures.py in
this directory: REPRESENTATIVE, hand-constructed `DiscoveredArticle`
instances (not independently-sourced raw bytes), but every row below is
produced by a live, unmocked call to `AuthorityTransformer(Config()).
transform()` -- the genuine `_lean_role_decisions()` ->
`_validate_role_decisions()` -> `pipeline_composer.compose_report()` ->
`authority_transformer._render_role_decisions_html()` ->
`report_contract.py` Section 19 -> `analytical_depth_gate.py` tier-gate
chain end to end, not a mocked or hand-computed result. This is also a
live proof that role_decisions actually reaches the rendered
``result["content"]`` HTML, not merely ``result["role_decisions"]``'s
structured list -- the exact defect class this phase exists to close.

Run directly: `python reportx-canary/phase1j_role_decision_representative_fixtures.py`
from the repo root, with the same venv used for `tests/`.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from automation.authority_transformer import AuthorityTransformer
from automation.config import Config
from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_contract import SECTION_19_ROLE_DECISION_MATRIX, evaluate_section_states
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
    "CVE (web-exposed RCE)": _article(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-90001", title="CVE-2026-90001 remote code execution",
        summary="A remote code execution vulnerability in a web-facing administrative endpoint allows "
                "unauthenticated attackers to execute arbitrary commands.",
        source="nvd", cve_id="CVE-2026-90001", cvss_score=9.1,
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
        summary="A new report finds ransomware operators increasingly exploit unpatched VPN devices for access, "
                "using stolen credentials and remote desktop protocol for lateral movement.",
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
    "General intelligence (no CVE/ransomware/AI-security signal)": _article(
        url="https://example.test/roundup", title="Weekly Security News Roundup",
        summary="A general roundup of security news items with no specific technical claim.",
        labels=["News"], source="global_rss",
    ),
}


def main() -> None:
    config = Config()
    print(f"{'Case':<46}{'Family':<22}{'#Decisions':<12}{'Roles':<38}{'Section 19':<32}{'Tier':<16}{'In rendered HTML?'}")
    for label, article in CASES.items():
        result = AuthorityTransformer(config).transform(article)
        decisions = result.get("role_decisions") or []
        roles = ", ".join(sorted({d["role"] for d in decisions})) or "--"
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context, role_decision_count=len(decisions))
        section_19 = next(r.state.value for r in resolutions if r.section == SECTION_19_ROLE_DECISION_MATRIX)
        in_html = "Role-Based Decisions" in result["content"]
        print(
            f"{label:<46}{result['report_family']:<22}{len(decisions):<12}{roles:<38}"
            f"{section_19:<32}{result['product_tier']:<16}{in_html}"
        )
        # Live proof, not just a printed table: the section heading must
        # appear in the rendered HTML whenever real decisions exist, and
        # must NOT appear when none exist (RX-P1J's own "omit the whole
        # section, don't render an empty heading" discipline).
        assert in_html == bool(decisions), f"{label}: role section presence disagrees with decision count"
        for d in decisions:
            assert d["evidence_claim_ids"], f"{label}: {d['role']} decision has no evidence basis"


if __name__ == "__main__":
    main()
    print("\nAll assertions passed: rendered HTML presence matches structured decision count for every case.")
