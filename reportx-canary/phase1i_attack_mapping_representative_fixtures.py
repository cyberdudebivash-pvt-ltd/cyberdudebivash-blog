"""ReportX Phase 1I structured-ATT&CK real-data verification set.

Unlike this directory's other canaries (independently-sourced real
incidents, checked-in raw source bytes, content-hash-verified), these 7
fixtures are REPRESENTATIVE, hand-constructed `DiscoveredArticle`
instances -- the same synthetic-but-realistic-shape convention already
used throughout this session's own test suites (e.g.
`tests/test_report_contract.py::_cve_article`,
`Sentinel-APEX/engine/tests/reportx/test_pipeline_composer.py::_cve_article`).
What is real and unmocked is the CODE PATH: every row below is produced
by a live call to `AuthorityTransformer(Config()).transform()`, exercising
the genuine `build_attack_mappings()` -> `report_contract.py` Section 11 ->
`analytical_depth_gate.py` tier-gate chain end to end, not a mocked or
hand-computed result.

Run directly: `python reportx-canary/phase1i_attack_mapping_representative_fixtures.py`
from the repo root, with the same venv used for `tests/`. Reproduces the
table in `docs/audits/REPORTX-PHASE1I-STRUCTURED-ATTACK-CERTIFICATION.md`
Section 5 exactly (CodeRabbit review on PR #117 asked for this table to be
reproducible with a real, checked-in script rather than only prose).
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
from automation.report_contract import SECTION_11_ATTACK_MAPPING, evaluate_section_states
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
    "Web-exposed CVE (SQLi)": _article(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-90001", title="CVE-2026-90001 SQL injection",
        summary="A SQL injection flaw in the login form allows authentication bypass via crafted input.",
        source="nvd", cve_id="CVE-2026-90001", cvss_score=8.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", cwe_ids=["CWE-89"], kev_listed=False,
    ),
    "Network-protocol CVE (DoS)": _article(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-90002", title="CVE-2026-90002 denial of service",
        summary="A malformed packet causes the network service to crash, resulting in denial of service.",
        source="nvd", cve_id="CVE-2026-90002", cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", cwe_ids=["CWE-400"], kev_listed=False,
    ),
    "Privilege-escalation CVE": _article(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-90003", title="CVE-2026-90003 privilege escalation",
        summary="A local user can exploit a flaw in the service to escalate privileges to SYSTEM.",
        source="nvd", cve_id="CVE-2026-90003", cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-269"], kev_listed=False,
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
    "AI security": _article(
        url="https://example.test/llm-prompt-injection-study", title="LLM Prompt Injection Study",
        summary="Researchers documented a prompt injection technique against a large language model deployment.",
        labels=["AI Security"], source="global_rss",
    ),
}


def main() -> None:
    config = Config()
    print(f"{'Case':<28}{'Family':<20}{'#Mappings':<11}{'Status(es)':<28}{'Section 11':<32}{'Tier'}")
    for label, article in CASES.items():
        result = AuthorityTransformer(config).transform(article)
        mappings = result.get("attack_mappings") or []
        statuses = ", ".join(sorted({m["status"] for m in mappings})) or "--"
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context, attack_mapping_count=len(mappings))
        section_11 = next(r.state.value for r in resolutions if r.section == SECTION_11_ATTACK_MAPPING)
        print(f"{label:<28}{result['report_family']:<20}{len(mappings):<11}{statuses:<28}{section_11:<32}{result['product_tier']}")


if __name__ == "__main__":
    main()
