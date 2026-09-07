from __future__ import annotations

from types import SimpleNamespace

from bs4 import BeautifulSoup
import pytest

from automation import cti_publication_recovery_v19_2 as v19_2
from automation.report_integrity import PublicationIntegrityError


def _visible(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for node in soup.find_all(["script", "style", "noscript"]):
        node.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())


def test_scrubber_removes_observed_prompt_leaks_and_preserves_evidence():
    html = """
    <article>
      <p>The user wants me to create a production report. Let me analyze the source.</p>
      <p>CVE-2026-86164 affects the cited Sales and Inventory System deployment.</p>
      <p>No preamble, no markdown fences. CDB_EXPLOITATION_STATUS</p>
    </article>
    """
    soup = BeautifulSoup(html, "html.parser")

    changed = v19_2.scrub_customer_visible_prompt_leakage(soup)
    visible = " ".join(soup.get_text(" ", strip=True).split())

    assert changed == 2
    assert "The user wants me to" not in visible
    assert "Let me analyze" not in visible
    assert "No preamble, no markdown fences" not in visible
    assert "CDB_EXPLOITATION_STATUS" not in visible
    assert "CVE-2026-86164 affects the cited Sales and Inventory System deployment." in visible


def test_scrubber_does_not_rewrite_code_or_preformatted_evidence():
    html = """
    <article>
      <pre>CDB_EXPLOITATION_STATUS = source_claim_only</pre>
      <code>No preamble, no markdown fences</code>
      <p>Verified source-linked evidence remains unchanged.</p>
    </article>
    """
    soup = BeautifulSoup(html, "html.parser")

    changed = v19_2.scrub_customer_visible_prompt_leakage(soup)

    assert changed == 0
    assert "CDB_EXPLOITATION_STATUS" in soup.get_text(" ", strip=True)
    assert "No preamble, no markdown fences" in soup.get_text(" ", strip=True)
    assert "Verified source-linked evidence remains unchanged." in soup.get_text(" ", strip=True)


def test_patched_v8_gate_always_calls_original_fail_closed_gate(monkeypatch):
    calls = []

    def original_gate(soup):
        calls.append(_visible(str(soup)))
        raise PublicationIntegrityError(["sentinel original gate executed"])

    monkeypatch.setattr(v19_2, "_ORIGINAL_V8_GATE", original_gate)
    soup = BeautifulSoup(
        "<article><p>The user wants me to write this report.</p><p>Source evidence survives.</p></article>",
        "html.parser",
    )

    with pytest.raises(PublicationIntegrityError, match="sentinel original gate executed"):
        v19_2._patched_v8_gate(soup)

    assert len(calls) == 1
    assert "The user wants me to" not in calls[0]
    assert "Source evidence survives." in calls[0]


def test_certification_binding_is_exact_and_not_customer_visible():
    certification = (
        "Public Intelligence Certification: FLASH_READY "
        "(automated evidence-graph certification — see Provenance for the source basis)"
    )
    context = SimpleNamespace(certification_status=certification)
    html = """
    <div class="cdb-cti-dossier">
      <div>EVIDENCE TIER <strong>SOURCE_ONLY_PRELIMINARY</strong></div>
      <p>Customer-visible evidence boundary.</p>
    </div>
    """

    rendered = v19_2._inject_certification_binding(html, context)
    soup = BeautifulSoup(rendered, "html.parser")
    root = soup.select_one(".cdb-cti-dossier")

    assert root is not None
    assert root["data-cdb-reportx-certification-binding"] == certification
    assert root["data-cdb-reportx-certification-binding-mode"] == "machine-only"
    assert certification in rendered
    assert "FLASH_READY" not in _visible(rendered)
    assert "SOURCE_ONLY_PRELIMINARY" in _visible(rendered)


def test_certification_binding_is_idempotent_when_exact_status_already_present():
    certification = "Public Intelligence Certification: TACTICAL_READY"
    context = SimpleNamespace(certification_status=certification)
    html = f'<div class="cdb-cti-dossier" data-existing="{certification}">Visible report</div>'

    rendered = v19_2._inject_certification_binding(html, context)
    soup = BeautifulSoup(rendered, "html.parser")
    root = soup.select_one(".cdb-cti-dossier")

    assert rendered == html
    assert root is not None
    assert root.get("data-cdb-reportx-certification-binding") is None


def test_empty_certification_never_creates_machine_binding():
    context = SimpleNamespace(certification_status="")
    html = '<div class="cdb-cti-dossier">Visible report</div>'

    assert v19_2._inject_certification_binding(html, context) == html


def test_telemetry_preserves_hard_invariants():
    telemetry = v19_2.telemetry_snapshot()

    assert telemetry["version"] == "v19.2"
    assert telemetry["v8_fail_closed_gate_preserved"] is True
    assert telemetry["reportx_quality_floors_changed"] is False
    assert telemetry["reportx_tier_engine_changed"] is False
    assert telemetry["provider_policy_changed"] is False
    assert telemetry["prices_changed"] is False
    assert telemetry["payment_system_changed"] is False
    assert telemetry["telemetry_contains_prompts"] is False
    assert telemetry["telemetry_contains_response_content"] is False
    assert telemetry["telemetry_contains_credentials"] is False
    assert telemetry["telemetry_contains_pii"] is False
