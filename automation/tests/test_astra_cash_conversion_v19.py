from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from automation import astra_cash_conversion_v19 as v19


def _v18_panel() -> str:
    return """
    <section class="cdbv18-commercial" data-astra-revenue-v18="true"
      data-report-id="CDB-CTI-TEST" data-report-family="cve_advisory">
      <div class="cdbv18-boundary">Paid tiers change delivery, not certainty.</div>
      <div class="cdbv18-grid">
        <article><a href="https://blog.cyberdudebivash.in/api.html"
          data-cdb-v18-cta="api_docs" data-cdb-tier="free">API DOCUMENTATION</a></article>
        <article><a href="https://blog.cyberdudebivash.in/api-dashboard.html"
          data-cdb-v18-cta="api_starter" data-cdb-tier="starter">GET API ACCESS</a></article>
        <article><a href="https://blog.cyberdudebivash.in/pricing.html"
          data-cdb-v18-cta="soc_pro" data-cdb-tier="pro">UNLOCK SOC PRO</a></article>
        <article><a href="https://blog.cyberdudebivash.in/pricing.html"
          data-cdb-v18-cta="enterprise" data-cdb-tier="enterprise">ENTERPRISE ACCESS</a></article>
      </div>
      <div class="cdbv18-primary"><a href="https://blog.cyberdudebivash.in/pricing.html"
        data-cdb-v18-cta="recommended" data-cdb-tier="pro">VIEW SOC PRO OPTIONS</a></div>
    </section>
    """


def _query(href: str) -> dict[str, list[str]]:
    parsed = urlparse(href)
    assert parsed.scheme == "https"
    assert parsed.netloc == "blog.cyberdudebivash.in"
    assert parsed.path == "/buy.html"
    return parse_qs(parsed.query)


def test_direct_checkout_url_is_tier_scoped_and_attributed():
    url = v19.direct_checkout_url("pro", "cve_advisory", "soc_pro")
    query = _query(url)
    assert query["plan"] == ["pro"]
    assert query["checkout"] == ["1"]
    assert query["utm_source"] == ["sentinel_apex_report"]
    assert query["utm_medium"] == ["cti_dossier"]
    assert query["utm_campaign"] == ["astra_cash_conversion_v19"]
    assert query["utm_content"] == ["pro_cve_advisory_soc_pro"]


def test_direct_checkout_url_refuses_non_paid_tier():
    with pytest.raises(ValueError):
        v19.direct_checkout_url("free", "general", "api_docs")


def test_v19_rewrites_every_paid_v18_cta_but_preserves_public_docs():
    rendered = v19.enhance_cash_conversion(
        _v18_panel(),
        article=SimpleNamespace(),
        context=SimpleNamespace(family="cve_advisory"),
    )

    assert v19.MARKER in rendered
    assert "data-cdb-v19-direct-checkout=\"true\"" in rendered
    assert "DIRECT CHECKOUT //" in rendered
    assert "Paid access changes delivery and entitlement, never intelligence certainty." in rendered

    from bs4 import BeautifulSoup
    soup = BeautifulSoup(rendered, "html.parser")
    free = soup.select_one('a[data-cdb-tier="free"]')
    assert free["href"] == "https://blog.cyberdudebivash.in/api.html"
    assert not free.has_attr("data-cdb-v19-direct-checkout")

    paid = soup.select('a[data-cdb-v19-direct-checkout="true"]')
    assert len(paid) == 4  # starter, pro card, enterprise, recommended pro
    assert {a["data-cdb-v19-plan"] for a in paid} == {"starter", "pro", "enterprise"}
    for anchor in paid:
        query = _query(anchor["href"])
        assert query["plan"] == [anchor["data-cdb-v19-plan"]]
        assert query["checkout"] == ["1"]
        assert query["utm_campaign"] == ["astra_cash_conversion_v19"]


def test_v19_is_idempotent_and_does_not_create_commerce_without_v18_panel():
    base = _v18_panel()
    once = v19.enhance_cash_conversion(base)
    twice = v19.enhance_cash_conversion(once)
    assert once == twice

    unrelated = "<article><h1>Evidence-only report</h1><p>No commercial panel.</p></article>"
    assert v19.enhance_cash_conversion(unrelated) == unrelated


def test_v19_telemetry_is_aggregate_and_makes_no_revenue_guarantee():
    telemetry = v19.telemetry_snapshot()
    assert telemetry["quality_or_evidence_gate_changed"] is False
    assert telemetry["provider_policy_changed"] is False
    assert telemetry["telemetry_contains_pii"] is False
    assert telemetry["telemetry_contains_credentials"] is False
    assert telemetry["telemetry_contains_payment_identifiers"] is False
    assert telemetry["revenue_guaranteed"] is False
    serialized = str(telemetry).lower()
    assert "email" not in serialized
    assert "api_key" not in serialized
