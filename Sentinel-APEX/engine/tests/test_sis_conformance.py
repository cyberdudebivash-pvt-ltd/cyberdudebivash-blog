import re
from pathlib import Path

TEMPLATES_ROOT = Path(__file__).parent.parent.parent / "templates"

# Canonical single-value `audience` enum — Sentinel Intelligence Standard
# (Sentinel-APEX/eios/sentinel-intelligence-standard.md) § 2.1. Keep in sync
# with that document. This test exists so drift between the two is caught
# automatically, rather than discovered by a future reader the way the
# pre-SIS "soc,ciso,threat-hunter" comma-joined value was (GCIEP v1).
SIS_AUDIENCE_VALUES = {
    "executive", "board", "soc", "detection-engineer", "hunting", "dfir",
}

_AUDIENCE_RE = re.compile(r'^audience:\s*"([^"]*)"', re.MULTILINE)


def _template_files():
    return sorted(TEMPLATES_ROOT.glob("*/*.md"))


def test_at_least_one_template_exists():
    # Sanity check: if the glob ever finds nothing (e.g. a directory-layout
    # change), every test below would vacuously pass instead of failing.
    assert _template_files()


def test_every_template_has_an_audience_field():
    for f in _template_files():
        assert _AUDIENCE_RE.search(f.read_text()), (
            f"{f} has no audience: front-matter field"
        )


def test_every_template_audience_value_is_single_valued():
    for f in _template_files():
        m = _AUDIENCE_RE.search(f.read_text())
        value = m.group(1) if m else None
        assert m and "," not in value, (
            f"{f} has a comma-joined audience value ({value!r}) — Sentinel "
            "Intelligence Standard § 2.1 requires a single-valued audience "
            "field, one template per distinguishing question"
        )


def test_every_template_audience_value_is_in_the_sis_enum():
    for f in _template_files():
        m = _AUDIENCE_RE.search(f.read_text())
        value = m.group(1) if m else None
        assert value in SIS_AUDIENCE_VALUES, (
            f"{f} has audience={value!r}, not in the Sentinel Intelligence "
            "Standard § 2.1 enum — update SIS if this is a deliberate new "
            "value, or fix the template if not"
        )
