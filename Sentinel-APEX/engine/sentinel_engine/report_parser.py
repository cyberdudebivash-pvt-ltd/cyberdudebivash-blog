"""Parser for published SENTINEL APEX report pages/dumps.

Turns a report (as published, including page chrome) into a structured
``ParsedReport`` so the quality gate can audit real production output —
section by section — instead of only validating drafts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

_RE_FRONT_MATTER = re.compile(r"\A---\s*\n(.*?\n)---\s*\n", re.DOTALL)

# Recognizes two section-marker conventions: the legacy `►`-prefixed style
# used by older published-page dumps (see tests/fixtures/INTEL-REPORT-*.txt),
# and the `##` ATX-style headings actually used by hand-authored reports in
# Sentinel-APEX/reports/drafts/ (e.g. SA-2026-0001). `##` only — not `#`
# (the document title lives in YAML front matter, not a level-1 heading) or
# `###`+ (sub-headings stay nested inside their parent section's body rather
# than becoming their own top-level section).
_RE_SECTION = re.compile(r"^(?:►|##)\s+(.+?)\s*$", re.MULTILINE)
_RE_DATE_LINE = re.compile(r"^[A-Z][a-z]+ \d{1,2}, \d{4}$")
_RE_SIGMA_START = re.compile(r"^title:\s*\S", re.MULTILINE)


@dataclass
class ParsedReport:
    title: str = ""
    severity: str = ""
    sections: dict[str, str] = field(default_factory=dict)
    sigma_yaml: str = ""
    raw: str = ""
    metadata: dict = field(default_factory=dict)

    def section(self, name_fragment: str) -> str:
        """Fetch a section by case-insensitive fragment of its heading."""
        frag = name_fragment.lower()
        for name, body in self.sections.items():
            if frag in name.lower():
                return body
        return ""

    def has_section(self, name_fragment: str) -> bool:
        frag = name_fragment.lower()
        return any(frag in name.lower() for name in self.sections)


def _extract_front_matter(text: str) -> tuple[dict, str]:
    """Splits a leading YAML front-matter block (--- ... ---) from the rest
    of the text, same convention as Sentinel-APEX/renderer/report-renderer.js.
    The legacy `►`-based page-dump fixtures have no front matter at all, so
    absence (or malformed YAML) is not an error — metadata just stays empty
    and the full text is treated as the body, same as before this existed."""
    m = _RE_FRONT_MATTER.match(text)
    if not m:
        return {}, text
    try:
        parsed = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        return {}, text
    if not isinstance(parsed, dict):
        return {}, text
    return parsed, text[m.end():]


def parse_report(text: str) -> ParsedReport:
    metadata, body = _extract_front_matter(text)
    report = ParsedReport(raw=text, metadata=metadata)
    # Front matter, when present, is the authoritative source — it's
    # authored deliberately, not inferred from prose. Fall back to the
    # text-scanning extractors for the legacy format, which has neither.
    report.title = str(metadata.get("title") or "") or _extract_title(body)
    fm_severity = str(metadata.get("severity") or "").upper()
    report.severity = fm_severity if fm_severity in SEVERITIES else _extract_severity(body)

    matches = list(_RE_SECTION.finditer(body))
    for i, m in enumerate(matches):
        name = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        report.sections[name] = body[start:end].strip()

    sigma_section = report.section("Sigma")
    if sigma_section:
        report.sigma_yaml = _extract_sigma(sigma_section)
    return report


def _extract_title(text: str) -> str:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if _RE_DATE_LINE.match(line.strip()):
            for candidate in lines[i + 1 : i + 4]:
                candidate = candidate.strip()
                if len(candidate) >= 15:
                    return candidate
    # fallback: first sentence of the executive summary
    m = _RE_SECTION.search(text)
    if m:
        body = text[m.end() :].strip()
        return body.split(".")[0][:160]
    return ""


def _extract_severity(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped in SEVERITIES:
            return stripped
    return ""


def _extract_sigma(section: str) -> str:
    """The Sigma section carries a filename line and framing text before the
    actual YAML; the rule starts at its ``title:`` key."""
    m = _RE_SIGMA_START.search(section)
    return section[m.start() :].strip() if m else ""
