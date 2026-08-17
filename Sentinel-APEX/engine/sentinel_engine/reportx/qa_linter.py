"""Grammar / synthesis QA — deterministic, fail-closed (ReportX Section 23).

Catches generation defects a template/LLM pipeline leaves behind: dangling
sentence fragments from an unsubstituted variable (the task's own example:
``"confirming active exploitation in the ."``), unresolved template
tokens, empty placeholders, duplicate/near-duplicate headings and
paragraphs, malformed code fences, and ragged markdown tables.

Modeled on ``quality.py``'s existing regex-gate style (same severity
vocabulary: ``block`` / ``warn``) rather than inventing a new pattern —
this module is meant to plug into the same ``GateFinding``/``GateResult``
shape the rest of the engine already uses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import GateFinding, GateResult

# ============================================================
# Dangling sentence fragments from an unsubstituted template variable.
# The task's own example: "confirming active exploitation in the ."
# ============================================================

_RE_DANGLING_DETERMINER = re.compile(
    r"\b(?:in|on|at|for|of|with|by|from|to)\s+(?:the|a|an)\s*[.!?]",
    re.IGNORECASE,
)
_RE_DANGLING_TRAILING_ARTICLE = re.compile(r"\b(?:the|a|an)\s*[.!?](?:\s|$)")

# ============================================================
# Unresolved template tokens / empty placeholders.
# ============================================================

_RE_UNRESOLVED_TEMPLATE = re.compile(
    r"\{\{[^{}]*\}\}"       # {{var}}
    r"|\$\{[^{}]*\}"        # ${var}
    r"|%\([a-zA-Z_][a-zA-Z0-9_]*\)s"  # %(var)s
    r"|\{[a-zA-Z_][a-zA-Z0-9_.]*\}",  # {var} -- Python str.format leftovers
)
_RE_EMPTY_PLACEHOLDER = re.compile(
    r"\[PLACEHOLDER\]|\bTODO\b|\bTBD\b|\bFIXME\b|\bundefined\b|\bNaN\b",
)
# Only flags "None" in a field-value context (preceded by a colon, an "is"/
# "was"/"are"/"were" copula, or "=") -- a bare standalone "None" elsewhere is
# far more often legitimate English ("None of the sources...", "None was
# found to corroborate...") than a leaked Python object. Caught as a real
# false positive by the Qilin/Spoonful of Comfort fixture's own prose
# ("None of this historical context is evidence...").
_RE_PYTHON_NONE_LEAK = re.compile(
    r"(?::\s*None(?![A-Za-z0-9_]))"
    r"|(?:\b(?:is|was|are|were)\s+None(?![A-Za-z0-9_]))"
    r"|(?:=\s*None(?![A-Za-z0-9_]))"
)

# ============================================================
# Structural defects.
# ============================================================

_RE_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)
_RE_DANGLING_COLON = re.compile(r":\s*\n\s*\n")  # a colon promising a list/detail that never follows
_RE_CODE_FENCE = re.compile(r"^```", re.MULTILINE)


@dataclass(frozen=True)
class QAFinding:
    check: str
    severity: str  # "block" | "warn"
    message: str
    excerpt: str = ""

    def to_dict(self) -> dict:
        return {"check": self.check, "severity": self.severity, "message": self.message, "excerpt": self.excerpt}


def _snippet(text: str, start: int, end: int, pad: int = 20) -> str:
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    return text[lo:hi].replace("\n", " ").strip()


def check_dangling_sentence_fragments(text: str) -> list[QAFinding]:
    findings = []
    for m in _RE_DANGLING_DETERMINER.finditer(text):
        findings.append(QAFinding(
            check="dangling_sentence_fragment", severity="block",
            message="Sentence ends with a preposition + bare determiner before punctuation "
                    "(an unsubstituted template variable, e.g. 'in the .').",
            excerpt=_snippet(text, m.start(), m.end()),
        ))
    return findings


def check_unresolved_templates(text: str) -> list[QAFinding]:
    findings = []
    for m in _RE_UNRESOLVED_TEMPLATE.finditer(text):
        findings.append(QAFinding(
            check="unresolved_template_variable", severity="block",
            message=f"Unresolved template token {m.group(0)!r} leaked into rendered output.",
            excerpt=_snippet(text, m.start(), m.end()),
        ))
    for m in _RE_EMPTY_PLACEHOLDER.finditer(text):
        findings.append(QAFinding(
            check="empty_placeholder", severity="block",
            message=f"Placeholder token {m.group(0)!r} leaked into rendered output.",
            excerpt=_snippet(text, m.start(), m.end()),
        ))
    for m in _RE_PYTHON_NONE_LEAK.finditer(text):
        findings.append(QAFinding(
            check="none_value_leak", severity="block",
            message="Literal 'None' leaked into rendered prose (an unset field rendered without a guard).",
            excerpt=_snippet(text, m.start(), m.end()),
        ))
    return findings


def check_duplicate_headings(text: str) -> list[QAFinding]:
    seen: dict[tuple[str, str], int] = {}
    findings = []
    for m in _RE_HEADING.finditer(text):
        level, title = m.group(1), m.group(2).strip().lower()
        key = (level, title)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] == 2:
            findings.append(QAFinding(
                check="duplicate_heading", severity="warn",
                message=f"Heading {m.group(2)!r} (level {len(level)}) appears more than once.",
                excerpt=m.group(0),
            ))
    return findings


def check_duplicate_paragraphs(text: str) -> list[QAFinding]:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if len(p.strip()) > 40]
    seen: dict[str, int] = {}
    findings = []
    for p in paragraphs:
        normalized = re.sub(r"\s+", " ", p).lower()
        seen[normalized] = seen.get(normalized, 0) + 1
        if seen[normalized] == 2:
            findings.append(QAFinding(
                check="duplicate_paragraph", severity="warn",
                message="An identical paragraph appears more than once in the same document.",
                excerpt=p[:120],
            ))
    return findings


def check_dangling_colon(text: str) -> list[QAFinding]:
    findings = []
    for m in _RE_DANGLING_COLON.finditer(text):
        findings.append(QAFinding(
            check="dangling_colon", severity="warn",
            message="A colon is immediately followed by a blank line — the promised list/detail never follows.",
            excerpt=_snippet(text, m.start(), m.end()),
        ))
    return findings


def check_code_fence_balance(text: str) -> list[QAFinding]:
    count = len(_RE_CODE_FENCE.findall(text))
    if count % 2 != 0:
        return [QAFinding(
            check="unbalanced_code_fence", severity="block",
            message=f"Odd number of ``` code-fence markers ({count}) — a code block is unclosed.",
        )]
    return []


def check_markdown_table_cell_counts(text: str) -> list[QAFinding]:
    findings = []
    lines = text.split("\n")
    header_cols = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("|"):
            header_cols = None
            continue
        cols = [c for c in stripped.strip("|").split("|")]
        if re.fullmatch(r"\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*", stripped.strip("|")):
            continue  # the '|---|---|' separator row itself
        if header_cols is None:
            header_cols = len(cols)
            continue
        if len(cols) != header_cols:
            findings.append(QAFinding(
                check="missing_table_cell", severity="block",
                message=f"Table row has {len(cols)} cells, header row declared {header_cols}.",
                excerpt=stripped[:120],
            ))
    return findings


def lint_text(text: str) -> list[QAFinding]:
    findings: list[QAFinding] = []
    findings += check_dangling_sentence_fragments(text)
    findings += check_unresolved_templates(text)
    findings += check_duplicate_headings(text)
    findings += check_duplicate_paragraphs(text)
    findings += check_dangling_colon(text)
    findings += check_code_fence_balance(text)
    findings += check_markdown_table_cell_counts(text)
    return findings


def to_gate_result(findings: list[QAFinding]) -> GateResult:
    """Bridges into the parent package's existing GateFinding/GateResult
    vocabulary so this linter's output can be merged with quality.py's
    other gates in a single publication decision."""
    return GateResult(findings=[GateFinding(gate=f"qa.{f.check}", severity=f.severity, message=f.message) for f in findings])


def critical_defect_count(findings: list[QAFinding]) -> int:
    """The premium gate: critical_language_defects == 0."""
    return sum(1 for f in findings if f.severity == "block")
