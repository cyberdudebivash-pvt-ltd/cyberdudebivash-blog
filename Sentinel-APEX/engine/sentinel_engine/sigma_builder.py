"""Evidence-driven Sigma rule construction.

Thin compatibility layer over the unified detection engine
(``detection_specs`` + ``detection_builder``). Sigma remains the canonical
detection format; this module preserves the original ``build_rules`` API and
embeds the per-report evidence into each rule's description. All detection
logic now lives in one place (``detection_specs.REGISTRY``) so a technique's
Sigma, KQL, Splunk and OSQuery outputs can never drift apart.
"""

from __future__ import annotations

import datetime as _dt

import yaml

from .detection_builder import to_sigma
from .detection_specs import REGISTRY, buildable_techniques  # re-exported
from .models import TechniqueMapping
from .quality import validate_sigma

__all__ = ["build_rules", "buildable_techniques"]


def build_rules(
    mappings: list[TechniqueMapping],
    references: list[str] | None = None,
    date: str | None = None,
) -> list[str]:
    """Build validated Sigma rules for mapped techniques that have specific
    detection logic, embedding each mapping's evidence. Returns YAML strings."""
    rules: list[str] = []
    date = date or _dt.date.today().isoformat()
    refs = list(references or [])
    for mapping in mappings:
        spec = REGISTRY.get(mapping.technique_id)
        if not spec:
            continue
        rule_yaml = to_sigma(spec, refs, date)
        # thread the report-specific evidence into the description
        rule = yaml.safe_load(rule_yaml)
        rule["description"] = (
            f"{spec.title}. Evidence basis: {mapping.evidence[:200]}. "
            "CYBERDUDEBIVASH SENTINEL APEX Detection Engineering."
        )
        rule["tags"] = [
            f"attack.{mapping.tactic}",
            f"attack.{mapping.technique_id.lower()}",
        ]
        rule_yaml = yaml.safe_dump(rule, sort_keys=False, width=100)
        problems = validate_sigma(rule_yaml)
        if problems:
            raise ValueError(f"generated Sigma rule failed validation: {problems}")
        rules.append(rule_yaml)
    return rules
