"""ReportX — evidence-first commercial intelligence product layer.

Builds on top of ``sentinel_engine``'s existing evidence-first primitives
(``models.Confidence``, ``models.IOC``, ``models.GateFinding``/
``GateResult``) rather than redefining them. This subpackage adds the
claim/evidence/source graph, threat-type schema isolation, and the
validators (contradiction engine, claim-support matrix, detection
governance, statistics registry, regulatory applicability, grammar/QA,
commercial readiness) that sit above a single normalized document.

Design principle carried over from the parent package's own README:
*evidence first, never fabricate — a field stays absent/NOT_ASSESSED
rather than guessed.*
"""

__version__ = "0.1.0"
