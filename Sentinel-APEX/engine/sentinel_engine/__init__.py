"""SENTINEL APEX Intelligence Engine — Phase 2 of the Intelligence Factory.

Single-responsibility, independently testable modules:

- ``normalizer``       raw source -> evidence-only NormalizedDoc
- ``ioc_extractor``    deterministic IOC extraction / defanging
- ``attack_mapper``    evidence-backed MITRE ATT&CK mapping
- ``entities``         curated-lexicon entity extraction
- ``enrichment``       NVD / EPSS / CISA KEV lookups (never fabricates)
- ``knowledge_graph``  persistent cross-report intelligence graph
- ``sigma_builder``    validated, evidence-driven Sigma rules
- ``quality``          executable publication quality gates
- ``report_parser``    parses published reports for auditing
- ``pipeline``         orchestrates source -> gated draft
"""

__version__ = "0.1.0"
