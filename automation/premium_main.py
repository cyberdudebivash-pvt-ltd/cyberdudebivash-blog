"""Production entry point for premium-grade Blogger syndication."""

from __future__ import annotations

import sys

from . import main as _main
from .premium_evidence_compiler import install_premium_evidence_compiler_overrides
from .premium_factory_throughput import install_factory_throughput_overrides
from .premium_incident_recovery import install_incident_recovery_overrides
from .premium_provider_budget import install_provider_budget_overrides
from .premium_publication import install_runtime_overrides
from .premium_release_hardening import install_release_hardening
from .premium_yield_contract_guard import install_yield_contract_guard
from .premium_yield_hardening import install_yield_hardening_overrides
from .provider_quota_ledger import install_provider_quota_ledger


def main() -> int:
    """Install the production runtime stack in its required dependency order."""
    # Install order is a production invariant. Provider-budget/recovery/yield
    # controls preserve the proven pre-Stage-2 safety chain; factory throughput
    # then adds family scheduling and model-scoped pacing. premium_publication
    # snapshots that active runtime into the production transformer/publisher.
    #
    # Stage-2 installs the durable quota ledger and deterministic evidence
    # compiler after the legacy generation/runtime layers. Stage-3 is strictly
    # last so it can reconcile fallback ranking, final pre-hash evidence
    # language, compact numeric grounding, and observed provider capability
    # hints against the complete live runtime graph without replacing ReportX,
    # publication integrity, artifact hashing, or Blogger fetch-back.
    install_provider_budget_overrides()
    install_incident_recovery_overrides(_main)
    install_yield_hardening_overrides()
    install_yield_contract_guard()
    install_factory_throughput_overrides(_main)
    install_runtime_overrides(_main)
    install_provider_quota_ledger()
    install_premium_evidence_compiler_overrides(_main)
    install_release_hardening(_main)
    return _main.main()


if __name__ == "__main__":
    sys.exit(main())
