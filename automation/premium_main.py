"""Production entry point for premium-grade Blogger syndication."""

from __future__ import annotations

import sys

from . import main as _main
from .cti_dossier_presentation import install_cti_dossier_presentation
from .cti_evidence_convergence import install_cti_evidence_convergence
from .cti_evidence_convergence_v7 import install_cti_evidence_convergence_v7
from .generation_evidence_admission import install_generation_evidence_admission
from .premium_capacity_recovery import install_premium_capacity_recovery
from .premium_capacity_runtime_binding import install_capacity_runtime_binding_fix
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
    # compiler after the legacy generation/runtime layers. Stage-3 reconciles
    # final evidence language and provider capability against the complete live
    # runtime graph. CTI Dossier v5 installs strictly after Stage-3. v6 remains
    # in the chain for backward compatibility; v7 installs with an explicit
    # function marker so the historical v5/v6 wrapper-name collision cannot
    # suppress convergence. Stage-4/v8 binds active article context to provider
    # candidate selection and rejects unsupported high-impact claims. Stage-5/v9
    # installs bounded <=900-token continuation recovery. v10 then rebinds that
    # recovery wrapper around the ACTUAL authority_transformer.call_llm consumer,
    # preserving Stage-4 as the inner evidence-admission layer. This final bind
    # closes the Python function-alias bug proven by production run #8623, where
    # v9 logged as installed but could never execute.
    install_provider_budget_overrides()
    install_incident_recovery_overrides(_main)
    install_yield_hardening_overrides()
    install_yield_contract_guard()
    install_factory_throughput_overrides(_main)
    install_runtime_overrides(_main)
    install_provider_quota_ledger()
    install_premium_evidence_compiler_overrides(_main)
    install_release_hardening(_main)
    install_cti_dossier_presentation(_main)
    install_cti_evidence_convergence(_main)
    install_cti_evidence_convergence_v7(_main)
    install_generation_evidence_admission(_main)
    install_premium_capacity_recovery(_main)
    install_capacity_runtime_binding_fix()
    return _main.main()


if __name__ == "__main__":
    sys.exit(main())
