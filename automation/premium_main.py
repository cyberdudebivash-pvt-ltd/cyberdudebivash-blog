"""Production entry point for premium-grade Blogger syndication."""

from __future__ import annotations

import sys

from . import main as _main
from .premium_incident_recovery import install_incident_recovery_overrides
from .premium_provider_budget import install_provider_budget_overrides
from .premium_publication import install_runtime_overrides
from .premium_yield_hardening import install_yield_hardening_overrides


def main() -> int:
    # Provider-budget overrides must be installed first. The P0 incident
    # recovery layer then rebalances the fixed completion budget and adds
    # structure-aware Groq model failover. Yield hardening consumes that
    # recovered runtime, adds model cooldowns/evidence-safe generation and
    # secondary-task routing, then the premium runtime snapshots the final
    # analyst-prompt and LLM-call functions into AuthorityTransformer.
    install_provider_budget_overrides()
    install_incident_recovery_overrides(_main)
    install_yield_hardening_overrides()
    install_runtime_overrides(_main)
    return _main.main()


if __name__ == "__main__":
    sys.exit(main())