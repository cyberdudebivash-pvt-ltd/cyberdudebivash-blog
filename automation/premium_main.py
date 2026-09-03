"""Production entry point for premium-grade Blogger syndication."""

from __future__ import annotations

import sys

from . import main as _main
from .premium_incident_recovery import install_incident_recovery_overrides
from .premium_provider_budget import install_provider_budget_overrides
from .premium_publication import install_runtime_overrides


def main() -> int:
    # Provider-budget overrides must be installed first. The P0 incident
    # recovery layer then rebalances the fixed completion budget, adds
    # structure-aware Groq model failover, and installs the zero-publication
    # availability guard. Finally the premium runtime snapshots those active
    # analyst-prompt and LLM-call functions into AuthorityTransformer.
    install_provider_budget_overrides()
    install_incident_recovery_overrides(_main)
    install_runtime_overrides(_main)
    return _main.main()


if __name__ == "__main__":
    sys.exit(main())