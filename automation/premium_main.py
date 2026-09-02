"""Production entry point for premium-grade Blogger syndication."""

from __future__ import annotations

import sys

from . import main as _main
from .premium_provider_budget import install_provider_budget_overrides
from .premium_publication import install_runtime_overrides


def main() -> int:
    # Provider-budget overrides must be installed first: the premium runtime
    # snapshots the active analyst-prompt and LLM-call functions into the
    # AuthorityTransformer module when install_runtime_overrides() runs.
    install_provider_budget_overrides()
    install_runtime_overrides(_main)
    return _main.main()


if __name__ == "__main__":
    sys.exit(main())
