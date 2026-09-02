"""Production entry point for premium-grade Blogger syndication."""

from __future__ import annotations

import sys

from . import main as _main
from .premium_publication import install_runtime_overrides


def main() -> int:
    install_runtime_overrides(_main)
    return _main.main()


if __name__ == "__main__":
    sys.exit(main())
