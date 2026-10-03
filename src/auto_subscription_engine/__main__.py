"""Entry point for ``python -m auto_subscription_engine``."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
