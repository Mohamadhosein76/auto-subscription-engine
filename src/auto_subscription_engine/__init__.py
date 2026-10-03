"""Auto Subscription Engine core package.

Aggregates public proxy subscription sources into a single normalized,
deduplicated subscription. Runs on GitHub Actions: no VPS, no Cloudflare.
"""

from .core.models import SUPPORTED_PROTOCOLS
from .core.version import VERSION as __version__

__all__ = ["SUPPORTED_PROTOCOLS", "__version__"]
