"""ASE core domain layer.

Stage 2 centralizes canonical models, protocol parsers, ingestion and
serialization here. Replaced legacy implementations are removed as each subsystem moves here.
"""

from .models import CanonicalProxy, ParsedConfig

__all__ = ["CanonicalProxy", "ParsedConfig"]
