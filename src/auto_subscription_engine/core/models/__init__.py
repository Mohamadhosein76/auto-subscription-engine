from .schema import (
    Authentication, CanonicalProxy, Endpoint, OriginFormat, ParseError,
    ParsedConfig, SCHEME_ALIASES, SUPPORTED_PROTOCOLS, CANONICAL_PROTOCOLS, SourceConfigError,
    TlsSpec, TransportSpec, UnknownProtocolError,
)
from .convert import canonical_to_legacy, legacy_to_canonical

__all__ = [
    "Authentication", "CanonicalProxy", "Endpoint", "OriginFormat",
    "ParseError", "ParsedConfig", "SCHEME_ALIASES", "SUPPORTED_PROTOCOLS", "CANONICAL_PROTOCOLS",
    "SourceConfigError", "TlsSpec", "TransportSpec", "UnknownProtocolError",
    "canonical_to_legacy", "legacy_to_canonical",
]
from .fingerprint import compute_canonical_fingerprint, compute_fingerprint, normalize_config
from .validation import ValidationResult, validate_config
