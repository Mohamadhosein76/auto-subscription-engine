"""Client artifact serializers."""
from .native import (
    write_client_manifest,
    write_mihomo_configs,
    write_mihomo_yaml,
    write_singbox_configs,
    write_singbox_json,
    write_uri_feed,
)

__all__ = [
    "write_client_manifest",
    "write_mihomo_configs",
    "write_mihomo_yaml",
    "write_singbox_configs",
    "write_singbox_json",
    "write_uri_feed",
]
