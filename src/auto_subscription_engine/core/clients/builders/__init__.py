"""Native config builders for supported proxy cores."""
from .singbox import UnsupportedNodeError, build_node_config, build_outbound
from .xray import build_xray_config, build_xray_outbound
from .hiddify import build_hiddify_config, build_hiddify_outbound
from .mihomo import build_mihomo_config, build_mihomo_proxy

__all__ = [
    "UnsupportedNodeError",
    "build_node_config",
    "build_outbound",
    "build_xray_config",
    "build_xray_outbound",
    "build_hiddify_config",
    "build_hiddify_outbound",
    "build_mihomo_config",
    "build_mihomo_proxy",
]
