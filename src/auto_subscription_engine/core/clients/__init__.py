"""Central multi-client subsystem.

Stage 7 owns client/core capabilities, native builders, runtime adapters,
compatibility evaluation, exporters and pinned core installation.  No client
logic should live at the package root.
"""
from __future__ import annotations

from .registry import CLIENTS, CORES, ClientSpec, CoreSpec, client_spec, core_spec

__all__ = [
    "CLIENTS",
    "CORES",
    "ClientSpec",
    "CoreSpec",
    "client_spec",
    "core_spec",
]
