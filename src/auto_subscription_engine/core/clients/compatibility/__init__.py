"""Runtime client compatibility stage.

The public symbols are loaded lazily so low-level builders can import the
capability/classification modules without creating an engine<->builder cycle.
"""
from __future__ import annotations

__all__ = ["CompatOptions", "CompatStageResult", "run_compat_stage"]


def __getattr__(name: str):
    if name in __all__:
        from .engine import CompatOptions, CompatStageResult, run_compat_stage

        return {
            "CompatOptions": CompatOptions,
            "CompatStageResult": CompatStageResult,
            "run_compat_stage": run_compat_stage,
        }[name]
    raise AttributeError(name)
