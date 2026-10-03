"""Production hardening subsystem.

Submodules are intentionally not eager-imported: publication depends on the
live pipeline, while low-level state persistence is used by that same pipeline.
Keeping this package initializer side-effect free avoids circular imports.
"""
