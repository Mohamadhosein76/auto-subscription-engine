"""Central platform abstraction for the ASE engine.

Every platform-specific decision in the codebase routes through this
package: canonical platform detection, executable naming, process
lifecycle, safe archive extraction and POSIX-only permission handling.
Platform logic must never be duplicated outside this package (Stage 12
cross-platform rule).
"""

from .detection import (
    SUPPORTED_PLATFORMS,
    canonical_platform,
    current_platform,
    is_posix,
    is_windows,
)
from .executable import (
    CORE_BINARY_BASE_NAMES,
    binary_base_name,
    binary_file_name,
    resolve_executable,
)
from .paths import runtime_dir, temp_root
from .process import (
    CREATE_NEW_PROCESS_GROUP_WIN,
    core_process_kwargs,
    terminate_process_tree,
)
from .archive import (
    ArchiveError,
    extract_member,
    extract_members,
    validate_member_name,
)

__all__ = [
    "SUPPORTED_PLATFORMS",
    "canonical_platform",
    "current_platform",
    "is_posix",
    "is_windows",
    "CORE_BINARY_BASE_NAMES",
    "binary_base_name",
    "binary_file_name",
    "resolve_executable",
    "runtime_dir",
    "temp_root",
    "CREATE_NEW_PROCESS_GROUP_WIN",
    "core_process_kwargs",
    "terminate_process_tree",
    "ArchiveError",
    "extract_member",
    "extract_members",
    "validate_member_name",
]
