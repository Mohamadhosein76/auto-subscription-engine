"""Cross-platform core process lifecycle.

POSIX keeps the existing safe process-group cleanup (each core in its own
session, SIGTERM -> SIGKILL to the group).  Windows uses
CREATE_NEW_PROCESS_GROUP and terminates the whole core process tree with
``taskkill /T /F`` as the bounded fallback - never touching unrelated
processes.
"""

from __future__ import annotations

import os
import signal
import subprocess

CREATE_NEW_PROCESS_GROUP_WIN = 0x00000200
_CREATE_NO_WINDOW = 0x08000000


def core_process_kwargs() -> dict:
    """Extra ``subprocess.Popen`` kwargs for a detached core process."""
    if os.name == "posix":
        return {"start_new_session": True}
    return {
        "creationflags": CREATE_NEW_PROCESS_GROUP_WIN | _CREATE_NO_WINDOW,
    }


def terminate_process_tree(process: subprocess.Popen) -> None:
    """Terminate the complete core process tree, best-effort and idempotent.

    Only processes belonging to this core's tree are signalled.
    """
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
        else:
            _taskkill_tree(process.pid, force=False) or process.terminate()
        try:
            process.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            _taskkill_tree(process.pid, force=True)
            if process.poll() is None:
                process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    except Exception:  # noqa: BLE001 - cleanup is best-effort and idempotent
        try:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
        except Exception:  # noqa: BLE001
            pass


def _taskkill_tree(pid: int, *, force: bool) -> bool:
    """Windows: terminate the process tree. Returns True when successful."""
    if os.name != "posix":
        import subprocess as sp

        argv = ["taskkill", "/T", "/PID", str(pid)]
        argv.append("/F" if force else "/W")
        try:
            result = sp.run(
                argv,
                stdout=sp.DEVNULL,
                stderr=sp.DEVNULL,
                timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            return result.returncode == 0
        except (OSError, sp.SubprocessError):
            return False
    return False
