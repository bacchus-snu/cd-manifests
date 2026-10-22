"""NVIDIA Fabric Manager partitions in shared NVSwitch mode, driven through `fmpm`.

A GPU group can use NVLink only while the Fabric Manager partition with
exactly its GPUs is active; partitions that share a GPU cannot be active
together.
"""
import subprocess

FMPM_TIMEOUT = 120


class FmError(Exception):
    """A Fabric Manager partition could not be activated or deactivated."""


def partition_id(group, p: dict) -> int:
    key = ",".join(map(str, sorted(group)))
    pid = (p.get("fm_partitions") or {}).get(key)
    if pid is None:
        raise FmError(f"no Fabric Manager partition for GPU positions [{key.replace(',', ', ')}]")
    return pid


def _fmpm(flag: str, pid: int, run) -> None:
    argv = ["fmpm", flag, str(pid)]
    try:
        r = run(argv, capture_output=True, text=True, timeout=FMPM_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as e:
        raise FmError(f"fmpm {flag} {pid}: {e}") from None
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip()
        raise FmError(f"fmpm {flag} {pid} exited {r.returncode}: {detail}")


def activate(group, p: dict, run=subprocess.run) -> None:
    """Activate the partition of exactly `group`'s GPU positions."""
    _fmpm("-a", partition_id(group, p), run)


def deactivate(group, p: dict, run=subprocess.run) -> None:
    _fmpm("-d", partition_id(group, p), run)
