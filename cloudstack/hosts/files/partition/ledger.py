"""Host-local record of what each running domain holds: one JSON file per
domain UUID, written when its start is admitted and removed when libvirt
releases it.

The record is a fail-closed safety check against overlapping placements, not
a source of truth. Callers hold `locked` across reading the other entries,
admitting a domain and writing its entry, so concurrent starts serialise.
"""
import fcntl
import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

from . import PartitionError

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _path(directory: Path, uuid: str) -> Path:
    uuid = uuid.strip().lower()
    if not _UUID.fullmatch(uuid):
        raise PartitionError(f"{uuid!r} is not a domain UUID")
    return directory / f"{uuid}.json"


@contextmanager
def locked(directory: Path):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(directory / ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _valid(entry) -> bool:
    def ints(v):
        return isinstance(v, list) and all(isinstance(x, int) and not isinstance(x, bool) for x in v)
    return (isinstance(entry, dict) and isinstance(entry.get("name"), str) and ints(entry.get("threads"))
            and ints(entry.get("positions"))
            and (entry.get("fm_partition") is None or isinstance(entry.get("fm_partition"), int)))


def entries(directory: Path) -> dict[str, dict]:
    """Every entry by UUID. An entry that cannot be read is an error: what it
    holds is unknown."""
    out = {}
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.json")):
        try:
            entry = json.loads(path.read_text())
        except (OSError, ValueError) as e:
            raise PartitionError(f"ledger entry {path} is unreadable: {e}") from None
        if not _valid(entry):
            raise PartitionError(f"ledger entry {path} is malformed")
        out[path.stem] = entry
    return out


def write(directory: Path, uuid: str, entry: dict) -> None:
    path = _path(directory, uuid)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{path.stem}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(entry, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def read(directory: Path, uuid: str) -> dict | None:
    path = _path(directory, uuid)
    try:
        entry = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise PartitionError(f"ledger entry {path} is unreadable: {e}") from None
    if not _valid(entry):
        raise PartitionError(f"ledger entry {path} is malformed")
    return entry


def find(directory: Path, name: str) -> str | None:
    """The UUID of the readable entry recorded for domain `name`."""
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            entry = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(entry, dict) and entry.get("name") == name:
            return path.stem
    return None


def remove(directory: Path, uuid: str) -> None:
    try:
        _path(directory, uuid).unlink()
    except FileNotFoundError:
        pass
