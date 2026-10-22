"""CPU, memory and PCI topology of a host, as sysfs and procfs report it."""
import re
from dataclasses import dataclass
from pathlib import Path

from . import PartitionError

_CPU_DIR = re.compile(r"cpu(\d+)")
_NODE_DIR = re.compile(r"node(\d+)")
_MEM_TOTAL = re.compile(r"^(?:Node \d+ )?MemTotal:\s+(\d+) kB$", re.M)
_PHYS_BITS = re.compile(r"^address sizes\s*:\s*(\d+) bits physical", re.M)


@dataclass(frozen=True)
class Thread:
    """One logical CPU. `core` is sysfs core_id, which is unique only within a
    package and may have gaps; the core itself is the `siblings` set."""
    socket: int
    node: int
    core: int
    siblings: tuple[int, ...]


@dataclass(frozen=True)
class Topology:
    threads: dict[int, Thread]
    node_threads: dict[int, list[int]]
    mem_total_kib: int
    phys_bits: int
    pci_node: dict[str, int]
    pci_device: dict[str, str]
    node_mem_kib: dict[int, int]
    # NUMA node of the bridge leading to each secondary PCI bus ("0000:16"),
    # which still places a slot whose device is absent.
    bus_node: dict[str, int]


def parse_cpulist(text: str) -> list[int]:
    threads = set()
    for part in text.strip().split(","):
        if part:
            lo, _, hi = part.partition("-")
            threads.update(range(int(lo), int(hi or lo) + 1))
    return sorted(threads)


def format_cpulist(threads) -> str:
    ranges = []
    for t in sorted(threads):
        if ranges and t == ranges[-1][1] + 1:
            ranges[-1][1] = t
        else:
            ranges.append([t, t])
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)


def _text(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError as e:
        raise PartitionError(f"cannot read {path}: {e.strerror}") from None


def _int(path: Path) -> int:
    value = _text(path)
    try:
        return int(value)
    except ValueError:
        raise PartitionError(f"{path} is not an integer: {value!r}") from None


def _match(pattern: re.Pattern, what: str, path: Path) -> int:
    m = pattern.search(_text(path))
    if not m:
        raise PartitionError(f"{path} has no {what}")
    return int(m.group(1))


def _pci_id(path: Path) -> str:
    value = _text(path)
    try:
        return f"{int(value, 16):04x}"
    except ValueError:
        raise PartitionError(f"{path} is not a PCI id: {value!r}") from None


def _dirs(path: Path, pattern: re.Pattern | None = None):
    if not path.is_dir():
        return []
    return sorted(d for d in path.iterdir() if pattern is None or pattern.fullmatch(d.name))


def read(sysfs: Path, proc: Path) -> Topology:
    system = sysfs / "devices" / "system"

    node_threads, node_mem_kib, thread_node = {}, {}, {}
    for d in _dirs(system / "node", _NODE_DIR):
        n = int(_NODE_DIR.fullmatch(d.name).group(1))
        node_threads[n] = parse_cpulist(_text(d / "cpulist"))
        node_mem_kib[n] = _match(_MEM_TOTAL, "MemTotal", d / "meminfo")
        for t in node_threads[n]:
            if t in thread_node:
                raise PartitionError(f"cpu{t} is in node {thread_node[t]} and node {n}")
            thread_node[t] = n
    if not node_threads:
        raise PartitionError(f"no NUMA node under {system / 'node'}")

    threads = {}
    for d in _dirs(system / "cpu", _CPU_DIR):
        t = int(_CPU_DIR.fullmatch(d.name).group(1))
        if (d / "online").exists() and _text(d / "online") != "1":
            raise PartitionError(f"cpu{t} is offline")
        if t not in thread_node:
            raise PartitionError(f"cpu{t} is in no NUMA node")
        topo = d / "topology"
        threads[t] = Thread(
            socket=_int(topo / "physical_package_id"),
            node=thread_node[t],
            core=_int(topo / "core_id"),
            siblings=tuple(parse_cpulist(_text(topo / "thread_siblings_list"))),
        )
    missing = sorted(set(thread_node) - set(threads))
    if missing:
        raise PartitionError(f"node {thread_node[missing[0]]} lists cpu{missing[0]}, which sysfs does not have")
    for t, thread in threads.items():
        if t not in thread.siblings:
            raise PartitionError(f"cpu{t} is not among its own siblings")
        for s in thread.siblings:
            other = threads.get(s)
            if other is None or (other.siblings, other.socket, other.node) != (thread.siblings, thread.socket, thread.node):
                raise PartitionError(f"cpu{t} and cpu{s} disagree on their core")

    pci_node, pci_device = {}, {}
    for d in _dirs(sysfs / "bus" / "pci" / "devices"):
        pci_node[d.name] = _int(d / "numa_node")
        pci_device[d.name] = f"{_pci_id(d / 'vendor')}:{_pci_id(d / 'device')}"

    bus_node = {}
    for d in _dirs(sysfs / "class" / "pci_bus"):
        if (d / "device" / "numa_node").exists():
            bus_node[d.name] = _int(d / "device" / "numa_node")

    return Topology(
        threads=dict(sorted(threads.items())),
        node_threads=dict(sorted(node_threads.items())),
        mem_total_kib=_match(_MEM_TOTAL, "MemTotal", proc / "meminfo"),
        phys_bits=_match(_PHYS_BITS, "address sizes", proc / "cpuinfo"),
        pci_node=pci_node,
        pci_device=pci_device,
        node_mem_kib=dict(sorted(node_mem_kib.items())),
        bus_node=bus_node,
    )
