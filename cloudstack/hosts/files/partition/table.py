"""A host's partition: housekeeping cores, one GPU unit per declared GPU
position, and the whole-core CPU pool."""
import re

from . import PartitionError
from .topology import Topology, format_cpulist

RULES = ("partitions", "any", "single")
_PCI_ID = re.compile(r"[0-9a-f]{4}:[0-9a-f]{4}")
_BUS = re.compile(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]")
_GIB_KIB = 1024 * 1024
_CARD_FIELDS = ("vendor_id", "device_id", "vendor_name", "device_name", "name")


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _gib(declared: dict, key: str) -> int:
    value = declared.get(key)
    if not _is_int(value) or value < 0:
        raise PartitionError(f"{key} must be a whole number of GiB, not {value!r}")
    return value


def validate_catalog(catalog: dict) -> dict[str, dict]:
    """Return the catalog's GPU types by tag."""
    if not isinstance(catalog, dict) or not isinstance(catalog.get("gpu_types"), list):
        raise PartitionError("catalog has no gpu_types list")
    types, owner = {}, {}
    for t in catalog["gpu_types"]:
        tag = t.get("tag") if isinstance(t, dict) else None
        if not isinstance(tag, str) or not tag or tag in types:
            raise PartitionError(f"catalog type tag {tag!r} is missing or repeated")
        where = f"catalog type {tag}"
        pci_ids = t.get("pci_ids")
        if not isinstance(pci_ids, list) or not pci_ids or not all(isinstance(i, str) and _PCI_ID.fullmatch(i) for i in pci_ids):
            raise PartitionError(f"{where}: pci_ids must list vendor:device ids")
        for i in pci_ids:
            if i in owner:
                raise PartitionError(f"{where}: pci id {i} also belongs to {owner[i]}")
            owner[i] = tag
        card = t.get("card")
        if not isinstance(card, dict) or not all(isinstance(card.get(f), str) and card[f] for f in _CARD_FIELDS):
            raise PartitionError(f"{where}: card needs {', '.join(_CARD_FIELDS)}")
        # pci_ids lists the GPU function first, then its companion functions.
        if pci_ids[0] != f"{card['vendor_id']}:{card['device_id']}":
            raise PartitionError(f"{where}: pci_ids must start with the card's vendor:device id")
        vcpu, ram = t.get("unit_vcpu"), t.get("unit_ram_gib")
        if not _is_int(vcpu) or vcpu <= 0 or vcpu % 2:
            raise PartitionError(f"{where}: unit_vcpu {vcpu!r} is not a positive even number")
        if not _is_int(ram) or ram <= 0:
            raise PartitionError(f"{where}: unit_ram_gib {ram!r} is not a positive number")
        classes = t.get("classes")
        if not isinstance(classes, dict) or not classes:
            raise PartitionError(f"{where}: no classes")
        for name, c in classes.items():
            rule = c.get("rule") if isinstance(c, dict) else None
            if rule not in RULES:
                raise PartitionError(f"{where}: class {name} has rule {rule!r}")
            counts = c.get("counts")
            if rule == "single":
                if counts is not None:
                    raise PartitionError(f"{where}: class {name} has rule single and takes no counts")
            elif (not isinstance(counts, list) or not counts
                  or not all(_is_int(n) and n >= 2 for n in counts) or counts != sorted(set(counts))):
                raise PartitionError(f"{where}: class {name} needs increasing counts of at least 2")
        types[tag] = t
    return types


def _positions(declared: dict) -> list[str]:
    positions = declared.get("gpu_positions") or []
    if not isinstance(positions, list) or not all(isinstance(b, str) and _BUS.fullmatch(b) for b in positions):
        raise PartitionError("gpu_positions must list PCI addresses like 0000:16:00.0")
    if len(set(positions)) != len(positions):
        raise PartitionError("gpu_positions repeats an address")
    return positions


def _groups(declared: dict, n_positions: int, cls: str, rule: str, class_counts: list[int]):
    """Return (groups, counts): counts holds every GPU count one VM may take."""
    raw = declared.get("gpu_groups")
    if rule != "partitions":
        if raw:
            raise PartitionError(f"gpu_groups is only for rule partitions; class {cls} has rule {rule}")
        return [], ([1] if rule == "single" else [1, *class_counts])
    if not raw or not isinstance(raw, list):
        raise PartitionError(f"class {cls} has rule partitions, which needs gpu_groups")
    groups = []
    for g in raw:
        if not isinstance(g, list) or not g or not all(_is_int(p) for p in g):
            raise PartitionError(f"group {g!r} is not a list of positions")
        for p in g:
            if not 0 <= p < n_positions:
                raise PartitionError(f"group {g} names undeclared position {p}")
        if len(set(g)) != len(g) or sorted(g) in groups:
            raise PartitionError(f"group {g} repeats a position or another group")
        if len(g) not in (1, *class_counts):
            raise PartitionError(f"group {g} has size {len(g)}, which class {cls} does not allow")
        groups.append(sorted(g))
    for i, a in enumerate(groups):
        for b in groups[i + 1:]:
            sa, sb = set(a), set(b)
            if sa & sb and not (sa <= sb or sb <= sa):
                raise PartitionError(f"groups {a} and {b} are not laminar")
    return groups, sorted({len(g) for g in groups})


def _fm_partitions(declared: dict, fabric_manager: bool, rule: str | None, groups: list[list[int]]) -> dict[str, int]:
    raw = declared.get("fm_partitions") or {}
    if not fabric_manager:
        if raw:
            raise PartitionError("fm_partitions is declared without fabric_manager")
        return {}
    if rule != "partitions":
        raise PartitionError("fabric_manager needs a class with rule partitions")
    if not isinstance(raw, dict):
        raise PartitionError("fm_partitions must map a group like \"0,1\" to a partition id")
    by_group = {}
    for key, pid in raw.items():
        try:
            group = sorted(int(p) for p in str(key).split(","))
        except ValueError:
            raise PartitionError(f"fm_partitions key {key!r} is not a group") from None
        if group not in groups:
            raise PartitionError(f"fm_partitions names {key}, which is not a group")
        if not _is_int(pid) or pid < 0 or pid in by_group.values():
            raise PartitionError(f"fm_partitions gives {key} the id {pid!r}, which is invalid or repeated")
        by_group[",".join(map(str, group))] = pid
    fm = {}
    for g in groups:
        key = ",".join(map(str, g))
        if key not in by_group:
            raise PartitionError(f"fm_partitions has no partition for group {g}")
        fm[key] = by_group[key]
    return fm


def _housekeeping_need(declared: dict, sockets: set[int]) -> dict[int, int]:
    raw = declared.get("housekeeping_cores")
    if not isinstance(raw, dict):
        raise PartitionError("housekeeping_cores must map a socket to a number of cores")
    need = {}
    for socket, n in raw.items():
        try:
            socket = int(socket)
        except ValueError:
            raise PartitionError(f"housekeeping_cores names socket {socket!r}") from None
        if socket not in sockets:
            raise PartitionError(f"housekeeping_cores names socket {socket}, which this host does not have")
        if not _is_int(n) or n < 0:
            raise PartitionError(f"housekeeping_cores gives socket {socket} {n!r} cores")
        need[socket] = n
    if not sum(need.values()):
        raise PartitionError("housekeeping_cores declares no core")
    return need


def _position_node(topo: Topology, p: int, bus: str) -> int:
    nodes = list(topo.node_threads)
    if bus in topo.pci_node:
        node = topo.pci_node[bus]
        if node == -1 and len(nodes) == 1:
            return nodes[0]
        if node not in topo.node_threads:
            raise PartitionError(f"position {p} ({bus}) has numa_node {node} on a host with nodes {nodes}")
        return node
    if len(nodes) == 1:
        return nodes[0]
    node = topo.bus_node.get(bus[:7])
    if node not in topo.node_threads:
        raise PartitionError(f"position {p} ({bus}) is absent and its NUMA node is unknown")
    return node


def render(topo: Topology, declared: dict, catalog: dict) -> dict:
    """Partition `topo` as `declared` asks.

    A core is a thread's sibling set. Cores are named and ordered by their
    lowest thread id: a unit takes the lowest free cores of its GPU's node in
    position order, then each socket's housekeeping takes its highest free
    cores, and every remaining core is in the pool. The host reserve is split
    evenly across nodes when checking that each node's memory fits.
    """
    types = validate_catalog(catalog)
    if not isinstance(declared, dict):
        raise PartitionError("declared inventory must be an object")

    cores = {}
    for t, thread in topo.threads.items():
        if len(thread.siblings) != 2:
            raise PartitionError(f"cpu{t} has {len(thread.siblings)} thread(s) in its core; a partition needs 2 threads per core")
        cores[thread.siblings[0]] = thread
    node_socket = {}
    for n, ts in topo.node_threads.items():
        sockets = {topo.threads[t].socket for t in ts}
        if not sockets:
            raise PartitionError(f"node {n} has no CPUs")
        if len(sockets) != 1:
            raise PartitionError(f"node {n} spans sockets {sorted(sockets)}")
        node_socket[n] = sockets.pop()

    positions = _positions(declared)
    gpu_type = declared.get("gpu_type")
    cls = declared.get("gpu_class")
    fabric_manager = declared.get("fabric_manager", False)
    if not isinstance(fabric_manager, bool):
        raise PartitionError("fabric_manager must be true or false")
    if positions:
        if not isinstance(gpu_type, str) or gpu_type not in types:
            raise PartitionError(f"gpu_type {gpu_type} is not in the catalog")
        gpu = types[gpu_type]
        if not isinstance(cls, str) or cls not in gpu["classes"]:
            raise PartitionError(f"class {cls} is not in the catalog for {gpu_type}")
        rule = gpu["classes"][cls]["rule"]
        groups, counts = _groups(declared, len(positions), cls, rule, gpu["classes"][cls].get("counts", []))
        unit_vcpu, unit_ram_gib = gpu["unit_vcpu"], gpu["unit_ram_gib"]
        overhead_gib = _gib(declared, "qemu_overhead_gib")
    else:
        for key in ("gpu_type", "gpu_class", "gpu_groups", "fm_partitions", "fabric_manager"):
            if declared.get(key):
                raise PartitionError(f"{key} is declared without gpu_positions")
        gpu = rule = unit_vcpu = unit_ram_gib = None
        groups, counts, overhead_gib = [], [], 0
    fm_partitions = _fm_partitions(declared, fabric_manager, rule, groups)
    reserve_gib = _gib(declared, "host_reserve_gib")
    housekeeping_need = _housekeeping_need(declared, set(node_socket.values()))

    free = {n: sorted(c for c, th in cores.items() if th.node == n) for n in topo.node_threads}
    socket_free = {}
    for n, cs in free.items():
        socket_free[node_socket[n]] = socket_free.get(node_socket[n], 0) + len(cs)

    units = []
    for p, bus in enumerate(positions):
        present = bus in topo.pci_node
        if present and topo.pci_device.get(bus) != gpu["pci_ids"][0]:
            raise PartitionError(f"position {p} ({bus}) holds {topo.pci_device.get(bus)}, not the {gpu_type} card {gpu['pci_ids'][0]}")
        node = _position_node(topo, p, bus)
        socket, need = node_socket[node], unit_vcpu // 2
        if len(free[node]) < need or socket_free[socket] - need < housekeeping_need.get(socket, 0):
            raise PartitionError(f"unit does not fit node {node}")
        taken, free[node] = free[node][:need], free[node][need:]
        socket_free[socket] -= need
        units.append({
            "position": p,
            "bus": bus,
            "present": present,
            "node": node,
            "threads": [list(cores[c].siblings) for c in taken],
            "hugepages_gib": unit_ram_gib,
        })

    housekeeping = []
    for socket, need in sorted(housekeeping_need.items()):
        candidates = sorted(c for n, cs in free.items() if node_socket[n] == socket for c in cs)
        if len(candidates) < need:
            raise PartitionError(f"housekeeping does not fit socket {socket}")
        for c in candidates[len(candidates) - need:]:
            free[cores[c].node].remove(c)
            housekeeping.extend(cores[c].siblings)

    unit_mem_gib = (unit_ram_gib or 0) + overhead_gib
    n_nodes = len(topo.node_threads)
    for n in topo.node_threads:
        on_node = sum(1 for u in units if u["node"] == n)
        if (n_nodes * on_node * unit_mem_gib + reserve_gib) * _GIB_KIB > n_nodes * topo.node_mem_kib[n]:
            raise PartitionError(f"node {n} memory does not fit units + reserve")
    if (len(units) * unit_mem_gib + reserve_gib) * _GIB_KIB > topo.mem_total_kib:
        raise PartitionError("host memory does not fit units + reserve")

    return {
        "gpu_type": gpu_type if positions else None,
        "gpu_class": cls if positions else None,
        "group_rule": rule,
        "counts": counts,
        "unit_vcpu": unit_vcpu,
        "unit_ram_gib": unit_ram_gib,
        "phys_bits": topo.phys_bits,
        "fabric_manager": fabric_manager,
        "housekeeping": sorted(housekeeping),
        "units": units,
        "groups": groups,
        "fm_partitions": fm_partitions,
        "pool": [t for n in sorted(free) for t in sorted(t for c in free[n] for t in cores[c].siblings)],
        "pool_cores": [{"node": n, "threads": list(cores[c].siblings)} for n in sorted(free) for c in free[n]],
    }


def hugepages_per_node(partition: dict) -> dict[int, int]:
    pages = {}
    for u in partition["units"]:
        pages[u["node"]] = pages.get(u["node"], 0) + u["hugepages_gib"]
    return dict(sorted(pages.items()))


def agent_values(partition: dict, declared: dict) -> dict[str, str]:
    units = partition["units"]
    overhead_gib = _gib(declared, "qemu_overhead_gib") if units else 0
    reserved_threads = len(partition["housekeeping"]) + sum(len(core) for u in units for core in u["threads"])
    reserved_gib = sum(u["hugepages_gib"] for u in units) + _gib(declared, "host_reserve_gib") + len(units) * overhead_gib
    tags = ["cpu"]
    if partition["gpu_type"]:
        tags += [partition["gpu_type"], f"{partition['gpu_type']}-{partition['gpu_class']}"]
    return {
        "host.reserved.cpu.count": str(reserved_threads),
        "host.reserved.mem.mb": str(reserved_gib * 1024),
        "host.tags": ",".join(tags),
    }


def kernel_args(partition: dict) -> str:
    args = []
    pages = hugepages_per_node(partition)
    if pages:
        args += ["default_hugepagesz=2M", "hugepagesz=1G",
                 "hugepages=" + ",".join(f"{n}:{k}" for n, k in pages.items())]
    args.append("irqaffinity=" + format_cpulist(partition["housekeeping"]))
    return " ".join(args)
