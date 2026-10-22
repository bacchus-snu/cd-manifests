"""A domain's place in the host partition: the rewrite applied before libvirt
defines it, and the validation that refuses any domain outside its place.

A domain with a PCI hostdev at a declared GPU position is a GPU VM: it runs
on the units of its GPUs and on 1 GiB hugepages of their nodes. Any other
domain is a pool VM: it runs on the whole pool cores named in its CloudStack
metadata. The validator enforces only those bounds, not sizes, which are the
management server's policy; the rewrite places a domain inside them, so a
rewritten domain is by construction one the validator accepts. The validator
reads XML as libvirt formats it, so it compares values, not spellings: CPU
sets, scaled sizes and PCI addresses.
"""
import io
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from . import PartitionError
from .topology import format_cpulist

NS = "http://cloudstack.apache.org/instance"
_C = f"{{{NS}}}"
_QEMU = "{http://libvirt.org/schemas/domain/qemu/1.0}"
_GIB_KIB = 1 << 20
_SCALE = {"k": 1, "m": 2, "g": 3, "t": 4, "p": 5, "e": 6}
_EXPANDER = {"q35": "pcie-expander-bus", "pc": "pci-expander-bus"}
_POOL_HUGEPAGES = "a pool VM may not use hugepages"


def _parse(xml: str) -> ET.Element:
    # libvirt domain XML never carries a document type; refusing one keeps
    # entity expansion out of the parser.
    if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        raise PartitionError("domain XML carries a document type")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        raise PartitionError(f"domain XML is malformed: {e}") from None
    if root.tag != "domain":
        raise PartitionError(f"<{root.tag}> is not a domain")
    return root


def _register_namespaces(xml: str) -> None:
    """Keep the document's prefixes on output. A default namespace is not
    registered: ElementTree would declare it on the root, moving the
    un-namespaced domain elements into it."""
    for _, (prefix, uri) in ET.iterparse(io.StringIO(xml), events=("start-ns",)):
        if not prefix:
            continue
        try:
            ET.register_namespace(prefix, uri)
        except ValueError:
            pass


def _outside_partition(root: ET.Element) -> list[str]:
    """Configuration that reaches host CPUs, memory or devices past the checks
    below, so no domain may carry it."""
    out = []
    for el in root:
        if el.tag.startswith(_QEMU):
            out.append(f"qemu:{el.tag[len(_QEMU):]} is not allowed: it configures QEMU past libvirt's checks")
    for devices in root.findall("devices"):
        for memory in devices.findall("memory"):
            out.append(f"memory device {memory.get('model') or '(no model)'} is not allowed: guest RAM comes only from <memory>")
        for hostdev in devices.findall("hostdev"):
            if hostdev.get("type") != "pci":
                out.append(f"hostdev of type {hostdev.get('type')} is not a declared GPU position")
    return out


def _c_int(text, what: str) -> int:
    """An unsigned integer as strtoul(text, base 0) reads it, as libvirt does."""
    s = (text or "").strip()
    try:
        if s[:2].lower() == "0x":
            return int(s[2:], 16)
        if len(s) > 1 and s[0] == "0":
            return int(s[1:], 8)
        return int(s, 10)
    except ValueError:
        raise PartitionError(f"{what} {text!r} is not a number") from None


def _cpuset(text) -> set[int]:
    """libvirt's CPU and node set syntax: ranges, commas and ^exclusions."""
    include, exclude = set(), set()
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        target = include
        if part.startswith("^"):
            target, part = exclude, part[1:]
        lo, sep, hi = part.partition("-")
        try:
            a, b = int(lo), int(hi) if sep else int(lo)
        except ValueError:
            raise PartitionError(f"{text!r} is not a CPU set") from None
        if a < 0 or b < a:
            raise PartitionError(f"{text!r} is not a CPU set")
        target.update(range(a, b + 1))
    return include - exclude


def _kib(value, unit, what: str) -> int:
    """A libvirt scaled integer in KiB; libvirt's default unit is KiB."""
    n = _c_int(value, what)
    unit = unit or "KiB"
    u = unit.lower()
    if u in ("b", "bytes"):
        factor = 1
    elif u[0] in _SCALE and (len(u) == 1 or u[1:] in ("ib", "b")):
        factor = (1000 if u[1:] == "b" else 1024) ** _SCALE[u[0]]
    else:
        raise PartitionError(f"{what} has unknown unit {unit!r}")
    if n * factor % 1024:
        raise PartitionError(f"{what} {n} {unit} is not a whole number of KiB")
    return n * factor // 1024


def _element_kib(el: ET.Element) -> int:
    return _kib(el.text, el.get("unit"), f"<{el.tag}>")


def _size(kib: int) -> str:
    return f"{kib // _GIB_KIB} GiB" if kib % _GIB_KIB == 0 else f"{kib} KiB"


def _pci_address(address: ET.Element) -> str:
    """The canonical dddd:bb:ss.f form of a libvirt PCI <address>; the domain defaults to 0."""
    d, b, s, f = (_c_int(address.get(k, "0"), f"PCI address {k}") for k in ("domain", "bus", "slot", "function"))
    return f"{d:04x}:{b:02x}:{s:02x}.{f:x}"


def _hostdev_buses(root: ET.Element) -> list[str]:
    hostdevs = [h for h in root.findall("devices/hostdev") if h.get("type") == "pci"]
    hostdevs += root.findall("devices/interface[@type='hostdev']")
    buses = []
    for h in hostdevs:
        address = h.find("source/address")
        if address is None:
            raise PartitionError("a PCI hostdev has no source address")
        buses.append(_pci_address(address))
    return buses


def _vcpus(root: ET.Element) -> int:
    vcpu = root.find("vcpu")
    return 1 if vcpu is None else _c_int(vcpu.text, "<vcpu>")


def _iothread_ids(root: ET.Element) -> list[int]:
    ids = [_c_int(t.get("id"), "iothread id") for t in root.findall("iothreadids/iothread")]
    if ids:
        return sorted(ids)
    n = root.findtext("iothreads")
    return list(range(1, _c_int(n, "<iothreads>") + 1)) if n is not None else []


def _instance(root: ET.Element):
    return root.find(f"metadata/{_C}instance")


def _assigned_cores(root: ET.Element) -> list | None:
    """The metadata's cores, each a tuple of thread ids (or its raw text when
    that is not a list of numbers); None without a cores element."""
    inst = _instance(root)
    cores = inst.find(f"{_C}cores") if inst is not None else None
    if cores is None:
        return None
    out = []
    for core in cores.findall(f"{_C}core"):
        text = (core.text or "").strip()
        try:
            out.append(tuple(int(t) for t in text.split(",")))
        except ValueError:
            out.append(text)
    return out


def _core_name(core) -> str:
    return ",".join(map(str, core)) if isinstance(core, tuple) else str(core)


@dataclass(frozen=True)
class _GpuPlan:
    """The group's units node by node; guest cell i lives on nodes[i]."""
    nodes: list[int]
    threads_by_node: list[list[int]]
    gib_by_node: list[int]
    buses_by_cell: list[list[str]]

    @property
    def threads(self) -> set[int]:
        return {t for ts in self.threads_by_node for t in ts}


def _units_by_bus(p: dict) -> dict[str, dict]:
    return {u["bus"]: u for u in p["units"]}


def _positions(buses: list[str], p: dict) -> tuple[int, ...]:
    by_bus = _units_by_bus(p)
    return tuple(sorted({by_bus[b]["position"] for b in buses if b in by_bus}))


def _unit_threads(positions: tuple[int, ...], p: dict) -> list[int]:
    by_position = {u["position"]: u for u in p["units"]}
    return sorted(t for q in positions for core in by_position[q]["threads"] for t in core)


def _gpu_plan(positions: tuple[int, ...], p: dict) -> _GpuPlan:
    by_position = {u["position"]: u for u in p["units"]}
    units = sorted((by_position[q] for q in positions), key=lambda u: (u["node"], u["position"]))
    nodes = sorted({u["node"] for u in units})
    per_node = [[u for u in units if u["node"] == n] for n in nodes]
    # The guest topology has one socket per node with equal cores per socket.
    if len({len(us) for us in per_node}) != 1:
        raise PartitionError(f"GPU positions {list(positions)} are not spread evenly over NUMA nodes {nodes}")
    return _GpuPlan(nodes,
                    [[t for u in us for core in u["threads"] for t in core] for us in per_node],
                    [sum(u["hugepages_gib"] for u in us) for us in per_node],
                    [[u["bus"] for u in us] for us in per_node])


def _gpu_layout(plan: _GpuPlan, vcpus: int, memory_kib: int | None) -> tuple[list[int], list[tuple[range, int]]]:
    """Spread the vCPUs and RAM evenly over the group's nodes: vCPU i runs on
    the i-th returned thread, each node's share on the first threads of its
    units in sibling order, and guest cell i holds node i's share of RAM in
    whole 1 GiB pages."""
    n = len(plan.nodes)
    per_node, rest = divmod(vcpus, n)
    if vcpus < 1 or rest or per_node > len(plan.threads_by_node[0]):
        raise PartitionError(f"{vcpus} vCPUs do not spread over the unit threads of nodes {plan.nodes}")
    if not memory_kib or memory_kib % (n * _GIB_KIB):
        raise PartitionError(f"memory {_size(memory_kib or 0)} does not split into whole GiB over nodes {plan.nodes}")
    gib = memory_kib // n // _GIB_KIB
    for node, budget in zip(plan.nodes, plan.gib_by_node):
        if gib > budget:
            raise PartitionError(f"{gib} GiB on node {node} exceeds the {budget} GiB of hugepages of its GPUs there")
    threads = [t for ts in plan.threads_by_node for t in ts[:per_node]]
    return threads, [(range(i * per_node, (i + 1) * per_node), gib) for i in range(n)]


def _pool_pins(cores: list[tuple[int, ...]], vcpus: int) -> list[int]:
    """vCPU 2k and 2k+1 run on the first and second thread of the k-th core."""
    return [cores[i // 2][i % 2] for i in range(vcpus)]


def _child(parent: ET.Element, tag: str) -> ET.Element:
    el = parent.find(tag)
    return el if el is not None else ET.SubElement(parent, tag)


def _replace(parent: ET.Element, tag: str) -> ET.Element:
    for el in parent.findall(tag):
        parent.remove(el)
    return ET.SubElement(parent, tag)


def _main_devices(root: ET.Element) -> ET.Element:
    all_devices = root.findall("devices")
    for devices in all_devices:
        if devices.find("emulator") is not None:
            return devices
    return all_devices[-1] if all_devices else ET.SubElement(root, "devices")


def _cpu(root: ET.Element) -> ET.Element:
    cpus = root.findall("cpu")
    if len(cpus) > 1:
        raise PartitionError("the domain has more than one <cpu> element")
    return cpus[0] if cpus else ET.SubElement(root, "cpu")


def _set_topology(root: ET.Element, sockets: int, cores: int, threads: int) -> None:
    topology = _child(_cpu(root), "topology")
    topology.attrib.clear()
    topology.set("sockets", str(sockets))
    topology.set("cores", str(cores))
    topology.set("threads", str(threads))


def _set_pins(root: ET.Element, vcpu_threads: list[int], emulator: set[int]) -> None:
    cputune = _child(root, "cputune")
    for tag in ("vcpupin", "emulatorpin", "iothreadpin"):
        for el in cputune.findall(tag):
            cputune.remove(el)
    for i, t in enumerate(vcpu_threads):
        ET.SubElement(cputune, "vcpupin", vcpu=str(i), cpuset=str(t))
    ET.SubElement(cputune, "emulatorpin", cpuset=format_cpulist(emulator))
    for i in _iothread_ids(root):
        ET.SubElement(cputune, "iothreadpin", iothread=str(i), cpuset=format_cpulist(emulator))


def _set_memballoon_none(root: ET.Element) -> None:
    balloons = [(d, b) for d in root.findall("devices") for b in d.findall("memballoon")]
    if not balloons:
        ET.SubElement(_main_devices(root), "memballoon", model="none")
        return
    for devices, balloon in balloons[1:]:
        devices.remove(balloon)
    balloon = balloons[0][1]
    balloon.attrib.clear()
    balloon.text = None
    for child in list(balloon):
        balloon.remove(child)
    balloon.set("model", "none")


def _machine_family(root: ET.Element) -> str:
    os_type = root.find("os/type")
    machine = os_type.get("machine", "") if os_type is not None else ""
    if "q35" in machine:
        return "q35"
    if machine == "pc" or "i440fx" in machine:
        return "pc"
    raise PartitionError(f"machine type {machine!r} has no expander bus for a multi-node GPU group")


def _guest_address(parent: ET.Element, bus: int, slot: int) -> None:
    for el in parent.findall("address"):
        parent.remove(el)
    ET.SubElement(parent, "address", type="pci", domain="0x0000", bus=f"0x{bus:02x}", slot=f"0x{slot:02x}",
                  function="0x0")


def _add_expander_buses(root: ET.Element, plan: _GpuPlan) -> None:
    """Put each guest cell's GPUs behind an expander bus bound to that cell.

    A PCI controller must sit on a bus of lower index, so each cell's bus is
    numbered before the root ports plugged into it."""
    family = _machine_family(root)
    devices = _main_devices(root)
    hostdevs = {}
    for d in root.findall("devices"):
        for h in d.findall("hostdev"):
            address = h.find("source/address")
            if h.get("type") == "pci" and address is not None:
                hostdevs[_pci_address(address)] = h
    indexes = [_c_int(c.get("index"), "controller index") for c in root.iter("controller")
               if c.get("type") == "pci" and c.get("index") is not None]
    index = max(indexes, default=0) + 1
    for cell, buses in enumerate(plan.buses_by_cell):
        expander = index
        index += 1
        controller = ET.SubElement(devices, "controller", type="pci", index=str(expander), model=_EXPANDER[family])
        ET.SubElement(ET.SubElement(controller, "target"), "node").text = str(cell)
        for slot, bus in enumerate(buses):
            if family == "q35":
                port = ET.SubElement(devices, "controller", type="pci", index=str(index), model="pcie-root-port")
                _guest_address(port, expander, slot)
                _guest_address(hostdevs[bus], index, 0)
                index += 1
            else:
                _guest_address(hostdevs[bus], expander, slot)


def _memory_kib(root: ET.Element) -> int | None:
    el = root.find("memory")
    return _element_kib(el) if el is not None else None


def rewrite_for_start(xml: str, p: dict) -> str:
    """Place the domain in the partition. Raises PartitionError when the domain
    cannot be placed; the caller then starts it unchanged and the validator
    refuses it with the reason."""
    root = _parse(xml)
    refused = _outside_partition(root)
    if refused:
        raise PartitionError(refused[0])
    _register_namespaces(xml)
    vcpus = _vcpus(root)
    buses = _hostdev_buses(root)
    by_bus = _units_by_bus(p)
    unknown = [b for b in buses if b not in by_bus]
    if unknown:
        raise PartitionError(f"hostdev {unknown[0]} is not a declared GPU position")
    positions = _positions(buses, p)
    if positions:
        plan = _gpu_plan(positions, p)
        threads, cells = _gpu_layout(plan, vcpus, _memory_kib(root))
        per_cell = len(cells[0][0])
        if per_cell % 2:
            _set_topology(root, len(plan.nodes), per_cell, 1)
        else:
            _set_topology(root, len(plan.nodes), per_cell // 2, 2)
        _set_pins(root, threads, set(p["housekeeping"]))
        numa = _replace(_cpu(root), "numa")
        for i, (cell_vcpus, gib) in enumerate(cells):
            ET.SubElement(numa, "cell", id=str(i), cpus=format_cpulist(cell_vcpus), memory=str(gib), unit="GiB")
        hugepages = _replace(_child(root, "memoryBacking"), "hugepages")
        ET.SubElement(hugepages, "page", size="1", unit="G", nodeset=format_cpulist(range(len(plan.nodes))))
        numatune = _replace(root, "numatune")
        ET.SubElement(numatune, "memory", mode="preferred", nodeset=format_cpulist(plan.nodes))
        for i, node in enumerate(plan.nodes):
            ET.SubElement(numatune, "memnode", cellid=str(i), mode="strict", nodeset=str(node))
        _set_memballoon_none(root)
        if len(plan.nodes) > 1:
            _add_expander_buses(root, plan)
    else:
        cores = _assigned_cores(root)
        if not cores:
            raise PartitionError("no core assignment in the domain metadata")
        if len(cores) != (vcpus + 1) // 2 or not all(isinstance(c, tuple) and len(c) == 2 for c in cores):
            raise PartitionError(f"{vcpus} vCPUs cannot run on cores {[_core_name(c) for c in cores]}")
        if root.find("memoryBacking/hugepages") is not None:
            raise PartitionError(_POOL_HUGEPAGES)
        if vcpus % 2:
            _set_topology(root, 1, vcpus, 1)
        else:
            _set_topology(root, 1, vcpus // 2, 2)
        _set_pins(root, _pool_pins(cores, vcpus), {t for c in cores for t in c})
    return ET.tostring(root, encoding="unicode")


def _vcpupins(root: ET.Element, vcpus: int, out: list[str]) -> dict[int, set[int]]:
    pins = {}
    for el in root.findall("cputune/vcpupin"):
        i = _c_int(el.get("vcpu"), "vcpupin vcpu")
        if i in pins:
            out.append(f"vCPU {i} has more than one vcpupin")
        pins[i] = _cpuset(el.get("cpuset"))
    for i in sorted(set(pins) - set(range(vcpus))):
        out.append(f"vcpupin for vCPU {i}, which the domain does not have")
    return pins


def _check_pins(root: ET.Element, expected: list[int], out: list[str]) -> None:
    pins = _vcpupins(root, len(expected), out)
    for i, t in enumerate(expected):
        if i not in pins:
            out.append(f"vCPU {i} has no vcpupin; it must be pinned to {t}")
        elif pins[i] != {t}:
            out.append(f"vcpupin of vCPU {i} is {format_cpulist(pins[i])}, not {t}")


def _check_gpu_pins(root: ET.Element, vcpus: int, allowed: set[int], out: list[str]) -> None:
    """Each vCPU runs alone on one thread of the group's units."""
    pins = _vcpupins(root, vcpus, out)
    owner = {}
    for i in range(vcpus):
        if i not in pins:
            out.append(f"vCPU {i} has no vcpupin; it must be pinned to one thread of its GPUs' units")
        elif len(pins[i]) != 1 or not pins[i] <= allowed:
            out.append(f"vcpupin of vCPU {i} is {format_cpulist(pins[i])}, which is not a thread of its GPUs' units")
        else:
            t = next(iter(pins[i]))
            if t in owner:
                out.append(f"vCPU {i} shares thread {t} with vCPU {owner[t]}")
            owner.setdefault(t, i)


def _check_emulator(root: ET.Element, allowed: set[int], where: str, out: list[str]) -> None:
    el = root.find("cputune/emulatorpin")
    if el is None:
        out.append("emulatorpin is missing")
    else:
        cs = _cpuset(el.get("cpuset"))
        if not cs or not cs <= allowed:
            out.append(f"emulatorpin {el.get('cpuset')} is outside {where}")
    pins = {_c_int(el.get("iothread"), "iothreadpin iothread"): el.get("cpuset")
            for el in root.findall("cputune/iothreadpin")}
    for i in _iothread_ids(root):
        if i not in pins:
            out.append(f"iothread {i} has no iothreadpin")
        elif not _cpuset(pins[i]) or not _cpuset(pins[i]) <= allowed:
            out.append(f"iothreadpin of iothread {i} ({pins[i]}) is outside {where}")


def _validate_pool(root: ET.Element, p: dict, vcpus: int, out: list[str]) -> list:
    cores = _assigned_cores(root)
    if not cores:
        out.append("no core assignment in the domain metadata")
        return []
    pool = {tuple(c["threads"]) for c in p["pool_cores"]}
    for core in cores:
        if core not in pool:
            out.append(f"core {_core_name(core)} is not a pool core of this host")
    if len(set(cores)) != len(cores):
        out.append("a core is assigned more than once")
    need = (vcpus + 1) // 2
    if len(cores) != need:
        out.append(f"{vcpus} vCPU{'s' * (vcpus != 1)} need {need} core{'s' * (need != 1)}, "
                   f"but {len(cores)} are assigned")
    good = [c for c in cores if isinstance(c, tuple)]
    if len(good) == len(cores) == need and all(len(c) == 2 for c in good):
        _check_pins(root, _pool_pins(good, vcpus), out)
    threads = {t for c in good for t in c}
    _check_emulator(root, threads, f"the assigned cores {format_cpulist(threads)}", out)
    if root.find("memoryBacking/hugepages") is not None:
        out.append(_POOL_HUGEPAGES)
    return good


def _page_cells(root: ET.Element, cell_ids) -> set[int]:
    """Guest cells whose memory libvirt backs with 1 GiB pages: a page with a
    nodeset serves those cells, a page without one serves the rest."""
    hugepages = root.find("memoryBacking/hugepages")
    if hugepages is None:
        return set()
    pages = [(_kib(pg.get("size"), pg.get("unit"), "hugepage size"),
              _cpuset(pg.get("nodeset")) if pg.get("nodeset") else None)
             for pg in hugepages.findall("page")]
    backed = set()
    for cell in cell_ids:
        sizes = {size for size, cells in pages if cells is not None and cell in cells}
        if not sizes:
            sizes = {size for size, cells in pages if cells is None}
        if sizes == {_GIB_KIB}:
            backed.add(cell)
    return backed


def _validate_gpu(root: ET.Element, p: dict, vcpus: int, positions: tuple[int, ...], sysfs: Path,
                  out: list[str]) -> None:
    by_position = {u["position"]: u for u in p["units"]}
    for q in positions:
        bus = by_position[q]["bus"]
        if not (sysfs / "bus" / "pci" / "devices" / bus).exists():
            out.append(f"GPU position {q} ({bus}) is absent")
    n = len(positions)
    rule = p["group_rule"]
    if rule == "partitions":
        if list(positions) not in p["groups"]:
            out.append(f"GPU positions {list(positions)} are not a group of this host")
    elif rule in ("any", "single"):
        if n not in p["counts"]:
            out.append(f"a GPU set of size {n} is not allowed here; sizes: {', '.join(map(str, p['counts']))}")
    else:
        out.append(f"this host has no GPU group rule ({rule})")
    try:
        plan = _gpu_plan(positions, p)
    except PartitionError as e:
        out.append(str(e))
        return
    _check_gpu_pins(root, vcpus, plan.threads, out)
    housekeeping = set(p["housekeeping"])
    _check_emulator(root, housekeeping, f"the housekeeping cores {format_cpulist(housekeeping)}", out)

    # Guest RAM may use only the 1 GiB pages of its own units: every cell is
    # strict on one of the group's nodes and backed by 1 GiB pages, and no node
    # gives more than its units reserve there.
    budget = sum(plan.gib_by_node)
    for tag in ("memory", "currentMemory", "maxMemory"):
        el = root.find(tag)
        if el is not None and _element_kib(el) > budget * _GIB_KIB:
            out.append(f"{tag} {_size(_element_kib(el))} exceeds the {budget} GiB of hugepages of its GPUs")
    cells = {_c_int(c.get("id"), "cell id"): _kib(c.get("memory"), c.get("unit"), "cell memory")
             for c in root.findall("cpu/numa/cell")}
    if not cells:
        out.append("the domain has no guest NUMA cells; its RAM must sit in cells strict on its GPUs' nodes")
    memnodes = {_c_int(m.get("cellid"), "memnode cellid"): m for m in root.findall("numatune/memnode")}
    used = dict.fromkeys(plan.nodes, 0)
    for i, kib in sorted(cells.items()):
        # The page backend rounds each cell up to whole pages.
        if kib % _GIB_KIB:
            out.append(f"guest cell {i} holds {_size(kib)}, not a whole number of 1 GiB pages")
            kib = -(-kib // _GIB_KIB) * _GIB_KIB
        m = memnodes.get(i)
        nodes = _cpuset(m.get("nodeset")) if m is not None else set()
        if m is None or m.get("mode") != "strict" or len(nodes) != 1 or not nodes <= set(plan.nodes):
            out.append(f"guest cell {i} is not strict on one node of its GPUs ({format_cpulist(plan.nodes)})")
        else:
            used[nodes.pop()] += kib
    for node, gib in zip(plan.nodes, plan.gib_by_node):
        if used[node] > gib * _GIB_KIB:
            out.append(f"guest cells on node {node} take {_size(used[node])}, "
                       f"more than the {gib} GiB of hugepages of its GPUs there")
    backed = _page_cells(root, cells)
    for i in sorted(cells):
        if i not in backed:
            out.append(f"guest cell {i} is not backed by 1 GiB hugepages")


def _check_ledger(ledger, threads: set[int], positions: tuple[int, ...], cores: list, out: list[str]) -> None:
    for entry in ledger:
        name = entry.get("name") or entry.get("uuid")
        held_threads = set(entry.get("threads") or [])
        held_positions = set(entry.get("positions") or [])
        reported = False
        for q in positions:
            if q in held_positions:
                out.append(f"GPU position {q} is held by running domain {name}")
                reported = True
        for core in cores:
            if set(core) & held_threads:
                out.append(f"core {_core_name(core)} is held by running domain {name}")
                reported = True
        if not reported and threads & held_threads:
            out.append(f"threads {format_cpulist(threads & held_threads)} are held by running domain {name}")


def validate(xml: str, p: dict, *, ledger=(), sysfs: Path = Path("/sys")) -> list[str]:
    """Violations of the partition by this domain; empty means accept.

    `ledger` holds the entries of the other running domains (their `threads`
    and `positions`). A GPU is present when sysfs lists its PCI device.
    """
    out: list[str] = []
    try:
        root = _parse(xml)
        vcpus = _vcpus(root)
        vcpu = root.find("vcpu")
        if vcpu is not None and vcpu.get("placement", "static") != "static":
            out.append(f"vcpu placement {vcpu.get('placement')} is not static")
        out.extend(_outside_partition(root))
        buses = _hostdev_buses(root)
        by_bus = _units_by_bus(p)
        for b in sorted(set(buses)):
            if b not in by_bus:
                out.append(f"hostdev {b} is not a declared GPU position")
            if buses.count(b) > 1:
                out.append(f"hostdev {b} is attached more than once")
        positions = _positions(buses, p)
        if positions:
            _validate_gpu(root, p, vcpus, positions, Path(sysfs), out)
            _check_ledger(ledger, set(_unit_threads(positions, p)), positions, [], out)
        else:
            cores = _validate_pool(root, p, vcpus, out)
            _check_ledger(ledger, {t for c in cores for t in c}, (), cores, out)
    except PartitionError as e:
        out.append(str(e))
    return out


def identity(xml: str) -> tuple[str, str]:
    """The domain's name and UUID."""
    root = _parse(xml)
    name, uuid = (root.findtext(tag, "").strip() for tag in ("name", "uuid"))
    if not name or not uuid:
        raise PartitionError("the domain has no name or UUID")
    return name, uuid


def gpu_group(xml: str, p: dict) -> tuple[int, ...] | None:
    """The declared GPU positions the domain attaches; None for a non-GPU domain."""
    return _positions(_hostdev_buses(_parse(xml)), p) or None


def claim(xml: str, p: dict) -> dict:
    """The host threads and GPU positions a running domain holds exclusively."""
    root = _parse(xml)
    positions = _positions(_hostdev_buses(root), p)
    if positions:
        return {"threads": _unit_threads(positions, p), "positions": list(positions)}
    cores = [c for c in _assigned_cores(root) or [] if isinstance(c, tuple)]
    return {"threads": sorted({t for c in cores for t in c}), "positions": []}
