import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import domain_fixtures as fx
from partition import PartitionError, domain

# Unit threads of the A6000 position on jimbeam, in sibling order.
A6000_THREADS = [0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21]
FERRARI_BUSES = ["0000:07:00.0", "0000:0f:00.0", "0000:47:00.0", "0000:4e:00.0",
                 "0000:87:00.0", "0000:90:00.0", "0000:b7:00.0", "0000:bd:00.0"]
FORD_BUSES = ["0000:01:00.0", "0000:41:00.0", "0000:81:00.0", "0000:c1:00.0"]
_KIB = {None: 1, "KiB": 1, "k": 1, "K": 1, "MiB": 1024, "M": 1024, "GiB": 1 << 20, "G": 1 << 20}


def kib(value, unit):
    return int(value) * _KIB[unit]


def violations(xml, p, **kw):
    return "\n".join(domain.validate(xml, p, **kw))


def topology(root):
    t = root.find("cpu/topology")
    return tuple(int(t.get(k)) for k in ("sockets", "cores", "threads"))


def cells(root):
    return [(int(c.get("id")), fx.cpulist(c.get("cpus")), kib(c.get("memory"), c.get("unit")))
            for c in root.findall("cpu/numa/cell")]


def memnodes(root):
    return sorted((int(m.get("cellid")), m.get("mode"), frozenset(fx.cpulist(m.get("nodeset"))))
                  for m in root.findall("numatune/memnode"))


def pages(root):
    return [(kib(pg.get("size"), pg.get("unit")), frozenset(fx.cpulist(pg.get("nodeset"))) if pg.get("nodeset") else None)
            for pg in root.findall("memoryBacking/hugepages/page")]


def gpu_guest_nodes(root):
    """For each GPU hostdev, the guest NUMA node of the expander bus it sits behind."""
    controllers = {int(c.get("index")): c for c in root.findall("devices/controller[@type='pci']")}
    out = []
    for h in root.findall("devices/hostdev[@type='pci']"):
        a = h.find("source/address")
        bus = f"{int(a.get('domain', '0'), 16):04x}:{int(a.get('bus'), 16):02x}:{int(a.get('slot'), 16):02x}.{int(a.get('function'), 16):x}"
        node, addr = None, h.find("address")
        while addr is not None and int(addr.get("bus"), 16) in controllers:
            c = controllers[int(addr.get("bus"), 16)]
            if c.get("model") in ("pcie-expander-bus", "pci-expander-bus"):
                node = int(c.findtext("target/node"))
                break
            addr = c.find("address")
        out.append((bus, node))
    return sorted(out)


def shape(xml):
    """What the rewrite decides, in a form independent of libvirt's formatting."""
    root = fx.parse(xml)
    numatune = root.find("numatune/memory")
    emulator = root.find("cputune/emulatorpin")
    return {
        "mode": root.find("cpu").get("mode"),
        "topology": topology(root),
        "cells": cells(root),
        "pins": fx.pins(root),
        "emulatorpin": fx.cpulist(emulator.get("cpuset")) if emulator is not None else None,
        "memory": (numatune.get("mode"), fx.cpulist(numatune.get("nodeset"))) if numatune is not None else None,
        "memnodes": memnodes(root),
        "pages": pages(root),
        "memballoon": [m.get("model") for m in root.findall("devices/memballoon")],
        "gpus": gpu_guest_nodes(root),
    }


class PoolVmTest(unittest.TestCase):
    def setUp(self):
        self.p = fx.partition("jimbeam")

    def test_pool_vm_pinned_to_assigned_cores(self):
        out = domain.rewrite_for_start(fx.fixture("pool"), self.p)
        root = fx.parse(out)
        self.assertEqual(fx.pins(root), {0: {8}, 1: {24}, 2: {9}, 3: {25}})
        self.assertEqual(root.find("cputune/emulatorpin").get("cpuset"), "8-9,24-25")
        self.assertEqual(topology(root), (1, 2, 2))
        self.assertEqual(root.find("cpu").get("mode"), "host-passthrough")
        self.assertEqual(len(root.findall("cpu")), 1)
        self.assertIsNone(root.find("cpu/numa"))
        self.assertIsNone(root.find("memoryBacking"))
        self.assertEqual(root.find("cputune/shares").text, "1250")
        self.assertEqual(domain.validate(out, self.p), [])

    def test_systemvm_pinned_to_one_core(self):
        out = domain.rewrite_for_start(fx.fixture("systemvm"), self.p)
        root = fx.parse(out)
        self.assertEqual(fx.pins(root), {0: {10}})
        self.assertEqual(fx.cpulist(root.find("cputune/emulatorpin").get("cpuset")), {10, 26})
        self.assertEqual(topology(root), (1, 1, 1))
        self.assertEqual(domain.validate(out, self.p), [])

    def test_validator_rejects_pool_vm_without_assignment(self):
        xml = fx.set_cores(fx.fixture("pool"), None)
        with self.assertRaises(PartitionError):
            domain.rewrite_for_start(xml, self.p)
        self.assertIn("no core assignment", violations(xml, self.p))
        self.assertIn("no core assignment", violations(fx.set_cores(fx.fixture("pool"), []), self.p))

    def test_validator_rejects_pins_not_equal_to_assignment(self):
        root = fx.parse(domain.rewrite_for_start(fx.fixture("pool"), self.p))
        root.find("cputune/vcpupin[@vcpu='1']").set("cpuset", "9")
        self.assertRegex(violations(ET.tostring(root, encoding="unicode"), self.p), r"vcpupin of vCPU 1 is 9, not 24")

        root = fx.parse(domain.rewrite_for_start(fx.fixture("pool"), self.p))
        root.find("cputune/emulatorpin").set("cpuset", "8-10,24-25")
        self.assertRegex(violations(ET.tostring(root, encoding="unicode"), self.p), r"emulatorpin 8-10,24-25 is outside")

        root = fx.parse(domain.rewrite_for_start(fx.fixture("pool"), self.p))
        ET.SubElement(root.find("cputune"), "vcpupin", vcpu="4", cpuset="10")
        self.assertRegex(violations(ET.tostring(root, encoding="unicode"), self.p), r"vcpupin for vCPU 4")

    def test_validator_rejects_overlapping_assignment(self):
        first = domain.rewrite_for_start(fx.fixture("pool"), self.p)
        second = fx.rename(fx.set_cores(fx.fixture("pool"), [[9, 25], [10, 26]]),
                           "i-2-42-VM", "7c3e2a10-5d4b-4f6e-9a81-0b2c3d4e5f62")
        second = domain.rewrite_for_start(second, self.p)
        held = {"name": "i-2-41-VM", **domain.claim(first, self.p)}
        self.assertEqual(held["threads"], [8, 9, 24, 25])
        self.assertEqual(domain.validate(second, self.p), [])
        self.assertRegex(violations(second, self.p, ledger=[held]), r"core 9,25 is held by running domain i-2-41-VM")

    def test_odd_vcpu_pool_vm_accepted_with_whole_cores(self):
        xml = domain.rewrite_for_start(fx.set_vcpus(fx.fixture("pool"), 3), self.p)
        root = fx.parse(xml)
        self.assertEqual(fx.pins(root), {0: {8}, 1: {24}, 2: {9}})
        self.assertEqual(fx.cpulist(root.find("cputune/emulatorpin").get("cpuset")), {8, 9, 24, 25})
        self.assertEqual(topology(root), (1, 3, 1))
        self.assertEqual(domain.validate(xml, self.p), [])
        # The idle sibling stays held, so no other domain gets half a core.
        self.assertEqual(domain.claim(xml, self.p)["threads"], [8, 9, 24, 25])

        one = domain.rewrite_for_start(fx.set_cores(fx.set_vcpus(fx.fixture("pool"), 1), [[8, 24]]), self.p)
        self.assertEqual(topology(fx.parse(one)), (1, 1, 1))
        self.assertEqual(domain.validate(one, self.p), [])
        system = domain.rewrite_for_start(fx.fixture("systemvm"), self.p)
        self.assertEqual(domain.validate(system, self.p), [])
        system3 = fx.set_cores(fx.set_vcpus(fx.fixture("systemvm"), 3), [[10, 26], [11, 27]])
        self.assertEqual(domain.validate(domain.rewrite_for_start(system3, self.p), self.p), [])

    def test_metadata_carries_no_vm_type(self):
        for name in ("pool", "systemvm", "a6000", "a100x1", "a100x2", "a100x8", "unknown-hostdev"):
            self.assertNotIn("cloudstack:type", fx.fixture(name), name)

    def test_validator_rejects_wrong_number_of_cores(self):
        xml = fx.set_cores(fx.fixture("pool"), [[8, 24], [9, 25], [10, 26]])
        with self.assertRaises(PartitionError):
            domain.rewrite_for_start(xml, self.p)
        self.assertIn("4 vCPUs need 2 cores, but 3 are assigned", violations(xml, self.p))

    def test_validator_rejects_unpinned_domain(self):
        self.assertRegex(violations(fx.fixture("pool"), self.p), r"vCPU 0 has no vcpupin; it must be pinned to 8")
        self.assertIn("emulatorpin is missing", violations(fx.fixture("pool"), self.p))
        self.assertRegex(violations(fx.fixture("a6000"), self.p, sysfs=fx.sysfs("jimbeam")),
                         r"vCPU 0 has no vcpupin; it must be pinned to one thread of its GPUs' units")

    def test_validator_rejects_pool_vm_on_unit_thread(self):
        for core in ([0, 16], [15, 31]):
            xml = domain.rewrite_for_start(fx.set_cores(fx.fixture("pool"), [core, [9, 25]]), self.p)
            self.assertIn(f"core {core[0]},{core[1]} is not a pool core", violations(xml, self.p))

    def test_validator_rejects_malformed_core(self):
        for core in ([24, 8], [8], [8, 24, 9]):
            xml = fx.set_cores(fx.fixture("pool"), [core, [9, 25]])
            self.assertIn("is not a pool core", violations(xml, self.p))

    def test_validator_rejects_hugepages_on_pool_vm(self):
        root = fx.parse(domain.rewrite_for_start(fx.fixture("pool"), self.p))
        hugepages = ET.SubElement(ET.SubElement(root, "memoryBacking"), "hugepages")
        ET.SubElement(hugepages, "page", size="2", unit="M")
        self.assertIn("a pool VM may not use hugepages", violations(ET.tostring(root, encoding="unicode"), self.p))

    def test_iothreads_follow_the_emulator(self):
        root = fx.parse(fx.fixture("pool"))
        ET.SubElement(root, "iothreads").text = "1"
        xml = domain.rewrite_for_start(ET.tostring(root, encoding="unicode"), self.p)
        out = fx.parse(xml)
        self.assertEqual(fx.cpulist(out.find("cputune/iothreadpin[@iothread='1']").get("cpuset")), {8, 9, 24, 25})
        self.assertEqual(domain.validate(xml, self.p), [])
        out.find("cputune").remove(out.find("cputune/iothreadpin"))
        self.assertIn("iothread 1 has no iothreadpin", violations(ET.tostring(out, encoding="unicode"), self.p))


QEMU_NS = "http://libvirt.org/schemas/domain/qemu/1.0"
MEMORY_DEVICES = [
    "<memory model='dimm'><source><pagesize unit='KiB'>1048576</pagesize></source>"
    "<target><size unit='GiB'>1</size><node>0</node></target></memory>",
    "<memory model='nvdimm'><source><path>/dev/hugepages1G/guest-a</path></source>"
    "<target><size unit='GiB'>1</size></target></memory>",
    "<memory model='virtio-pmem' access='shared'><source><path>/dev/hugepages1G/guest-b</path></source>"
    "<target><size unit='GiB'>1</size></target></memory>",
    "<memory model='virtio-mem'><source><pagesize unit='KiB'>1048576</pagesize></source>"
    "<target><size unit='GiB'>1</size><node>0</node><block unit='KiB'>2048</block></target></memory>",
]
OTHER_HOSTDEVS = [
    "<hostdev mode='subsystem' type='mdev' model='vfio-pci' display='off'>"
    "<source><address uuid='c2177883-f1bb-47f0-914d-32a22e3a8804'/></source></hostdev>",
    "<hostdev mode='subsystem' type='usb'><source><vendor id='0x1234'/><product id='0xbeef'/></source></hostdev>",
    "<hostdev mode='capabilities' type='misc'><source><char>/dev/input/event3</char></source></hostdev>",
]


class OutsideThePartitionTest(unittest.TestCase):
    """Configuration that reaches host resources past the partition is refused
    on every domain, and the rewrite does not place such a domain."""

    CASES = [("pool", "jimbeam"), ("a6000", "jimbeam")]

    def test_validator_rejects_memory_devices(self):
        for name, host in self.CASES:
            p = fx.partition(host)
            good = domain.rewrite_for_start(fx.fixture(name), p)
            for device in MEMORY_DEVICES:
                with self.subTest(fixture=name, device=device[:40]):
                    xml = fx.add_device(good, device)
                    self.assertIn("memory device", violations(xml, p, sysfs=fx.sysfs(host)))
                    with self.assertRaises(PartitionError):
                        domain.rewrite_for_start(fx.add_device(fx.fixture(name), device), p)

    def test_validator_rejects_qemu_passthrough(self):
        for name, host in self.CASES:
            p = fx.partition(host)
            for tag, child, attrs in (("commandline", "arg", {"value": "-smp"}),
                                      ("override", "device", {"alias": "hostdev0"})):
                with self.subTest(fixture=name, element=tag):
                    root = fx.parse(domain.rewrite_for_start(fx.fixture(name), p))
                    ET.SubElement(ET.SubElement(root, f"{{{QEMU_NS}}}{tag}"), f"{{{QEMU_NS}}}{child}", attrs)
                    xml = ET.tostring(root, encoding="unicode")
                    self.assertIn(f"qemu:{tag} is not allowed", violations(xml, p, sysfs=fx.sysfs(host)))
                    with self.assertRaises(PartitionError):
                        domain.rewrite_for_start(xml, p)

    def test_validator_rejects_hostdev_that_is_not_a_pci_position(self):
        for name, host in self.CASES:
            p = fx.partition(host)
            good = domain.rewrite_for_start(fx.fixture(name), p)
            for device in OTHER_HOSTDEVS:
                kind = fx.parse(device).get("type")
                with self.subTest(fixture=name, hostdev=kind):
                    xml = fx.add_device(good, device)
                    self.assertIn(f"hostdev of type {kind} is not a declared GPU position",
                                  violations(xml, p, sysfs=fx.sysfs(host)))
                    with self.assertRaises(PartitionError):
                        domain.rewrite_for_start(fx.add_device(fx.fixture(name), device), p)

    def test_rewrite_refuses_pool_vm_with_hugepages(self):
        p = fx.partition("jimbeam")
        root = fx.parse(fx.fixture("pool"))
        ET.SubElement(ET.SubElement(root, "memoryBacking"), "hugepages")
        with self.assertRaises(PartitionError):
            domain.rewrite_for_start(ET.tostring(root, encoding="unicode"), p)


class GpuVmTest(unittest.TestCase):
    def test_a6000_vm_shape(self):
        p = fx.partition("jimbeam")
        out = domain.rewrite_for_start(fx.fixture("a6000"), p)
        root = fx.parse(out)
        self.assertEqual(fx.pins(root), {i: {t} for i, t in enumerate(A6000_THREADS)})
        self.assertEqual(root.find("cputune/emulatorpin").get("cpuset"), "15,31")
        self.assertEqual(cells(root), [(0, set(range(12)), 24 << 20)])
        self.assertEqual(memnodes(root), [(0, "strict", frozenset({0}))])
        memory = root.find("numatune/memory")
        self.assertEqual((memory.get("mode"), memory.get("nodeset")), ("preferred", "0"))
        page = root.find("memoryBacking/hugepages/page")
        self.assertEqual((page.get("size"), page.get("unit"), page.get("nodeset")), ("1", "G", "0"))
        self.assertEqual(topology(root), (1, 6, 2))
        self.assertEqual(len(root.findall("cpu")), 1)
        self.assertEqual(root.find("cpu").get("mode"), "host-passthrough")
        balloons = root.findall("devices/memballoon")
        self.assertEqual([(b.get("model"), len(b), sorted(b.attrib)) for b in balloons], [("none", 0, ["model"])])
        self.assertEqual(root.findall("devices/controller"), [])
        self.assertEqual(domain.gpu_group(out, p), (0,))
        self.assertEqual(domain.validate(out, p, sysfs=fx.sysfs("jimbeam")), [])

    def test_gpu_group(self):
        p = fx.partition("ferrari")
        self.assertEqual(domain.gpu_group(fx.fixture("a100x2"), p), (0, 1))
        self.assertEqual(domain.gpu_group(fx.fixture("a100x8"), p), tuple(range(8)))
        self.assertIsNone(domain.gpu_group(fx.fixture("pool"), p))
        root = fx.parse(fx.fixture("a100x1"))
        del root.find("devices/hostdev/source/address").attrib["domain"]
        self.assertEqual(domain.gpu_group(ET.tostring(root, encoding="unicode"), p), (5,))

    def test_a100x1_on_second_node(self):
        p = fx.partition("ferrari")
        out = domain.rewrite_for_start(fx.fixture("a100x1"), p)
        root = fx.parse(out)
        unit = p["units"][5]
        self.assertEqual(unit["node"], 1)
        self.assertEqual(fx.pins(root), {i: {t} for i, t in enumerate(t for c in unit["threads"] for t in c)})
        self.assertEqual(memnodes(root), [(0, "strict", frozenset({1}))])
        self.assertEqual(pages(root), [(1 << 20, frozenset({0}))])
        self.assertEqual(fx.cpulist(root.find("cputune/emulatorpin").get("cpuset")), set(p["housekeeping"]))
        self.assertEqual(domain.validate(out, p, sysfs=fx.sysfs("ferrari")), [])

    def test_a100x2_listed_group_ok(self):
        p = fx.partition("ferrari")
        out = domain.rewrite_for_start(fx.fixture("a100x2"), p)
        root = fx.parse(out)
        self.assertEqual(topology(root), (1, 12, 2))
        self.assertEqual(len(cells(root)), 1)
        self.assertEqual(root.findall("devices/controller"), [])
        self.assertEqual(domain.validate(out, p, sysfs=fx.sysfs("ferrari")), [])

    def test_validator_rejects_group_not_in_table(self):
        p = fx.partition("ferrari")
        xml = fx.gpu_domain(fx.fixture("a100x2"), FERRARI_BUSES[1:3], 24, 192)
        out = domain.rewrite_for_start(xml, p)
        self.assertIn("GPU positions [1, 2] are not a group of this host", violations(out, p, sysfs=fx.sysfs("ferrari")))

    def test_validator_any_accepts_present_subset_of_allowed_size(self):
        p = fx.partition("ford")
        self.assertEqual(p["group_rule"], "any")
        out = domain.rewrite_for_start(fx.gpu_domain(fx.fixture("a100x2"), [FORD_BUSES[0], FORD_BUSES[3]], 24, 192), p)
        self.assertEqual(domain.gpu_group(out, p), (0, 3))
        self.assertEqual(domain.validate(out, p, sysfs=fx.sysfs("ford")), [])

    def test_validator_any_rejects_size_not_in_counts(self):
        p = fx.partition("ford")
        out = domain.rewrite_for_start(fx.gpu_domain(fx.fixture("a100x2"), FORD_BUSES[:3], 36, 288), p)
        self.assertIn("a GPU set of size 3 is not allowed here", violations(out, p, sysfs=fx.sysfs("ford")))

    def test_validator_any_rejects_absent_position(self):
        p = fx.partition("ford")
        out = domain.rewrite_for_start(fx.gpu_domain(fx.fixture("a100x2"), [FORD_BUSES[0], FORD_BUSES[3]], 24, 192), p)
        with tempfile.TemporaryDirectory() as tmp:
            sysfs = Path(tmp) / "sys"
            shutil.copytree(fx.sysfs("ford"), sysfs)
            shutil.rmtree(sysfs / "bus/pci/devices" / FORD_BUSES[3])
            self.assertIn(f"GPU position 3 ({FORD_BUSES[3]}) is absent", violations(out, p, sysfs=sysfs))

    def test_validator_partitions_rejects_absent_position(self):
        p = fx.partition("ferrari")
        out = domain.rewrite_for_start(fx.fixture("a100x2"), p)
        with tempfile.TemporaryDirectory() as tmp:
            sysfs = Path(tmp) / "sys"
            shutil.copytree(fx.sysfs("ferrari"), sysfs)
            shutil.rmtree(sysfs / "bus/pci/devices" / FERRARI_BUSES[1])
            self.assertIn("GPU position 1", violations(out, p, sysfs=sysfs))

    def test_validator_single_rejects_two_gpus(self):
        p = fx.partition("ferrari")
        p.update(group_rule="single", counts=[1], groups=[], fm_partitions={}, fabric_manager=False)
        out = domain.rewrite_for_start(fx.fixture("a100x2"), p)
        self.assertIn("a GPU set of size 2 is not allowed here", violations(out, p, sysfs=fx.sysfs("ferrari")))
        one = domain.rewrite_for_start(fx.fixture("a100x1"), p)
        self.assertEqual(domain.validate(one, p, sysfs=fx.sysfs("ferrari")), [])

    def test_validator_rejects_gpus_spread_unevenly_over_nodes(self):
        p = fx.partition("ferrari")
        p.update(group_rule="any", counts=[1, 2, 4, 8], groups=[], fm_partitions={}, fabric_manager=False)
        xml = fx.gpu_domain(fx.fixture("a100x2"), [FERRARI_BUSES[i] for i in (0, 1, 2, 4)], 48, 384)
        with self.assertRaises(PartitionError):
            domain.rewrite_for_start(xml, p)
        self.assertIn("are not spread evenly over NUMA nodes", violations(xml, p, sysfs=fx.sysfs("ferrari")))

    def test_a100x8_two_cells_and_expander_buses(self):
        p = fx.partition("ferrari")
        out = domain.rewrite_for_start(fx.fixture("a100x8"), p)
        root = fx.parse(out)
        self.assertEqual(int(root.find("vcpu").text), 8 * p["unit_vcpu"])
        self.assertEqual(topology(root), (2, 24, 2))
        self.assertEqual(cells(root), [(0, set(range(48)), 384 << 20), (1, set(range(48, 96)), 384 << 20)])
        self.assertEqual(memnodes(root), [(0, "strict", frozenset({0})), (1, "strict", frozenset({1}))])
        memory = root.find("numatune/memory")
        self.assertEqual((memory.get("mode"), fx.cpulist(memory.get("nodeset"))), ("preferred", {0, 1}))
        self.assertEqual(pages(root), [(1 << 20, frozenset({0, 1}))])
        expected = [t for u in sorted(p["units"], key=lambda u: (u["node"], u["position"])) for c in u["threads"] for t in c]
        self.assertEqual(fx.pins(root), {i: {t} for i, t in enumerate(expected)})
        models = sorted(c.get("model") for c in root.findall("devices/controller"))
        self.assertEqual(models, ["pcie-expander-bus"] * 2 + ["pcie-root-port"] * 8)
        node_of = {u["bus"]: u["node"] for u in p["units"]}
        self.assertEqual(gpu_guest_nodes(root), sorted((b, node_of[b]) for b in FERRARI_BUSES))
        self.assertEqual(domain.validate(out, p, sysfs=fx.sysfs("ferrari")), [])

    def test_a100x8_on_pc_uses_pci_expander_bus(self):
        p = fx.partition("ferrari")
        root = fx.parse(fx.fixture("a100x8"))
        root.find("os/type").set("machine", "pc")
        out = domain.rewrite_for_start(ET.tostring(root, encoding="unicode"), p)
        out_root = fx.parse(out)
        models = sorted(c.get("model") for c in out_root.findall("devices/controller"))
        self.assertEqual(models, ["pci-expander-bus"] * 2)
        node_of = {u["bus"]: u["node"] for u in p["units"]}
        self.assertEqual(gpu_guest_nodes(out_root), sorted((b, node_of[b]) for b in FERRARI_BUSES))
        self.assertEqual(domain.validate(out, p, sysfs=fx.sysfs("ferrari")), [])

    def test_gpu_vm_smaller_than_its_units_is_placed(self):
        p = fx.partition("jimbeam")
        bus = ["0000:16:00.0"]
        out = domain.rewrite_for_start(fx.gpu_domain(fx.fixture("a6000"), bus, 8, 16), p)
        root = fx.parse(out)
        self.assertEqual(fx.pins(root), {i: {t} for i, t in enumerate(A6000_THREADS[:8])})
        self.assertEqual(topology(root), (1, 4, 2))
        self.assertEqual(cells(root), [(0, set(range(8)), 16 << 20)])
        self.assertEqual(domain.validate(out, p, sysfs=fx.sysfs("jimbeam")), [])

        out = domain.rewrite_for_start(fx.gpu_domain(fx.fixture("a6000"), bus, 5, 24), p)
        root = fx.parse(out)
        self.assertEqual(fx.pins(root), {i: {t} for i, t in enumerate(A6000_THREADS[:5])})
        self.assertEqual(topology(root), (1, 5, 1))
        self.assertEqual(domain.validate(out, p, sysfs=fx.sysfs("jimbeam")), [])

        p = fx.partition("ferrari")
        out = domain.rewrite_for_start(fx.gpu_domain(fx.fixture("a100x8"), FERRARI_BUSES, 48, 384), p)
        root = fx.parse(out)
        self.assertEqual(topology(root), (2, 12, 2))
        self.assertEqual(cells(root), [(0, set(range(24)), 192 << 20), (1, set(range(24, 48)), 192 << 20)])
        by_node = {n: [t for u in sorted(p["units"], key=lambda u: u["position"]) if u["node"] == n
                       for c in u["threads"] for t in c] for n in (0, 1)}
        self.assertEqual(fx.pins(root), {i: {t} for i, t in enumerate(by_node[0][:24] + by_node[1][:24])})
        self.assertEqual(domain.validate(out, p, sysfs=fx.sysfs("ferrari")), [])

    def test_gpu_vm_size_bounded_by_its_units(self):
        p = fx.partition("jimbeam")
        bus = ["0000:16:00.0"]
        jimbeam = fx.sysfs("jimbeam")
        for vcpus, gib in ((13, 24), (12, 25)):
            with self.assertRaises(PartitionError):
                domain.rewrite_for_start(fx.gpu_domain(fx.fixture("a6000"), bus, vcpus, gib), p)
        good = domain.rewrite_for_start(fx.fixture("a6000"), p)

        root = fx.parse(good)
        root.find("vcpu").text = "13"
        root.find("vcpu").set("current", "13")
        ET.SubElement(root.find("cputune"), "vcpupin", vcpu="12", cpuset="6")
        self.assertIn("vcpupin of vCPU 12 is 6, which is not a thread of its GPUs' units",
                      violations(ET.tostring(root, encoding="unicode"), p, sysfs=jimbeam))

        root = fx.parse(good)
        root.find("cputune/vcpupin[@vcpu='1']").set("cpuset", "0")
        self.assertIn("vCPU 1 shares thread 0 with vCPU 0", violations(ET.tostring(root, encoding="unicode"), p, sysfs=jimbeam))

        root = fx.parse(good)
        root.find("cputune/vcpupin[@vcpu='0']").set("cpuset", "1")
        root.find("cputune/vcpupin[@vcpu='2']").set("cpuset", "0")
        self.assertEqual(domain.validate(ET.tostring(root, encoding="unicode"), p, sysfs=jimbeam), [])

        root = fx.parse(good)
        for tag in ("memory", "currentMemory"):
            root.find(tag).text = str(25 << 20)
        root.find("cpu/numa/cell").set("memory", "25")
        found = violations(ET.tostring(root, encoding="unicode"), p, sysfs=jimbeam)
        self.assertIn("memory 25 GiB exceeds the 24 GiB of hugepages of its GPUs", found)
        self.assertIn("guest cells on node 0 take 25 GiB, more than the 24 GiB of hugepages of its GPUs there", found)

        root = fx.parse(good)
        ET.SubElement(root, "maxMemory", slots="16", unit="KiB").text = str(32 << 20)
        self.assertIn("maxMemory 32 GiB exceeds the 24 GiB of hugepages of its GPUs",
                      violations(ET.tostring(root, encoding="unicode"), p, sysfs=jimbeam))

    def test_gpu_cell_memory_is_whole_pages(self):
        """A cell backed by 1 GiB pages takes whole pages, so 1.5 GiB uses 2."""
        p = fx.partition("ferrari")
        root = fx.parse(domain.rewrite_for_start(fx.fixture("a100x2"), p))
        numa = root.find("cpu/numa")
        for cell in list(numa):
            numa.remove(cell)
        numatune = root.find("numatune")
        for memnode in numatune.findall("memnode"):
            numatune.remove(memnode)
        for i in range(128):
            cell = ET.SubElement(numa, "cell", id=str(i), memory=str(3 << 19), unit="KiB")
            if i == 0:
                cell.set("cpus", "0-23")
            ET.SubElement(numatune, "memnode", cellid=str(i), mode="strict", nodeset="0")
        page = root.find("memoryBacking/hugepages/page")
        del page.attrib["nodeset"]
        xml = ET.tostring(root, encoding="unicode")
        found = violations(xml, p, sysfs=fx.sysfs("ferrari"))
        self.assertIn("guest cell 0 holds 1572864 KiB, not a whole number of 1 GiB pages", found)
        self.assertIn("guest cell 127 holds 1572864 KiB, not a whole number of 1 GiB pages", found)
        self.assertIn("guest cells on node 0 take 256 GiB, more than the 192 GiB of hugepages of its GPUs there", found)

    def test_gpu_memory_per_node_stays_within_its_units_there(self):
        p = fx.partition("ferrari")
        p.update(group_rule="any", counts=[1, 2, 4, 8], groups=[], fm_partitions={}, fabric_manager=False)
        ferrari = fx.sysfs("ferrari")
        xml = fx.gpu_domain(fx.fixture("a100x2"), [FERRARI_BUSES[i] for i in (0, 1, 4, 5)], 48, 384)
        good = domain.rewrite_for_start(xml, p)
        self.assertEqual(domain.validate(good, p, sysfs=ferrari), [])

        root = fx.parse(good)
        cell0, cell1 = root.findall("cpu/numa/cell")
        cell0.set("memory", "288")
        cell1.set("memory", "96")
        self.assertIn("guest cells on node 0 take 288 GiB, more than the 192 GiB of hugepages of its GPUs there",
                      violations(ET.tostring(root, encoding="unicode"), p, sysfs=ferrari))

        root = fx.parse(good)
        root.find("numatune/memnode[@cellid='1']").set("nodeset", "0")
        self.assertIn("guest cells on node 0 take 384 GiB, more than the 192 GiB of hugepages of its GPUs there",
                      violations(ET.tostring(root, encoding="unicode"), p, sysfs=ferrari))

    def test_validator_rejects_unknown_hostdev(self):
        p = fx.partition("jimbeam")
        xml = fx.fixture("unknown-hostdev")
        with self.assertRaises(PartitionError):
            domain.rewrite_for_start(xml, p)
        self.assertIn("hostdev 0000:16:00.1 is not a declared GPU position", violations(xml, p, sysfs=fx.sysfs("jimbeam")))
        self.assertIn("hostdev 0000:16:00.0 is not a declared GPU position",
                      violations(fx.fixture("a6000"), fx.partition("jackdaniels"), sysfs=fx.sysfs("jackdaniels")))

    def test_validator_rejects_gpu_memory_outside_its_nodes(self):
        p = fx.partition("ferrari")
        good = domain.rewrite_for_start(fx.fixture("a100x1"), p)
        not_strict = "guest cell 0 is not strict on one node of its GPUs (1)"
        for attr, value in (("nodeset", "0"), ("nodeset", "0-1"), ("mode", "preferred")):
            root = fx.parse(good)
            root.find("numatune/memnode").set(attr, value)
            self.assertIn(not_strict, violations(ET.tostring(root, encoding="unicode"), p, sysfs=fx.sysfs("ferrari")))
        root = fx.parse(good)
        root.find("numatune").remove(root.find("numatune/memnode"))
        self.assertIn(not_strict, violations(ET.tostring(root, encoding="unicode"), p, sysfs=fx.sysfs("ferrari")))
        root = fx.parse(good)
        root.find("cpu").remove(root.find("cpu/numa"))
        self.assertIn("the domain has no guest NUMA cells", violations(ET.tostring(root, encoding="unicode"), p, sysfs=fx.sysfs("ferrari")))
        root = fx.parse(good)
        root.find("memoryBacking/hugepages/page").set("size", "2048")
        root.find("memoryBacking/hugepages/page").set("unit", "KiB")
        self.assertIn("not backed by 1 GiB hugepages", violations(ET.tostring(root, encoding="unicode"), p, sysfs=fx.sysfs("ferrari")))
        root = fx.parse(good)
        root.remove(root.find("memoryBacking"))
        self.assertIn("not backed by 1 GiB hugepages", violations(ET.tostring(root, encoding="unicode"), p, sysfs=fx.sysfs("ferrari")))

    def test_validator_rejects_gpu_emulator_outside_housekeeping(self):
        p = fx.partition("jimbeam")
        root = fx.parse(domain.rewrite_for_start(fx.fixture("a6000"), p))
        root.find("cputune/emulatorpin").set("cpuset", "0-5")
        self.assertIn("emulatorpin 0-5 is outside the housekeeping cores 15,31",
                      violations(ET.tostring(root, encoding="unicode"), p, sysfs=fx.sysfs("jimbeam")))

    def test_validator_rejects_gpu_held_by_running_domain(self):
        p = fx.partition("ferrari")
        x2 = domain.rewrite_for_start(fx.fixture("a100x2"), p)
        x8 = domain.rewrite_for_start(fx.fixture("a100x8"), p)
        held = {"name": "i-2-102-VM", **domain.claim(x2, p)}
        self.assertEqual(held["positions"], [0, 1])
        self.assertIn("GPU position 0 is held by running domain i-2-102-VM",
                      violations(x8, p, ledger=[held], sysfs=fx.sysfs("ferrari")))


class XmlHandlingTest(unittest.TestCase):
    def test_metadata_namespace_and_cputune_children_kept(self):
        p = fx.partition("jimbeam")
        out = domain.rewrite_for_start(fx.fixture("pool"), p)
        root = fx.parse(out)
        ns = f"{{{fx.NS}}}"
        self.assertEqual(root.find(f"metadata/{ns}instance/{ns}zone").text, "snucse")
        self.assertIn("<cloudstack:zone", out)
        self.assertEqual(len(root.findall("cputune")), 1)
        self.assertEqual(root.find("cputune/shares").text, "1250")

    def test_missing_cputune_is_added(self):
        p = fx.partition("jimbeam")
        root = fx.parse(fx.fixture("pool"))
        root.remove(root.find("cputune"))
        out = fx.parse(domain.rewrite_for_start(ET.tostring(root, encoding="unicode"), p))
        self.assertEqual(fx.pins(out), {0: {8}, 1: {24}, 2: {9}, 3: {25}})

    def test_document_type_is_refused(self):
        p = fx.partition("jimbeam")
        xml = "<!DOCTYPE domain [<!ENTITY a 'x'>]>" + fx.fixture("pool")
        with self.assertRaises(PartitionError):
            domain.rewrite_for_start(xml, p)
        self.assertIn("document type", violations(xml, p))

    def test_malformed_xml_is_a_violation(self):
        self.assertTrue(domain.validate("<domain>", fx.partition("jimbeam")))

    def test_default_namespace_in_metadata_stays_off_the_domain(self):
        lease = "http://example.org/lease"
        # A default namespace registered with ElementTree is process-wide.
        self.addCleanup(ET._namespace_map.pop, lease, None)
        p = fx.partition("jimbeam")
        xml = fx.fixture("pool").replace(
            "</metadata>", f'<lease xmlns="{lease}"><until>2026-10-21T00:00:00</until></lease>\n</metadata>')
        out = domain.rewrite_for_start(xml, p)
        root = fx.parse(out)
        self.assertEqual(root.tag, "domain")
        self.assertEqual(root.findtext(f"metadata/{{{lease}}}lease/{{{lease}}}until"), "2026-10-21T00:00:00")
        self.assertEqual(domain.validate(out, p), [])


class TransformerTest(unittest.TestCase):
    def run_transformer(self, *args, partition_text=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partition.json"
            if partition_text is not None:
                path.write_text(partition_text)
            env = {**os.environ, "CLOUDSTACK_PARTITION_FILE": str(path)}
            return subprocess.run([sys.executable, str(fx.TRANSFORMER), *args],
                                  capture_output=True, text=True, env=env, timeout=60)

    def test_transformer_rewrites_with_the_partition_file(self):
        r = self.run_transformer("transform", fx.fixture("a6000"), partition_text=json.dumps(fx.partition("jimbeam")))
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(fx.pins(fx.parse(r.stdout)), {i: {t} for i, t in enumerate(A6000_THREADS)})

    def test_transformer_output_stays_clean_of_fd2_writes(self):
        """Writes below Python's sys.stderr (C extensions, the interpreter)
        reach file descriptor 2, which the agent reads with the XML."""
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "transformer.py"
            shutil.copy(fx.TRANSFORMER, copy)
            package = Path(tmp) / "partition"
            package.mkdir()
            (package / "__init__.py").write_text("")
            (package / "domain.py").write_text(
                "import os\n"
                "os.write(2, b'written to fd 2 at import\\n')\n\n\n"
                "def rewrite_for_start(xml, p):\n"
                "    os.write(2, b'written to fd 2 while rewriting\\n')\n"
                "    return xml.upper()\n")
            (Path(tmp) / "partition.json").write_text("{}")
            env = {**os.environ, "CLOUDSTACK_PARTITION_FILE": str(Path(tmp) / "partition.json")}
            r = subprocess.run([sys.executable, str(copy), "transform", "<domain/>"],
                               capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "<DOMAIN/>", ""))

    def test_transformer_prints_input_on_error(self):
        xml = fx.fixture("a6000")
        for text in ("{not json", None, '{"units": 3}'):
            r = self.run_transformer("transform", xml, partition_text=text)
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, xml, ""), text)

    def test_bad_xml_is_returned_unchanged(self):
        r = self.run_transformer("transform", "<domain>", partition_text=json.dumps(fx.partition("jimbeam")))
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "<domain>", ""))

    def test_unplaceable_domain_is_returned_unchanged(self):
        xml = fx.set_cores(fx.fixture("pool"), None)
        r = self.run_transformer("transform", xml, partition_text=json.dumps(fx.partition("jimbeam")))
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, xml, ""))


XMLCHECK_IMAGE = "cloudstack-partition-xmlcheck:trixie"
# libvirt's own parser and formatter (the in-process test driver).
_FORMAT = ('d=$(mktemp -d) || exit 9; cat > "$d/d.xml" '
           '&& virsh -q -c test:///default "define $d/d.xml; dumpxml $1"; rc=$?; rm -rf "$d"; exit $rc')
_VALIDATE = 'd=$(mktemp -d) || exit 9; cat > "$d/d.xml" && virt-xml-validate "$d/d.xml" domain; rc=$?; rm -rf "$d"; exit $rc'


def libvirt_tools():
    """The argv prefix that runs a shell with the libvirt client tools, or None.

    It uses the local tools, or else the image above: debian:trixie (the
    hosts' libvirt) with libvirt-clients and libxml2-utils.
    """
    if shutil.which("virsh") and shutil.which("virt-xml-validate"):
        return []
    docker = shutil.which("docker")
    if docker and subprocess.run([docker, "image", "inspect", XMLCHECK_IMAGE], capture_output=True).returncode == 0:
        return [docker, "run", "--rm", "-i", "--user", f"{os.getuid()}:{os.getgid()}", XMLCHECK_IMAGE]
    return None


class SchemaTest(unittest.TestCase):
    CASES = [("pool", "jimbeam", None), ("systemvm", "jimbeam", None), ("a6000", "jimbeam", None),
             ("a100x1", "ferrari", None), ("a100x2", "ferrari", None), ("a100x8", "ferrari", None),
             ("a100x8", "ferrari", "pc")]

    def test_rewritten_xml_validates_against_schema(self):
        """libvirt parses each rewritten fixture and formats it again; that
        document must satisfy the domain schema, keep everything the rewrite
        decided, and pass the validator, which reads that format at start."""
        tools = libvirt_tools()
        if tools is None:
            self.skipTest(f"neither virt-xml-validate nor the {XMLCHECK_IMAGE} image is available")
        for name, host, machine in self.CASES:
            with self.subTest(fixture=name, machine=machine):
                p = fx.partition(host)
                root = fx.parse(fx.fixture(name))
                if machine:
                    root.find("os/type").set("machine", machine)
                out = domain.rewrite_for_start(ET.tostring(root, encoding="unicode"), p)
                test_root = fx.parse(out)
                # libvirt's test driver defines only domains of type "test".
                test_root.set("type", "test")
                r = subprocess.run([*tools, "sh", "-c", _FORMAT, "sh", test_root.findtext("name")],
                                   input=ET.tostring(test_root, encoding="unicode"),
                                   capture_output=True, text=True, timeout=180)
                self.assertEqual(r.returncode, 0, r.stderr)
                formatted = r.stdout
                self.assertEqual(shape(formatted), shape(out))
                self.assertEqual(domain.validate(formatted, p, sysfs=fx.sysfs(host)), [])

                checked = fx.parse(formatted)
                # libvirt formats a NIC without option ROM as <rom file=''/>,
                # which its own schema rejects; the rewrite never touches NICs.
                for rom in checked.findall("devices/interface/rom[@file='']"):
                    del rom.attrib["file"]
                r = subprocess.run([*tools, "sh", "-c", _VALIDATE], input=ET.tostring(checked, encoding="unicode"),
                                   capture_output=True, text=True, timeout=180)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("validates", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
