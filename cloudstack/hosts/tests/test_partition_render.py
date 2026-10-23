import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = HERE.parent / "files"
FIXTURES = HERE / "fixtures"
CATALOG_FILE = HERE.parents[2] / "argocd" / "atrium" / "cloudstack" / "compute-catalog.json"
CLI = FILES / "partition-render"

sys.path.insert(0, str(FILES))
from partition import PartitionError, table, topology  # noqa: E402

JIMBEAM = {
    "gpu_type": "a6000",
    "gpu_positions": ["0000:16:00.0"],
    "gpu_class": "pcie",
    "housekeeping_cores": {"1": 1},
    "host_reserve_gib": 4,
    "qemu_overhead_gib": 2,
    "fabric_manager": False,
}
I7 = {
    "gpu_type": "gtx1080",
    "gpu_positions": ["0000:01:00.0"],
    "gpu_class": "pcie",
    "housekeeping_cores": {"0": 1},
    "host_reserve_gib": 2,
    "qemu_overhead_gib": 1,
    "fabric_manager": False,
}
JACKDANIELS = {
    "housekeeping_cores": {"0": 1},
    "host_reserve_gib": 4,
}
FERRARI_BUSES = ["0000:07:00.0", "0000:0f:00.0", "0000:47:00.0", "0000:4e:00.0",
                 "0000:87:00.0", "0000:90:00.0", "0000:b7:00.0", "0000:bd:00.0"]
FERRARI_GROUPS = ([[p] for p in range(8)] + [[0, 1], [2, 3], [4, 5], [6, 7]]
                  + [[0, 1, 2, 3], [4, 5, 6, 7], list(range(8))])
FERRARI = {
    "gpu_type": "a100-80g",
    "gpu_positions": FERRARI_BUSES,
    "gpu_class": "nvswitch",
    "gpu_groups": FERRARI_GROUPS,
    "fm_partitions": {",".join(map(str, g)): i for i, g in enumerate(reversed(FERRARI_GROUPS))},
    "housekeeping_cores": {"0": 2, "1": 2},
    "host_reserve_gib": 16,
    "qemu_overhead_gib": 2,
    "fabric_manager": True,
}
FORD = {
    "gpu_type": "a100-40g",
    "gpu_positions": ["0000:01:00.0", "0000:41:00.0", "0000:81:00.0", "0000:c1:00.0"],
    "gpu_class": "nvlink",
    "housekeeping_cores": {"0": 4},
    "host_reserve_gib": 8,
    "qemu_overhead_gib": 2,
    "fabric_manager": False,
}


def load_catalog():
    return json.loads(CATALOG_FILE.read_text())


def catalog_with(tag, **fields):
    catalog = load_catalog()
    for t in catalog["gpu_types"]:
        if t["tag"] == tag:
            t.update(fields)
    return catalog


def declared(base, **changes):
    d = copy.deepcopy(base)
    for k, v in changes.items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    return d


def read(host, edit=None):
    src = FIXTURES / f"sysfs-{host}"
    if edit is None:
        return topology.read(src / "sys", src / "proc")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / host
        shutil.copytree(src, root)
        edit(root)
        return topology.read(root / "sys", root / "proc")


def render(host, decl, catalog=None, edit=None):
    return table.render(read(host, edit), decl, catalog or load_catalog())


def pci(root, bus):
    return root / "sys" / "bus" / "pci" / "devices" / bus


def set_mem_total(root, kib):
    (root / "sys/devices/system/node/node0/meminfo").write_text(f"Node 0 MemTotal:       {kib} kB\n")
    (root / "proc/meminfo").write_text(f"MemTotal:       {kib} kB\n")


class TopologyTest(unittest.TestCase):
    def test_core_id_repeats_per_package(self):
        t = read("jimbeam")
        self.assertEqual(t.threads[0], topology.Thread(socket=0, node=0, core=0, siblings=(0, 16)))
        self.assertEqual(t.threads[8], topology.Thread(socket=1, node=1, core=0, siblings=(8, 24)))
        self.assertEqual(t.node_threads, {0: list(range(0, 8)) + list(range(16, 24)),
                                          1: list(range(8, 16)) + list(range(24, 32))})
        self.assertEqual(t.mem_total_kib, 65604020)
        self.assertEqual(t.node_mem_kib, {0: 32582552, 1: 33021468})
        self.assertEqual(t.phys_bits, 52)
        self.assertEqual(t.pci_node, {"0000:16:00.0": 0, "0000:16:00.1": 0})
        self.assertEqual(t.pci_device, {"0000:16:00.0": "10de:2230", "0000:16:00.1": "10de:1aef"})

    def test_core_id_not_contiguous(self):
        t = read("jackdaniels")
        self.assertEqual(t.threads[7].core, 8)
        self.assertEqual(t.threads[13], topology.Thread(socket=0, node=0, core=14, siblings=(13, 27)))
        self.assertEqual(t.phys_bits, 46)

    def test_numa_node_minus_one_is_read_as_is(self):
        self.assertEqual(read("i7").pci_node["0000:01:00.0"], -1)

    def test_offline_cpu_refused(self):
        def offline(root):
            (root / "sys/devices/system/cpu/cpu5/online").write_text("0\n")
        with self.assertRaisesRegex(PartitionError, "cpu5 is offline"):
            read("i7", offline)


class CatalogTest(unittest.TestCase):
    def test_catalog_cards_match_discovered(self):
        discovered = json.loads((FIXTURES / "listGpuCards.json").read_text())["gpucard"]
        types = {t["tag"]: t for t in load_catalog()["gpu_types"]}
        # Companion functions are the card's other PCI functions as the hosts report them.
        companions = {"a6000": read("jimbeam").pci_device["0000:16:00.1"],
                      "gtx1080": read("i7").pci_device["0000:01:00.1"]}
        self.assertEqual(len(discovered), 2)
        for card in discovered:
            tag = {"2230": "a6000", "1b80": "gtx1080"}[card["deviceid"]]
            self.assertEqual(types[tag]["card"], {
                "vendor_id": card["vendorid"],
                "device_id": card["deviceid"],
                "vendor_name": card["vendorname"],
                "device_name": card["devicename"],
                "name": card["name"],
            })
            self.assertEqual(types[tag]["pci_ids"],
                             [f"{card['vendorid']}:{card['deviceid']}", companions[tag]])

    def test_catalog_values(self):
        types = {t["tag"]: t for t in load_catalog()["gpu_types"]}
        self.assertEqual([t["tag"] for t in load_catalog()["gpu_types"]],
                         ["a6000", "gtx1080", "a100-40g", "a100-80g"])
        self.assertEqual((types["a6000"]["unit_vcpu"], types["a6000"]["unit_ram_gib"]), (12, 24))
        self.assertEqual((types["gtx1080"]["unit_vcpu"], types["gtx1080"]["unit_ram_gib"]), (6, 12))
        for tag in ("a6000", "gtx1080"):
            self.assertEqual(types[tag]["classes"], {"pcie": {"rule": "single"}})
        self.assertEqual(types["a100-40g"]["pci_ids"], ["10de:20b0"])
        self.assertEqual((types["a100-40g"]["unit_vcpu"], types["a100-40g"]["unit_ram_gib"]), (12, 96))
        self.assertEqual(types["a100-40g"]["classes"], {
            "nvswitch": {"rule": "partitions", "counts": [2, 4, 8]},
            "nvlink": {"rule": "any", "counts": [2, 4]},
        })
        self.assertEqual(types["a100-80g"]["pci_ids"], ["10de:20b2"])
        self.assertEqual((types["a100-80g"]["unit_vcpu"], types["a100-80g"]["unit_ram_gib"]), (12, 96))
        self.assertEqual(types["a100-80g"]["classes"],
                         {"nvswitch": {"rule": "partitions", "counts": [2, 4, 8]}})

    def test_catalog_extra_fields_ignored(self):
        catalog = load_catalog()
        self.assertIn("cpu_only", catalog)
        bare = {"gpu_types": [{k: v for k, v in t.items() if k not in ("lease_hours", "lease_expiry_action")}
                              for t in catalog["gpu_types"]]}
        extra = copy.deepcopy(catalog)
        for t in extra["gpu_types"]:
            for c in t["classes"].values():
                c["keyed_min_count"] = 3
        for host, decl in (("jimbeam", JIMBEAM), ("i7", I7), ("ford", FORD), ("ferrari", FERRARI)):
            self.assertEqual(render(host, decl, catalog=extra), render(host, decl, catalog=bare), host)

    def test_hosts_carry_the_cpu_only_offerings_tag(self):
        # the CPU-only offering, and the resource limits, are keyed by the catalog's cpu_only tag
        tag = load_catalog()["cpu_only"]["tag"]
        for host, decl in (("jimbeam", JIMBEAM), ("jackdaniels", JACKDANIELS)):
            self.assertEqual(table.agent_values(render(host, decl), decl)["host.tags"].split(",")[0], tag, host)


class RenderTest(unittest.TestCase):
    def test_jimbeam_unit_takes_node0(self):
        p = render("jimbeam", JIMBEAM)
        self.assertEqual(p["units"], [{
            "position": 0, "bus": "0000:16:00.0", "present": True, "node": 0,
            "threads": [[0, 16], [1, 17], [2, 18], [3, 19], [4, 20], [5, 21]],
            "hugepages_gib": 24,
        }])
        self.assertEqual(p["housekeeping"], [15, 31])
        self.assertEqual(p["pool"], [6, 7, 22, 23] + list(range(8, 15)) + list(range(24, 31)))
        self.assertEqual(len(p["pool"]), 18)
        self.assertEqual(p["pool_cores"],
                         [{"node": 0, "threads": [6, 22]}, {"node": 0, "threads": [7, 23]}]
                         + [{"node": 1, "threads": [c, c + 16]} for c in range(8, 15)])
        self.assertEqual(table.hugepages_per_node(p), {0: 24})
        self.assertEqual((p["gpu_type"], p["gpu_class"], p["group_rule"], p["counts"]),
                         ("a6000", "pcie", "single", [1]))
        self.assertEqual((p["unit_vcpu"], p["unit_ram_gib"], p["phys_bits"]), (12, 24, 52))
        self.assertEqual((p["fabric_manager"], p["groups"], p["fm_partitions"]), (False, [], {}))
        self.assertEqual(table.agent_values(p, JIMBEAM), {
            "host.reserved.cpu.count": "14",
            "host.reserved.mem.mb": str((24 + 4 + 2) * 1024),
            "host.tags": "cpu,a6000,a6000-pcie",
        })
        self.assertEqual(table.kernel_args(p),
                         "default_hugepagesz=2M hugepagesz=1G hugepages=0:24 irqaffinity=15,31")

    def test_i7_gtx_unit_three_cores_pool_empty(self):
        p = render("i7", I7)
        self.assertEqual([u["threads"] for u in p["units"]], [[[0, 4], [1, 5], [2, 6]]])
        self.assertEqual(p["housekeeping"], [3, 7])
        self.assertEqual(p["pool"], [])
        self.assertEqual(p["pool_cores"], [])
        self.assertEqual(table.hugepages_per_node(p), {0: 12})
        self.assertEqual(table.agent_values(p, I7), {
            "host.reserved.cpu.count": "8",
            "host.reserved.mem.mb": str((12 + 2 + 1) * 1024),
            "host.tags": "cpu,gtx1080,gtx1080-pcie",
        })
        self.assertEqual(table.kernel_args(p),
                         "default_hugepagesz=2M hugepagesz=1G hugepages=0:12 irqaffinity=3,7")

    def test_i7_memory_must_fit(self):
        need = (12 + 2 + 1) * 1024 * 1024
        p = render("i7", I7, edit=lambda root: set_mem_total(root, need))
        self.assertEqual(p["units"][0]["hugepages_gib"], 12)
        with self.assertRaises(PartitionError) as e:
            render("i7", I7, edit=lambda root: set_mem_total(root, need - 1))
        self.assertEqual(str(e.exception), "node 0 memory does not fit units + reserve")

    def test_jackdaniels_pool_is_all_but_housekeeping(self):
        p = render("jackdaniels", JACKDANIELS)
        self.assertEqual(p["units"], [])
        self.assertEqual(p["housekeeping"], [13, 27])
        self.assertEqual(p["pool"], list(range(0, 13)) + list(range(14, 27)))
        self.assertEqual(p["pool_cores"], [{"node": 0, "threads": [c, c + 14]} for c in range(13)])
        self.assertEqual((p["gpu_type"], p["gpu_class"], p["group_rule"], p["counts"]),
                         (None, None, None, []))
        values = table.agent_values(p, JACKDANIELS)
        self.assertEqual(values["host.tags"], "cpu")
        self.assertEqual(values["host.reserved.cpu.count"], "2")
        self.assertEqual(values["host.reserved.mem.mb"], str(4 * 1024))
        self.assertNotIn("hugepages", table.kernel_args(p))
        self.assertEqual(table.kernel_args(p), "irqaffinity=13,27")

    def test_ferrari_units_follow_positions(self):
        p = render("ferrari", FERRARI)
        for u in p["units"]:
            pos = u["position"]
            first = (0 if pos < 4 else 64) + 6 * (pos % 4)
            self.assertEqual(u["bus"], FERRARI_BUSES[pos])
            self.assertEqual(u["node"], pos // 4)
            self.assertTrue(u["present"])
            self.assertEqual(u["threads"], [[c, c + 128] for c in range(first, first + 6)])
            self.assertEqual(u["hugepages_gib"], 96)
        self.assertEqual([u["position"] for u in p["units"]], list(range(8)))
        self.assertEqual(p["housekeeping"], [62, 63, 126, 127, 190, 191, 254, 255])
        self.assertEqual(len(p["pool"]), 152)
        self.assertEqual(len(p["pool_cores"]), 76)
        self.assertEqual((p["group_rule"], p["counts"]), ("partitions", [1, 2, 4, 8]))
        self.assertEqual(p["groups"], FERRARI_GROUPS)
        self.assertEqual(p["fm_partitions"], FERRARI["fm_partitions"])
        self.assertTrue(p["fabric_manager"])
        self.assertEqual(table.agent_values(p, FERRARI), {
            "host.reserved.cpu.count": str(8 + 8 * 12),
            "host.reserved.mem.mb": str((8 * 96 + 16 + 8 * 2) * 1024),
            "host.tags": "cpu,a100-80g,a100-80g-nvswitch",
        })
        self.assertEqual(table.kernel_args(p),
                         "default_hugepagesz=2M hugepagesz=1G hugepages=0:384,1:384 "
                         "irqaffinity=62-63,126-127,190-191,254-255")

    def test_ford_class_nvlink_rule_any(self):
        p = render("ford", FORD)
        self.assertEqual(p["group_rule"], "any")
        self.assertEqual(p["groups"], [])
        self.assertEqual(p["counts"], [1, 2, 4])
        self.assertEqual(p["fm_partitions"], {})
        self.assertEqual(table.agent_values(p, FORD)["host.tags"], "cpu,a100-40g,a100-40g-nvlink")
        self.assertEqual(p["pool"], [24, 25, 26, 27, 56, 57, 58, 59])
        self.assertEqual(p["housekeeping"], [28, 29, 30, 31, 60, 61, 62, 63])

    def test_agent_cpus_are_twice_the_pool_cores(self):
        for host, decl in (("jimbeam", JIMBEAM), ("i7", I7), ("jackdaniels", JACKDANIELS),
                           ("ferrari", FERRARI), ("ford", FORD)):
            with self.subTest(host=host):
                p = render(host, decl)
                reported = len(read(host).threads) - int(table.agent_values(p, decl)["host.reserved.cpu.count"])
                self.assertEqual(reported, 2 * len(p["pool_cores"]))
                self.assertEqual(sorted(p["pool"]), sorted(t for c in p["pool_cores"] for t in c["threads"]))

    def test_ferrari_class_nvswitch_needs_partitions(self):
        with self.assertRaisesRegex(PartitionError, "gpu_groups"):
            render("ferrari", declared(FERRARI, gpu_groups=None, fm_partitions=None))

    def test_any_and_single_take_no_groups(self):
        with self.assertRaisesRegex(PartitionError, "gpu_groups"):
            render("ford", declared(FORD, gpu_groups=[[0, 1]]))

    def test_class_not_in_catalog_rejected(self):
        with self.assertRaisesRegex(PartitionError, "class nvswitch"):
            render("jimbeam", declared(JIMBEAM, gpu_class="nvswitch"))

    def test_gpu_type_not_in_catalog_rejected(self):
        with self.assertRaisesRegex(PartitionError, "gpu_type rtx9000"):
            render("jimbeam", declared(JIMBEAM, gpu_type="rtx9000"))

    def test_missing_position_keeps_unit(self):
        full = render("ferrari", FERRARI)
        p = render("ferrari", FERRARI, edit=lambda root: shutil.rmtree(pci(root, FERRARI_BUSES[3])))
        self.assertFalse(p["units"][3]["present"])
        self.assertEqual(p["units"][3]["threads"], full["units"][3]["threads"])
        self.assertEqual(p["units"][3]["hugepages_gib"], 96)
        self.assertEqual(p["units"][3]["node"], 0)
        full["units"][3]["present"] = False
        self.assertEqual(p, full)

    def test_missing_position_needs_a_known_node_on_multi_node_host(self):
        def remove(root):
            shutil.rmtree(pci(root, FERRARI_BUSES[3]))
            shutil.rmtree(root / "sys/class/pci_bus" / FERRARI_BUSES[3][:7])
        with self.assertRaisesRegex(PartitionError, "NUMA node"):
            render("ferrari", FERRARI, edit=remove)

    def test_numa_node_minus_one_is_node0_on_single_node_host(self):
        p = render("i7", I7)
        self.assertEqual(p["units"][0]["node"], 0)
        self.assertTrue(p["units"][0]["present"])

    def test_numa_node_minus_one_refused_on_multi_node_host(self):
        def unknown(root):
            (pci(root, "0000:16:00.0") / "numa_node").write_text("-1\n")
        with self.assertRaisesRegex(PartitionError, "numa_node"):
            render("jimbeam", JIMBEAM, edit=unknown)

    def test_ford_rejects_unit_that_does_not_fit(self):
        with self.assertRaises(PartitionError) as e:
            render("ford", FORD, catalog=catalog_with("a100-40g", unit_vcpu=16))
        self.assertEqual(str(e.exception), "unit does not fit node 0")

    def test_rejects_non_laminar_groups(self):
        decl = declared(FERRARI, gpu_groups=[[0, 1], [1, 2]], fm_partitions={"0,1": 1, "1,2": 2})
        with self.assertRaisesRegex(PartitionError, "laminar"):
            render("ferrari", decl)

    def test_rejects_group_size_not_in_class(self):
        decl = declared(FERRARI, gpu_groups=[[0, 1, 2]], fm_partitions={"0,1,2": 1})
        with self.assertRaisesRegex(PartitionError, "size"):
            render("ferrari", decl)

    def test_fabric_manager_needs_a_partition_id_per_group(self):
        fm = dict(FERRARI["fm_partitions"])
        del fm["0,1"]
        with self.assertRaisesRegex(PartitionError, "fm_partitions"):
            render("ferrari", declared(FERRARI, fm_partitions=fm))

    def test_rejects_odd_unit_vcpu(self):
        with self.assertRaisesRegex(PartitionError, "unit_vcpu"):
            render("jimbeam", JIMBEAM, catalog=catalog_with("a6000", unit_vcpu=11))

    def test_rejects_group_with_undeclared_position(self):
        decl = declared(FERRARI, gpu_groups=[[0], [8]], fm_partitions={"0": 1, "8": 2})
        with self.assertRaisesRegex(PartitionError, "undeclared position 8"):
            render("ferrari", decl)

    def test_rejects_mixed_gpu_types_on_one_host(self):
        def other_type(root):
            (pci(root, FERRARI_BUSES[5]) / "device").write_text("0x20b0\n")
        with self.assertRaisesRegex(PartitionError, "10de:20b0"):
            render("ferrari", FERRARI, edit=other_type)

    def test_rejects_companion_function_as_position(self):
        with self.assertRaisesRegex(PartitionError, "0000:16:00.1"):
            render("jimbeam", declared(JIMBEAM, gpu_positions=["0000:16:00.1"]))

    def test_malformed_counts_refused_not_crashed(self):
        catalog = load_catalog()
        for t in catalog["gpu_types"]:
            if t["tag"] == "a100-40g":
                t["classes"]["nvlink"]["counts"] = [2, "4"]
        with self.assertRaisesRegex(PartitionError, "counts"):
            render("jimbeam", JIMBEAM, catalog=catalog)

    def test_rejects_core_without_two_threads(self):
        def smt_off(root):
            for cpu in (0, 4):
                (root / f"sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list").write_text(f"{cpu}\n")
        with self.assertRaisesRegex(PartitionError, "2 threads"):
            render("i7", I7, edit=smt_off)


class CliTest(unittest.TestCase):
    def run_cli(self, host, decl, *args):
        src = FIXTURES / f"sysfs-{host}"
        return subprocess.run(
            [sys.executable, str(CLI), "--sysfs", str(src / "sys"), "--proc", str(src / "proc"),
             "--declared", json.dumps(decl), "--catalog", str(CATALOG_FILE), *args],
            capture_output=True, text=True)

    def test_cli_writes_partition_and_prints_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "partition.json"
            r = self.run_cli("jimbeam", JIMBEAM, "--out", str(out), "--agent-values", "--kernel-args")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stderr, "")
            self.assertEqual(json.loads(r.stdout), {
                "changed": True,
                "agent_values": {
                    "host.reserved.cpu.count": "14",
                    "host.reserved.mem.mb": "30720",
                    "host.tags": "cpu,a6000,a6000-pcie",
                },
                "kernel_args": "default_hugepagesz=2M hugepagesz=1G hugepages=0:24 irqaffinity=15,31",
            })
            self.assertEqual(json.loads(out.read_text()), render("jimbeam", JIMBEAM))
            again = self.run_cli("jimbeam", JIMBEAM, "--out", str(out))
            self.assertEqual(json.loads(again.stdout), {"changed": False})

    def test_cli_refuses_with_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "partition.json"
            r = self.run_cli("jimbeam", declared(JIMBEAM, gpu_class="nvlink"), "--out", str(out))
            self.assertEqual(r.returncode, 1)
            self.assertEqual(r.stdout, "")
            self.assertIn("class nvlink", r.stderr)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
