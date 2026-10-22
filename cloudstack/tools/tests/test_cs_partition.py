import builtins
import importlib
import io
import json
import os
import sys
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cs_partition  # noqa: E402


def fake_cs(command, **params):
    configs = {
        ("gpu.detach.on.stop", None): "false",
        ("gpu.detach.on.stop", "d-snucse"): "true",
        ("capacity.skipcounting.hours", None): "3600",
        ("drs.automatic.enable", "c-1"): "false",
        ("storage.overprovisioning.factor", "p-1"): "2.0",
    }
    if command == "listConfigurations":
        if "keyword" in params:
            return {"configuration": [{"name": "max.account.gpus", "value": "20"},
                                      {"name": "max.account.cpus", "value": "40"},
                                      {"name": "not.max", "value": "x"}]}
        scope = params.get("domainid") or params.get("clusterid") or params.get("storageid")
        value = configs.get((params["name"], scope))
        return {"configuration": [{"name": params["name"], "value": value}]} if value is not None else {}
    if command == "listDomains":
        return {"domain": [{"id": "d-root", "path": "ROOT"}, {"id": "d-snucse", "path": "ROOT/snucse"}]}
    if command == "listClusters":
        return {"cluster": [{"id": "c-1", "name": "302bldg-kvm"}]}
    if command == "listStoragePools":
        return {"storagepool": [{"id": "p-1", "name": "derby-local", "scope": "HOST", "type": "Filesystem"}]}
    if command == "listVirtualMachines":
        return {"virtualmachine": [{"id": "v1", "serviceofferingname": "small"}]}
    if command == "listServiceOfferings":
        return {"serviceoffering": [{"name": "small", "cpunumber": 1, "cpuspeed": 2000, "memory": 4096,
                                     "offerha": False}]}
    if command == "listHosts":
        return {"host": [{"name": "derby", "cpuspeed": 3600, "cpunumber": 8},
                         {"name": "jackdaniels", "cpuspeed": 2400, "cpunumber": 28}]}
    if command == "listGpuCards":
        return {"gpucard": [{"name": "NVIDIA RTX A6000", "id": "g1", "vendorid": "10de", "deviceid": "2230"}]}
    if command == "listSystemVms":
        return {"systemvm": [{"name": "s-1-VM", "id": "sv1"}]}
    if command == "listRouters":
        return {"router": []}
    if command == "listVolumes":
        assert params.get("listsystemvms") == "true"
        return {"volume": [{"vmname": "s-1-VM", "storage": "derby-local", "storageid": "p-1"},
                           {"vmname": "user-vm", "storage": "derby-local", "storageid": "p-1"}]}
    raise AssertionError(command)


class ShowConfigTest(unittest.TestCase):
    def setUp(self):
        self.text = cs_partition.render(cs_partition.collect(fake_cs))

    def test_show_config_lists_domain_overrides(self):
        self.assertIn("global gpu.detach.on.stop = false", self.text)
        self.assertIn("domain ROOT/snucse gpu.detach.on.stop = true", self.text)
        self.assertIn("domain ROOT gpu.detach.on.stop = None", self.text)

    def test_unknown_keys_print_none(self):
        self.assertIn("global vm.allocation.algorithm = None", self.text)

    def test_only_max_account_keys(self):
        self.assertIn("global max.account.gpus = 20", self.text)
        self.assertNotIn("not.max", self.text)

    def test_min_host_speed_and_pool_scope(self):
        self.assertIn("min host cpuspeed = 2400", self.text)
        self.assertIn("pool derby-local storage.overprovisioning.factor=2.0 scope=HOST type=Filesystem", self.text)
        self.assertIn("system vm root s-1-VM pool=derby-local scope=HOST", self.text)

    def test_offering_vm_count(self):
        self.assertIn("name=small", self.text)
        self.assertIn("vms=1", self.text)


INVENTORY = {"all": {
    "vars": {"ansible_user": "root"},
    "children": {
        "cloudstack_hosts": {"hosts": {
            "derby": {"ansible_host": "derby.snucse.org", "gpu_type": "gtx1080"},
            "jackdaniels": {"ansible_host": "jackdaniels.snucse.org"},
            "ferrari": {"ansible_host": "ferrari.snucse.org"},
        }},
        "cloudstack_gateway": {"hosts": {"derby": None, "jackdaniels": None}},
        "bacchus_login": {"vars": {"ansible_user": "bacchus", "ansible_become": True},
                          "hosts": {"jackdaniels": None}},
    },
}}

POSITIONS = ["0000:07:00.0", "0000:0f:00.0", "0000:47:00.0", "0000:4e:00.0"]
# a host of the partitions rule: four positions, pairs and the whole set
FERRARI = {
    "gpu_type": "a100-80g", "gpu_class": "nvswitch", "group_rule": "partitions", "counts": [1, 2, 4],
    "units": [{"position": p, "bus": bus, "present": True, "node": p // 2, "threads": [], "hugepages_gib": 96}
              for p, bus in enumerate(POSITIONS)],
    "groups": [[0], [1], [2], [3], [0, 1], [2, 3], [0, 1, 2, 3]],
    "pool_cores": [{"node": 0, "threads": [10, 42]}, {"node": 1, "threads": [26, 58]}],
}
JACKDANIELS = {
    "gpu_type": None, "gpu_class": None, "group_rule": None, "counts": [], "units": [], "groups": [],
    "pool_cores": [{"node": 0, "threads": [c, c + 14]} for c in range(1, 14)],
}
DERBY = {
    "gpu_type": "gtx1080", "gpu_class": "pcie", "group_rule": "single", "counts": [1],
    "units": [{"position": 0, "bus": "0000:01:00.0", "present": True, "node": 0, "threads": [], "hugepages_gib": 12}],
    "groups": [], "pool_cores": [],
}


class FakeZone:
    """The admin API of a zone with three hosts, as the partition tool calls it."""

    def __init__(self):
        self.calls = []
        self.hosts = [{"id": "h-derby", "name": "derby", "cpunumber": 0},
                      {"id": "h-jd", "name": "jackdaniels", "cpunumber": 26},
                      {"id": "h-ferrari", "name": "ferrari", "cpunumber": 4}]
        self.groups = {}
        self.cores = {}
        self.domains = [{"id": "d-root", "path": "ROOT"}, {"id": "d-snucse", "path": "ROOT/snucse"},
                        {"id": "d-other", "path": "ROOT/other"}]
        self.accounts = [{"id": "a-1", "name": "alice", "domainid": "d-snucse", "accounttype": 0, "roletype": "User"},
                         {"id": "a-2", "name": "bob", "domainid": "d-snucse", "accounttype": 0, "roletype": "User"},
                         {"id": "a-3", "name": "bob", "domainid": "d-other", "accounttype": 0, "roletype": "User"},
                         {"id": "a-4", "name": "member", "domainid": "d-root", "accounttype": 1, "roletype": "Admin"}]

    def __call__(self, command, post=False, **params):
        self.calls.append((command, params))
        if command == "listHosts":
            hosts = [h for h in self.hosts if params.get("name") in (None, h["name"])]
            return {"host": [dict(h) for h in hosts]}
        if command == "updateHostGpuGroups":
            self.groups[params["hostid"]] = json.loads(params["groups"])
            return {"hostgpugroups": {"hostid": params["hostid"]}}
        if command == "updateHostPoolCores":
            cores = json.loads(params["cores"])
            self.cores[params["hostid"]] = [{"hostid": params["hostid"], "core": c["threads"][0], **c} for c in cores]
            return {"hostpoolcore": self.cores[params["hostid"]]}
        if command == "listHostGpuGroups":
            rule = self.groups.get(params["hostid"])
            if rule is None:
                return {}
            groups = sorted(sorted(g) for g in rule.get("groups", []))
            return {"hostgpugroups": [{"hostid": params["hostid"], "rule": rule["rule"],
                                       **({"groups": groups} if groups else {})}]}
        if command == "listHostPoolCores":
            return {"hostpoolcore": list(self.cores.get(params["hostid"], []))}
        if command == "updateHostMoveRate":
            return {"success": True}
        if command == "listDomains":
            return {"domain": list(self.domains)}
        if command == "listAccounts":
            return {"account": [dict(a) for a in self.accounts if a["name"] == params.get("name")]}
        if command == "createResourceLimitRequest":
            return {"resourcelimitrequest": {"id": "req-1", "state": "Pending"}}
        if command == "approveResourceLimitRequest":
            return {"resourcelimitrequest": {"id": params["id"], "state": "Approved"}}
        raise AssertionError(command)

    def writes(self):
        return [(c, p) for c, p in self.calls if not c.startswith("list")]


class PartitionToolTest(unittest.TestCase):
    LIVE = {"derby": DERBY, "jackdaniels": JACKDANIELS, "ferrari": FERRARI}

    def setUp(self):
        self.zone = FakeZone()
        self.ssh = []

        def run(argv, **kwargs):
            self.ssh.append(argv)
            host = argv[-3].split("@")[1].split(".")[0]
            return mock.Mock(returncode=0, stdout=json.dumps(self.LIVE[host]), stderr="")

        for p in (mock.patch.object(cs_partition.subprocess, "run", run),
                  mock.patch.object(cs_partition, "load_inventory", lambda: INVENTORY)):
            p.start()
            self.addCleanup(p.stop)

    def tool(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            status = cs_partition.main(list(argv), cs=self.zone)
        return status, out.getvalue()

    def test_ssh_destination_follows_the_inventory(self):
        self.assertEqual(cs_partition.ssh_destination("derby", INVENTORY), "root@derby.snucse.org")
        self.assertEqual(cs_partition.ssh_destination("jackdaniels", INVENTORY), "bacchus@jackdaniels.snucse.org")
        with self.assertRaisesRegex(ValueError, "not in the inventory"):
            cs_partition.ssh_destination("porsche", INVENTORY)

    def test_register_groups_reads_live_partition_json_not_fixture_render(self):
        opened = []
        real_open = builtins.open

        def watch(path, *args, **kwargs):
            opened.append(str(path))
            return real_open(path, *args, **kwargs)

        with mock.patch("builtins.open", watch):
            status, _ = self.tool("register-groups", "jackdaniels")
        self.assertEqual(status, 0)
        self.assertEqual(self.ssh, [["ssh", "-o", "BatchMode=yes", "-J", "martini", "bacchus@jackdaniels.snucse.org",
                                     "cat", "/etc/cloudstack/agent/partition.json"]])
        self.assertFalse([p for p in opened if p.endswith("partition.json")], "a local partition file was read")
        registered = [c["threads"] for c in self.zone.cores["h-jd"]]
        self.assertEqual(registered, [c["threads"] for c in JACKDANIELS["pool_cores"]])

    def test_register_groups_registers_groups_and_pool_cores(self):
        status, out = self.tool("register-groups", "ferrari")
        self.assertEqual(status, 0)
        self.assertEqual([c for c, _ in self.zone.writes()], ["updateHostPoolCores", "updateHostGpuGroups"])
        self.assertEqual(json.loads(self.zone.writes()[0][1]["cores"]), FERRARI["pool_cores"])
        self.assertEqual(self.zone.groups["h-ferrari"], {"rule": "partitions", "groups": [
            [POSITIONS[0]], [POSITIONS[1]], [POSITIONS[2]], [POSITIONS[3]],
            POSITIONS[:2], POSITIONS[2:], POSITIONS]})
        status, _ = self.tool("register-groups", "derby")
        self.assertEqual(self.zone.groups["h-derby"], {"rule": "single"})
        self.assertEqual(self.zone.cores["h-derby"], [], "a host without pool cores registers none")
        self.zone.calls.clear()
        status, out = self.tool("register-groups", "jackdaniels")
        self.assertEqual([c for c, _ in self.zone.writes()], ["updateHostPoolCores"])
        self.assertIn("no GPUs", out)

    def test_register_groups_pool_cores_only_registers_no_gpu_groups(self):
        status, _ = self.tool("register-groups", "ferrari", "--pool-cores")
        self.assertEqual(status, 0)
        self.assertEqual([c for c, _ in self.zone.writes()], ["updateHostPoolCores"])
        self.assertNotIn("h-ferrari", self.zone.groups)

    def test_register_groups_of_an_unknown_host_fails(self):
        status, out = self.tool("register-groups", "porsche")
        self.assertEqual(status, 1)
        self.assertEqual(self.zone.writes(), [])

    def test_check_groups_detects_difference(self):
        for host in ("derby", "jackdaniels", "ferrari"):
            self.tool("register-groups", host)
        status, out = self.tool("check-groups")
        self.assertEqual((status, out.strip().splitlines()[-1]), (0, "every host: the registration matches the partition"))
        # a group the host does not have
        self.zone.groups["h-ferrari"]["groups"][-1] = POSITIONS[:3]
        status, out = self.tool("check-groups")
        self.assertEqual(status, 1)
        self.assertIn("ferrari: GPU groups", out)
        self.assertNotIn("jackdaniels:", out)
        self.assertEqual(self.tool("check-groups", "--pool-cores")[0], 0, "--pool-cores compares only the pool cores")
        # the agent counting other CPUs than twice the pool cores
        self.zone.hosts[1]["cpunumber"] = 28
        status, out = self.tool("check-groups", "jackdaniels")
        self.assertEqual(status, 1)
        self.assertIn("jackdaniels: the agent reports 28 CPUs, twice the 13 pool cores is 26", out)
        self.assertEqual(self.tool("check-groups", "jackdaniels", "--pool-cores")[0], 0,
                         "before the agent reports the partition, the pool cores alone can match")
        # a missing pool core
        self.zone.cores["h-jd"].pop()
        status, out = self.tool("check-groups", "jackdaniels", "--pool-cores")
        self.assertEqual(status, 1)
        self.assertIn("jackdaniels: pool cores", out)

    def test_check_groups_checks_the_named_hosts(self):
        self.tool("register-groups", "jackdaniels", "--pool-cores")
        self.ssh.clear()
        status, out = self.tool("check-groups", "jackdaniels", "--pool-cores")
        self.assertEqual((status, out.strip()), (0, "jackdaniels: the registration matches the partition"))
        self.assertEqual([argv[-3] for argv in self.ssh], ["bacchus@jackdaniels.snucse.org"], "only the named host is read")
        self.tool("register-groups", "derby")
        self.assertEqual(self.tool("check-groups", "derby")[0], 0, "a host is checked after its own registration")
        status, out = self.tool("check-groups")
        self.assertEqual(status, 1, "without names every host is checked, and ferrari is not registered")
        self.assertIn("ferrari: GPU groups registered none", out)
        status, out = self.tool("check-groups", "porsche")
        self.assertEqual(status, 1)
        self.assertIn("porsche: not a KVM host of the zone", out)

    def test_an_api_error_shows_the_servers_reason(self):
        for key, value in (("CLOUDSTACK_API_URL", "http://cloudstack.test/client/api"), ("CLOUDSTACK_API_KEY", "k"),
                           ("CLOUDSTACK_SECRET_KEY", "s")):
            os.environ.setdefault(key, value)
        sys.path.insert(0, str(cs_partition.SYNC_DIR))
        self.addCleanup(sys.path.remove, str(cs_partition.SYNC_DIR))
        sync = importlib.import_module("sync")

        def refusing(command, post=False, **params):
            if command.startswith("list"):
                return self.zone(command, **params)
            raise urllib.error.HTTPError("http://cloudstack.test/client/api", 431, "", {},
                                         io.BytesIO(b'{"errortext": "alice already has a pending request"}'))

        out = io.StringIO()
        with mock.patch.object(cs_partition, "SYNC", sync), redirect_stdout(out):
            status = cs_partition.main(["set-quota", "alice", "--cpu", "2", "--memory", "2048", "--storage", "20",
                                        "--expiry", "2026-12-31"], cs=refusing)
        self.assertEqual(status, 1)
        self.assertIn("alice already has a pending request", out.getvalue())

    def test_set_move_rate_calls_update_host_move_rate(self):
        status, _ = self.tool("set-move-rate", "jackdaniels", "920")
        self.assertEqual(status, 0)
        self.assertEqual(self.zone.writes(), [("updateHostMoveRate", {"hostid": "h-jd", "mbps": 920})])

    def test_set_quota_creates_and_approves_grant(self):
        status, out = self.tool("set-quota", "alice", "--cpu", "8", "--memory", "16384", "--storage", "200",
                                "--gpu", "a6000=1", "--gpu", "gtx1080=2", "--expiry", "2026-12-31")
        self.assertEqual(status, 0)
        self.assertEqual(self.zone.writes(), [
            ("createResourceLimitRequest", {"account": "alice", "domainid": "d-snucse", "cpu": 8, "memory": 16384,
                                            "storage": 200, "expiry": "2026-12-31",
                                            "gpu[0].type": "a6000", "gpu[0].count": 1,
                                            "gpu[1].type": "gtx1080", "gpu[1].count": 2}),
            ("approveResourceLimitRequest", {"id": "req-1"})])
        self.assertNotIn("updateResourceLimit", [c for c, _ in self.zone.calls])

    def test_set_quota_names_the_domain_of_an_ambiguous_account(self):
        args = ("--cpu", "2", "--memory", "2048", "--storage", "20", "--expiry", "2026-12-31")
        status, out = self.tool("set-quota", "bob", *args)
        self.assertEqual((status, self.zone.writes()), (1, []))
        self.assertIn("--domain", out)
        status, _ = self.tool("set-quota", "bob", "--domain", "ROOT/other", *args)
        self.assertEqual(status, 0)
        self.assertEqual(self.zone.writes()[0][1]["domainid"], "d-other")

    def test_set_quota_skips_admin_type_accounts(self):
        status, out = self.tool("set-quota", "member", "--cpu", "8", "--memory", "16384", "--storage", "200",
                                "--expiry", "2026-12-31")
        self.assertEqual(status, 0)
        self.assertEqual(self.zone.writes(), [])
        self.assertIn("member: Admin-type account, skipped", out)

    def test_no_set_config(self):
        with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            cs_partition.main(["set-config", "capacity.skipcounting.hours", "0"], cs=self.zone)


if __name__ == "__main__":
    unittest.main()
