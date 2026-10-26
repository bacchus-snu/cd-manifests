import base64
import importlib
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import tomllib
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest import mock

os.environ.setdefault("CLOUDSTACK_API_URL", "http://cloudstack.test/client/api")
os.environ.setdefault("CLOUDSTACK_API_KEY", "k")
os.environ.setdefault("CLOUDSTACK_SECRET_KEY", "s")
sync = importlib.import_module("sync")


class GuestAccountsTest(unittest.TestCase):
    def test_parses_tags_into_username_to_ids(self):
        vm = {"tags": [
            {"key": "ssh.account.foo", "value": "Alice, bob,alice,"},
            {"key": "ssh.account.bar", "value": "carol"},
            {"key": "unrelated", "value": "x"},
        ]}
        self.assertEqual(sync.guest_accounts(vm), {"foo": ["alice", "bob"], "bar": ["carol"]})

    def test_ignores_invalid_usernames_and_empty_values(self):
        vm = {"tags": [
            {"key": "ssh.account.Bad Name", "value": "alice"},
            {"key": "ssh.account.", "value": "alice"},
            {"key": "ssh.account.ok", "value": " , "},
        ]}
        self.assertEqual(sync.guest_accounts(vm), {})

    def test_no_tags(self):
        self.assertEqual(sync.guest_accounts({}), {})

    def test_numbered_continuation_tags_merge_in_order(self):
        vm = {"tags": [
            {"key": "ssh.account.student.2", "value": "eve,alice"},
            {"key": "ssh.account.student", "value": "alice,bob"},
            {"key": "ssh.account.student.1", "value": "carol, dave"},
            {"key": "ssh.account.student.x", "value": "mallory"},
        ]}
        self.assertEqual(sync.guest_accounts(vm), {"student": ["alice", "bob", "carol", "dave", "eve"]})


class PlanTargetsTest(unittest.TestCase):
    def test_base_and_guest_targets(self):
        vms = [{
            "id": "vm-1", "name": "Web1", "account": "alice",
            "nic": [{"ipaddress": "10.94.1.5"}],
            "tags": [{"key": "ssh.account.foo", "value": "bob,carol"}],
        }, {
            "id": "vm-2", "name": "proj1", "account": "PrjAcct-1", "projectid": "p-1",
            "nic": [{"ipaddress": "10.94.1.6"}],
        }, {
            "id": "vm-3", "name": "noip", "account": "alice", "nic": [],
        }]
        members = {"p-1": {"dave", "erin"}}
        wanted, reach = sync.plan_targets(vms, members)
        self.assertEqual(set(wanted), {"web1", "web1:foo", "proj1"})
        self.assertEqual(wanted["web1"]["options"]["username"], "ubuntu")
        self.assertEqual(wanted["web1:foo"]["options"]["username"], "foo")
        self.assertEqual(wanted["web1:foo"]["options"]["host"], "10.94.1.5")
        self.assertEqual(wanted["web1:foo"]["description"], "cloudstack:vm:vm-1:guest:foo")
        self.assertEqual(reach["web1"], {"account-alice"})
        self.assertEqual(reach["web1:foo"], {"account-bob", "account-carol"})
        self.assertEqual(reach["proj1"], {"account-dave", "account-erin"})

    def test_targets_carry_every_required_field(self):
        wanted, _ = sync.plan_targets([{"id": "vm-1", "name": "a", "account": "alice",
                                        "nic": [{"ipaddress": "10.94.1.5"}]}], {})
        # the bastion's API rejects a target write that leaves any of these out
        self.assertIs(wanted["a"]["options"]["allow_insecure_algos"], False)
        self.assertIs(wanted["a"]["ticket_requests_disabled"], True)
        self.assertIs(wanted["a"]["ticket_require_approval"], True)
        self.assertIs(wanted["a"]["require_approval"], False)

    def test_the_target_follows_the_ssh_name(self):
        vms = [{"id": "vm-1", "name": "snucse-bob-test", "sshname": "snucse-bob-web", "account": "bob",
                "nic": [{"ipaddress": "10.94.1.5"}], "tags": [{"key": "ssh.account.foo", "value": "carol"}]},
               {"id": "vm-2", "name": "VM-3c34a293", "account": "bob", "nic": [{"ipaddress": "10.94.1.6"}]}]
        wanted, reach = sync.plan_targets(vms, {})
        self.assertEqual(set(wanted), {"snucse-bob-web", "snucse-bob-web:foo", "vm-3c34a293"})
        self.assertEqual(reach["snucse-bob-web:foo"], {"account-carol"})

    def test_a_shared_target_name_reaches_none_of_its_vms(self):
        vms = [{"id": "vm-1", "name": "Web", "account": "alice", "nic": [{"ipaddress": "10.94.1.5"}]},
               {"id": "vm-2", "name": "x", "sshname": "web", "account": "mallory", "nic": [{"ipaddress": "10.94.1.6"}],
                "tags": [{"key": "ssh.account.root", "value": "mallory"}]},
               {"id": "vm-3", "name": "other", "account": "bob", "nic": [{"ipaddress": "10.94.1.7"}]}]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            wanted, reach = sync.plan_targets(vms, {})
        self.assertEqual(set(wanted), {"other"})
        self.assertEqual(set(reach), {"other"})
        self.assertIn("vm-1, vm-2 share the target name web", out.getvalue())


class TargetRenamesTest(unittest.TestCase):
    def target(self, tid, name, description):
        return {"id": tid, "name": name, "description": description, "options": {"host": "10.94.1.5", "username": "ubuntu"}}

    def test_a_renamed_vm_keeps_its_targets(self):
        old = self.target("t1", "snucse-bob-old", "cloudstack:vm:vm-1:root:v1")
        guest = self.target("t2", "snucse-bob-old:foo", "cloudstack:vm:vm-1:guest:foo")
        wanted = {"snucse-bob-new": {"description": "cloudstack:vm:vm-1:root:v2"},
                  "snucse-bob-new:foo": {"description": "cloudstack:vm:vm-1:guest:foo"}}
        renames = sync.target_renames(wanted, {t["name"]: t for t in (old, guest)})
        self.assertEqual({n: t["id"] for n, t in renames.items()}, {"snucse-bob-new": "t1", "snucse-bob-new:foo": "t2"})

    def test_a_name_still_wanted_or_unmanaged_is_never_taken(self):
        # vm-1 moved from x to y while vm-2 took x: x's target goes to vm-2 by name, and y is a new target
        x = self.target("t1", "x", "cloudstack:vm:vm-1:root:v1")
        other = self.target("t3", "z", "vm:vm-3:root:v3")
        wanted = {"x": {"description": "cloudstack:vm:vm-2:root:v2"},
                  "y": {"description": "cloudstack:vm:vm-1:root:v1"},
                  "w": {"description": "cloudstack:vm:vm-3:root:v3"}}
        self.assertEqual(sync.target_renames(wanted, {"x": x, "z": other}), {})

    def test_a_target_already_named_right_is_left_to_the_update(self):
        t = self.target("t1", "x", "cloudstack:vm:vm-1:root:v1")
        self.assertEqual(sync.target_renames({"x": {"description": "cloudstack:vm:vm-1:root:v2"}}, {"x": t}), {})


class CloseSessionsTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        sessions = {"items": [
            {"id": "s1", "username": "bob", "target_sessions": [{"id": "ts1", "target_id": "t1"}]},
            {"id": "s2", "username": "carol", "target_sessions": [{"id": "ts2", "target_id": "t1"}]},
            {"id": "s3", "username": "bob", "target_sessions": [{"id": "ts3", "target_id": "t2"}]},
        ], "offset": 0, "total": 3}

        def fake(method, path, body=None):
            self.calls.append((method, path))
            if method == "GET" and path.startswith("/sessions"):
                return 200, sessions
            return 200, None
        self._orig = sync.warpgate
        sync.warpgate = fake

    def tearDown(self):
        sync.warpgate = self._orig

    def test_closes_only_matching_user_and_target(self):
        sync.close_sessions("t1", {"bob"})
        self.assertIn(("POST", "/sessions/s1/close"), self.calls)
        self.assertNotIn(("POST", "/sessions/s2/close"), self.calls)
        self.assertNotIn(("POST", "/sessions/s3/close"), self.calls)

    def test_closes_all_on_target_when_no_user_filter(self):
        sync.close_sessions("t1", None)
        self.assertIn(("POST", "/sessions/s1/close"), self.calls)
        self.assertIn(("POST", "/sessions/s2/close"), self.calls)
        self.assertNotIn(("POST", "/sessions/s3/close"), self.calls)


class UserRolesTest(unittest.TestCase):
    ROLES = {"admins": {"id": "r-admins"}, "account-bob": {"id": "r-bob"}}

    def setUp(self):
        self.calls, self.assigned = [], []

        def fake(method, path, body=None):
            self.calls.append((method, path))
            if method == "GET":
                return 200, self.assigned
            return 200, None
        self._orig = sync.warpgate
        sync.warpgate = fake

    def tearDown(self):
        sync.warpgate = self._orig

    def test_regrants_revoked_role(self):
        self.assigned = [{"name": "account-bob", "is_active": True}, {"name": "admins", "is_active": False}]
        revoked = sync.sync_user_roles({"id": "u1", "username": "bob"}, {"account-bob", "admins"}, self.ROLES)
        self.assertEqual(self.calls[1:], [("POST", "/users/u1/roles/r-admins")])
        self.assertEqual(revoked, set())

    def test_revokes_active_admin_rights(self):
        self.assigned = [{"name": "account-bob", "is_active": True}, {"name": "admins", "is_active": True},
                         {"name": "admin", "is_active": True}]
        revoked = sync.sync_user_roles({"id": "u1", "username": "bob"}, {"account-bob"}, self.ROLES)
        self.assertEqual(self.calls[1:], [("DELETE", "/users/u1/roles/r-admins")])
        self.assertEqual(revoked, {"admins"})

    def test_already_revoked_is_left_alone(self):
        self.assigned = [{"name": "account-bob", "is_active": True}, {"name": "admins", "is_active": False}]
        revoked = sync.sync_user_roles({"id": "u1", "username": "bob"}, {"account-bob"}, self.ROLES)
        self.assertEqual(self.calls[1:], [])
        self.assertEqual(revoked, set())


class DemotedSessionsTest(unittest.TestCase):
    def setUp(self):
        self.closed = []
        self._orig = sync.close_sessions
        sync.close_sessions = lambda target_id, usernames=None: self.closed.append((target_id, usernames))

    def tearDown(self):
        sync.close_sessions = self._orig

    def test_closes_only_where_own_account_does_not_reach(self):
        reach = {"vm-bob": {"account-bob"}, "vm-carol": {"account-carol"},
                 "vm-carol-guest-bob": {"account-bob"}, "vm-new": {"account-carol"}}
        targets = {"vm-bob": {"id": "t-bob"}, "vm-carol": {"id": "t-carol"},
                   "vm-carol-guest-bob": {"id": "t-guest"}, "manual": {"id": "t-manual"}}
        sync.close_demoted_sessions({"bob": "account-bob"}, targets, reach)
        self.assertEqual(self.closed, [("t-carol", {"bob"})])

    def test_nothing_without_demotions(self):
        sync.close_demoted_sessions({}, {"vm-carol": {"id": "t-carol"}}, {"vm-carol": {"account-carol"}})
        self.assertEqual(self.closed, [])


class TrustScriptTest(unittest.TestCase):
    def test_script_contains_keys_and_sshd_dropin(self):
        script = sync.render_trust_script(["ssh-ed25519 BBB warpgate", "ssh-ed25519 AAA warpgate"])
        self.assertTrue(script.startswith("#!/bin/sh\n"))
        self.assertIn("cat > /etc/ssh/warpgate_keys <<'EOF'\nssh-ed25519 AAA warpgate\nssh-ed25519 BBB warpgate\nEOF\n", script)
        self.assertIn("AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/warpgate_keys", script)
        self.assertIn("/etc/ssh/sshd_config.d/50-warpgate.conf", script)

    def test_shell_options_stay_inside(self):
        # CloudStack appends a user's script to this one as text
        script = sync.render_trust_script(["ssh-ed25519 AAA warpgate"])
        self.assertTrue(script.startswith("#!/bin/sh\n(\nset -e\n"))
        self.assertTrue(script.endswith("\n)\n"))
        failing = re.sub(r"(?s)\nset -e\n.*\n\)\n$", "\nset -e\nfalse\n)\n", script)
        out = subprocess.run(["sh", "-c", failing + "\n\necho user part ran\n"], capture_output=True, text=True)
        self.assertIn("user part ran", out.stdout)


class NetworkHookTest(unittest.TestCase):
    """Runs the rendered boot hook under sh against a stand-in cloudinit package."""
    FALLBACK = {"version": 2, "ethernets": {"eth0": {"dhcp4": True, "match": {"macaddress": "1e:00:00:00:00:01"}, "set-name": "eth0"}}}
    STAGES = '''
import json, os
STATE = os.environ["FAKE_CLOUDINIT"]

def _load():
    with open(STATE) as f:
        return json.load(f)

class _Distro:
    def generate_fallback_config(self):
        return _load()["fallback"]

    def apply_network_config(self, cfg, bring_up=False):
        s = _load()
        s["applied"].append([cfg, bring_up])
        with open(STATE, "w") as f:
            json.dump(s, f)
        return s["no_activator"]

class _DataSource:
    source = "/dev/sr1"

class Init:
    distro = _Distro()

    def read_cfg(self):
        pass

    def fetch(self, existing="check"):
        ds = _DataSource()
        if "network_json" in _load():
            ds.network_json = _load()["network_json"]
        return ds
'''
    UTIL = '''
import json, os

def mount_cb(device, callback):
    with open(os.environ["FAKE_CLOUDINIT"]) as f:
        drive = json.load(f)["drive"]
    if device != "/dev/sr1" or drive is None:
        raise OSError("cannot mount " + device)
    return callback(drive)
'''
    # stands in for cloud-init's interpreter and insists on isolation
    PYTHON = '''#!/bin/sh
[ "$1" = -I ] && [ "$2" = - ] || { echo "interpreter not isolated: $*" >&2; exit 97; }
exec %s -c 'import sys; sys.path.insert(0, sys.argv[1]); exec(compile(sys.stdin.read(), "<stdin>", "exec"))' "$ROOT/py"
'''
    MTUS = {"10.94.0.0/16": 1450, "192.168.0.0/24": 1500}

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        os.makedirs(f"{self.root}/bin")
        os.makedirs(f"{self.root}/py/cloudinit")
        open(f"{self.root}/py/cloudinit/__init__.py", "w").close()
        for name, body in (("stages", self.STAGES), ("util", self.UTIL)):
            with open(f"{self.root}/py/cloudinit/{name}.py", "w") as f:
                f.write(body)
        os.makedirs(f"{self.root}/drive/cloudstack/metadata")
        with open(f"{self.root}/drive/cloudstack/metadata/local-ipv4.txt", "w") as f:
            f.write("10.94.1.5\n")
        stubs = {"cloud-init": f"#!{self.root}/bin/python\n", "python": self.PYTHON % sys.executable,
                 "ifup": '#!/bin/sh\necho "$@" >> "$ROOT/ifup.log"\n'}
        for name, body in stubs.items():
            with open(f"{self.root}/bin/{name}", "w") as f:
                f.write(body)
            os.chmod(f"{self.root}/bin/{name}", 0o755)
        with open(f"{self.root}/route", "w") as f:
            f.write("Iface\tDestination\tGateway\neth0\t00000000\t01005E0A\n")
        self.cfg = f"{self.root}/90-network-fallback.cfg"
        with open(f"{self.root}/hook.sh", "w") as f:
            f.write(sync.render_network_hook(self.MTUS).replace(sync.NETWORK_FALLBACK_CFG, self.cfg)
                    .replace("/proc/net/route", f"{self.root}/route").replace("time.sleep(1)", "time.sleep(0)"))

    def run_hook(self, **state):
        state = {"fallback": self.FALLBACK, "applied": [], "no_activator": False, "drive": f"{self.root}/drive", **state}
        with open(f"{self.root}/state.json", "w") as f:
            json.dump(state, f)
        env = {**os.environ, "ROOT": self.root, "PATH": f"{self.root}/bin:{os.environ['PATH']}",
               "FAKE_CLOUDINIT": f"{self.root}/state.json"}
        out = subprocess.run(["sh", f"{self.root}/hook.sh"], env=env, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(f"{self.root}/state.json") as f:
            return json.load(f)["applied"]

    def kept(self):
        with open(self.cfg) as f:
            return json.load(f)

    def ifup_calls(self):
        try:
            with open(f"{self.root}/ifup.log") as f:
                return f.read().split()
        except FileNotFoundError:
            return []

    def with_mtu(self, mtu):
        cfg = json.loads(json.dumps(self.FALLBACK))
        cfg["ethernets"]["eth0"]["mtu"] = mtu
        return cfg

    def test_empty_description_gets_the_fallback_with_the_mtu(self):
        applied = self.run_hook(network_json={})
        self.assertEqual(applied, [[self.with_mtu(1450), True]])
        self.assertEqual(self.kept(), {"network": self.with_mtu(1450)})
        self.assertEqual(self.ifup_calls(), [])

    def test_no_description_gets_the_mtu_too(self):
        self.assertEqual(self.run_hook(network_json=None), [[self.with_mtu(1450), True]])

    def test_address_outside_the_table_keeps_dhcp_mtu(self):
        with open(f"{self.root}/drive/cloudstack/metadata/local-ipv4.txt", "w") as f:
            f.write("172.16.0.9\n")
        self.assertEqual(self.run_hook(network_json={}), [[self.FALLBACK, True]])

    def test_unreadable_drive_keeps_dhcp_mtu(self):
        self.assertEqual(self.run_hook(network_json={}, drive=None), [[self.FALLBACK, True]])

    def test_current_fallback_is_left_alone(self):
        self.run_hook(network_json={})
        self.assertEqual(self.run_hook(network_json={}), [])

    def test_stale_fallback_is_replaced(self):
        with open(self.cfg, "w") as f:
            json.dump({"network": {"version": 2, "ethernets": {"eth0": {"match": {"macaddress": "1e:00:00:00:00:99"}}}}}, f)
        self.assertEqual(self.run_hook(network_json={}), [[self.with_mtu(1450), True]])
        self.assertEqual(self.kept(), {"network": self.with_mtu(1450)})

    def test_ifup_without_an_activator(self):
        self.run_hook(network_json={}, no_activator=True)
        self.assertEqual(self.ifup_calls(), ["eth0"])

    def test_ifup_when_activation_leaves_no_route(self):
        # cloud-init may pick an activator for a network service the guest does not run
        with open(f"{self.root}/route", "w") as f:
            f.write("Iface\tDestination\tGateway\n")
        self.assertEqual(self.run_hook(network_json={}), [[self.with_mtu(1450), True]])
        self.assertEqual(self.ifup_calls(), ["eth0"])

    def test_described_network_drops_the_kept_fallback(self):
        self.run_hook(network_json={})
        links = {"links": [{"id": "eth0", "type": "phy"}], "networks": []}
        self.assertEqual(self.run_hook(network_json=links), [])
        self.assertFalse(os.path.exists(self.cfg))

    def test_other_datasources_are_left_alone(self):
        self.assertEqual(self.run_hook(), [])

    def test_no_cloud_init(self):
        os.remove(f"{self.root}/bin/cloud-init")
        env = {**os.environ, "PATH": f"{self.root}/bin:/usr/bin:/bin"}
        out = subprocess.run(["sh", f"{self.root}/hook.sh"], env=env, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)


class UserDataTest(unittest.TestCase):
    KEYS = ["ssh-ed25519 AAA warpgate"]
    MTUS = {"10.94.0.0/16": 1450}

    def test_parts_in_order(self):
        import email
        msg = email.message_from_string(sync.render_userdata(self.KEYS, self.MTUS))
        parts = [(p.get_content_type(), p.get_payload()) for p in msg.get_payload()]
        self.assertEqual(parts, [("text/cloud-boothook", sync.render_network_hook(self.MTUS)),
                                 ("text/x-shellscript", sync.render_trust_script(self.KEYS))])

    def test_detected_as_mime_and_stable(self):
        # CloudStack takes the first line starting with "#" or "Content-Type:" as the format
        text = sync.render_userdata(self.KEYS, self.MTUS)
        first = next(line for line in text.split("\n") if line.startswith(("#", "Content-Type:")))
        self.assertTrue(first.startswith("Content-Type: multipart/mixed"))
        self.assertEqual(text, sync.render_userdata(self.KEYS, self.MTUS))
        self.assertNotEqual(sync.userdata_name(text), sync.userdata_name(sync.render_userdata(["ssh-ed25519 BBB warpgate"], self.MTUS)))
        self.assertNotEqual(sync.userdata_name(text), sync.userdata_name(sync.render_userdata(self.KEYS, {"10.94.0.0/16": 1400})))

    def test_network_mtus(self):
        networks = [{"cidr": "10.94.0.0/16", "privatemtu": 1450}, {"cidr": "10.1.0.0/24", "privatemtu": 1500},
                    {"cidr": "10.1.0.0/24", "privatemtu": 1400}, {"name": "l2", "privatemtu": 1500}, {"cidr": "10.2.0.0/24"}]
        self.assertEqual(sync.network_mtus(networks), {"10.94.0.0/16": 1450, "10.1.0.0/24": 1400})

    def test_name_is_stable_hash_of_content(self):
        a = sync.userdata_name(sync.render_trust_script(["ssh-ed25519 AAA warpgate"]))
        b = sync.userdata_name(sync.render_trust_script(["ssh-ed25519 AAA warpgate"]))
        c = sync.userdata_name(sync.render_trust_script(["ssh-ed25519 BBB warpgate"]))
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertTrue(a.startswith("warpgate-ssh-"))
        self.assertEqual(len(a), len("warpgate-ssh-") + 8)


class TemplateUserDataTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.templates = [
            {"id": "t-ours", "name": "ubuntu-24.04", "templatetype": "USER",
             "userdataid": "ud-old", "userdataname": "warpgate-ssh"},
            {"id": "t-theirs", "name": "custom", "templatetype": "USER",
             "userdataid": "ud-x", "userdataname": "my-cloud-config"},
            {"id": "t-bare", "name": "debian-13", "templatetype": "USER"},
            {"id": "t-sys", "name": "SystemVM", "templatetype": "SYSTEM"},
        ]
        self.userdata = [{"id": "ud-old", "name": "warpgate-ssh", "userdata": "x"},
                         {"id": "ud-x", "name": "my-cloud-config", "userdata": "y"}]

        def fake_cs(command, **params):
            self.calls.append((command, params))
            if command == "listUserData":
                return {"userdata": list(self.userdata)}
            if command == "registerUserData":
                self.userdata.append({"id": "ud-new", "name": params["name"], "userdata": params["userdata"]})
                return {}
            if command == "listTemplates":
                return {"template": self.templates}
            if command == "listNetworks":
                return {"network": [{"name": "guest", "cidr": "10.94.0.0/16", "privatemtu": 1450}]}
            return {}

        def no_wg(method, path, body=None):
            raise AssertionError("the user data follows the declared keys, not Warpgate")
        self._orig = (sync.cloudstack, sync.warpgate)
        sync.cloudstack, sync.warpgate = fake_cs, no_wg

    def tearDown(self):
        sync.cloudstack, sync.warpgate = self._orig

    def test_registers_links_and_cleans_up(self):
        sync.sync_template_userdata(["ssh-ed25519 AAA warpgate"])
        cmds = [c for c, _ in self.calls]
        self.assertIn("registerUserData", cmds)
        links = [p for c, p in self.calls if c == "linkUserDataToTemplate"]
        self.assertEqual({p["templateid"] for p in links}, {"t-ours", "t-bare"})
        self.assertTrue(all(p["userdataid"] == "ud-new" and p["userdatapolicy"] == "APPEND" for p in links))
        deletes = [p for c, p in self.calls if c == "deleteUserData"]
        self.assertEqual([p["id"] for p in deletes], ["ud-old"])
        import base64
        register = next(p for c, p in self.calls if c == "registerUserData")
        self.assertTrue(register["post"])  # too long for a query string
        registered = base64.b64decode(register["userdata"]).decode()
        self.assertIn("text/cloud-boothook", registered)
        self.assertIn('mtus = {"10.94.0.0/16": 1450}', registered)
        self.assertIn("cloudstack/password/vm_password.txt", registered)
        self.assertNotIn("data-server", registered)
        self.assertIn("ssh-ed25519 AAA warpgate\n", registered)


def openssh_key(algorithm=b"ssh-ed25519", key=b"\x01" * 32, cipher=b"none", kdf=b"none", count=1):
    """An OpenSSH private key file around a made-up public key, and that public
    key; the private section is filler, as only the header is read."""
    def s(data):
        return len(data).to_bytes(4, "big") + data
    public = s(algorithm) + s(key)
    blob = (b"openssh-key-v1\0" + s(cipher) + s(kdf) + s(b"") + count.to_bytes(4, "big")
            + s(public) + s(b"\0" * 64))
    body = base64.b64encode(blob).decode()
    text = "\n".join(["-----BEGIN OPENSSH PRIVATE KEY-----", *(body[i:i + 70] for i in range(0, len(body), 70)),
                      "-----END OPENSSH PRIVATE KEY-----"]) + "\n"
    return text, f"{algorithm.decode()} {base64.b64encode(public).decode()}"


class OpensshPublicKeyTest(unittest.TestCase):
    def test_reads_the_public_key_from_the_header(self):
        text, public = openssh_key(b"ssh-rsa", b"\x00\x01\x02")
        self.assertEqual(sync.openssh_public_key(text), public)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "needs ssh-keygen")
    def test_agrees_with_ssh_keygen(self):
        with tempfile.TemporaryDirectory() as d:
            for kind in ("ed25519", "rsa"):
                path = os.path.join(d, kind)
                subprocess.run(["ssh-keygen", "-q", "-t", kind, "-N", "", "-C", "comment", "-f", path], check=True)
                with open(path) as f:
                    derived = sync.openssh_public_key(f.read())
                with open(path + ".pub") as f:
                    self.assertEqual(derived, " ".join(f.read().split()[:2]))
                listed = subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", path + ".pub"], check=True,
                                        capture_output=True, text=True).stdout.split()[1]
                self.assertEqual(sync.ssh_fingerprint(derived), listed)

    def test_refuses_what_warpgate_could_not_import_or_this_cannot_read(self):
        whole = base64.b64encode(b"openssh-key-v1\0" + (4).to_bytes(4, "big") + b"no").decode()
        cases = {
            "passphrase": openssh_key(cipher=b"aes256-ctr", kdf=b"bcrypt")[0],
            "pkcs8": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
            "two keys": openssh_key(count=2)[0],
            "truncated": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{whole}\n-----END OPENSSH PRIVATE KEY-----\n",
            "not base64": "-----BEGIN OPENSSH PRIVATE KEY-----\n%%%%\n-----END OPENSSH PRIVATE KEY-----\n",
            "empty": "",
        }
        for name, text in cases.items():
            with self.assertRaises(ValueError, msg=name):
                sync.openssh_public_key(text)


class DeclaredClientKeysTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def write(self, name, text):
        with open(os.path.join(self.dir, name), "w") as f:
            f.write(text)

    def test_one_file_per_label(self):
        ed, ed_pub = openssh_key(b"ssh-ed25519", b"\x01" * 32)
        rsa, rsa_pub = openssh_key(b"ssh-rsa", b"\x02" * 8)
        self.write("client-ed25519", ed)
        self.write("client-rsa", rsa)
        self.write("client-other", openssh_key(b"ssh-ed25519", b"\x03" * 32)[0])  # not a declared label
        self.assertEqual(sync.declared_client_keys(self.dir),
                         {"client-ed25519": (ed, ed_pub), "client-rsa": (rsa, rsa_pub)})

    def test_a_missing_key_fails_the_run_rather_than_shrinking_the_declaration(self):
        self.write("client-ed25519", openssh_key()[0])
        with self.assertRaisesRegex(RuntimeError, "warpgate client key client-rsa: .*No such file"):
            sync.declared_client_keys(self.dir)
        with self.assertRaisesRegex(RuntimeError, "warpgate client key client-ed25519"):
            sync.declared_client_keys(os.path.join(self.dir, "missing"))

    def test_a_key_in_another_format_fails_the_run(self):
        self.write("client-ed25519", "-----BEGIN PRIVATE KEY-----\nMC4CAQAw\n-----END PRIVATE KEY-----\n")
        self.write("client-rsa", openssh_key(b"ssh-rsa", b"\x02" * 8)[0])
        with self.assertRaisesRegex(RuntimeError, "client-ed25519: not an OpenSSH private key"):
            sync.declared_client_keys(self.dir)

    def test_one_key_under_two_labels_fails_the_run(self):
        text, _ = openssh_key()
        self.write("client-ed25519", text)
        self.write("client-rsa", text)
        with self.assertRaisesRegex(RuntimeError, "same key"):
            sync.declared_client_keys(self.dir)


class SyncClientKeysTest(unittest.TestCase):
    def setUp(self):
        self.ed = openssh_key(b"ssh-ed25519", b"\x01" * 32)
        self.rsa = openssh_key(b"ssh-rsa", b"\x02" * 8)
        self.declared = {"client-ed25519": self.ed, "client-rsa": self.rsa}
        self.keys, self.calls = [], []
        self.reads_as = None  # what Warpgate computes for an imported key, if not its real public key

        def fake_wg(method, path, body=None):
            self.calls.append((method, path, body))
            if method == "GET":
                return 200, [dict(k) for k in self.keys]
            if method == "POST":
                public = self.reads_as or sync.openssh_public_key(body["secret_key"])
                if any(k["public_key"] == public for k in self.keys):
                    return 409, None
                key = {"id": f"k{len(self.calls)}", "label": body["label"], "public_key": public,
                       "is_default": body["is_default"]}
                self.keys.append(key)
                return 201, dict(key)
            key_id = path.rsplit("/", 1)[1]
            if method == "PUT":
                key = next(k for k in self.keys if k["id"] == key_id)
                key.update(label=body["label"], is_default=body["is_default"])
                return 200, dict(key)
            if method == "DELETE":
                if len(self.keys) <= 1:
                    raise RuntimeError("warpgate DELETE: 400 At least one SSH client key must remain")
                self.keys = [k for k in self.keys if k["id"] != key_id]
                return 204, None
            raise AssertionError(method)
        self._orig = sync.warpgate
        sync.warpgate = fake_wg
        self.addCleanup(setattr, sync, "warpgate", self._orig)

    def held(self, label, key, is_default=True, key_id=None):
        return {"id": key_id or label, "label": label, "public_key": key[1], "is_default": is_default}

    def run_sync(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            public = sync.sync_client_keys(self.declared)
        return public, out.getvalue()

    def test_keys_already_held_change_nothing(self):
        self.keys = [self.held("client-ed25519", self.ed), self.held("client-rsa", self.rsa)]
        public, _ = self.run_sync()
        self.assertEqual(public, sorted([self.ed[1], self.rsa[1]]))
        self.assertEqual([c[0] for c in self.calls], ["GET"])

    def test_a_missing_key_is_imported_as_a_default_key(self):
        self.keys = [self.held("client-ed25519", self.ed)]
        _, out = self.run_sync()
        self.assertEqual(self.calls[1], ("POST", "/ssh/own-keys",
                                         {"label": "client-rsa", "secret_key": self.rsa[0], "is_default": True}))
        self.assertEqual(len(self.calls), 2)
        self.assertIn(f"warpgate client key client-rsa imported ({sync.ssh_fingerprint(self.rsa[1])})", out)

    def test_other_keys_go_once_the_declared_ones_are_in(self):
        stray = openssh_key(b"ssh-ed25519", b"\x09" * 32)
        self.keys = [self.held("generated", stray), self.held("client-ed25519", self.ed)]
        _, out = self.run_sync()
        self.assertEqual([c[0] for c in self.calls], ["GET", "POST", "DELETE"])
        self.assertEqual(self.calls[-1][1], "/ssh/own-keys/generated")
        self.assertEqual(sorted(k["public_key"] for k in self.keys), sorted([self.ed[1], self.rsa[1]]))
        self.assertIn(f"warpgate client key generated removed ({sync.ssh_fingerprint(stray[1])})", out)

    def test_a_declared_key_gets_its_label_and_the_default_flag(self):
        self.keys = [self.held("old name", self.ed, is_default=False, key_id="k-ed"), self.held("client-rsa", self.rsa)]
        self.run_sync()
        self.assertEqual(self.calls[1:], [("PUT", "/ssh/own-keys/k-ed", {"label": "client-ed25519", "is_default": True})])

    def test_a_key_warpgate_reads_as_another_key_fails_the_run(self):
        self.keys = [self.held("generated", openssh_key(b"ssh-ed25519", b"\x09" * 32)), self.held("client-ed25519", self.ed)]
        self.reads_as = "ssh-rsa OTHER"
        with self.assertRaisesRegex(RuntimeError, "client-rsa: Warpgate reads it as a different key"):
            self.run_sync()
        self.assertNotIn("DELETE", [c[0] for c in self.calls])

    def test_a_conflicting_import_fails_the_run(self):
        self.keys = [{"id": "x", "label": "x", "public_key": "ssh-rsa SAME", "is_default": True},
                     self.held("client-ed25519", self.ed)]
        self.reads_as = "ssh-rsa SAME"
        with self.assertRaisesRegex(RuntimeError, "client-rsa: Warpgate reads it as a different key"):
            self.run_sync()
        self.assertNotIn("DELETE", [c[0] for c in self.calls])

    def test_a_declaration_keeping_none_of_the_held_keys_is_refused(self):
        self.keys = [self.held("client-ed25519", openssh_key(b"ssh-ed25519", b"\x09" * 32)),
                     self.held("client-rsa", openssh_key(b"ssh-rsa", b"\x09" * 8))]
        with self.assertRaisesRegex(RuntimeError, "keeps none of the keys Warpgate holds"):
            self.run_sync()
        self.assertEqual([c[0] for c in self.calls], ["GET"])

    def test_a_warpgate_without_keys_takes_the_declared_ones(self):
        _, out = self.run_sync()
        self.assertEqual([c[0] for c in self.calls], ["GET", "POST", "POST"])


class BastionStepsTest(unittest.TestCase):
    STEPS = ("sync_console_endpoints", "prune_management_servers", "load_roles", "sync_roles", "sync_oidc_providers",
             "sync_settings", "sync_compute_catalog", "declared_client_keys", "sync_client_keys", "sync_warpgate",
             "sync_template_userdata", "restore_console_proxy_state", "sync_console_certificate")

    def test_the_template_user_data_trusts_the_declared_keys(self):
        with mock.patch.multiple(sync, **{step: mock.DEFAULT for step in self.STEPS}) as m, \
                mock.patch.multiple(sync, WARPGATE_HOST="warpgate.example", WARPGATE_TLS_NAME="warpgate.example",
                                    WARPGATE_TOKEN="token"):
            for step in ("sync_oidc_providers", "sync_settings", "sync_compute_catalog"):
                m[step].return_value = []
            m["declared_client_keys"].return_value = {"client-ed25519": ("secret", "ssh-ed25519 AAA")}
            m["sync_client_keys"].return_value = ["ssh-ed25519 AAA"]
            sync.main()
        m["sync_client_keys"].assert_called_once_with({"client-ed25519": ("secret", "ssh-ed25519 AAA")})
        m["sync_template_userdata"].assert_called_once_with(["ssh-ed25519 AAA"])

    def test_a_key_failure_holds_back_only_the_user_data(self):
        with mock.patch.multiple(sync, **{step: mock.DEFAULT for step in self.STEPS}) as m, \
                mock.patch.multiple(sync, WARPGATE_HOST="warpgate.example", WARPGATE_TLS_NAME="warpgate.example",
                                    WARPGATE_TOKEN="token"), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            for step in ("sync_oidc_providers", "sync_settings", "sync_compute_catalog"):
                m[step].return_value = []
            m["declared_client_keys"].side_effect = RuntimeError("warpgate client key client-rsa: missing")
            with self.assertRaisesRegex(RuntimeError, "warpgate client keys not reconciled"):
                sync.main()
        self.assertEqual({s: m[s].call_count for s in self.STEPS if s not in ("sync_client_keys", "sync_template_userdata")},
                         {s: 1 for s in self.STEPS if s not in ("sync_client_keys", "sync_template_userdata")})
        self.assertEqual((m["sync_client_keys"].call_count, m["sync_template_userdata"].call_count), (0, 0))
        self.assertIn("error: warpgate client key client-rsa: missing", out.getvalue())


class WarpgateKeysManifestTest(unittest.TestCase):
    """Warpgate creates its database from the declared keys and the sync job
    keeps the client keys; both read the same Secret."""

    def read(self, name):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), name)) as f:
            return f.read()

    def test_the_job_and_the_bastion_read_one_declaration(self):
        sync_manifest, bastion = self.read("sync.yaml"), self.read("warpgate.yaml")
        (vault,) = [d + "\n" for d in bastion.split("\n---\n")
                    if "kind: VaultStaticSecret\nmetadata:\n  name: warpgate-ssh-keys\n" in d]
        self.assertIn("  path: cloudstack/warpgate-ssh-keys\n", vault)
        self.assertIn("  destination:\n    create: true\n    name: warpgate-ssh-keys\n"
                      "  rolloutRestartTargets:\n    - kind: StatefulSet\n      name: warpgate\n", vault)
        volume = re.search(r"\n            - name: warpgate-client-keys\n              secret:\n((?:                .*\n)+)",
                           sync_manifest).group(1)
        self.assertIn("secretName: warpgate-ssh-keys\n", volume)
        self.assertIn("optional: true\n", volume)
        self.assertEqual(re.findall(r"- key: (\S+)\n\s+path: \1\n", volume), list(sync.WARPGATE_CLIENT_KEY_LABELS))
        self.assertIn(f"- name: warpgate-client-keys\n                  mountPath: {sync.WARPGATE_CLIENT_KEYS_DIR}\n",
                      sync_manifest)
        volume = re.search(r"\n        - name: ssh-keys\n          secret:\n((?:            .*\n)+)", bastion).group(1)
        self.assertIn("secretName: warpgate-ssh-keys\n", volume)
        self.assertIn("optional: true\n", volume)
        self.assertEqual(re.findall(r"- key: (\S+)\n\s+path: \1\n", volume),
                         ["client-ed25519", "client-rsa", "host-ed25519", "host-rsa"])

    def test_only_the_setup_container_sees_the_keys(self):
        bastion = self.read("warpgate.yaml")
        self.assertIn("keys=/ssh-keys db=/data/db/db.sqlite3\n", bastion)
        self.assertIn("--import-ssh-host-keys $keys --import-ssh-client-keys $keys\n", bastion)
        # a new database is checked before it takes the place of none
        self.assertLess(bastion.index("check /data/db.new/db.sqlite3\n"), bastion.index("mv /data/db.new /data/db\n"))
        self.assertEqual(bastion.count("mountPath: /ssh-keys\n"), 1)  # the setup container's
        self.assertIsNone(re.search(r"^ssh:\n(?:  .*\n)*?  keys:", self.read("warpgate-config.yaml"), re.M))


class CatalogTest(unittest.TestCase):
    def test_loads_entries_and_defaults(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write('[[template]]\nname = "ubuntu-24.04-20260911"\ndisplay = "Ubuntu 24.04 LTS"\n'
                    'url = "https://example/u.img"\nchecksum = "{SHA-256}ab"\nostype = "Ubuntu 24.04 LTS"\nuser = "ubuntu"\n'
                    '[[template]]\nname = "debian-13-20260914"\ndisplay = "Debian 13"\nurl = "https://example/d.qcow2"\n'
                    'checksum = "{SHA-512}cd"\nostype = "Other Linux (64-bit)"\nuser = "debian"\nfeatured = true\n')
        try:
            cat = sync.load_catalog(f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual([c["name"] for c in cat], ["ubuntu-24.04-20260911", "debian-13-20260914"])
        self.assertFalse(cat[0]["featured"])
        self.assertTrue(cat[1]["featured"])

    def test_missing_file_is_empty(self):
        self.assertEqual(sync.load_catalog("/nonexistent/templates.toml"), [])


class TemplateUserTest(unittest.TestCase):
    def test_base_target_uses_template_user(self):
        vms = [{"id": "vm-1", "name": "a", "account": "alice", "templateid": "t-deb", "nic": [{"ipaddress": "10.94.1.5"}]},
               {"id": "vm-2", "name": "b", "account": "alice", "templateid": "t-unknown", "nic": [{"ipaddress": "10.94.1.6"}]}]
        wanted, _ = sync.plan_targets(vms, {}, {"t-deb": "debian"})
        self.assertEqual(wanted["a"]["options"]["username"], "debian")
        self.assertEqual(wanted["b"]["options"]["username"], "ubuntu")


class SyncTemplatesTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.templates = [
            {"id": "t-old", "name": "ubuntu-24.04", "templatetype": "USER", "ispublic": True, "isfeatured": False, "ostypeid": "os-ubu"},
            {"id": "t-deb", "name": "debian-13-20260914", "templatetype": "USER", "ispublic": False, "isfeatured": False, "ostypeid": "os-other"},
            {"id": "t-sys", "name": "SystemVM", "templatetype": "SYSTEM", "ispublic": True},
        ]

        def fake_cs(command, **params):
            self.calls.append((command, params))
            if command == "listTemplates":
                return {"template": list(self.templates)}
            if command == "listOsTypes":
                return {"ostype": [{"id": "os-ubu", "description": "Ubuntu 24.04 LTS"}, {"id": "os-other", "description": "Other Linux (64-bit)"},
                                   {"id": "os-deb12", "description": "Debian GNU/Linux 12 (64-bit)"}]}
            if command == "listZones":
                return {"zone": [{"id": "z-1"}]}
            if command == "registerTemplate":
                self.templates.append({"id": "t-new", "name": params["name"], "templatetype": "USER", "ispublic": True,
                                       "isfeatured": params["isfeatured"] == "true", "ostypeid": params["ostypeid"]})
                return {}
            return {}
        self._orig = sync.cloudstack
        sync.cloudstack = fake_cs

    def tearDown(self):
        sync.cloudstack = self._orig

    def test_registers_fixes_flags_and_hides_uncatalogued(self):
        catalog = [
            {"name": "ubuntu-24.04-20260911", "display": "Ubuntu 24.04 LTS", "url": "https://example/u.img", "checksum": "{SHA-256}ab", "ostype": "Ubuntu 24.04 LTS", "user": "ubuntu", "featured": True},
            {"name": "debian-13-20260914", "display": "Debian 13", "url": "https://example/d.qcow2", "checksum": "{SHA-512}cd", "ostype": "Other Linux (64-bit)", "user": "debian", "featured": False},
        ]
        users = sync.sync_templates(catalog)
        reg = [p for c, p in self.calls if c == "registerTemplate"]
        self.assertEqual(len(reg), 1)
        self.assertEqual(reg[0]["name"], "ubuntu-24.04-20260911")
        self.assertEqual(reg[0]["ostypeid"], "os-ubu")
        self.assertEqual((reg[0]["ispublic"], reg[0]["isfeatured"], reg[0]["passwordenabled"]), ("true", "true", "true"))
        perms = [p for c, p in self.calls if c == "updateTemplatePermissions"]
        self.assertIn({"id": "t-deb", "ispublic": "true", "isfeatured": "false"}, perms)
        self.assertIn({"id": "t-old", "ispublic": "false", "isfeatured": "false"}, perms)
        self.assertEqual(users, {"t-new": "ubuntu", "t-deb": "debian"})
        self.assertEqual([c for c, _ in self.calls if c == "updateTemplate"], [])

    def test_os_type_follows_the_catalog(self):
        catalog = [{"name": "debian-13-20260914", "display": "Debian 13", "url": "https://example/d.qcow2", "checksum": "{SHA-512}cd",
                    "ostype": "Debian GNU/Linux 12 (64-bit)", "user": "debian", "featured": False}]
        sync.sync_templates(catalog)
        updates = [p for c, p in self.calls if c == "updateTemplate"]
        self.assertEqual(updates, [{"id": "t-deb", "ostypeid": "os-deb12"}])


class TrustScriptIncludeTest(unittest.TestCase):
    def test_script_ensures_include_and_openrc(self):
        script = sync.render_trust_script(["ssh-ed25519 AAA warpgate"])
        self.assertIn("Include /etc/ssh/sshd_config.d/*.conf", script)
        self.assertIn("[ -f /etc/ssh/sshd_config ]", script)  # openSUSE keeps the vendor file elsewhere
        self.assertIn("rc-service sshd reload", script)

    def test_script_installs_and_runs_the_password_hook(self):
        script = sync.render_trust_script(["ssh-ed25519 AAA warpgate"])
        hook = sync.render_password_script()
        self.assertIn(f"cat > {sync.PASSWORD_SCRIPT} <<'EOF'\n{hook}EOF\n", script)
        self.assertIn(f"{sync.PASSWORD_SCRIPT} || true\n", script)
        self.assertTrue(sync.PASSWORD_SCRIPT.startswith("/var/lib/cloud/scripts/per-boot/"))
        self.assertNotIn("\nEOF\n", hook)  # would end the heredoc early

    def test_password_hook_reads_the_config_drive(self):
        hook = sync.render_password_script()
        for wanted in ('LABEL="config-2"', "cloudstack/password/vm_password.txt", "chpasswd",
                       "/var/lib/cloud/cloudstack-password.sha256"):
            self.assertIn(wanted, hook)
        for gone in ("data-server", "8080", "send_my_password"):
            self.assertNotIn(gone, hook)


class PasswordHookTest(unittest.TestCase):
    """Runs the rendered hook under sh with stand-ins for the system tools."""
    STATE = "/var/lib/cloud/cloudstack-password.sha256"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.bin, self.drive_dir = f"{self.root}/bin", f"{self.root}/drive"
        os.makedirs(self.bin)
        os.makedirs(f"{self.drive_dir}/cloudstack/password")
        stubs = {
            # util-linux and busybox both print one "<device>: KEY=..." line per device
            "blkid": 'test -e "$ROOT/has-drive" && echo \'/dev/sr1: UUID="2026" LABEL="config-2" TYPE="iso9660"\'',
            "mount": 'eval "mnt=\\${$#}"; cp -R "$ROOT/drive/." "$mnt/"',
            "umount": "true",
            "python3": "exit 1",
            "getent": 'echo "ubuntu:x:1000:1000::/home/ubuntu:/bin/sh"',
            "chpasswd": 'cat >> "$ROOT/chpasswd.log"',
        }
        for name, body in stubs.items():
            with open(f"{self.bin}/{name}", "w") as f:
                f.write(f"#!/bin/sh\n{body}\n")
            os.chmod(f"{self.bin}/{name}", 0o755)
        with open(f"{self.root}/hook.sh", "w") as f:
            f.write(sync.render_password_script().replace(self.STATE, f"{self.root}/state.sha256"))

    def drive(self, password):
        open(f"{self.root}/has-drive", "w").close()
        path = f"{self.drive_dir}/cloudstack/password/vm_password.txt"
        if password is None:
            if os.path.exists(path):
                os.remove(path)
        else:
            with open(path, "w") as f:
                f.write(password)

    def boot(self):
        env = dict(os.environ, ROOT=self.root, PATH=f"{self.bin}:{os.environ['PATH']}")
        result = subprocess.run(["sh", f"{self.root}/hook.sh"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            with open(f"{self.root}/chpasswd.log") as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []

    def test_password_hook_applies_only_a_changed_password(self):
        self.drive("first secret")
        self.assertEqual(self.boot(), ["ubuntu:first secret"])
        self.assertEqual(self.boot(), ["ubuntu:first secret"])  # same password: not again
        self.drive("reset secret")
        self.assertEqual(self.boot(), ["ubuntu:first secret", "ubuntu:reset secret"])

    def test_password_hook_keeps_its_state_private(self):
        state = f"{self.root}/state.sha256"
        self.drive("first secret")
        self.boot()
        self.assertEqual(os.stat(state).st_mode & 0o777, 0o600)
        os.chmod(state, 0o644)
        self.drive("reset secret")
        self.boot()
        self.assertEqual(os.stat(state).st_mode & 0o777, 0o600)

    def test_password_hook_without_config_drive(self):
        self.assertEqual(self.boot(), [])

    def test_password_hook_without_password_file(self):
        self.drive(None)
        self.assertEqual(self.boot(), [])


class RootVolumeTest(unittest.TestCase):
    def test_owner_target_carries_root_volume(self):
        vms = [{"id": "vm-1", "name": "a", "account": "alice", "nic": [{"ipaddress": "10.94.1.5"}],
                "tags": [{"key": "ssh.account.foo", "value": "bob"}]},
               {"id": "vm-2", "name": "b", "account": "alice", "nic": [{"ipaddress": "10.94.1.6"}]}]
        wanted, _ = sync.plan_targets(vms, {}, root_by_vm={"vm-1": "vol-9"})
        self.assertEqual(wanted["a"]["description"], "cloudstack:vm:vm-1:root:vol-9")
        self.assertEqual(wanted["a:foo"]["description"], "cloudstack:vm:vm-1:guest:foo")
        self.assertEqual(wanted["b"]["description"], "cloudstack:vm:vm-2")


class StaleKnownHostsTest(unittest.TestCase):
    def test_drops_unused_and_refreshed_addresses(self):
        known = [{"id": "k1", "host": "10.94.1.5", "port": 22},
                 {"id": "k2", "host": "10.94.1.6", "port": 22},
                 {"id": "k3", "host": "10.94.1.7", "port": 22},
                 {"id": "k4", "host": "10.94.1.5", "port": 2222}]
        targets = [{"name": "a", "options": {"kind": "Ssh", "host": "10.94.1.5", "port": 22}},
                   {"name": "a:foo", "options": {"kind": "Ssh", "host": "10.94.1.5", "port": 22}},
                   {"name": "b", "options": {"kind": "Ssh", "host": "10.94.1.6", "port": 22}},
                   {"name": "web", "options": {"kind": "Http", "url": "https://10.94.1.7"}}]
        stale = sync.stale_known_hosts(known, targets, refreshed={("10.94.1.6", 22)})
        self.assertEqual([k["id"] for k in stale], ["k2", "k3", "k4"])


def pem(der):
    return f"-----BEGIN CERTIFICATE-----\n{base64.b64encode(der).decode()}\n-----END CERTIFICATE-----\n"


LEAF, INT1, INT2 = pem(b"leaf"), pem(b"intermediate-1"), pem(b"intermediate-2")
KEY = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
DOMAIN = "console-proxy.cloud.snucse.org"
INSIDE = datetime(2026, 10, 17, 19, 30, tzinfo=timezone.utc)  # 04:30 UTC+9
OUTSIDE = datetime(2026, 10, 17, 3, 0, tzinfo=timezone.utc)  # 12:00 UTC+9


def kst(dt):
    return dt.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%dT%H:%M:%S%z")


class ConsoleCertificateTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        with open(f"{self.dir}/tls.crt", "w") as f:
            f.write(LEAF + INT1 + INT2)
        with open(f"{self.dir}/tls.key", "w") as f:
            f.write(KEY)
        self.ssl_enabled = "true"
        self.state = "Auto"  # consoleproxy.management.state
        self.proxies = [{"id": "cp-1", "name": "v-1-VM", "publicip": "10.94.254.175", "agentstate": "Up"}]
        self.presented = {"10.94.254.175": b"older"}
        self.events = []
        self.calls = []
        self.upload_error = None
        self.failed_jobs = set()

        def fake_cs(command, post=False, **params):
            self.calls.append((command, post, params))
            if command == "listConfigurations":
                value = self.ssl_enabled if params["name"] == "consoleproxy.sslEnabled" else self.state
                return {"configuration": [{"name": params["name"], "value": value}]}
            if command == "listSystemVms":
                return {"systemvm": list(self.proxies)}
            if command == "listEvents":
                return {"event": list(self.events)}
            if command == "uploadCustomCertificate":
                if self.upload_error:
                    raise self.upload_error
                self.state = "ResetSuspending"  # what the upload does on the server
                return {"jobid": f"job-{len(self.calls)}"}
            if command == "queryAsyncJobResult":
                if params["jobid"] in self.failed_jobs:
                    return {"jobid": params["jobid"], "jobstatus": 2, "jobresult": {"errortext": "rejected"}}
                return {"jobid": params["jobid"], "jobstatus": 1}
            if command == "updateConfiguration":
                self.state = params["value"]
                return {"configuration": {"name": params["name"], "value": params["value"]}}
            if command == "rebootSystemVm":
                return {"jobid": f"reboot-{params['id']}"}
            raise AssertionError(f"unexpected {command}")

        def fake_presented(ip, port=443):
            self.probes.append(ip)
            answer = self.presented[ip]
            return answer.pop(0) if isinstance(answer, list) else answer

        self.probes = []
        for p in (mock.patch.object(sync, "cloudstack", fake_cs),
                  mock.patch.object(sync, "presented_certificate", fake_presented),
                  mock.patch.object(sync, "CONSOLE_TLS_DIR", self.dir),
                  mock.patch.object(sync.time, "sleep", lambda s: None)):
            p.start()
            self.addCleanup(p.stop)

    def uploads(self):
        return [(post, params) for command, post, params in self.calls if command == "uploadCustomCertificate"]

    def test_skips_when_ssl_disabled(self):
        self.ssl_enabled = "false"
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(self.uploads(), [])

    def test_no_upload_when_every_proxy_presents_the_leaf(self):
        self.proxies.append({"name": "v-2-VM", "publicip": "10.94.254.180", "agentstate": "Up"})
        self.presented = {"10.94.254.175": b"leaf", "10.94.254.180": b"leaf"}
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(self.uploads(), [])

    def test_uploads_chain_then_leaf(self):
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(self.uploads(), [
            (True, {"certificate": INT2, "id": 1, "name": "console-chain-1", "domainsuffix": DOMAIN}),
            (True, {"certificate": INT1, "id": 2, "name": "console-chain-2", "domainsuffix": DOMAIN}),
            (True, {"certificate": LEAF, "privatekey": KEY, "domainsuffix": DOMAIN}),
        ])

    def test_defers_replacement_outside_the_window(self):
        sync.sync_console_certificate(OUTSIDE)
        self.assertEqual(self.uploads(), [])

    def test_replaces_inside_the_window(self):
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(len(self.uploads()), 3)

    def test_serves_missing_certificate_any_time(self):
        self.presented = {"10.94.254.175": b""}
        sync.sync_console_certificate(OUTSIDE)
        self.assertEqual(len(self.uploads()), 3)

    def test_uploads_when_a_proxy_serves_no_certificate(self):
        self.presented = {"10.94.254.175": b""}
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(len(self.uploads()), 3)

    def test_waits_after_recent_upload(self):
        self.events = [{"created": kst(INSIDE - timedelta(minutes=10))}]
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(self.uploads(), [])

    def test_retries_after_the_interval(self):
        self.events = [{"created": kst(INSIDE - timedelta(minutes=61))}]
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(len(self.uploads()), 3)

    def test_event_time_with_offset(self):
        self.events = [{"created": "2026-10-18T04:10:00+0900"}]  # 25 minutes before now
        sync.sync_console_certificate(datetime(2026, 10, 17, 19, 35, tzinfo=timezone.utc))
        self.assertEqual(self.uploads(), [])

    def test_skips_without_certificate_files(self):
        os.remove(f"{self.dir}/tls.crt")
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(self.calls, [])

    def test_skips_without_running_proxy(self):
        self.proxies = [{"name": "v-1-VM"}]
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(self.uploads(), [])

    def test_skips_when_a_proxy_is_unobservable(self):
        self.proxies.append({"name": "v-2-VM", "publicip": "10.94.254.180", "agentstate": "Up"})
        self.presented = {"10.94.254.175": b"older", "10.94.254.180": None}
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(self.uploads(), [])
        self.assertNotIn("listEvents", [c[0] for c in self.calls])

    def test_proxy_whose_agent_is_not_up_is_unobservable(self):
        self.proxies[0]["agentstate"] = "Disconnected"
        self.presented = {"10.94.254.175": b""}
        sync.sync_console_certificate(INSIDE)
        self.assertEqual(self.uploads(), [])
        self.assertEqual(self.probes, [])

    def test_an_empty_answer_is_probed_again(self):
        self.presented = {"10.94.254.175": [b"", b"leaf"]}  # serving starts a moment after the agent connects
        sync.sync_console_certificate(OUTSIDE)
        self.assertEqual(self.uploads(), [])
        self.assertEqual(self.probes, ["10.94.254.175", "10.94.254.175"])

    def test_upload_error_fails_the_run(self):
        self.upload_error = RuntimeError("rejected")
        with self.assertRaises(RuntimeError):
            sync.sync_console_certificate(INSIDE)

    def test_waits_for_each_upload_job(self):
        sync.sync_console_certificate(INSIDE)
        steps = [c for c, _, _ in self.calls if c in ("uploadCustomCertificate", "queryAsyncJobResult")]
        self.assertEqual(steps, ["uploadCustomCertificate", "queryAsyncJobResult"] * 3)

    def test_restores_the_state_then_reboots_the_proxies(self):
        self.proxies.append({"id": "cp-2", "name": "v-2-VM", "publicip": "10.94.254.180", "agentstate": "Up"})
        self.presented["10.94.254.180"] = b"older"
        sync.sync_console_certificate(INSIDE)
        after = [(c, p) for c, _, p in self.calls][-3:]
        self.assertEqual(after, [
            ("updateConfiguration", {"name": "consoleproxy.management.state", "value": "Auto"}),
            ("rebootSystemVm", {"id": "cp-1"}),
            ("rebootSystemVm", {"id": "cp-2"}),
        ])
        self.assertEqual(self.state, "Auto")

    def test_failed_job_fails_the_run_without_reboot(self):
        self.failed_jobs = {"job-6"}  # the leaf, after two chain uploads and their queries
        with self.assertRaises(RuntimeError):
            sync.sync_console_certificate(INSIDE)
        self.assertNotIn("rebootSystemVm", [c for c, _, _ in self.calls])


class ConsoleProxyStateTest(unittest.TestCase):
    def run_with(self, state):
        calls = []

        def fake_cs(command, **params):
            calls.append((command, params))
            if command == "listConfigurations":
                return {"configuration": [{"name": params["name"], "value": state}]}
            return {}

        with mock.patch.object(sync, "cloudstack", fake_cs):
            sync.restore_console_proxy_state()
        return [c for c in calls if c[0] == "updateConfiguration"]

    def test_restores_leftover_reset_suspending(self):
        self.assertEqual(self.run_with("ResetSuspending"),
                         [("updateConfiguration", {"name": "consoleproxy.management.state", "value": "Auto"})])

    def test_leaves_other_states_alone(self):
        for state in ("Auto", "Manual", "Suspending"):
            self.assertEqual(self.run_with(state), [])


class ManagementServerRecordsTest(unittest.TestCase):
    def run_with(self, servers):
        calls = []

        def fake_cs(command, **params):
            calls.append((command, params))
            if command == "listManagementServers":
                return {"managementserver": servers}
            return {}

        with mock.patch.object(sync, "cloudstack", fake_cs):
            sync.prune_management_servers()
        return [p["id"] for c, p in calls if c == "removeManagementServer"]

    def test_removes_down_records_while_one_is_up(self):
        servers = [{"id": "a", "state": "Down"}, {"id": "b", "state": "Up"}, {"id": "c", "state": "Down"}]
        self.assertEqual(self.run_with(servers), ["a", "c"])

    def test_keeps_everything_without_a_server_up(self):
        self.assertEqual(self.run_with([{"id": "a", "state": "Down"}, {"id": "b", "state": "Down"}]), [])


class WaitForJobTest(unittest.TestCase):
    def test_polls_until_done(self):
        answers = iter([{"jobstatus": 0}, {"jobstatus": 0}, {"jobstatus": 1, "jobresult": {"ok": True}}])
        with mock.patch.object(sync, "cloudstack", lambda command, **p: next(answers)), \
                mock.patch.object(sync.time, "sleep", lambda s: None):
            self.assertEqual(sync.wait_for_job("j")["jobresult"], {"ok": True})

    def test_gives_up_after_the_timeout(self):
        clock = iter(range(0, 1000, 10))
        with mock.patch.object(sync, "cloudstack", lambda command, **p: {"jobstatus": 0}), \
                mock.patch.object(sync.time, "sleep", lambda s: None), \
                mock.patch.object(sync.time, "monotonic", lambda: next(clock)):
            with self.assertRaises(RuntimeError):
                sync.wait_for_job("j", timeout=60)


class PresentedCertificateTest(unittest.TestCase):
    def presented(self, outcome):
        with mock.patch.object(sync.ssl, "get_server_certificate", side_effect=outcome):
            return sync.presented_certificate("10.94.254.175")

    def test_certificate(self):
        self.assertEqual(self.presented([LEAF]), b"leaf")

    def test_refused_or_failed_handshake_serves_none(self):
        self.assertEqual(self.presented(ConnectionRefusedError()), b"")
        self.assertEqual(self.presented(ssl.SSLError()), b"")

    def test_unreachable_cannot_be_observed(self):
        self.assertIsNone(self.presented(TimeoutError()))
        self.assertIsNone(self.presented(OSError(113, "No route to host")))


class CloudStackPostTest(unittest.TestCase):
    def test_post_puts_parameters_in_the_body(self):
        seen = []

        def fake_urlopen(req, timeout):
            seen.append(req)
            return io.BytesIO(json.dumps({"uploadcustomcertificateresponse": {"jobid": "j"}}).encode())

        with mock.patch.object(sync.urllib.request, "urlopen", fake_urlopen):
            self.assertEqual(sync.cloudstack("uploadCustomCertificate", post=True, certificate="x"), {"jobid": "j"})
        req = seen[0]
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.full_url, sync.API_URL)
        self.assertIn(b"signature=", req.data)
        self.assertIn(b"command=uploadCustomCertificate", req.data)


class ConsoleEndpointsTest(unittest.TestCase):
    def test_ports_are_tls(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(f"{tmp.name}/namespace", "w") as f:
            f.write("cloudstack")
        written = []

        def fake_kube(method, path, body=None):
            if method == "GET":
                return 404, {}
            written.append(body)
            return 201, {}

        with mock.patch.object(sync, "SA_DIR", tmp.name), \
                mock.patch.object(sync, "kube", fake_kube), \
                mock.patch.object(sync, "cloudstack", lambda command, **p: {"systemvm": [{"publicip": "10.94.254.175"}]}):
            sync.sync_console_endpoints()
        self.assertEqual([(p["name"], p["port"]) for p in written[0]["ports"]], [("https", 443), ("websocket", 8443)])


REPO_ROLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "roles.toml")


def decision(role, api):
    """The first matching rule's permission, matched case-insensitively like the server; None if no rule matches."""
    for rule, permission in role["rules"]:
        if re.fullmatch(re.escape(rule).replace(r"\*", ".*"), api, re.IGNORECASE):
            return permission
    return None


# Every command the student UI calls, by page; the SNUCSE User role allows these and nothing else.
STUDENT_UI_COMMANDS = (
    # sign-in and every page: the API list, capabilities, the user, the zones, the GUI theme, icons, job results
    "listApis", "listCapabilities", "listUsers", "listZones", "listGuiThemes", "listResourceIcon", "queryAsyncJobResult",
    # dashboard: limits and remaining storage quota, counts, events, GPU slots, leases, the latest quota request
    "listAccounts", "listVirtualMachines", "listVolumes", "listSnapshots", "listEvents", "listServiceOfferings",
    # instances: list, details, metrics tab, console, the actions offered
    "listVirtualMachinesMetrics", "listVirtualMachinesUsageHistory", "createConsoleEndpoint", "startVirtualMachine",
    "stopVirtualMachine", "rebootVirtualMachine", "restoreVirtualMachine", "updateVirtualMachine", "scaleVirtualMachine",
    "resetPasswordForVirtualMachine", "destroyVirtualMachine", "renewVirtualMachineLease",
    # deploy wizard and reinstall: images, offerings, the placement check and the capacity it shows
    "deployVirtualMachine", "listTemplates", "listOsCategories", "listDiskOfferings", "checkPlacement",
    "listPlacementCapacity", "listResourceLimits",
    # volumes: list, metrics tab, create, rename, attach, detach, resize, download, delete
    "listVolumesMetrics", "listVolumesUsageHistory", "createVolume", "updateVolume", "attachVolume", "detachVolume",
    "resizeVolume", "extractVolume", "deleteVolume", "destroyVolume", "recoverVolume",
    # snapshots (rename included) and recurring snapshots of a volume
    "createSnapshot", "updateSnapshot", "deleteSnapshot", "revertSnapshot", "listSnapshotPolicies",
    "createSnapshotPolicy", "deleteSnapshotPolicies",
    # tags of instances, volumes and snapshots
    "listTags", "createTags", "deleteTags",
    # API keys on the user's profile page
    "listUserKeys", "getUserKeys", "registerUserKeys", "deleteUserKeys", "listUserKeyRules",
    # quota requests
    "listResourceLimitRequests", "createResourceLimitRequest", "cancelResourceLimitRequest",
)


class RoleCatalogTest(unittest.TestCase):
    def load(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(text)
        self.addCleanup(os.unlink, f.name)
        return sync.load_roles(f.name)

    def test_loads_ordered_rules(self):
        roles = self.load('[[role]]\nname = "R"\ntype = "Admin"\ndescription = "d"\n'
                          'rules = [["createRole", "deny"], ["*", "allow"]]\n')
        self.assertEqual(roles, [{"name": "R", "type": "Admin", "description": "d",
                                  "rules": [("createRole", "deny"), ("*", "allow")]}])

    def test_rejects_bad_entries(self):
        for text in ('[[role]]\nname = "R"\ntype = "Root"\nrules = [["*", "allow"]]\n',
                     '[[role]]\nname = "R"\ntype = "User"\nrules = [["*", "maybe"]]\n',
                     '[[role]]\nname = "R"\ntype = "User"\nrules = []\n',
                     '[[role]]\nname = "R"\ntype = "User"\nrules = [["*", "allow"]]\n'
                     '[[role]]\nname = "R"\ntype = "User"\nrules = [["*", "allow"]]\n'):
            with self.assertRaises(ValueError):
                self.load(text)

    def test_missing_file_is_empty(self):
        self.assertEqual(sync.load_roles("/nonexistent/roles.toml"), [])

    def test_members_do_not_move_users_between_accounts(self):
        member = {r["name"]: r for r in sync.load_roles(REPO_ROLES)}["Bacchus Member"]
        self.assertEqual(decision(member, "moveUser"), "deny")
        self.assertIn(("moveUser", "deny"), member["rules"])
        # an exact name: the other user commands keep their own rules
        for api in ("listUsers", "disableUser", "enableUser"):
            self.assertEqual(decision(member, api), "allow", api)

    def test_repository_catalog_leaves_providers_and_source_deleting_moves_to_root(self):
        member = {r["name"]: r for r in sync.load_roles(REPO_ROLES)}["Bacchus Member"]

        def permission(api):  # the first matching rule decides, case-insensitively
            return next(p for rule, p in member["rules"] if re.fullmatch(re.escape(rule).replace(r"\*", ".*"), api, re.I))
        for api in ("createOidcProvider", "updateOidcProvider", "deleteOidcProvider", "listOidcProviders",
                    "migrateVolume", "migrateVirtualMachine", "migrateVirtualMachineWithVolume"):
            self.assertEqual(permission(api), "deny", api)
        for api in ("oidcLogin", "migrateSystemVm", "listVolumes", "startVirtualMachine"):
            self.assertEqual(permission(api), "allow", api)

    def test_students_cannot_archive_or_delete_events(self):
        user = {r["name"]: r for r in sync.load_roles(REPO_ROLES)}["SNUCSE User"]
        for api in ("archiveEvents", "deleteEvents"):
            self.assertEqual(decision(user, api), "deny", api)
            self.assertNotIn((api, "allow"), user["rules"])
        # the denies name the two commands only: reading events stays
        self.assertEqual(decision(user, "listEvents"), "allow")
        self.assertTrue(all("*" not in rule for rule, permission in user["rules"] if rule.lower().endswith("events")))

    def test_members_do_not_read_the_directory_configuration(self):
        member = {r["name"]: r for r in sync.load_roles(REPO_ROLES)}["Bacchus Member"]
        self.assertEqual(decision(member, "listLdapConfigurations"), "deny")
        self.assertIn(("listLdapConfigurations", "deny"), member["rules"])
        # an exact name: the other lists keep their own rules
        for api in ("listLdapUsers", "listUsers", "listAccounts", "listConfigurations"):
            self.assertEqual(decision(member, api), "allow", api)

    def test_default_deny_keeps_the_ui_needed_allows_and_the_new_user_apis(self):
        user = {r["name"]: r for r in sync.load_roles(REPO_ROLES)}["SNUCSE User"]
        self.assertEqual(user["rules"][-1], ("*", "deny"))
        self.assertEqual([rule for rule, permission in user["rules"][:-1] if permission != "allow"], [])
        allows = [rule for rule, permission in user["rules"] if permission == "allow"]
        # one command per allow: a wildcard is a case-insensitive substring and would open every command containing it
        self.assertEqual([rule for rule in allows if not re.fullmatch(r"[A-Za-z]+", rule)], [])
        self.assertEqual(len(set(STUDENT_UI_COMMANDS)), len(STUDENT_UI_COMMANDS))
        self.assertEqual(sorted(allows), sorted(STUDENT_UI_COMMANDS))
        for api in STUDENT_UI_COMMANDS:
            self.assertEqual(decision(user, api), "allow", api)
            self.assertEqual(decision(user, api.lower()), "allow", api)
        # the placement, quota request and lease commands: their annotation no longer reaches a default-deny role
        for api in ("checkPlacement", "listPlacementCapacity", "createResourceLimitRequest", "listResourceLimitRequests",
                    "cancelResourceLimitRequest", "renewVirtualMachineLease"):
            self.assertIn((api, "allow"), user["rules"])

    def test_default_deny_closes_what_the_student_ui_does_not_offer(self):
        user = {r["name"]: r for r in sync.load_roles(REPO_ROLES)}["SNUCSE User"]
        # no allow reaches a command that merely resembles an allowed one, or one an old wildcard deny matched by
        # accident (*Iso* in listHypervisorCapabilities, *Nic* in listCniConfiguration)
        for api in ("createSnapshotFromVMSnapshot", "listVolumesForImport", "listZonesMetrics", "listHypervisorCapabilities",
                    "listCniConfiguration", "listSystemVmsUsageHistory", "listEventTypes", "listVMSnapshot"):
            self.assertEqual(decision(user, api), "deny", api)
        # what the student UI no longer offers, so the role no longer allows
        for api in ("archiveEvents", "deleteEvents", "listGpuDevices", "listNetworks", "listSecurityGroups", "listIsos",
                    "createTemplate", "attachIso", "createSSHKeyPair", "listAffinityGroups", "updateVMAffinityGroup",
                    "listInstanceGroups", "listUserData", "resetUserDataForVirtualMachine", "listAnnotations",
                    "listDetailOptions", "uploadVolume", "getUploadParamsForVolume", "changeOfferingForVolume",
                    "changeServiceForVirtualMachine", "expungeVirtualMachine", "recoverVirtualMachine",
                    "setVirtualMachineLease", "listLdapConfigurations", "listHypervisors", "listHosts", "updateUser"):
            self.assertEqual(decision(user, api), "deny", api)

    def test_repository_catalog(self):
        roles = {r["name"]: r for r in sync.load_roles(REPO_ROLES)}
        member = roles["Bacchus Member"]
        self.assertEqual(member["type"], "Admin")
        self.assertEqual(member["rules"][-1], ("*", "allow"))
        denied = {rule for rule, permission in member["rules"][:-1] if permission == "deny"}
        self.assertEqual(len(denied), len(member["rules"]) - 1)
        for api in ("createRole", "updateRolePermission", "importRole", "updateConfiguration", "ldapConfig",
                    "createAccount", "createUser", "updateAccount", "updateUser", "issueCertificate"):
            self.assertIn(api, denied)
        for api in ("createExtension", "registerExtension", "updateRegisteredExtension", "runCustomAction", "addCustomAction"):
            self.assertEqual(decision(member, api), "deny", api)
        for api in ("listExtensions", "listCustomActions", "prepareHostForMaintenance", "deployVirtualMachine",
                    "createVMSnapshot", "revertToVMSnapshot", "listGpuDevices"):
            self.assertEqual(decision(member, api), "allow", api)
        user = roles["SNUCSE User"]
        self.assertEqual(user["type"], "User")
        self.assertEqual(len(user["rules"]), len(STUDENT_UI_COMMANDS) + 1)
        self.assertEqual(user["rules"][-1], ("*", "deny"))
        self.assertEqual(decision(user, "updateUser"), "deny")
        self.assertNotIn(("updateUser", "allow"), user["rules"])

        for api in ("createWebhook", "createBucket", "createKubernetesCluster", "createSharedFileSystem",
                    "deployVnfAppliance", "createDnsZone", "createKMSKey", "createVMSchedule",
                    "setupUserTwoFactorAuthentication", "runCustomAction", "uploadResourceIcon", "listGpuDevices",
                    "addObjectStoragePool", "createHSMProfile", "createPrivateGateway", "listASNumbers",
                    "createVMSnapshot", "revertToVMSnapshot", "deleteVMSnapshot", "listVMSnapshot",
                    "createSnapshotFromVMSnapshot"):
            self.assertEqual(decision(user, api), "deny", api)
        # the commands the UI calls that no role type annotation would reach once the role is default-deny
        for api in ("listGuiThemes", "createConsoleEndpoint", "listVirtualMachinesMetrics", "listResourceIcon",
                    "getUserKeys", "recoverVolume"):
            self.assertIn((api, "allow"), user["rules"])
        for api in ("createSnapshotPolicy", "listSnapshotPolicies", "deployVirtualMachine", "listVolumes",
                    "createSnapshot", "listSnapshots", "revertSnapshot", "deleteSnapshot"):
            self.assertEqual(decision(user, api), "allow", api)
        # placement verdicts and capacity maxima: annotated for every user role, but the role must not rely on
        # the annotation fallback, which a default-deny rule would end
        for api in ("checkPlacement", "listPlacementCapacity"):
            self.assertIn((api, "allow"), user["rules"])
            self.assertEqual(decision(user, api), "allow", api)
        self.assertEqual(decision(user, "updateHostMoveRate"), "deny")
        # resource limit requests: users ask, cancel and list their own; the role must not rely on the annotation fallback,
        # and the decisions stay with the roles that reach them through other rules
        for api in ("createResourceLimitRequest", "listResourceLimitRequests", "cancelResourceLimitRequest"):
            self.assertIn((api, "allow"), user["rules"])
            self.assertEqual(decision(user, api), "allow", api)
        for api in ("approveResourceLimitRequest", "rejectResourceLimitRequest", "revokeResourceLimitRequest"):
            self.assertEqual(decision(user, api), "deny", api)
            self.assertEqual(decision(member, api), "allow", api)
        # users renew the lease of their running instances; setting a lease stays with the roles that reach the admin API
        self.assertIn(("renewVirtualMachineLease", "allow"), user["rules"])
        self.assertEqual(decision(user, "renewVirtualMachineLease"), "allow")
        self.assertNotEqual(decision(user, "setVirtualMachineLease"), "allow")
        self.assertEqual(decision(member, "setVirtualMachineLease"), "allow")


class OfferingLeaseTest(unittest.TestCase):
    def test_lease_comes_from_the_catalog_type(self):
        self.assertEqual(sync.offering_lease({"name": "a100-40g", "lease_hours": 36}),
                         {"leasehours": "36", "leaseexpiryaction": "STOP"})
        self.assertEqual(sync.offering_lease({"name": "a6000", "lease_hours": 48, "lease_expiry_action": "DESTROY"}),
                         {"leasehours": "48", "leaseexpiryaction": "DESTROY"})
        self.assertEqual(sync.offering_lease({"name": "cpu"}), {}, "a type without lease_hours has no lease")
        for bad in ({"lease_hours": 0}, {"lease_hours": -1}, {"lease_hours": "36"}, {"lease_hours": True},
                    {"lease_hours": 36, "lease_expiry_action": "PAUSE"}):
            with self.assertRaises(ValueError, msg=str(bad)):
                sync.offering_lease({"name": "t", **bad})

    def test_lease_change_is_in_place(self):
        type_36 = {"name": "a100-40g", "lease_hours": 36}
        live = {"id": "o-1", "name": "a100-40g-1", "leasehours": 36, "leaseexpiryaction": "STOP"}
        self.assertEqual(sync.offering_lease_update(live, type_36), {}, "in step")
        self.assertEqual(sync.offering_lease_update(live, {**type_36, "lease_hours": 48}),
                         {"leasehours": "48", "leaseexpiryaction": "STOP"})
        self.assertEqual(sync.offering_lease_update(live, {**type_36, "lease_expiry_action": "DESTROY"}),
                         {"leasehours": "36", "leaseexpiryaction": "DESTROY"})
        self.assertEqual(sync.offering_lease_update({"id": "o-2"}, type_36), {"leasehours": "36", "leaseexpiryaction": "STOP"},
                         "an offering without a lease gets the type's")
        self.assertEqual(sync.offering_lease_update(live, {"name": "a100-40g"}), {"leasehours": "0"},
                         "a type that no longer has lease_hours removes the lease")
        self.assertEqual(sync.offering_lease_update({"id": "o-3", "leaseexpiryaction": "STOP"}, {"name": "cpu"}), {},
                         "an offering without leasehours has no lease to remove")


class SyncRolesTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.roles = [{"id": "r-user", "name": "User", "type": "User", "isdefault": True}]
        self.perms = {}
        self.scramble = False

        def fake_cs(command, **params):
            self.calls.append((command, params))
            if command == "listRoles":
                return {"role": [dict(r) for r in self.roles]}
            if command == "listRolePermissions":
                rules = self.perms.get(params["roleid"], [])
                return {"rolepermission": [{"rule": r, "permission": p} for r, p in rules]}
            if command == "importRole":
                role = next((r for r in self.roles if r["name"] == params["name"]), None)
                if role is None:
                    role = {"id": f"r-{len(self.roles)}", "name": params["name"], "type": params["type"]}
                    self.roles.append(role)
                role["description"] = params["description"]
                n = len([k for k in params if k.endswith(".rule")])
                rules = [(params[f"rules[{i}].rule"], params[f"rules[{i}].permission"]) for i in range(n)]
                self.perms[role["id"]] = list(reversed(rules)) if self.scramble else rules
                return {"role": dict(role)}
            return {}
        self._orig = sync.cloudstack
        sync.cloudstack = fake_cs

    def tearDown(self):
        sync.cloudstack = self._orig

    ENTRY = {"name": "Bacchus Member", "type": "Admin", "description": "ops",
             "rules": [("createRole", "deny"), ("*", "allow")]}

    def imports(self):
        return [p for c, p in self.calls if c == "importRole"]

    def test_creates_missing_role_with_ordered_rules(self):
        sync.sync_roles([self.ENTRY])
        (imp,) = self.imports()
        self.assertTrue(imp["post"])
        self.assertEqual((imp["name"], imp["type"], imp["forced"]), ("Bacchus Member", "Admin", "true"))
        self.assertEqual((imp["rules[0].rule"], imp["rules[0].permission"]), ("createRole", "deny"))
        self.assertEqual((imp["rules[1].rule"], imp["rules[1].permission"]), ("*", "allow"))

    def test_leaves_matching_role_alone(self):
        self.roles.append({"id": "r-m", "name": "Bacchus Member", "type": "Admin", "description": "ops"})
        self.perms["r-m"] = list(self.ENTRY["rules"])
        sync.sync_roles([self.ENTRY])
        self.assertEqual(self.imports(), [])

    def test_reimports_drifted_rules_or_description(self):
        self.roles.append({"id": "r-m", "name": "Bacchus Member", "type": "Admin", "description": "ops"})
        self.perms["r-m"] = [("*", "allow")]
        sync.sync_roles([self.ENTRY])
        self.assertEqual(len(self.imports()), 1)
        self.calls.clear()
        self.roles[-1]["description"] = "old"
        sync.sync_roles([self.ENTRY])
        self.assertEqual(len(self.imports()), 1)

    def test_never_touches_built_in_or_retyped_roles(self):
        self.roles.append({"id": "r-m", "name": "Bacchus Member", "type": "User", "description": "ops"})
        sync.sync_roles([self.ENTRY, {**self.ENTRY, "name": "User", "type": "User"}])
        self.assertEqual(self.imports(), [])

    def test_order_read_back_wrong_fails_the_run(self):
        self.scramble = True
        with self.assertRaises(RuntimeError):
            sync.sync_roles([self.ENTRY])


REPO_PROVIDERS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "idps.toml")
REPO_SYNC_MANIFEST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sync.yaml")
REPO_KUSTOMIZATION = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kustomization.yaml")


class ProvidersFromIdpsTomlTest(unittest.TestCase):
    def load(self, text):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        self.addCleanup(os.unlink, tmp.name)
        tmp.write(text)
        tmp.close()
        return sync.load_providers(tmp.name)

    def test_providers_from_idps_toml(self):
        providers = {p["name"]: p for p in sync.load_providers(REPO_PROVIDERS)}
        self.assertEqual(list(providers), ["snucse", "bacchus"])
        snucse, bacchus = providers["snucse"]["params"], providers["bacchus"]["params"]
        self.assertEqual((providers["snucse"]["domain"], providers["snucse"]["role"]), ("ROOT/snucse", "SNUCSE User"))
        self.assertEqual((providers["bacchus"]["domain"], providers["bacchus"]["role"]), ("ROOT", "Bacchus Member"))
        # the student username is the SNUCSE ID username claim, the member username the lowercased address
        self.assertEqual((snucse["usernameclaim"], snucse["lowercaseusername"]), ("username", False))
        self.assertEqual((bacchus["usernameclaim"], bacchus["lowercaseusername"]), ("email", True))
        self.assertEqual(snucse["admission"], {"groups_claim": "groups", "allowed_groups": ["major"]})
        self.assertEqual(bacchus["admission"], {"groups_claim": "https://bacchus.io/groups",
                                                "allowed_groups": ["regular-members@bacchus.snucse.org"],
                                                "subject_prefix": "google-apps|"})
        self.assertEqual((snucse["requireverifiedemail"], bacchus["requireverifiedemail"]), (False, True))
        self.assertEqual(bacchus["authorizeparams"], {"connection": "bacchus-workspace"})
        self.assertEqual((snucse["jit"], bacchus["jit"]), (True, True))
        self.assertEqual(snucse["endsessionurl"], "https://id.snucse.org/o/session/end")
        self.assertEqual(bacchus["endsessionurl"], bacchus["issuer"] + "oidc/logout")
        self.assertTrue(snucse["endsessionlabel"] and bacchus["endsessionlabel"])
        self.assertEqual((snucse["cacertificate"], bacchus["cacertificate"]), ("", ""))
        self.assertEqual((snucse["enabled"], bacchus["enabled"]), (True, True))
        self.assertEqual(providers["snucse"]["membership_source"], {})
        self.assertEqual(providers["bacchus"]["membership_source"], {})
        for p in (snucse, bacchus):
            self.assertEqual(p["scopes"], "openid profile email")
            self.assertTrue(p["issuer"].startswith("https://"))
            self.assertIn("/client/api?command=oidcLogin&amp;provider=snucse", p["refusal"])
            self.assertNotIn("/gate/", p["refusal"])
        # one bastion namespace: no student username can be a member username, and the other way round
        self.assertIsNone(re.fullmatch(snucse["usernamepattern"], "someone@bacchus.snucse.org"))
        self.assertIsNone(re.fullmatch(bacchus["usernamepattern"], "someone"))
        self.assertIsNotNone(re.fullmatch(snucse["usernamepattern"], "someone"))
        self.assertIsNotNone(re.fullmatch(bacchus["usernamepattern"], "someone@bacchus.snucse.org"))

    def test_every_provider_reaches_the_job(self):
        names = [p["name"] for p in sync.load_providers(REPO_PROVIDERS)]
        with open(REPO_SYNC_MANIFEST) as f:
            manifest = f.read()
        for name in names:
            for suffix in ("CLIENT_ID", "CLIENT_SECRET"):
                self.assertIn(f"- name: OIDC_{name.upper()}_{suffix}\n", manifest)
        with open(REPO_KUSTOMIZATION) as f:
            self.assertRegex(f.read(), r"name: cloudstack-sync\n    files:\n(      - .*\n)*      - idps.toml\n")
        self.assertEqual(sync.PROVIDERS_PATH, "/opt/sync/idps.toml")

    def test_rejects_malformed_entries(self):
        good = ('[[provider]]\nname = "p"\nlabel = "P"\nissuer = "https://p.example"\nusername_claim = "u"\n'
                'username_pattern = "[a-z]+"\ngroups_claim = "g"\nallowed_groups = ["a"]\ndomain = "ROOT"\nrole = "R"\n')
        self.assertEqual([p["name"] for p in self.load(good)], ["p"])
        for text in (good.replace('name = "p"', 'name = "P-1"'),
                     good.replace('issuer = "https://p.example"\n', ""),
                     good + 'require_verifed_email = true\n',
                     good + 'end_session_url = "https://p.example/logout"\n',
                     good + good):
            with self.assertRaises(ValueError):
                self.load(text)

    def test_missing_file_is_empty(self):
        self.assertEqual(sync.load_providers("/nonexistent/idps.toml"), [])


class LoginPageTest(unittest.TestCase):
    def test_sign_in_is_the_clients_own(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "config.json")) as f:
            config = json.load(f)
        # the page lists the providers and folds the password form itself
        self.assertIs(config["foldPasswordLogin"], True)
        self.assertNotIn("/gate/", config["loginFooter"])
        self.assertNotIn("cs-password-login", config["loginFooter"])
        self.assertNotIn("user-layout-login", config["loginFooter"])

    def test_only_the_student_sign_in_is_listed(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "config.json")) as f:
            config = json.load(f)
        names = [p["name"] for p in sync.load_providers(REPO_PROVIDERS)]
        # every other provider sits in the folded section with the password form
        self.assertEqual(sorted(config["foldedLoginProviders"]), sorted(name for name in names if name != "snucse"))

    def test_no_other_way_in(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, "kustomization.yaml")) as f:
            kustomization = f.read()
        with open(os.path.join(here, "resources.yaml")) as f:
            routes = f.read()
        self.assertNotIn("gate", re.findall(r"^  - (\S+)\.yaml$", kustomization, re.M))
        self.assertNotIn("value: /gate/", routes)
        self.assertFalse(os.path.exists(os.path.join(here, "gate.py")))
        # the stock OAuth sign-in is gone from the server; no rule names it any more
        rules = [rule for role in sync.load_roles(REPO_ROLES) for rule, _ in role["rules"]]
        self.assertEqual([rule for rule in rules if "oauth" in rule.lower()], [])


# the locales of the UI's language menu, in its order
UI_LANGUAGES = ("en", "hi", "te", "ja_JP", "ko_KR", "zh_CN", "ar", "ca", "de_DE", "es", "fr_FR", "it_IT", "hu", "nl_NL",
                "nb_NO", "pl", "pt_BR", "ru_RU", "el_GR")


class UiConfigTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "config.json")) as f:
            self.config = json.load(f)

    def test_the_instance_page_names_the_bastion_and_the_account_it_logs_in_as(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        access = self.config["instanceAccess"]
        with open(os.path.join(here, "warpgate-config.yaml")) as f:
            ssh_port = int(re.search(r"^ssh:\n(?:  .*\n)*?  listen: \"[^\"]*:(\d+)\"", f.read(), re.M).group(1))
        self.assertEqual((access["sshHost"], access["sshPort"]), ("cloud.snucse.org", ssh_port))
        # the page looks the account up by template family, the bastion by template: they must agree
        for entry in sync.load_catalog(os.path.join(here, "templates.toml")):
            self.assertEqual(access["loginAccounts"].get(entry["name"].split("-")[0].lower()), entry["user"], entry["name"])

    def test_the_guest_list_checks_names_by_the_sign_in_rules(self):
        # a guest is named by an account name, which each sign-in provider derives by its username pattern
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "idps.toml"), "rb") as f:
            providers = tomllib.load(f)["provider"]
        self.assertEqual(self.config["instanceAccess"]["guestPatterns"],
                         [p["username_pattern"] for p in providers if p.get("enabled", True)])

    def test_the_ui_hides_for_users_only_what_their_role_cannot_express(self):
        hidden = self.config["hidden"]
        self.assertEqual(sorted(hidden), ["User"], "Bacchus members and root keep the full UI")
        user = hidden["User"]
        # pages whose list command the student UI still needs elsewhere: the menu entry goes, the route stays
        self.assertEqual(sorted(user["sidebar"]), sorted(["template", "snapshotpolicy", "event", "account", "zones",
                                                           "computeoffering", "diskoffering", "apidocs"]))
        self.assertEqual(user["header"], [])
        for row in ("project", "template", "network", "bucket"):
            self.assertIn(row, user["dashboard"])
        for kept in ("vm", "cpu", "memory", "gpu", "volume", "storage", "gpuslots", "leases", "requests", "help", "events"):
            self.assertNotIn(kept, user["dashboard"])
        # a snapshot of a root disk boots a new instance, like a template or a detached root
        self.assertEqual(user["deploy"], ["dynamicscalingenabled", "keyboard"])
        self.assertEqual(user["actions"], ["vm.createSnapshot"])
        for field in ("vm.name", "vm.state", "vm.serviceofferingname", "vm.gpucardname", "vm.gpucount", "vm.leaseexpirydate"):
            self.assertNotIn(field, user["details"])
        # one zone, and the instance's state is on the instance list
        self.assertEqual(user["columns"], ["volume.vmstate", "volume.zonename"])
        # what a role cannot call is never listed here: the API list hides it
        for entry in user["sidebar"]:
            self.assertNotIn(entry, ("guestnetwork", "vpc", "securitygroups", "vmsnapshot", "kubernetes", "iso"))

    def test_the_header_offers_the_manual_and_two_languages(self):
        # students get en and ko_KR; Bacchus members and root keep every language
        self.assertNotIn("languages", self.config)
        hidden_languages = self.config["hidden"]["User"]["languages"]
        self.assertLessEqual(set(hidden_languages), set(UI_LANGUAGES))
        self.assertEqual([key for key in UI_LANGUAGES if key not in hidden_languages], ["en", "ko_KR"])
        self.assertEqual(self.config["docBase"], "https://docs.cloud.snucse.org")
        self.assertIs(self.config["allowSettingTheme"], False)
        self.assertIs(self.config["showGpuSlots"], True)
        self.assertIs(self.config["showCpuSpeed"], False)
        for link in self.config["userCard"]["links"]:
            self.assertNotIn("apache.org", link["link"])
        # the pages users work in open the manual; any other help opens the upstream guides of this release
        mappings = self.config["docHelpMappings"]
        self.assertEqual(mappings["adminguide/virtual_machines.html"], "instance.html")
        self.assertEqual(mappings["adminguide/storage.html"], "instance.html")
        for prefix in ("adminguide/", "installguide/", "conceptsandterminology/", "plugins/"):
            self.assertEqual(mappings[prefix], "https://docs.cloudstack.apache.org/en/4.23.0.0/" + prefix)
        self.assertLess(list(mappings).index("adminguide/storage.html"), list(mappings).index("adminguide/"))


class SyncOidcProvidersTest(unittest.TestCase):
    ENTRY = {"name": "students", "domain": "ROOT/students", "role": "Student", "membership_source": {},
             "params": {"label": "Students", "issuer": "https://id.example", "scopes": "openid profile email",
                        "authorizeparams": {}, "usernameclaim": "username", "lowercaseusername": False,
                        "usernamepattern": "[a-z]+", "requireverifiedemail": False,
                        "admission": {"groups_claim": "groups", "allowed_groups": ["major"]}, "refusal": "<p>No.</p>",
                        "jit": True, "endsessionurl": "https://id.example/session/end", "endsessionlabel": "Log out",
                        "cacertificate": "", "enabled": True}}
    ENV = {"OIDC_STUDENTS_CLIENT_ID": "client-1", "OIDC_STUDENTS_CLIENT_SECRET": "very-secret"}

    def setUp(self):
        self.calls = []
        self.live = []
        self.state = {"metadata": {"name": "cloudstack-sync-state", "resourceVersion": "1"}}
        self.puts = []
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(f"{tmp.name}/namespace", "w") as f:
            f.write("cloudstack")

        def fake_cs(command, **params):
            self.calls.append((command, params))
            if command == "listOidcProviders":
                return {"oidcprovider": [dict(p) for p in self.live]}
            if command == "listDomains":
                return {"domain": [{"id": "d-root", "path": "ROOT"}, {"id": "d-students", "path": "ROOT/students"}]}
            if command == "listRoles":
                return {"role": [{"id": "r-student", "name": "Student"}, {"id": "r-admin", "name": "Root Admin"}]}
            return {}

        def fake_kube(method, path, body=None):
            self.assertEqual(path, "/api/v1/namespaces/cloudstack/configmaps/cloudstack-sync-state")
            if method == "GET":
                return 200, json.loads(json.dumps(self.state))
            self.puts.append(body)
            self.state = body
            return 200, body

        for p in (mock.patch.object(sync, "cloudstack", fake_cs), mock.patch.object(sync, "kube", fake_kube),
                  mock.patch.object(sync, "SA_DIR", tmp.name)):
            p.start()
            self.addCleanup(p.stop)

    def provider_calls(self):
        return [(c, p) for c, p in self.calls if c in ("createOidcProvider", "updateOidcProvider")]

    def listed(self, **overrides):
        params = self.ENTRY["params"]
        provider = {"id": "op-1", "name": "students", "label": params["label"], "issuer": params["issuer"],
                    "clientid": "client-1", "scopes": params["scopes"], "usernameclaim": "username",
                    "lowercaseusername": False, "usernamepattern": "[a-z]+", "requireverifiedemail": False,
                    "admission": '{"groups_claim":"groups","allowed_groups":["major"]}', "refusal": "<p>No.</p>",
                    "jit": True, "endsessionurl": "https://id.example/session/end", "endsessionlabel": "Log out",
                    "domainid": "d-students", "domainpath": "/students/", "roleid": "r-student", "rolename": "Student",
                    "enabled": True, "callbackurl": "https://cloud.example/client/oidc/callback/students"}
        provider.update(overrides)
        return provider

    def run_sync(self, catalog=None, env=None):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            failed = sync.sync_oidc_providers([self.ENTRY] if catalog is None else catalog, self.ENV if env is None else env)
        return failed, out.getvalue()

    def test_creates_a_missing_provider_with_its_client(self):
        failed, out = self.run_sync()
        self.assertEqual(failed, [])
        ((command, params),) = self.provider_calls()
        self.assertEqual(command, "createOidcProvider")
        self.assertTrue(params["post"])
        self.assertEqual(params["name"], "students")
        self.assertEqual((params["clientid"], params["clientsecret"]), ("client-1", "very-secret"))
        self.assertEqual((params["domainid"], params["roleid"]), ("d-students", "r-student"))
        self.assertEqual((params["jit"], params["lowercaseusername"], params["enabled"]), ("true", "false", "true"))
        self.assertEqual(json.loads(params["admission"]), {"groups_claim": "groups", "allowed_groups": ["major"]})
        self.assertEqual((params["endsessionurl"], params["endsessionlabel"]), ("https://id.example/session/end", "Log out"))
        self.assertNotIn("authorizeparams", params)
        self.assertNotIn("cacertificate", params)
        self.assertIn("OpenID provider students created", out)
        (put,) = self.puts
        self.assertEqual(set(put["data"]), {"oidc.students.clientsecret"})
        self.assertEqual(put["metadata"]["resourceVersion"], "1")
        self.assertNotIn("very-secret", json.dumps(put) + out)

    def test_provider_without_client_credentials_is_not_created(self):
        failed, out = self.run_sync(env={})
        self.assertEqual((failed, self.provider_calls(), self.puts), ([], [], []))
        self.assertIn("no OIDC_STUDENTS_CLIENT_ID and OIDC_STUDENTS_CLIENT_SECRET; not created", out)

    def test_matching_provider_is_left_alone(self):
        self.run_sync()
        self.live = [self.listed()]
        self.calls.clear()
        self.puts.clear()
        self.assertEqual(self.run_sync(), ([], ""))
        self.assertEqual((self.provider_calls(), self.puts), ([], []))

    def test_drift_is_written_back_and_nothing_else(self):
        self.run_sync()
        self.live = [self.listed(label="Old", refusal=None, jit=False, admission='{"allowed_groups":["major"],"groups_claim":"groups"}',
                                 endsessionurl=None, endsessionlabel=None, domainid="d-root")]
        self.calls.clear()
        failed, out = self.run_sync()
        ((command, params),) = self.provider_calls()
        self.assertEqual(command, "updateOidcProvider")
        self.assertEqual(params["id"], "op-1")
        self.assertEqual({k: v for k, v in params.items() if k not in ("id", "post")},
                         {"label": "Students", "refusal": "<p>No.</p>", "jit": "true", "domainid": "d-students",
                          "endsessionurl": "https://id.example/session/end", "endsessionlabel": "Log out"})
        self.assertIn("OpenID provider students updated: domainid, endsessionlabel, endsessionurl, jit, label, refusal", out)

    def test_optional_values_left_out_of_the_catalog_are_removed(self):
        self.run_sync()
        entry = {**self.ENTRY, "params": {**self.ENTRY["params"], "refusal": "", "endsessionurl": "", "endsessionlabel": ""}}
        self.live = [self.listed(authorizeparams='{"prompt":"login"}', cacertificate="-----BEGIN CERTIFICATE-----")]
        self.calls.clear()
        self.run_sync(catalog=[entry])
        ((_, params),) = self.provider_calls()
        self.assertEqual({k: v for k, v in params.items() if k not in ("id", "post")},
                         {"refusal": "", "endsessionurl": "", "endsessionlabel": "", "authorizeparams": "", "cacertificate": ""})

    def test_a_changed_secret_is_written_once(self):
        self.run_sync()
        self.live = [self.listed()]
        self.calls.clear()
        env = {**self.ENV, "OIDC_STUDENTS_CLIENT_SECRET": "rotated"}
        self.run_sync(env=env)
        ((_, params),) = self.provider_calls()
        self.assertEqual((params["clientid"], params["clientsecret"]), ("client-1", "rotated"))
        self.calls.clear()
        self.run_sync(env=env)
        self.assertEqual(self.provider_calls(), [])

    def test_a_changed_client_brings_its_secret(self):
        self.run_sync()
        self.live = [self.listed(clientid="client-0")]
        self.calls.clear()
        self.run_sync()
        ((_, params),) = self.provider_calls()
        self.assertEqual((params["clientid"], params["clientsecret"]), ("client-1", "very-secret"))

    def test_lost_state_writes_the_secret_again(self):
        self.live = [self.listed()]
        self.run_sync()
        ((_, params),) = self.provider_calls()
        self.assertEqual(set(params) - {"id", "post"}, {"clientid", "clientsecret"})

    def test_membership_source_waits_for_its_secret(self):
        entry = {**self.ENTRY, "membership_source": {"type": "google-directory"}}
        self.run_sync()
        self.live = [self.listed()]
        self.calls.clear()
        failed, out = self.run_sync(catalog=[entry])
        self.assertEqual(self.provider_calls(), [])
        self.assertIn("membership source waits for OIDC_STUDENTS_MEMBERSHIP_SECRET", out)

        env = {**self.ENV, "OIDC_STUDENTS_MEMBERSHIP_SECRET": '{"type": "service_account"}'}
        self.run_sync(catalog=[entry], env=env)
        ((_, params),) = self.provider_calls()
        self.assertEqual(json.loads(params["membershipsource"]), {"type": "google-directory"})
        self.assertEqual(params["membershipsecret"], '{"type": "service_account"}')
        self.assertIn("oidc.students.membershipsecret", self.state["data"])

        self.live = [self.listed(membershipsource='{"type":"google-directory"}')]
        self.calls.clear()
        self.run_sync(catalog=[entry], env=env)
        self.assertEqual(self.provider_calls(), [])

        self.run_sync(env=env)
        ((_, params),) = self.provider_calls()
        self.assertEqual((params["membershipsource"], params["membershipsecret"]), ("", ""))
        self.assertNotIn("oidc.students.membershipsecret", self.state["data"])

    def test_a_provider_the_catalog_does_not_list_is_disabled_not_deleted(self):
        self.live = [self.listed(), self.listed(id="op-2", name="intruder", clientid="x")]
        self.run_sync()
        self.assertIn(("updateOidcProvider", {"post": True, "id": "op-2", "enabled": "false"}), self.provider_calls())
        self.assertNotIn("deleteOidcProvider", [c for c, _ in self.calls])
        self.calls.clear()
        self.live[1]["enabled"] = False
        self.run_sync()
        self.assertFalse([p for c, p in self.provider_calls() if p.get("id") == "op-2"])

    def test_a_listing_without_configuration_changes_nothing(self):
        self.live = [{"id": "op-1", "name": "students", "label": "Students"}]
        failed, out = self.run_sync()
        self.assertEqual((failed, self.provider_calls()), (["providers"], []))
        self.assertIn("not a root administrator", out)

    def test_one_provider_failing_holds_back_none_of_the_others(self):
        broken = {**self.ENTRY, "name": "elsewhere", "domain": "ROOT/missing"}
        env = {**self.ENV, "OIDC_ELSEWHERE_CLIENT_ID": "c", "OIDC_ELSEWHERE_CLIENT_SECRET": "s"}
        failed, out = self.run_sync(catalog=[broken, self.ENTRY], env=env)
        self.assertEqual(failed, ["elsewhere"])
        self.assertEqual([p["name"] for c, p in self.provider_calls()], ["students"])
        self.assertIn("error: OpenID provider elsewhere: domain ROOT/missing", out)

    # every step of a run but the providers'
    STEPS = ("sync_console_endpoints", "prune_management_servers", "load_roles", "sync_roles", "declared_client_keys",
             "sync_client_keys", "sync_warpgate", "sync_template_userdata", "restore_console_proxy_state",
             "sync_console_certificate")

    def test_an_unreadable_catalog_fails_the_run_after_every_other_step(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        self.addCleanup(os.unlink, tmp.name)
        tmp.write("[[provider]\n")
        tmp.close()
        with mock.patch.multiple(sync, **{step: mock.DEFAULT for step in self.STEPS}) as steps, \
                mock.patch.multiple(sync, PROVIDERS_PATH=tmp.name, WARPGATE_HOST="warpgate.example",
                                    WARPGATE_TLS_NAME="warpgate.example", WARPGATE_TOKEN="token"), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            with self.assertRaisesRegex(RuntimeError, "OpenID providers not reconciled: providers"):
                sync.main()
        self.assertEqual({step: steps[step].call_count for step in self.STEPS}, dict.fromkeys(self.STEPS, 1))
        self.assertEqual(self.calls, [])
        self.assertIn("error: OpenID providers:", out.getvalue())


class SsoProvidersTest(unittest.TestCase):
    def test_parses_domain_paths(self):
        self.assertEqual(sync.sso_providers("ROOT=bacchus, ROOT/snucse=snucse,"),
                         {"ROOT": "bacchus", "ROOT/snucse": "snucse"})

    def test_rejects_malformed(self):
        for spec in ("ROOT", "=bacchus", "ROOT="):
            with self.assertRaises(ValueError):
                sync.sso_providers(spec)


def paged(items, params):
    """One page of a list response; like the server, an unpaged request gets only the first page."""
    size = params.get("pagesize", sync.LIST_PAGE_SIZE)
    start = (params.get("page", 1) - 1) * size
    return items[start:start + size]


class WarpgateSsoTest(unittest.TestCase):
    """Credentials follow the provider of the user's domain."""

    def setUp(self):
        self.wg_users = {"bob": {"id": "wu-bob", "username": "bob", "description": "cloudstack:user:u-bob"}}
        self.creds = {"wu-bob": [{"id": "c-null", "provider": None, "email": "bob@snu.ac.kr"},
                                 {"id": "c-old", "provider": "snucse", "email": "old@snu.ac.kr"}]}
        self.wg_calls = []
        self.account_states = {}  # (domain id, account name) -> state; enabled when absent
        users = [
            {"id": "u-bob", "username": "bob", "account": "bob", "domainid": "d-snucse", "email": "bob@snu.ac.kr",
             "state": "enabled", "accounttype": 0},
            {"id": "u-m", "username": "m@bacchus.snucse.org", "account": "m@bacchus.snucse.org", "domainid": "d-root",
             "email": "m@bacchus.snucse.org", "state": "enabled", "accounttype": 1},
            {"id": "u-x", "username": "x", "account": "x", "domainid": "d-other", "email": "x@example.org",
             "state": "enabled", "accounttype": 0},
            {"id": "u-admin", "username": "admin", "account": "admin", "domainid": "d-root", "state": "enabled", "accounttype": 1},
        ]

        def fake_cs(command, **params):
            if command == "listDomains":
                return {"domain": paged([{"id": "d-root", "path": "ROOT"}, {"id": "d-snucse", "path": "ROOT/snucse"},
                                         {"id": "d-other", "path": "ROOT/other"}], params)}
            if command == "listUsers":
                return {"user": paged(users, params)}
            if command == "listAccounts":
                return {"account": paged([{"id": f"a-{u['account']}", "name": u["account"], "domainid": u["domainid"],
                                           "state": self.account_states.get((u["domainid"], u["account"]), "enabled")}
                                          for u in users], params)}
            return {}

        def fake_wg(method, path, body=None):
            self.wg_calls.append((method, path, body))
            if method == "GET" and path == "/roles":
                return 200, [{"id": "r-admins", "name": "admins", "description": "cloudstack:admins"},
                             {"id": "r-bob", "name": "account-bob", "description": "cloudstack:account:a-bob"},
                             {"id": "r-m", "name": "account-m@bacchus.snucse.org", "description": "cloudstack:account:a-m"}]
            if method == "GET" and path == "/users":
                return 200, list(self.wg_users.values())
            if method == "POST" and path == "/users":
                self.wg_users[body["username"]] = {"id": f"wu-{body['username']}", "username": body["username"],
                                                   "description": body["description"]}
                return 201, {}
            m = re.fullmatch(r"/users/([^/]+)/credentials/sso", path)
            if m and method == "GET":
                return 200, list(self.creds.get(m.group(1), []))
            if m and method == "POST":
                self.creds.setdefault(m.group(1), []).append({"id": "c-new", **body})
                return 201, {}
            if re.fullmatch(r"/users/[^/]+/roles", path):
                return 200, []
            if path in ("/targets", "/ssh/known-hosts"):
                return 200, []
            return 200, {}

        self.fake_cs_orig = fake_cs
        patches = [mock.patch.object(sync, "cloudstack", fake_cs), mock.patch.object(sync, "warpgate", fake_wg),
                   mock.patch.object(sync, "WARPGATE_SSO", "ROOT=bacchus,ROOT/snucse=snucse"),
                   mock.patch.object(sync, "load_catalog", lambda: []),
                   mock.patch.object(sync, "sync_templates", lambda catalog: {})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_provider_per_domain_and_unmapped_domains_skipped(self):
        sync.sync_warpgate()
        created = {b["username"] for m, p, b in self.wg_calls if m == "POST" and p == "/users"}
        self.assertEqual(created, {"m@bacchus.snucse.org"})
        posted = {(p, b["provider"], b["email"]) for m, p, b in self.wg_calls
                  if m == "POST" and p.endswith("/credentials/sso")}
        self.assertEqual(posted, {("/users/wu-bob/credentials/sso", "snucse", "bob@snu.ac.kr"),
                                  ("/users/wu-m@bacchus.snucse.org/credentials/sso", "bacchus", "m@bacchus.snucse.org")})
        deleted = {p for m, p, b in self.wg_calls if m == "DELETE" and "/credentials/sso/" in p}
        self.assertEqual(deleted, {"/users/wu-bob/credentials/sso/c-null", "/users/wu-bob/credentials/sso/c-old"})

    def test_passwords_open_nothing(self):
        self.wg_users["bob"]["credential_policy"] = {"http": ["Sso"], "ssh": None}
        sync.sync_warpgate()
        params = [b for m, p, b in self.wg_calls if m == "PUT" and p == "/parameters"]
        self.assertEqual(params, [{"ssh_client_auth_password": False, "password_login_mode": "Minimized"}])
        policies = {p: b for m, p, b in self.wg_calls if m == "PUT" and p.startswith("/users/")}
        self.assertEqual(list(policies), ["/users/wu-m@bacchus.snucse.org"])  # bob already has it
        body = policies["/users/wu-m@bacchus.snucse.org"]
        self.assertEqual((body["username"], body["credential_policy"]), ("m@bacchus.snucse.org", {"http": ["Sso"]}))
        self.assertIn("description", body)

    def test_parameters_left_alone_when_set(self):
        orig = sync.warpgate

        def wg(method, path, body=None):
            if method == "GET" and path == "/parameters":
                return 200, {"ssh_client_auth_password": False, "password_login_mode": "Minimized", "other": 1}
            return orig(method, path, body)
        with mock.patch.object(sync, "warpgate", wg):
            sync.sync_warpgate_parameters()
        self.assertFalse([c for c in self.wg_calls if c[1] == "/parameters"])

    def test_same_name_in_two_domains_is_not_mirrored(self):
        twin = {"id": "u-bob2", "username": "bob", "account": "bob", "domainid": "d-root", "email": "bob@bacchus.snucse.org",
                "state": "enabled", "accounttype": 1}
        listed = sync.cloudstack("listUsers")["user"]
        accounts = sync.cloudstack("listAccounts")["account"] + [
            {"id": "a-bob2", "name": "bob", "domainid": "d-root", "state": "enabled"}]

        def cs(c, **p):
            if c == "listUsers":
                return {"user": listed + [twin]}
            if c == "listAccounts":
                return {"account": accounts}
            return self.fake_cs_orig(c, **p)
        with mock.patch.object(sync, "cloudstack", cs):
            sync.sync_warpgate()
        self.assertFalse([b for m, p, b in self.wg_calls if m == "POST" and p == "/users/wu-bob/credentials/sso"])
        self.assertIn(("DELETE", "/users/wu-bob", None), self.wg_calls)

    def test_disabled_account_loses_its_bastion_user(self):
        self.account_states[("d-snucse", "bob")] = "disabled"
        sync.sync_warpgate()
        self.assertIn(("DELETE", "/users/wu-bob", None), self.wg_calls)
        self.assertFalse([p for m, p, b in self.wg_calls if m == "POST" and p == "/users/wu-bob/credentials/sso"])

    def test_locked_account_loses_its_bastion_user(self):
        self.account_states[("d-snucse", "bob")] = "locked"
        sync.sync_warpgate()
        self.assertIn(("DELETE", "/users/wu-bob", None), self.wg_calls)

    def test_account_state_is_per_domain(self):
        # a disabled account of the same name in another domain leaves this one's user in place
        self.account_states[("d-root", "bob")] = "disabled"
        sync.sync_warpgate()
        self.assertNotIn(("DELETE", "/users/wu-bob", None), self.wg_calls)

    def test_users_past_the_first_page_are_kept(self):
        with mock.patch.object(sync, "LIST_PAGE_SIZE", 1):
            sync.sync_warpgate()
        self.assertNotIn(("DELETE", "/users/wu-bob", None), self.wg_calls)
        created = {b["username"] for m, p, b in self.wg_calls if m == "POST" and p == "/users"}
        self.assertEqual(created, {"m@bacchus.snucse.org"})

    def test_empty_mapping_fails_instead_of_removing_everyone(self):
        with mock.patch.object(sync, "WARPGATE_SSO", ""):
            with self.assertRaises(ValueError):
                sync.sync_warpgate()
        self.assertFalse([c for c in self.wg_calls if c[0] == "DELETE"])


class TargetRenameRunTest(unittest.TestCase):
    """A renamed VM keeps its bastion target, the target's roles and the host key pinned for it."""

    setUp = WarpgateSsoTest.setUp

    def test_the_target_is_renamed_in_place(self):
        vm = {"id": "vm-1", "name": "snucse-bob-old", "sshname": "snucse-bob-new", "account": "bob",
              "domainid": "d-snucse", "nic": [{"ipaddress": "10.94.1.5"}]}
        targets = [{"id": "t1", "name": "snucse-bob-old", "description": "cloudstack:vm:vm-1:root:v1",
                    "options": {"kind": "Ssh", "host": "10.94.1.5", "port": 22, "username": "ubuntu"}}]
        known = [{"id": "k1", "host": "10.94.1.5", "port": 22}]
        orig_cs, orig_wg = sync.cloudstack, sync.warpgate

        def cs(command, **params):
            if command == "listVirtualMachines":
                return {"virtualmachine": paged([vm], params)}
            if command == "listVolumes":
                return {"volume": paged([{"id": "v1", "virtualmachineid": "vm-1"}], params)}
            return orig_cs(command, **params)

        def wg(method, path, body=None):
            if method == "GET" and path in ("/targets", "/ssh/known-hosts"):
                self.wg_calls.append((method, path, body))
                return 200, targets if path == "/targets" else known
            return orig_wg(method, path, body)
        with mock.patch.object(sync, "cloudstack", cs), mock.patch.object(sync, "warpgate", wg):
            sync.sync_warpgate()
        writes = [(m, p, (b or {}).get("name")) for m, p, b in self.wg_calls
                  if m in ("POST", "PUT", "DELETE") and p.startswith(("/targets", "/ssh"))]
        self.assertIn(("PUT", "/targets/t1", "snucse-bob-new"), writes)
        self.assertNotIn(("POST", "/targets", "snucse-bob-new"), writes)
        self.assertNotIn(("DELETE", "/targets/t1", None), writes)
        self.assertFalse([w for w in writes if w[1].startswith("/ssh/known-hosts")], "the host key stays pinned")

    def run_with(self, vm, targets, target_roles):
        orig_cs, orig_wg = sync.cloudstack, sync.warpgate

        def cs(command, **params):
            if command == "listVirtualMachines":
                return {"virtualmachine": paged([vm], params)}
            if command == "listVolumes":
                return {"volume": paged([{"id": "v1", "virtualmachineid": vm["id"]}], params)}
            return orig_cs(command, **params)

        def wg(method, path, body=None):
            if method == "GET" and path in ("/targets", "/ssh/known-hosts"):
                self.wg_calls.append((method, path, body))
                return 200, targets if path == "/targets" else []
            m = re.fullmatch(r"/targets/([^/]+)/roles", path)
            if method == "GET" and m:
                return 200, target_roles.get(m.group(1), [])
            return orig_wg(method, path, body)
        demoted_calls = []
        with mock.patch.object(sync, "cloudstack", cs), mock.patch.object(sync, "warpgate", wg), \
                mock.patch.object(sync, "close_demoted_sessions", lambda d, t, r: demoted_calls.append((d, dict(t), r))):
            sync.sync_warpgate()
        return demoted_calls

    def test_a_target_taken_over_by_another_account_loses_the_old_roles_first(self):
        vm = {"id": "vm-2", "name": "web", "account": "bob", "domainid": "d-snucse", "nic": [{"ipaddress": "10.94.1.9"}]}
        targets = [{"id": "t1", "name": "web", "description": "cloudstack:vm:vm-1:root:v0",
                    "options": {"kind": "Ssh", "host": "10.94.1.5", "port": 22, "username": "ubuntu"}}]
        self.run_with(vm, targets, {"t1": [{"id": "r-alice", "name": "account-alice", "description": "cloudstack:account:a-alice"}]})
        calls = [(m, p) for m, p, b in self.wg_calls]
        self.assertLess(calls.index(("DELETE", "/targets/t1/roles/r-alice")), calls.index(("PUT", "/targets/t1")),
                        "the previous owner cannot reach the new VM, not even for a moment")

    def test_sessions_of_the_demoted_are_closed_on_a_renamed_target_in_the_same_run(self):
        vm = {"id": "vm-1", "name": "snucse-bob-old", "sshname": "snucse-bob-new", "account": "bob",
              "domainid": "d-snucse", "nic": [{"ipaddress": "10.94.1.5"}]}
        targets = [{"id": "t1", "name": "snucse-bob-old", "description": "cloudstack:vm:vm-1:root:v1",
                    "options": {"kind": "Ssh", "host": "10.94.1.5", "port": 22, "username": "ubuntu"}}]
        (demoted, seen, reach), = self.run_with(vm, targets, {})
        self.assertEqual(seen["snucse-bob-new"]["id"], "t1")
        self.assertIn("snucse-bob-new", reach)


SETTINGS_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_main_with(**results):
    """Runs main() with every step it calls replaced by a stand-in that finds nothing to reconcile, but for the
    steps given, which return the results given. Returns how often each stand-in ran and the error main() ended
    with."""
    steps = [n for n in sync.main.__code__.co_names if callable(getattr(sync, n, None)) and n not in results]
    with mock.patch.multiple(sync, **{n: mock.DEFAULT for n in steps}) as patched, \
            mock.patch.multiple(sync, **{n: mock.Mock(return_value=r) for n, r in results.items()}), \
            mock.patch.multiple(sync, WARPGATE_HOST="warpgate.example", WARPGATE_TLS_NAME="warpgate.example",
                                WARPGATE_TOKEN="token"):
        for step in patched.values():
            step.return_value = []
        try:
            sync.main()
            error = None
        except RuntimeError as e:
            error = e
        return {n: patched[n].call_count for n in steps}, error


class SyncSettingsTest(unittest.TestCase):
    CATALOG = {"gpu_types": [{"tag": "a6000"}, {"tag": "gtx1080"}, {"tag": "a100-40g"}]}
    SCOPE_PARAMS = ("zoneid", "clusterid", "storageid", "domainid", "accountid")

    def setUp(self):
        self.calls = []
        self.refuse = set()
        self.started = "2020-01-01T00:00:00+0000"
        self.state = {"metadata": {"name": "cloudstack-sync-state", "resourceVersion": "1"}}
        # (scope parameter, object id) -> key -> (value, dynamic, category); the global listing names every key
        self.config = {
            (None, None): {
                "capacity.skipcounting.hours": ("3600", False, "Advanced"),
                "vm.allocation.algorithm": ("random", True, "Advanced"),
                "max.account.gpus": ("20", False, "Account Defaults"),
                "cluster.cpu.allocated.capacity.disablethreshold": ("0.85", True, "Alert"),
                "storage.overprovisioning.factor": ("2", True, "Storage"),
                "vm.root.disk.size.min": ("10", True, "Advanced"),
                "enable.dynamic.scale.vm": ("false", True, "Advanced"),
                "incorrect.login.attempts.allowed": ("0", False, "Advanced"),
                "resource.limit.host.tags": ("cpu", True, "Advanced"),
                "resource.request.smtp.username": ("", True, "Advanced"),
                "resource.request.smtp.password": ("x8Jq0w==", True, "Secure"),
            },
            ("zoneid", "z-1"): {"enable.dynamic.scale.vm": ("false", True, "Advanced")},
            ("domainid", "d-root"): {"vm.root.disk.size.min": ("10", True, "Advanced")},
            ("domainid", "d-snucse"): {"vm.root.disk.size.min": ("10", True, "Advanced")},
            ("clusterid", "c-1"): {"cluster.cpu.allocated.capacity.disablethreshold": ("0.85", True, "Alert")},
            ("storageid", "p-1"): {"storage.overprovisioning.factor": ("2.0", True, "Storage")},
            ("storageid", "p-2"): {"storage.overprovisioning.factor": ("1", True, "Storage")},
        }
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(f"{tmp.name}/namespace", "w") as f:
            f.write("cloudstack")

        def fake_cs(command, post=False, **params):
            self.calls.append((command, params))
            scope = next(((p, params[p]) for p in self.SCOPE_PARAMS if p in params), (None, None))
            if command == "listConfigurations":
                assert params.get("page", 1) == 1
                return {"configuration": [{"name": k, "value": v, "isdynamic": d, "category": c}
                                          for k, (v, d, c) in self.config.get(scope, {}).items()]}
            if command == "updateConfiguration":
                assert post, "settings are written by POST"
                if params["name"] in self.refuse:
                    raise urllib.error.HTTPError("http://cloudstack.test", 431, "Only the Root Admin role can change "
                                                 f"{params['name']}", {}, io.BytesIO(b"{}"))
                _, dynamic, category = self.config[scope][params["name"]]
                self.config[scope][params["name"]] = (params["value"], dynamic, category)
                return {"configuration": {"name": params["name"], "value": params["value"]}}
            if command == "listZones":
                return {"zone": [{"id": "z-1", "name": "snucse"}]}
            if command == "listClusters":
                return {"cluster": [{"id": "c-1", "name": "302bldg-kvm"}]}
            if command == "listStoragePools":
                return {"storagepool": [{"id": "p-1", "name": "derby-local"}, {"id": "p-2", "name": "eggnog-local"}]}
            if command == "listDomains":
                return {"domain": [{"id": "d-root", "path": "ROOT"}, {"id": "d-snucse", "path": "ROOT/snucse"}]}
            if command == "listAccounts":
                return {"account": []}
            if command == "listManagementServers":
                return {"managementserver": [{"name": "ms-0", "state": "Up", "lastserverstart": self.started},
                                             {"name": "ms-1", "state": "Down",
                                              "lastserverstart": "2019-01-01T00:00:00+0000"}]}
            raise AssertionError(command)

        def fake_kube(method, path, body=None):
            self.assertTrue(path.endswith("/namespaces/cloudstack/configmaps/cloudstack-sync-state"), path)
            if method == "GET":
                return 200, json.loads(json.dumps(self.state))
            self.state = body
            return 200, body

        for p in (mock.patch.object(sync, "cloudstack", fake_cs), mock.patch.object(sync, "kube", fake_kube),
                  mock.patch.object(sync, "SA_DIR", tmp.name)):
            p.start()
            self.addCleanup(p.stop)

    def run_sync(self, settings, catalog=None, env=None):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            failed = sync.sync_settings(settings, catalog if catalog is not None else {"gpu_types": []}, env or {})
        return failed, out.getvalue()

    def updates(self):
        return [p for c, p in self.calls if c == "updateConfiguration"]

    def test_sync_settings_applies_only_differences(self):
        settings = [{"key": "vm.allocation.algorithm", "value": "firstfitmostconsumed"},
                    {"key": "max.account.gpus", "value": 20},
                    {"key": "capacity.skipcounting.hours", "value": "3600"},
                    {"key": "storage.overprovisioning.factor", "scope": "storagepool", "target": "*", "value": 1.0}]
        failed, out = self.run_sync(settings)
        self.assertEqual(failed, [])
        self.assertEqual([(u["name"], u["value"], u.get("storageid")) for u in self.updates()],
                         [("vm.allocation.algorithm", "firstfitmostconsumed", None),
                          ("storage.overprovisioning.factor", "1.0", "p-1")],
                         "only what differs; 1.0 equals a stored 1.0 or 1")
        self.assertIn("'random' -> 'firstfitmostconsumed'", out)
        self.calls.clear()
        failed, out = self.run_sync(settings)
        self.assertEqual((failed, self.updates()), ([], []), "a second run writes nothing")

    def test_sync_settings_skips_unknown_key(self):
        failed, out = self.run_sync([{"key": "volume.move.keep.source", "value": True},
                                     {"key": "vm.allocation.algorithm", "value": "firstfitmostconsumed"}])
        self.assertEqual(failed, [], "a key of a patch that is not deployed yet is no error")
        self.assertEqual([u["name"] for u in self.updates()], ["vm.allocation.algorithm"])
        self.assertIn("setting volume.move.keep.source: unknown to this management server, skipped", out)

    def test_sync_settings_reports_restart_required_for_a_non_dynamic_key(self):
        failed, out = self.run_sync([{"key": "capacity.skipcounting.hours", "value": 0},
                                     {"key": "vm.allocation.algorithm", "value": "firstfitmostconsumed"},
                                     {"key": "max.account.gpus", "value": 20}])
        self.assertEqual(failed, [])
        self.assertEqual(self.config[(None, None)]["capacity.skipcounting.hours"][0], "0")
        self.assertEqual(re.findall(r"restart required: (\S+)", out), ["capacity.skipcounting.hours"],
                         "only a changed key that is not dynamic")
        # kept where an operator reads it and repeated every run until every running management server has
        # started after the write
        self.assertIn("restart.capacity.skipcounting.hours", self.state["data"])
        self.calls.clear()
        failed, out = self.run_sync([{"key": "capacity.skipcounting.hours", "value": 0}])
        self.assertEqual((failed, self.updates()), ([], []))
        self.assertEqual(re.findall(r"restart required: (\S+)", out), ["capacity.skipcounting.hours"])
        self.started = "2999-01-01T00:00:00+0000"
        failed, out = self.run_sync([{"key": "capacity.skipcounting.hours", "value": 0}])
        self.assertNotIn("restart required", out)
        self.assertNotIn("restart.capacity.skipcounting.hours", self.state["data"])

    def test_sync_settings_scopes(self):
        failed, out = self.run_sync([
            {"key": "incorrect.login.attempts.allowed", "value": 5},
            {"key": "vm.root.disk.size.min", "scope": "domain", "target": "ROOT/snucse", "value": 12},
            {"key": "cluster.cpu.allocated.capacity.disablethreshold", "scope": "cluster", "target": "302bldg-kvm",
             "value": 1.0},
            {"key": "storage.overprovisioning.factor", "scope": "storagepool", "target": "eggnog-local", "value": 1.5},
            {"key": "enable.dynamic.scale.vm", "scope": "zone", "target": "*", "value": True}])
        self.assertEqual(failed, [])
        self.assertEqual([{k: v for k, v in u.items()} for u in self.updates()], [
            {"name": "incorrect.login.attempts.allowed", "value": "5"},
            {"name": "vm.root.disk.size.min", "value": "12", "domainid": "d-snucse"},
            {"name": "cluster.cpu.allocated.capacity.disablethreshold", "value": "1.0", "clusterid": "c-1"},
            {"name": "storage.overprovisioning.factor", "value": "1.5", "storageid": "p-2"},
            {"name": "enable.dynamic.scale.vm", "value": "true", "zoneid": "z-1"}])
        self.assertEqual(self.config[("domainid", "d-root")]["vm.root.disk.size.min"][0], "10", "the other domain keeps its value")
        self.calls.clear()
        failed, _ = self.run_sync([{"key": "storage.overprovisioning.factor", "scope": "storagepool", "target": "*",
                                    "value": "1.0"}])
        self.assertEqual([(u["value"], u["storageid"]) for u in self.updates()], [("1.0", "p-1"), ("1.0", "p-2")],
                         "* is every pool")

    def test_sync_settings_host_tags_come_from_the_catalog(self):
        failed, out = self.run_sync([{"key": "resource.limit.host.tags", "value": "cpu,a6000"}], catalog=self.CATALOG)
        self.assertEqual(failed, ["resource.limit.host.tags"], "an entry for the derived key is refused")
        self.assertIn("error: setting resource.limit.host.tags:", out)
        self.assertEqual([(u["name"], u["value"]) for u in self.updates()],
                         [("resource.limit.host.tags", "cpu,a6000,gtx1080,a100-40g")])
        self.calls.clear()
        failed, _ = self.run_sync([], catalog={**self.CATALOG, "cpu_only": {"name": "cpu", "tag": "cpu"},
                                               "gpu_types": self.CATALOG["gpu_types"] + [{"tag": "h100"}]})
        self.assertEqual([u["value"] for u in self.updates()], ["cpu,a6000,gtx1080,a100-40g,h100"],
                         "a new GPU type is one catalog edit")
        self.calls.clear()
        with mock.patch.object(sync, "COMPUTE_CATALOG_PATH", "/nonexistent/compute-catalog.json"), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            sync.sync_settings([], None, {})
        self.assertEqual(self.updates(), [], "without a catalog nothing is derived")

    def test_sync_settings_reads_value_env_and_never_logs_it(self):
        settings = [{"key": "resource.request.smtp.username", "value_env": "SMTP_USERNAME"}]
        failed, out = self.run_sync(settings, env={"SMTP_USERNAME": "relay-user"})
        self.assertEqual(failed, [])
        self.assertEqual([(u["name"], u["value"]) for u in self.updates()],
                         [("resource.request.smtp.username", "relay-user")])
        self.assertNotIn("relay-user", out)
        self.assertIn("value from SMTP_USERNAME", out)
        self.calls.clear()
        self.assertEqual(self.run_sync(settings, env={"SMTP_USERNAME": "relay-user"})[0], [])
        self.assertEqual(self.updates(), [], "a second run writes nothing")
        failed, out = self.run_sync(settings, env={})
        self.assertEqual((failed, self.updates()), (["resource.request.smtp.username"], []))
        self.assertIn("SMTP_USERNAME", out)

    def test_sync_settings_compares_an_encrypted_value_by_digest(self):
        settings = [{"key": "resource.request.smtp.password", "value_env": "SMTP_PASSWORD"}]
        failed, out = self.run_sync(settings, env={"SMTP_PASSWORD": "pa55-word"})
        self.assertEqual((failed, [(u["name"], u["value"]) for u in self.updates()]),
                         ([], [("resource.request.smtp.password", "pa55-word")]))
        self.assertNotIn("pa55-word", out)
        self.assertIn("value from SMTP_PASSWORD", out)
        # an encrypted setting lists differently each time, so the digest of what was written decides
        self.assertNotIn("pa55-word", json.dumps(self.state))
        self.calls.clear()
        self.assertEqual(self.run_sync(settings, env={"SMTP_PASSWORD": "pa55-word"})[0], [])
        self.assertEqual(self.updates(), [], "the same secret is not written again")
        self.run_sync(settings, env={"SMTP_PASSWORD": "rotated"})
        self.assertEqual([u["name"] for u in self.updates()], ["resource.request.smtp.password"])

    def test_sync_settings_failing_entry_does_not_stop_the_rest(self):
        self.refuse.add("incorrect.login.attempts.allowed")
        failed, out = self.run_sync([
            {"key": "vm.root.disk.size.min", "scope": "domain", "target": "ROOT/missing", "value": 12},
            {"key": "incorrect.login.attempts.allowed", "value": 5},
            {"key": "capacity.skipcounting.hours", "value": 0, "value_env": "X"},
            {"key": "vm.root.disk.size.min", "scope": "cluster", "target": "302bldg-kvm", "value": 12},
            {"key": "max.account.gpus", "scope": "global", "target": "ROOT", "value": 0},
            {"key": "vm.allocation.algorithm", "value": "firstfitmostconsumed"},
            {"key": "vm.allocation.algorithm", "scope": "global", "value": "firstfit"},
            {"key": "storage.overprovisioning.factor", "scope": "storagepool", "target": "derby-local", "value": 1.5},
            {"key": "storage.overprovisioning.factor", "scope": "storagepool", "target": "*", "value": 1.0}])
        self.assertEqual(failed, ["vm.root.disk.size.min (domain ROOT/missing)", "incorrect.login.attempts.allowed",
                                  "capacity.skipcounting.hours", "vm.root.disk.size.min (cluster 302bldg-kvm)",
                                  "max.account.gpus", "vm.allocation.algorithm",
                                  "storage.overprovisioning.factor (storagepool derby-local)"])
        self.assertIn("error: setting incorrect.login.attempts.allowed: HTTP Error 431", out)
        self.assertIn("not a cluster setting", out)
        self.assertIn("declared more than once", out)
        self.assertIn("the entry for every storagepool sets it already", out)
        self.assertEqual([(u["name"], u.get("storageid")) for u in self.updates()],
                         [("incorrect.login.attempts.allowed", None), ("storage.overprovisioning.factor", "p-1")],
                         "the refused write was tried and the rest still applied")

    def test_settings_reach_the_job(self):
        self.assertEqual(sync.SETTINGS_PATH, "/opt/sync/settings.toml")
        with open(os.path.join(SETTINGS_REPO, "kustomization.yaml")) as f:
            files = re.search(r"name: cloudstack-sync\n    files:\n((?:      - .*\n)*)", f.read()).group(1)
        self.assertIn("      - settings.toml\n", files)
        entries = sync.load_settings(os.path.join(SETTINGS_REPO, "settings.toml"))
        for entry in entries:
            sync.checked_setting(entry, {e["value_env"]: "" for e in entries if "value_env" in e})
        keys = [(e["key"], e.get("scope", "global"), e.get("target")) for e in entries]
        self.assertEqual(len(keys), len(set(keys)), "every setting is declared once")
        self.assertFalse([k for k in keys if k[2] not in (None, "*") and (k[0], k[1], "*") in keys])
        self.assertEqual(sync.load_settings("/nonexistent/settings.toml"), [])

    def test_a_destroy_deletes_at_once(self):
        # there is no recoverable Destroyed state for instances or volumes
        entries = {e["key"]: e for e in sync.load_settings(os.path.join(SETTINGS_REPO, "settings.toml"))}
        self.assertIs(entries["expunge.on.destroy"]["value"], True)

    def test_the_catalog_reaches_the_job(self):
        self.assertEqual(sync.COMPUTE_CATALOG_PATH, "/opt/sync/compute-catalog.json")
        with open(os.path.join(SETTINGS_REPO, "kustomization.yaml")) as f:
            files = re.search(r"name: cloudstack-sync\n    files:\n((?:      - .*\n)*)", f.read()).group(1)
        self.assertIn("      - compute-catalog.json\n", files)
        catalog = sync.load_compute_catalog(os.path.join(SETTINGS_REPO, "compute-catalog.json"))
        self.assertEqual(sync.resource_limit_host_tags(catalog),
                         ",".join(["cpu"] + [t["tag"] for t in catalog["gpu_types"]]))

    def test_a_failing_setting_fails_the_run_after_every_other_step(self):
        ran, error = run_main_with(sync_settings=["vm.allocation.algorithm"])
        self.assertRegex(str(error), "settings not applied: vm.allocation.algorithm")
        self.assertIn("sync_console_certificate", ran)
        self.assertEqual(ran, dict.fromkeys(ran, 1), "every other step ran once")


REPO_COMPUTE_CATALOG = os.path.join(SETTINGS_REPO, "compute-catalog.json")
A100_40G_CARD = {"vendor_id": "10de", "device_id": "20b0", "vendor_name": "NVIDIA Corporation",
                 "device_name": "GA100 [A100 SXM4 40GB]", "name": "NVIDIA Corporation GA100 [A100 SXM4 40GB]"}
A6000_CARD = {"vendor_id": "10de", "device_id": "2230", "vendor_name": "NVIDIA Corporation",
              "device_name": "GA102GL [RTX A6000]", "name": "NVIDIA Corporation GA102GL [RTX A6000]"}
FULL_GPU_SET = ["a6000-1", "gtx1080-1", "a100-40g-1", "a100-40g-nvswitch-2", "a100-40g-nvswitch-4", "a100-40g-nvswitch-8",
                "a100-40g-nvlink-2", "a100-40g-nvlink-4", "a100-80g-1", "a100-80g-nvswitch-2", "a100-80g-nvswitch-4",
                "a100-80g-nvswitch-8"]


class SyncOfferingsTest(unittest.TestCase):
    CPU_ONLY = {"name": "cpu", "tag": "cpu", "min_vcpu": 2, "max_vcpu": 4096, "min_memory_mib": 32,
                "max_memory_mib": 67108864}

    def catalog(self, **cpu_only):
        return {"cpu_only": {**self.CPU_ONLY, **cpu_only}, "gpu_types": [
            {"tag": "a6000", "card": A6000_CARD, "unit_vcpu": 12, "unit_ram_gib": 24,
             "classes": {"pcie": {"rule": "single"}}, "lease_hours": 36},
            {"tag": "a100-40g", "card": A100_40G_CARD, "unit_vcpu": 12, "unit_ram_gib": 96, "lease_hours": 36,
             "classes": {"nvswitch": {"rule": "partitions", "counts": [2, 4, 8]},
                         "nvlink": {"rule": "any", "counts": [2, 4]}}}]}

    def setUp(self):
        self.calls = []
        self.hosts = [{"id": "h-1", "name": "derby", "cpuspeed": 3600}, {"id": "h-2", "name": "jimbeam", "cpuspeed": 2600},
                      {"id": "h-3", "name": "jackdaniels", "cpuspeed": 2400}, {"id": "h-4", "name": "new"}]
        self.cards = [{"id": "card-2230", "vendorid": "10de", "deviceid": "2230", "name": A6000_CARD["name"]},
                      {"id": "card-1b80", "vendorid": "10de", "deviceid": "1b80",
                       "name": "NVIDIA Corporation GP104 [GeForce GTX 1080]"},
                      {"id": "card-20b0", "vendorid": "10de", "deviceid": "20b0", "name": A100_40G_CARD["name"]}]
        self.profiles = [{"id": f"vp-{c['deviceid']}", "name": "passthrough", "gpucardid": c["id"]} for c in self.cards]
        self.profiles.append({"id": "vp-2230-q", "name": "A6000-12Q", "gpucardid": "card-2230"})
        self.offerings = []

        def fake_cs(command, post=False, **params):
            self.calls.append((command, params))
            if command == "listHosts":
                self.assertEqual(params.get("type"), "Routing")
                return {"host": [dict(h) for h in self.hosts]}
            if command == "listGpuCards":
                return {"gpucard": [dict(c) for c in self.cards]}
            if command == "createGpuCard":
                card = {"id": f"card-{params['deviceid']}", "vendorid": params["vendorid"], "deviceid": params["deviceid"],
                        "name": params["name"]}
                self.cards.append(card)
                self.profiles.append({"id": f"vp-{params['deviceid']}", "name": "passthrough", "gpucardid": card["id"]})
                return {"gpucard": card}
            if command == "listVgpuProfiles":
                return {"vgpuprofile": [dict(p) for p in self.profiles if p["gpucardid"] == params["gpucardid"]]}
            if command == "listServiceOfferings":
                self.assertEqual(params.get("state"), "all", "inactive offerings hold names too")
                return {"serviceoffering": [json.loads(json.dumps(o)) for o in self.offerings]}
            if command == "createServiceOffering":
                self.offerings.append(self.listed(f"o-{len(self.offerings)}", params))
                return {"serviceoffering": self.offerings[-1]}
            if command == "updateServiceOffering":
                o = next(o for o in self.offerings if o["id"] == params["id"])
                o.update({k: params[k] for k in ("name", "state", "leaseexpiryaction") if k in params})
                if "leasehours" in params:
                    if str(params["leasehours"]) == "0":
                        o.pop("leasehours", None)
                        o.pop("leaseexpiryaction", None)
                    else:
                        o["leasehours"] = int(params["leasehours"])
                        o.setdefault("leaseexpiryaction", "STOP")
                return {"serviceoffering": o}
            raise AssertionError(f"{command} {params}")

        patcher = mock.patch.object(sync, "cloudstack", fake_cs)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def listed(oid, p):
        """An offering as listServiceOfferings shows the one createServiceOffering made."""
        o = {"id": oid, "name": p["name"], "state": "Active", "iscustomized": str(p.get("customized")) == "true",
             "cpuspeed": int(p["cpuspeed"]), "storagetype": p.get("storagetype", "shared"),
             "offerha": str(p.get("offerha")) == "true", "dynamicscalingenabled": str(p.get("dynamicscalingenabled")) != "false",
             "diskofferingstrictness": str(p.get("diskofferingstrictness")) == "true",
             "rootdisksize": int(p.get("rootdisksize", 0)), "hosttags": p.get("hosttags")}
        if "cpunumber" in p:
            o.update(cpunumber=int(p["cpunumber"]), memory=int(p["memory"]))
        if "mincpunumber" in p:
            o["serviceofferingdetails"] = {k: str(p[k]) for k in ("mincpunumber", "maxcpunumber", "minmemory", "maxmemory")}
        if "vgpuprofileid" in p:
            o.update(vgpuprofileid=p["vgpuprofileid"], gpucount=int(p["gpucount"]))
        if "leasehours" in p:
            o.update(leasehours=int(p["leasehours"]), leaseexpiryaction=p.get("leaseexpiryaction", "STOP"))
        return o

    def run_sync(self, catalog):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            failed = sync.sync_gpu_cards(catalog) + sync.sync_offerings(catalog)
        return failed, out.getvalue()

    def created(self):
        return {p["name"]: p for c, p in self.calls if c == "createServiceOffering"}

    def writes(self):
        return [(c, p) for c, p in self.calls if not c.startswith("list")]

    def test_sync_offerings_creates_cpu_and_gpu_offerings(self):
        failed, out = self.run_sync(self.catalog())
        self.assertEqual(failed, [])
        created = self.created()
        self.assertEqual(list(created), ["cpu", "a6000-1", "a100-40g-1", "a100-40g-nvswitch-2", "a100-40g-nvswitch-4",
                                         "a100-40g-nvswitch-8", "a100-40g-nvlink-2", "a100-40g-nvlink-4"])
        nvlink2 = created["a100-40g-nvlink-2"]
        self.assertEqual((nvlink2["cpunumber"], nvlink2["memory"], nvlink2["gpucount"], nvlink2["vgpuprofileid"]),
                         (24, 2 * 96 * 1024, 2, "vp-20b0"), "n units of the type, its card's passthrough profile")
        self.assertEqual(created["a6000-1"]["vgpuprofileid"], "vp-2230")
        for p in created.values():
            self.assertEqual((p["storagetype"], p["offerha"], p["diskofferingstrictness"]), ("local", "false", "true"))
            self.assertFalse({"diskofferingid", "rootdisksize"} & set(p), "a compute-only root whose size the user picks")
        self.assertIn("offering a100-40g-nvlink-4 created", out)
        self.calls.clear()
        failed, out = self.run_sync(self.catalog())
        self.assertEqual((failed, self.writes()), ([], []), "a second run changes nothing")

    def test_sync_offerings_versions_changed_offering(self):
        self.run_sync(self.catalog())
        catalog = self.catalog()
        catalog["gpu_types"][0]["unit_vcpu"] = 16
        self.calls.clear()
        failed, out = self.run_sync(catalog)
        self.assertEqual(failed, [])
        self.assertEqual([(c, p.get("name"), p.get("state")) for c, p in self.writes()],
                         [("updateServiceOffering", "a6000-1-v1", "Inactive"), ("createServiceOffering", "a6000-1", None)])
        self.assertEqual(self.created()["a6000-1"]["cpunumber"], 16)
        self.assertIn("offering a6000-1: cpunumber changed", out)
        catalog["gpu_types"][0]["unit_ram_gib"] = 32
        self.calls.clear()
        self.run_sync(catalog)
        self.assertEqual([p.get("name") for c, p in self.writes()], ["a6000-1-v2", "a6000-1"])
        self.assertEqual(sorted(o["name"] for o in self.offerings if o["name"].startswith("a6000-1")),
                         ["a6000-1", "a6000-1-v1", "a6000-1-v2"])
        self.assertEqual([o["state"] for o in self.offerings if o["name"].startswith("a6000-1-v")], ["Inactive", "Inactive"])

    def test_sync_offerings_never_deletes(self):
        for name in ("small", "small-gpu", "a6000"):
            self.offerings.append({"id": f"old-{name}", "name": name, "state": "Active", "cpunumber": 2, "cpuspeed": 2000,
                                   "memory": 4096, "storagetype": "local"})
        failed, _ = self.run_sync(self.catalog())
        self.assertEqual(failed, [])
        self.assertFalse([p for c, p in self.writes() if p.get("id", "").startswith("old-")])
        catalog = self.catalog()
        del catalog["gpu_types"][1]
        self.calls.clear()
        self.run_sync(catalog)
        self.assertEqual(self.writes(), [], "a type gone from the catalog keeps its offerings")
        self.assertEqual(len(self.offerings), 11)

    def test_sync_offerings_one_gpu_per_card_multi_per_class(self):
        self.run_sync(self.catalog())
        created = self.created()
        self.assertEqual(created["a100-40g-1"]["hosttags"], "a100-40g")
        self.assertEqual(created["a100-40g-nvlink-2"]["hosttags"], "a100-40g,a100-40g-nvlink")
        self.assertEqual(created["a100-40g-nvswitch-8"]["hosttags"], "a100-40g,a100-40g-nvswitch")
        self.assertEqual(created["a6000-1"]["hosttags"], "a6000")
        self.assertEqual([n for n in created if n.startswith("a6000")], ["a6000-1"], "no multi-GPU offering over PCIe")

    def test_sync_offerings_full_gpu_set(self):
        with open(REPO_COMPUTE_CATALOG) as f:
            catalog = json.load(f)
        failed, _ = self.run_sync(catalog)
        self.assertEqual(failed, [])
        self.assertEqual(sorted(self.created()), sorted(FULL_GPU_SET + ["cpu"]))
        units = {"a100-40g": (12, 96), "a100-80g": (12, 96), "a6000": (12, 24), "gtx1080": (6, 12)}
        for name, p in self.created().items():
            if name != "cpu":
                tag, n = name.rsplit("-", 1)[0].rsplit("-nv", 1)[0], int(name.rsplit("-", 1)[1])
                self.assertEqual((p["cpunumber"], p["memory"]), (n * units[tag][0], n * units[tag][1] * 1024), name)

    def test_cpu_offering_is_constrained_with_fixed_speed(self):
        self.run_sync(self.catalog())
        cpu = self.created()["cpu"]
        self.assertEqual({k: cpu[k] for k in ("customized", "cpuspeed", "mincpunumber", "maxcpunumber", "minmemory",
                                              "maxmemory", "hosttags")},
                         {"customized": "true", "cpuspeed": 2400, "mincpunumber": 2, "maxcpunumber": 4096, "minmemory": 32,
                          "maxmemory": 67108864, "hosttags": "cpu"},
                         "the lowest speed of the KVM hosts that report one")
        self.assertFalse({"cpunumber", "memory", "vgpuprofileid", "gpucount"} & set(cpu))
        self.hosts = [h for h in self.hosts if h.get("cpuspeed") != 2400]
        self.calls.clear()
        self.run_sync(self.catalog())
        self.assertEqual(self.writes(), [], "the slowest host leaving keeps the offering: every host still passes")
        self.hosts.append({"id": "h-5", "name": "slow", "cpuspeed": 2100})
        self.calls.clear()
        self.run_sync(self.catalog())
        self.assertEqual([(c, p.get("name")) for c, p in self.writes()],
                         [("updateServiceOffering", "cpu-v1"), ("createServiceOffering", "cpu")],
                         "a slower host makes a new CPU-only offering; GPU offerings do not depend on the speed")
        self.assertEqual(self.created()["cpu"]["cpuspeed"], 2100)

    def test_cpu_offering_comes_from_the_catalog_section(self):
        self.run_sync(self.catalog())
        self.calls.clear()
        failed, out = self.run_sync(self.catalog(min_vcpu=4))
        self.assertEqual(failed, [])
        self.assertEqual([(c, p.get("name")) for c, p in self.writes()],
                         [("updateServiceOffering", "cpu-v1"), ("createServiceOffering", "cpu")])
        self.assertEqual(self.created()["cpu"]["mincpunumber"], 4)
        self.assertIn("offering cpu: mincpunumber changed", out)
        catalog = self.catalog()
        del catalog["cpu_only"]
        self.offerings.clear()
        self.calls.clear()
        failed, out = self.run_sync(catalog)
        self.assertEqual(failed, ["cpu"])
        self.assertIn("error: offering cpu:", out)
        self.assertNotIn("cpu", self.created())
        self.assertEqual(len(self.created()), 7, "the GPU offerings still sync")

    def test_every_offering_is_not_dynamically_scalable(self):
        with open(REPO_COMPUTE_CATALOG) as f:
            self.run_sync(json.load(f))
        self.assertEqual(len(self.created()), 13)
        for name, p in self.created().items():
            self.assertEqual(p["dynamicscalingenabled"], "false", name)

    def test_sync_offerings_keyed_min_count(self):
        catalog = self.catalog()
        del catalog["gpu_types"][0]
        classes = catalog["gpu_types"][0]["classes"]
        classes["nvlink"]["keyed_min_count"] = 3
        self.run_sync(catalog)
        created = self.created()
        self.assertEqual(created["a100-40g-2"]["hosttags"], "a100-40g", "below its keyed_min_count the card alone keys it")
        self.assertEqual(created["a100-40g-nvlink-4"]["hosttags"], "a100-40g,a100-40g-nvlink")
        self.assertNotIn("a100-40g-nvlink-2", created)
        self.assertEqual(created["a100-40g-nvswitch-2"]["hosttags"], "a100-40g,a100-40g-nvswitch", "the default is 2")

    def test_sync_gpu_cards_creates_missing_card_once(self):
        with open(REPO_COMPUTE_CATALOG) as f:
            catalog = json.load(f)
        self.cards = [c for c in self.cards if c["deviceid"] != "20b0"]
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(sync.sync_gpu_cards(catalog), [])
        created = [p for c, p in self.calls if c == "createGpuCard"]
        self.assertEqual([p["deviceid"] for p in created], ["20b0", "20b2"], "never for a discovered card")
        self.assertEqual(created[1], {"vendorid": "10de", "deviceid": "20b2", "vendorname": "NVIDIA Corporation",
                                      "devicename": "GA100 [A100 SXM4 80GB]",
                                      "name": "NVIDIA Corporation GA100 [A100 SXM4 80GB]"})
        self.calls.clear()
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            sync.sync_gpu_cards(catalog)
        self.assertEqual(self.writes(), [])

    def test_sync_offerings_skips_type_without_units(self):
        catalog = self.catalog()
        catalog["gpu_types"][1]["unit_vcpu"] = None
        failed, out = self.run_sync(catalog)
        self.assertEqual(failed, [])
        self.assertEqual(list(self.created()), ["cpu", "a6000-1"])
        self.assertIn("GPU type a100-40g: no unit size yet, no offerings", out)

    def test_sync_offerings_sets_gpu_lease_hours(self):
        with open(REPO_COMPUTE_CATALOG) as f:
            self.run_sync(json.load(f))
        for name, p in self.created().items():
            if name == "cpu":
                self.assertFalse({"leasehours", "leaseexpiryaction"} & set(p), "CPU-only instances have no lease")
            else:
                self.assertEqual((p["leasehours"], p["leaseexpiryaction"]), ("36", "STOP"), name)

    def test_sync_offerings_lease_hours_change_is_in_place(self):
        self.run_sync(self.catalog())
        catalog = self.catalog()
        catalog["gpu_types"][1]["lease_hours"] = 48
        del catalog["gpu_types"][0]["lease_hours"]
        self.calls.clear()
        failed, out = self.run_sync(catalog)
        self.assertEqual(failed, [])
        updates = {next(o["name"] for o in self.offerings if o["id"] == p["id"]): p for c, p in self.writes()}
        self.assertEqual([c for c, _ in self.writes()], ["updateServiceOffering"] * 7, "no -v<k> rename, no new offering")
        self.assertEqual(updates["a6000-1"], {"id": updates["a6000-1"]["id"], "leasehours": "0"})
        self.assertEqual(updates["a100-40g-nvswitch-8"]["leasehours"], "48")
        self.assertNotIn("leasehours", next(o for o in self.offerings if o["name"] == "a6000-1"))
        catalog["gpu_types"][1]["lease_expiry_action"] = "DESTROY"
        catalog["gpu_types"][0]["lease_hours"] = 36
        catalog["gpu_types"][0]["lease_expiry_action"] = "DESTROY"
        self.calls.clear()
        self.run_sync(catalog)
        self.assertEqual({p["leaseexpiryaction"] for c, p in self.writes()}, {"DESTROY"})
        self.assertEqual(len(self.writes()), 7)

    def test_shipped_catalog(self):
        with open(REPO_COMPUTE_CATALOG) as f:
            catalog = json.load(f)
        self.assertEqual(catalog["cpu_only"], self.CPU_ONLY)
        for t in catalog["gpu_types"]:
            self.assertEqual((t["lease_hours"], t.get("lease_expiry_action", "STOP")), (36, "STOP"), t["tag"])
            for c in t["classes"].values():
                self.assertEqual(c.get("keyed_min_count", 2), 2)

    def test_a_failing_offering_fails_the_run_after_every_other_step(self):
        ran, error = run_main_with(sync_compute_catalog=["a6000-1"])
        self.assertRegex(str(error), "compute catalog not reconciled: a6000-1")
        self.assertIn("sync_settings", ran)
        self.assertEqual(ran, dict.fromkeys(ran, 1), "every other step ran once")

    def test_sync_compute_catalog_cards_before_offerings(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self.addCleanup(os.unlink, tmp.name)
        json.dump(self.catalog(), tmp)
        tmp.close()
        self.cards = [c for c in self.cards if c["deviceid"] != "20b0"]
        self.profiles = [p for p in self.profiles if p["gpucardid"] != "card-20b0"]
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(sync.sync_compute_catalog(tmp.name), [])
            self.assertEqual(sync.sync_compute_catalog("/nonexistent/compute-catalog.json"), [])
        writes = [c for c, _ in self.writes()]
        self.assertEqual(writes[0], "createGpuCard")
        self.assertEqual(self.created()["a100-40g-1"]["vgpuprofileid"], "vp-20b0")


if __name__ == "__main__":
    unittest.main()
