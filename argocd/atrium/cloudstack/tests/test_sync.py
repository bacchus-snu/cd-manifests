import base64
import importlib
import io
import json
import os
import ssl
import subprocess
import tempfile
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

    def test_ssh_options_carry_every_required_field(self):
        wanted, _ = sync.plan_targets([{"id": "vm-1", "name": "a", "account": "alice",
                                        "nic": [{"ipaddress": "10.94.1.5"}]}], {})
        # the bastion's API rejects a target whose allow_insecure_algos is absent
        self.assertIs(wanted["a"]["options"]["allow_insecure_algos"], False)


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


class TrustScriptTest(unittest.TestCase):
    def test_script_contains_keys_and_sshd_dropin(self):
        script = sync.render_trust_script(["ssh-ed25519 BBB warpgate", "ssh-ed25519 AAA warpgate"])
        self.assertTrue(script.startswith("#!/bin/sh\n"))
        self.assertIn("cat > /etc/ssh/warpgate_keys <<'EOF'\nssh-ed25519 AAA warpgate\nssh-ed25519 BBB warpgate\nEOF\n", script)
        self.assertIn("AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/warpgate_keys", script)
        self.assertIn("/etc/ssh/sshd_config.d/50-warpgate.conf", script)

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
            return {}

        def fake_wg(method, path, body=None):
            return 200, [{"public_key": "ssh-ed25519 AAA warpgate", "is_default": True}]
        self._orig = (sync.cloudstack, sync.warpgate)
        sync.cloudstack, sync.warpgate = fake_cs, fake_wg

    def tearDown(self):
        sync.cloudstack, sync.warpgate = self._orig

    def test_registers_links_and_cleans_up(self):
        sync.sync_template_userdata()
        cmds = [c for c, _ in self.calls]
        self.assertIn("registerUserData", cmds)
        links = [p for c, p in self.calls if c == "linkUserDataToTemplate"]
        self.assertEqual({p["templateid"] for p in links}, {"t-ours", "t-bare"})
        self.assertTrue(all(p["userdataid"] == "ud-new" and p["userdatapolicy"] == "APPEND" for p in links))
        deletes = [p for c, p in self.calls if c == "deleteUserData"]
        self.assertEqual([p["id"] for p in deletes], ["ud-old"])
        import base64
        registered = base64.b64decode(next(p["userdata"] for c, p in self.calls if c == "registerUserData")).decode()
        self.assertIn("cloudstack/password/vm_password.txt", registered)
        self.assertNotIn("data-server", registered)
        self.assertNotIn("listNetworks", cmds)


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


if __name__ == "__main__":
    unittest.main()
