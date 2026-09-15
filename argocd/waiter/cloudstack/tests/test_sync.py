import importlib
import os
import unittest

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


class CloseSessionsTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        sessions = {"items": [
            {"id": "s1", "username": "bob", "target_id": "t1"},
            {"id": "s2", "username": "carol", "target_id": "t1"},
            {"id": "s3", "username": "bob", "target_id": "t2"},
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
            {"id": "t-old", "name": "ubuntu-24.04", "templatetype": "USER", "ispublic": True, "isfeatured": False},
            {"id": "t-deb", "name": "debian-13-20260914", "templatetype": "USER", "ispublic": False, "isfeatured": False},
            {"id": "t-sys", "name": "SystemVM", "templatetype": "SYSTEM", "ispublic": True},
        ]

        def fake_cs(command, **params):
            self.calls.append((command, params))
            if command == "listTemplates":
                return {"template": list(self.templates)}
            if command == "listOsTypes":
                return {"ostype": [{"id": "os-ubu", "description": "Ubuntu 24.04 LTS"}, {"id": "os-other", "description": "Other Linux (64-bit)"}]}
            if command == "listZones":
                return {"zone": [{"id": "z-1"}]}
            if command == "registerTemplate":
                self.templates.append({"id": "t-new", "name": params["name"], "templatetype": "USER", "ispublic": True, "isfeatured": params["isfeatured"] == "true"})
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


class TrustScriptIncludeTest(unittest.TestCase):
    def test_script_ensures_include_and_openrc(self):
        script = sync.render_trust_script(["ssh-ed25519 AAA warpgate"])
        self.assertIn("Include /etc/ssh/sshd_config.d/*.conf", script)
        self.assertIn("rc-service sshd reload", script)


if __name__ == "__main__":
    unittest.main()
