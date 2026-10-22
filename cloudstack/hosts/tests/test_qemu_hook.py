import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import syslog
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import domain_fixtures as fx
from partition import domain, fm

FAKE_FMPM = """#!/bin/sh
echo "$@" >> "$FMPM_RECORD"
exit "${FMPM_EXIT:-0}"
"""
FAKE_VIRSH = """#!/bin/sh
echo "$@" >> "$VIRSH_RECORD"
exit 1
"""
POOL_UUID = "7c3e2a10-5d4b-4f6e-9a81-0b2c3d4e5f61"
X2_UUID = "6b7c8d9e-0f1a-4b2c-8d3e-4f5a6b7c8d02"


def load_hook():
    """The hook as a module, for paths that write to syslog."""
    loader = importlib.machinery.SourceFileLoader("qemu_hook", str(fx.HOOK))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


class HookWithoutLibraryTest(unittest.TestCase):
    """libvirt stops a running domain when its reconnect hook fails, so only
    the operations that need the partition library may fail without it."""

    def run_copy(self, library, op, sub):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "qemu"
            shutil.copy(fx.HOOK, copy)
            # The hook's own directory comes first on sys.path, so this shadows
            # any installed library.
            package = Path(tmp) / "partition"
            package.mkdir()
            # A regular package, so it shadows an installed one instead of merging with it.
            (package / "__init__.py").write_text(
                'raise RuntimeError("the partition library is broken")\n' if library == "broken" else "")
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "CLOUDSTACK_PARTITION_FILE": str(Path(tmp) / "partition.json"),
                   "CLOUDSTACK_PARTITION_LEDGER": str(Path(tmp) / "ledger")}
            return subprocess.run([sys.executable, str(copy), "i-2-41-VM", op, sub, "-"],
                                  input=fx.fixture("pool"), capture_output=True, text=True, env=env, timeout=60)

    def test_hook_without_library(self):
        for library in ("missing", "broken"):
            for op, sub in (("reconnect", "begin"), ("started", "begin"), ("stopped", "end"), ("start", "begin")):
                r = self.run_copy(library, op, sub)
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""), (library, op))
            r = self.run_copy(library, "migrate", "begin")
            self.assertEqual((r.returncode, r.stdout), (1, ""), library)
            self.assertIn("live migration is disabled", r.stderr)
            r = self.run_copy(library, "prepare", "begin")
            self.assertEqual((r.returncode, r.stdout), (1, ""), library)
            self.assertRegex(r.stderr, r"refused: .*(partition|broken)")
            self.assertNotIn("Traceback", r.stderr)

    def test_release_without_library_logs_and_exits_0(self):
        hook = load_hook()
        with tempfile.TemporaryDirectory() as tmp:
            hook.LEDGER = Path(tmp) / "ledger"
            with mock.patch.dict(sys.modules, {"partition": None}), mock.patch("syslog.syslog") as logged, \
                    mock.patch("syslog.openlog"), mock.patch("sys.stdin", io.StringIO(fx.fixture("pool"))), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                rc = hook.main(["qemu", "i-2-41-VM", "release", "end", "-"])
        self.assertEqual(rc, 0)
        self.assertIn("release failed", err.getvalue())
        logged.assert_called_once()
        self.assertRegex(logged.call_args.args[1], r"release failed: .*partition")


class HookTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ledger = self.root / "ledger"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, text in (("fmpm", FAKE_FMPM), ("virsh", FAKE_VIRSH)):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        self.fmpm_record = self.root / "fmpm.log"
        self.virsh_record = self.root / "virsh.log"
        self.partition_file = self.root / "partition.json"
        self.fmpm_exit = 0
        self.use("jimbeam")

    def tearDown(self):
        self._tmp.cleanup()

    def use(self, host):
        self.host = host
        self.p = fx.partition(host)
        self.partition_file.write_text(json.dumps(self.p))

    def hook(self, name, op, sub, xml=""):
        env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "CLOUDSTACK_PARTITION_FILE": str(self.partition_file),
            "CLOUDSTACK_PARTITION_LEDGER": str(self.ledger),
            "CLOUDSTACK_PARTITION_SYSFS": str(fx.sysfs(self.host)),
            "FMPM_RECORD": str(self.fmpm_record),
            "FMPM_EXIT": str(self.fmpm_exit),
            "VIRSH_RECORD": str(self.virsh_record),
        }
        return subprocess.run([sys.executable, str(fx.HOOK), name, op, sub, "-"], input=xml,
                              capture_output=True, text=True, env=env, timeout=60)

    def fmpm_calls(self):
        return self.fmpm_record.read_text().splitlines() if self.fmpm_record.exists() else []

    def entry(self, uuid):
        path = self.ledger / f"{uuid}.json"
        return json.loads(path.read_text()) if path.exists() else None

    def rewritten(self, name):
        return domain.rewrite_for_start(fx.fixture(name), self.p)

    def test_hook_migrate_begin_always_refuses(self):
        for host, name in (("jimbeam", "pool"), ("jimbeam", "a6000"), ("ferrari", "a100x2")):
            self.use(host)
            r = self.hook(name, "migrate", "begin", self.rewritten(name))
            self.assertEqual(r.returncode, 1, name)
            self.assertIn("live migration is disabled", r.stderr)
            self.assertEqual(r.stdout, "")
        r = self.hook("i-2-41-VM", "migrate", "begin", "")
        self.assertEqual((r.returncode, "live migration is disabled" in r.stderr), (1, True))

    def test_hook_prepare_accepts_and_records_pool_vm(self):
        r = self.hook("i-2-41-VM", "prepare", "begin", self.rewritten("pool"))
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
        self.assertEqual(self.entry(POOL_UUID), {
            "name": "i-2-41-VM", "uuid": POOL_UUID, "threads": [8, 9, 24, 25], "positions": [], "fm_partition": None})
        self.assertEqual([p.name for p in self.ledger.iterdir() if not p.name.startswith(".")], [f"{POOL_UUID}.json"])

    def test_hook_prepare_exit1_and_reason_on_stderr(self):
        r = self.hook("i-2-41-VM", "prepare", "begin", fx.fixture("pool"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("vCPU 0 has no vcpupin; it must be pinned to 8", r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertIsNone(self.entry(POOL_UUID))

    def test_hook_prepare_refuses_without_partition_file(self):
        self.partition_file.unlink()
        r = self.hook("i-2-41-VM", "prepare", "begin", self.rewritten("pool"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("partition", r.stderr)
        self.partition_file.write_text("{broken")
        r = self.hook("i-2-41-VM", "prepare", "begin", self.rewritten("pool"))
        self.assertEqual(r.returncode, 1)
        self.assertIsNone(self.entry(POOL_UUID))

    def test_ledger_cleared_at_release(self):
        first = self.rewritten("pool")
        second = domain.rewrite_for_start(
            fx.rename(fx.set_cores(fx.fixture("pool"), [[9, 25], [10, 26]]), "i-2-42-VM",
                      "7c3e2a10-5d4b-4f6e-9a81-0b2c3d4e5f62"), self.p)
        self.assertEqual(self.hook("i-2-41-VM", "prepare", "begin", first).returncode, 0)
        r = self.hook("i-2-42-VM", "prepare", "begin", second)
        self.assertEqual(r.returncode, 1)
        self.assertIn("core 9,25 is held by running domain i-2-41-VM", r.stderr)

        r = self.hook("i-2-41-VM", "release", "end", first)
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertIsNone(self.entry(POOL_UUID))
        self.assertEqual(self.hook("i-2-42-VM", "prepare", "begin", second).returncode, 0)

    def test_hook_prepare_refuses_unreadable_ledger_entry(self):
        self.ledger.mkdir(parents=True)
        (self.ledger / "0b0b0b0b-0000-4000-8000-000000000000.json").write_text("{")
        r = self.hook("i-2-41-VM", "prepare", "begin", self.rewritten("pool"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("ledger", r.stderr)

    def test_hook_prepare_activates_fm_partition(self):
        self.use("ferrari")
        self.assertTrue(self.p["fabric_manager"])
        pid = self.p["fm_partitions"]["0,1"]
        r = self.hook("i-2-102-VM", "prepare", "begin", self.rewritten("a100x2"))
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(self.fmpm_calls(), [f"-a {pid}"])
        self.assertEqual(self.entry(X2_UUID)["fm_partition"], pid)
        self.assertEqual(self.entry(X2_UUID)["positions"], [0, 1])

    def test_hook_release_deactivates_fm_partition(self):
        self.use("ferrari")
        pid = self.p["fm_partitions"]["0,1"]
        xml = self.rewritten("a100x2")
        self.assertEqual(self.hook("i-2-102-VM", "prepare", "begin", xml).returncode, 0)
        r = self.hook("i-2-102-VM", "release", "end", xml)
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(self.fmpm_calls(), [f"-a {pid}", f"-d {pid}"])
        self.assertIsNone(self.entry(X2_UUID))

    def test_hook_release_without_entry_leaves_fabric_alone(self):
        self.use("ferrari")
        r = self.hook("i-2-102-VM", "release", "end", self.rewritten("a100x2"))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.fmpm_calls(), [])

    def test_hook_prepare_fm_failure_refuses_without_entry(self):
        self.use("ferrari")
        self.fmpm_exit = 3
        r = self.hook("i-2-102-VM", "prepare", "begin", self.rewritten("a100x2"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("fmpm", r.stderr)
        self.assertIsNone(self.entry(X2_UUID))

    def test_hook_release_logs_fm_failure_and_exits_0(self):
        self.use("ferrari")
        xml = self.rewritten("a100x2")
        self.assertEqual(self.hook("i-2-102-VM", "prepare", "begin", xml).returncode, 0)
        hook = load_hook()
        hook.PARTITION_FILE, hook.LEDGER, hook.SYSFS = self.partition_file, self.ledger, fx.sysfs(self.host)
        env = {"PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
               "FMPM_RECORD": str(self.fmpm_record), "FMPM_EXIT": "1"}
        with mock.patch.dict(os.environ, env), mock.patch("syslog.syslog") as logged, mock.patch("syslog.openlog"), \
                mock.patch("sys.stdin", io.StringIO(xml)), contextlib.redirect_stderr(io.StringIO()) as err:
            rc = hook.main(["qemu", "i-2-102-VM", "release", "end", "-"])
        self.assertEqual(rc, 0)
        self.assertIn("fmpm", err.getvalue())
        logged.assert_called_once()
        self.assertEqual(logged.call_args.args[0], syslog.LOG_ERR)
        self.assertIn("fmpm -d", logged.call_args.args[1])
        self.assertIsNone(self.entry(X2_UUID))

    def test_hook_no_fabric_manager_on_pcie_host(self):
        r = self.hook("i-2-93-VM", "prepare", "begin", self.rewritten("a6000"))
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(self.fmpm_calls(), [])
        entry = self.entry("4d5e6f70-8192-4a3b-9c4d-5e6f708192a3")
        self.assertEqual((entry["threads"], entry["positions"], entry["fm_partition"]),
                         ([*range(6), *range(16, 22)], [0], None))

    def test_hook_other_ops_are_silent(self):
        xml = self.rewritten("pool")
        for op, sub in (("start", "begin"), ("started", "begin"), ("stopped", "end"), ("reconnect", "begin"),
                        ("attach", "begin"), ("restore", "begin")):
            r = self.hook("i-2-41-VM", op, sub, xml)
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""), op)
        self.assertFalse(self.ledger.exists() and any(self.ledger.glob("*.json")))

    def test_hook_does_not_call_libvirt(self):
        self.use("ferrari")
        xml = self.rewritten("a100x2")
        for op, sub in (("prepare", "begin"), ("release", "end"), ("migrate", "begin"), ("started", "begin")):
            self.hook("i-2-102-VM", op, sub, xml)
        self.assertFalse(self.virsh_record.exists())
        for path in [fx.HOOK, fx.TRANSFORMER, *sorted((fx.FILES / "partition").glob("*.py"))]:
            text = path.read_text()
            self.assertNotRegex(text, r"(?m)^\s*(import|from)\s+libvirt\b", path)
            self.assertNotIn("virsh", text, path)


class FabricManagerTest(unittest.TestCase):
    def setUp(self):
        self.p = fx.partition("ferrari")
        self.calls = []

    def run_ok(self, argv, **kw):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def test_activate_and_deactivate_name_the_group_partition(self):
        pid = self.p["fm_partitions"]["4,5,6,7"]
        self.assertEqual(fm.partition_id((7, 6, 5, 4), self.p), pid)
        fm.activate((4, 5, 6, 7), self.p, run=self.run_ok)
        fm.deactivate((7, 6, 5, 4), self.p, run=self.run_ok)
        self.assertEqual(self.calls, [["fmpm", "-a", str(pid)], ["fmpm", "-d", str(pid)]])

    def test_failure_raises(self):
        def fail(argv, **kw):
            return subprocess.CompletedProcess(argv, 2, "", "partition is in use")
        with self.assertRaisesRegex(fm.FmError, "partition is in use"):
            fm.activate((0, 1), self.p, run=fail)

        def missing(argv, **kw):
            raise FileNotFoundError(argv[0])
        with self.assertRaisesRegex(fm.FmError, "fmpm"):
            fm.deactivate((0, 1), self.p, run=missing)

    def test_group_without_partition_raises(self):
        with self.assertRaisesRegex(fm.FmError, "no Fabric Manager partition"):
            fm.activate((1, 2), self.p, run=self.run_ok)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
