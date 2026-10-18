import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "files" / "libvirt-vm-xml-transformer.py"
spec = importlib.util.spec_from_file_location("xml_transformer", HOOK)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)

GPU = ("0x0000", "0x16", "0x00", "0x0")
AUDIO = ("0x0000", "0x16", "0x00", "0x1")


def domain(*devices, cputune="<cputune><shares>2000</shares></cputune>"):
    hostdevs = "".join(
        f"<hostdev mode='subsystem' type='pci' managed='yes'><source>"
        f"<address domain='{d}' bus='{b}' slot='{s}' function='{f}'/></source></hostdev>"
        for d, b, s, f in devices)
    return (
        "<domain type='kvm'><name>i-2-10-VM</name>"
        "<metadata><cloudstack:instance xmlns:cloudstack='http://cloudstack.apache.org/instance'>"
        "<cloudstack:zone>snucse</cloudstack:zone></cloudstack:instance></metadata>"
        "<memory>25165824</memory><vcpu current='16'>16</vcpu>"
        f"{cputune}<cpu mode='custom' match='exact'><model fallback='allow'>Broadwell-noTSX-IBRS</model></cpu>"
        f"<devices><disk type='file' device='disk'/>{hostdevs}</devices></domain>")


class Sysfs:
    """A /sys tree with the given NUMA nodes and PCI device nodes."""

    def __init__(self, nodes, devices):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        for n, cpus in nodes.items():
            d = self.root / "devices/system/node" / f"node{n}"
            d.mkdir(parents=True)
            (d / "cpulist").write_text(cpus + "\n")
        for (dom, bus, slot, fn), node in devices.items():
            name = f"{int(dom, 16):04x}:{int(bus, 16):02x}:{int(slot, 16):02x}.{int(fn, 16):x}"
            d = self.root / "bus/pci/devices" / name
            d.mkdir(parents=True)
            (d / "numa_node").write_text(f"{node}\n")

    def __enter__(self):
        return self.root

    def __exit__(self, *exc):
        self.dir.cleanup()


TWO_NODES = {0: "0-7,16-23", 1: "8-15,24-31"}


class TransformTest(unittest.TestCase):
    def test_gpu_vm_follows_device_node(self):
        with Sysfs(TWO_NODES, {GPU: 0, AUDIO: 0}) as sysfs:
            out = ET.fromstring(hook.transform(domain(GPU, AUDIO), sysfs))
        self.assertEqual(out.find("vcpu").get("cpuset"), "0-7,16-23")
        self.assertEqual(out.find("vcpu").text, "16")
        self.assertEqual(out.find("cputune/emulatorpin").get("cpuset"), "0-7,16-23")
        memory = out.find("numatune/memory")
        self.assertEqual((memory.get("mode"), memory.get("nodeset")), ("preferred", "0"))

    def test_vm_without_hostdev_unchanged(self):
        xml = domain()
        with Sysfs(TWO_NODES, {}) as sysfs:
            self.assertEqual(hook.transform(xml, sysfs), xml)

    def test_single_node_host_unchanged(self):
        xml = domain(GPU)
        with Sysfs({0: "0-7"}, {GPU: 0}) as sysfs:
            self.assertEqual(hook.transform(xml, sysfs), xml)

    def test_device_without_node_unchanged(self):
        xml = domain(GPU)
        with Sysfs(TWO_NODES, {GPU: -1}) as sysfs:
            self.assertEqual(hook.transform(xml, sysfs), xml)

    def test_devices_on_two_nodes_unchanged(self):
        other = ("0x0000", "0x98", "0x00", "0x0")
        xml = domain(GPU, other)
        with Sysfs(TWO_NODES, {GPU: 0, other: 1}) as sysfs:
            self.assertEqual(hook.transform(xml, sysfs), xml)

    def test_cloudstack_metadata_namespace_kept(self):
        with Sysfs(TWO_NODES, {GPU: 1}) as sysfs:
            out = hook.transform(domain(GPU), sysfs)
        ns = "{http://cloudstack.apache.org/instance}"
        self.assertEqual(ET.fromstring(out).find(f"metadata/{ns}instance/{ns}zone").text, "snucse")
        self.assertIn("<cloudstack:zone>snucse</cloudstack:zone>", out)

    def test_existing_cputune_children_kept(self):
        with Sysfs(TWO_NODES, {GPU: 1}) as sysfs:
            out = ET.fromstring(hook.transform(domain(GPU), sysfs))
        self.assertEqual(out.find("cputune/shares").text, "2000")
        self.assertEqual(len(out.findall("cputune")), 1)
        self.assertEqual(out.find("cputune/emulatorpin").get("cpuset"), "8-15,24-31")

    def test_document_type_is_refused(self):
        xml = "<!DOCTYPE domain [<!ENTITY a 'x'>]>" + domain(GPU)
        with Sysfs(TWO_NODES, {GPU: 0}) as sysfs:
            self.assertEqual(hook.transform(xml, sysfs), xml)

    def test_missing_cputune_is_added(self):
        with Sysfs(TWO_NODES, {GPU: 0}) as sysfs:
            out = ET.fromstring(hook.transform(domain(GPU, cputune=""), sysfs))
        self.assertEqual(out.find("cputune/emulatorpin").get("cpuset"), "0-7,16-23")


class CommandLineTest(unittest.TestCase):
    def run_hook(self, *args):
        return subprocess.run([sys.executable, str(HOOK), *args], capture_output=True, text=True, check=True)

    def test_bad_xml_is_returned_unchanged(self):
        self.assertEqual(self.run_hook("transform", "<domain>").stdout, "<domain>")

    def test_vm_without_hostdev_round_trips(self):
        xml = domain()
        self.assertEqual(self.run_hook("transform", xml).stdout, xml)


if __name__ == "__main__":
    unittest.main()
