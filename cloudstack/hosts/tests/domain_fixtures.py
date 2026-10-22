"""Partitions and domain XML shared by the domain and qemu hook tests.

Partitions are rendered from the sysfs fixtures and declared inventories of
the partition renderer's tests, so both suites describe the same hosts.
"""
import copy
import functools
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = HERE.parent / "files"
FIXTURES = HERE / "fixtures"
TRANSFORMER = FILES / "libvirt-vm-xml-transformer.py"
HOOK = FILES / "libvirt-qemu-hook"
NS = "http://cloudstack.apache.org/instance"

sys.path.insert(0, str(FILES))
import test_partition_render as renderer  # noqa: E402

DECLARED = {
    "jimbeam": renderer.JIMBEAM,
    "i7": renderer.I7,
    "jackdaniels": renderer.JACKDANIELS,
    "ferrari": renderer.FERRARI,
    "ford": renderer.FORD,
}


@functools.cache
def _partition(host):
    return renderer.render(host, DECLARED[host])


def partition(host):
    return copy.deepcopy(_partition(host))


def sysfs(host):
    return FIXTURES / f"sysfs-{host}" / "sys"


def fixture(name):
    return (FIXTURES / f"domain-{name}.xml").read_text()


def parse(xml):
    return ET.fromstring(xml)


def cpulist(text):
    out = set()
    for part in text.split(","):
        lo, _, hi = part.partition("-")
        out.update(range(int(lo), int(hi or lo) + 1))
    return out


def pins(root):
    return {int(p.get("vcpu")): cpulist(p.get("cpuset")) for p in root.findall("cputune/vcpupin")}


def hostdev_buses(root):
    out = []
    for a in root.findall("devices/hostdev[@type='pci']/source/address"):
        d, b, s, f = (int(a.get(k, "0"), 16) for k in ("domain", "bus", "slot", "function"))
        out.append(f"{d:04x}:{b:02x}:{s:02x}.{f:x}")
    return out


def set_cores(xml, cores):
    """Replace the core assignment in the CloudStack metadata; None removes it."""
    root = parse(xml)
    inst = root.find(f"metadata/{{{NS}}}instance")
    old = inst.find(f"{{{NS}}}cores")
    if old is not None:
        inst.remove(old)
    if cores is not None:
        el = ET.SubElement(inst, f"{{{NS}}}cores")
        for c in cores:
            ET.SubElement(el, f"{{{NS}}}core").text = ",".join(map(str, c))
    return ET.tostring(root, encoding="unicode")


def add_device(xml, device):
    """`xml` with the device element `device` (XML text) in its main <devices>."""
    root = parse(xml)
    main = next(d for d in root.findall("devices") if d.find("emulator") is not None)
    main.append(ET.fromstring(device))
    return ET.tostring(root, encoding="unicode")


def rename(xml, name, uuid):
    root = parse(xml)
    root.find("name").text = name
    root.find("uuid").text = uuid
    return ET.tostring(root, encoding="unicode")


def set_vcpus(xml, n):
    root = parse(xml)
    vcpu = root.find("vcpu")
    vcpu.text = str(n)
    vcpu.set("current", str(n))
    return ET.tostring(root, encoding="unicode")


def gpu_domain(xml, buses, vcpus, gib):
    """`xml` with its PCI hostdevs replaced by `buses` and its size set."""
    root = parse(xml)
    for devices in root.findall("devices"):
        for h in devices.findall("hostdev"):
            devices.remove(h)
    main = next(d for d in root.findall("devices") if d.find("emulator") is not None)
    for bus in buses:
        dom, b, sf = bus.split(":")
        s, f = sf.split(".")
        h = ET.SubElement(main, "hostdev", mode="subsystem", type="pci", managed="yes", display="off")
        ET.SubElement(h, "driver", name="vfio")
        ET.SubElement(ET.SubElement(h, "source"), "address",
                      domain=f"0x{dom}", bus=f"0x{b}", slot=f"0x{s}", function=f"0x{f}")
    vcpu = root.find("vcpu")
    vcpu.text = str(vcpus)
    vcpu.set("current", str(vcpus))
    for tag in ("memory", "currentMemory"):
        root.find(tag).text = str(gib * 1024 * 1024)
    return ET.tostring(root, encoding="unicode")
