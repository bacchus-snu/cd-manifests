#!/usr/bin/env python3
"""CloudStack KVM agent hook: libvirt domain XML transformer.

The agent runs `<this> <method> <domain xml>` before it defines a VM and uses
what is printed as the domain XML. A VM given PCI devices (GPU passthrough)
on a host with several NUMA nodes is kept on the node its devices hang off:
vCPUs and the emulator thread run on that node's CPUs and memory is preferably
taken from it. `preferred`, not `strict`: VMs without devices are not pinned
and may use that node's memory too, and a strict policy would then fail the
allocation instead of spilling to the other node.

Any other VM, and any input this cannot handle, is printed back unchanged.
"""

import io
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _pci_name(address):
    d, b, s, f = (int(address.get(k), 16) for k in ("domain", "bus", "slot", "function"))
    return f"{d:04x}:{b:02x}:{s:02x}.{f:x}"


def _device_nodes(root, sysfs):
    nodes = set()
    for address in root.findall("devices/hostdev[@type='pci']/source/address"):
        node = int((sysfs / "bus/pci/devices" / _pci_name(address) / "numa_node").read_text())
        nodes.add(node)
    return nodes


def _register_namespaces(xml):
    for _, (prefix, uri) in ET.iterparse(io.StringIO(xml), events=("start-ns",)):
        ET.register_namespace(prefix, uri)


def transform(xml, sysfs=Path("/sys")):
    # libvirt domain XML never carries a document type; refusing one keeps
    # entity expansion out of the parser
    if "<!DOCTYPE" in xml:
        return xml
    _register_namespaces(xml)
    root = ET.fromstring(xml)
    nodes = _device_nodes(root, sysfs)
    host_nodes = list((sysfs / "devices/system/node").glob("node[0-9]*"))
    if len(nodes) != 1 or len(host_nodes) < 2:
        return xml
    node = nodes.pop()
    if node < 0:
        return xml
    cpus = (sysfs / "devices/system/node" / f"node{node}" / "cpulist").read_text().strip()

    vcpu = root.find("vcpu")
    if vcpu is None:
        return xml
    vcpu.set("cpuset", cpus)
    cputune = root.find("cputune")
    if cputune is None:
        cputune = ET.SubElement(root, "cputune")
    emulatorpin = cputune.find("emulatorpin")
    if emulatorpin is None:
        emulatorpin = ET.SubElement(cputune, "emulatorpin")
    emulatorpin.set("cpuset", cpus)
    numatune = root.find("numatune")
    if numatune is None:
        numatune = ET.SubElement(root, "numatune")
    memory = numatune.find("memory")
    if memory is None:
        memory = ET.SubElement(numatune, "memory")
    memory.attrib.clear()
    memory.set("mode", "preferred")
    memory.set("nodeset", str(node))
    return ET.tostring(root, encoding="unicode")


def main(argv):
    xml = argv[-1] if len(argv) > 1 else ""
    try:
        out = transform(xml)
    except Exception:
        out = xml
    sys.stdout.write(out)


if __name__ == "__main__":
    main(sys.argv)
