#!/usr/bin/python3
"""CloudStack KVM agent hook: places a domain in the host partition before
libvirt defines it.

The agent runs `<this> <method> <domain xml>` and uses what is printed as the
domain XML. A domain that cannot be placed, and any error, prints the input
unchanged; the libvirt qemu hook then refuses that domain with the reason.
Nothing is written to stderr, because the agent reads it as part of the XML.

CLOUDSTACK_PARTITION_FILE overrides /etc/cloudstack/agent/partition.json.
"""
import json
import os
import sys
from pathlib import Path


def main(argv: list[str]) -> None:
    xml = argv[-1] if len(argv) > 1 else ""
    try:
        sys.path.insert(1, "/usr/local/lib/cloudstack-partition")
        from partition import domain
        path = Path(os.environ.get("CLOUDSTACK_PARTITION_FILE", "/etc/cloudstack/agent/partition.json"))
        out = domain.rewrite_for_start(xml, json.loads(path.read_text()))
    except Exception:
        out = xml
    sys.stdout.write(out)


if __name__ == "__main__":
    # On the descriptor, so writes below sys.stderr are silenced too.
    os.dup2(os.open(os.devnull, os.O_WRONLY), 2)
    main(sys.argv)
