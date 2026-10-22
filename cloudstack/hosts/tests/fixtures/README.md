# Test fixtures

- `sysfs-<host>/sys` and `sysfs-<host>/proc` hold only the files the partition renderer reads.
- `sysfs-jimbeam`, `sysfs-i7` (derby) and `sysfs-jackdaniels` are copied from read-only captures of the live hosts (2026-10-19). The captures list only NVIDIA PCI functions, so `vendor` is `0x10de` throughout.
- `sysfs-eggnog`, `sysfs-faust` and `sysfs-cojito` are copied the same way from their hosts' captures (2026-10-19). They differ from `sysfs-i7` only in MemTotal, by a few kB. `render.yaml` renders each host's partition from its tree.
- `sysfs-ferrari` and `sysfs-ford` are **synthetic** (not yet measured): built from the hardware table of the GPU-partition design, one NUMA node per socket (NPS1), AMD-style numbering (thread n and n + total cores are siblings), and illustrative GPU bus addresses, each with its upstream bridge under `class/pci_bus`.
- `listGpuCards.json` is the zone's `listGpuCards` output recorded on 2026-10-19 (card ids omitted).
