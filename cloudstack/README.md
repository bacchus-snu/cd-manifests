# cloudstack

Host-side configuration for the CloudStack KVM hosts. The management server and
the overlay gateway live in the atrium cluster (`argocd/atrium/cloudstack`); the
zone, offerings and global settings are configured through the CloudStack API
and recorded in the Bacchus howto (`infra/cloudstack.md`).

`auth0-setup.sh` registers the Auth0 applications of the bacchus OpenID
provider (`argocd/atrium/cloudstack/idps.toml`) and of Warpgate and stores
their credentials in Vault; it needs an Auth0 tenant administrator (usage in
the script).

```
hosts/
├── inventory.yaml   # hosts, addresses, overlays, gateway and storage roles, partitions
├── site.yaml        # configure the hosts (network files and kernel arguments only take
│                    # effect on reboot)
├── apply.sh         # run site.yaml as it is in a given commit, in the background
├── render.yaml      # render the per-host files into hosts/out/ without connecting, and
│                    # regenerate the atrium-side host lists from the inventory
├── files/           # the partition renderer and its library, the libvirt qemu hook and
│                    # the agent's domain XML hook (tests in tests/)
└── templates/
```

`python3 -m unittest discover -s hosts/tests` runs the tests of the renderer
and the hooks.

`tools/cs_partition.py` registers each host's partition with the management
server from the host's live `/etc/cloudstack/agent/partition.json`, read over
SSH as the inventory reaches the host (`register-groups <host> [--pool-cores]`,
`check-groups [<host> ...] [--pool-cores]`), sets a host's volume copy rate
(`set-move-rate`) and enters quota grants (`set-quota`), calling the API with
the sync job's keys from the cluster secret; `--help` lists the arguments.
Zone settings are `argocd/atrium/cloudstack/settings.toml`'s, which the sync
job applies. `python3 -m unittest discover -s tools/tests` runs its tests.

## Usage

The hosts are reachable only from the campus network; from outside, jump through
martini, e.g. `-e "ansible_ssh_common_args='-J martini'"` or a `ProxyJump` entry
in `~/.ssh/config` for the names the inventory connects to
(`derby.snucse.org eggnog.snucse.org faust.snucse.org cojito.snucse.org jimbeam.snucse.org`).
Hosts in the `bacchus_login` group are reached as `bacchus`, whose sudo
password Ansible reads from Vault (`passwords/nodes/<host>`) while it runs, so
`vault login` first; the password is never written anywhere.
From outside the campus the first SSH connection is refused and the following
ones pass, so retry once (Ansible: `-e ansible_ssh_retries=3`). Work on one host
at a time: dozens of simultaneous connections through martini have had the
source address cut off for minutes.

Hosts are changed from a commit, never from a working tree:
`hosts/apply.sh <commit> [ansible-playbook args]` exports what `site.yaml`
reads at that commit (`cloudstack/hosts` and the compute catalog) into
`.scratch/rollout/<commit id>/tree` and runs it there in the background,
detached from the terminal, one host at a time with the martini jump and SSH
retries. The log next to the tree ends with `EXIT <code>`; the tree and the
log are readable by their owner only, and concurrent runs export one commit
once. It takes
`ansible-playbook` from `PATH` or from `ANSIBLE_PLAYBOOK`; `APPLY_DRY_RUN=1`
only exports the tree and prints the command.

```console
$ cd hosts
$ ansible-playbook -i inventory.yaml render.yaml            # review hosts/out/<host>/
$ ./apply.sh <commit> --limit derby --check                 # see the log for what would change
$ ./apply.sh <commit> --limit derby
$ ssh root@derby reboot                                     # network and kernel changes apply on reboot
```

Every host also gets an input firewall (`/etc/nftables.d/host.nft`): VXLAN is
accepted from the other VTEPs only, guests reach the host only for DNS and
ping, and the campus reaches only SSH, VXLAN and ICMP (storage, consoles and
the agent are served on the management overlay, which stays open). It is
applied immediately. Because guest traffic leaves masqueraded to a host
address, the gateway table also keeps guests away from the hosts and from the
atrium VTEP's VXLAN port.

`/etc/nftables.conf` only includes `/etc/nftables.d/*.nft`, and each of those
files deletes and recreates just its own table. Reload with `systemctl reload nftables`;
never stop or restart the unit: its stop action is `nft flush ruleset`, which
also deletes the agent's security group tables.

Network changes are never applied to a live network: the playbook writes
`/etc/network/interfaces` (keeping a backup) and the host is rebooted.

## Host partition

Each host is split into housekeeping cores for the host itself, one GPU unit
(whole cores and 1 GiB hugepages on the GPU's NUMA node) per GPU position, and
the CPU pool for CPU-only VMs. `partition-render` computes it on the host from
sysfs, the host's inventory variables (listed in `inventory.yaml`) and the GPU
catalog `argocd/atrium/cloudstack/compute-catalog.json`, and writes
`/etc/cloudstack/agent/partition.json`. When the declared partition does not
fit the hardware it refuses with the reason, and the run stops on that host
before its partition file, boot configuration or hooks change. `site.yaml` then
installs:

- the kernel arguments (`/etc/default/grub.d/90-partition.cfg`): the units'
  hugepages per NUMA node and `irqaffinity` on the housekeeping cores.
  `update-grub` runs whenever `/boot/grub/grub.cfg` is older than the drop-in,
  so a run that failed before it is completed by the next one. They take
  effect at the next reboot; every run whose host still booted without them
  says so at its end;
- the `/dev/hugepages1G` mount and libvirt's `hugetlbfs_mount`;
- `AllowedCPUs` on `system.slice`, `user.slice` and `init.scope`, so the
  host's own processes stay on the housekeeping cores. The run applies them at
  once (`systemctl daemon-reload`, also whenever systemd reports a unit not
  yet reloaded) and fails the host unless systemd shows all three equal to
  the housekeeping cores;
- the libvirt qemu hook (`/etc/libvirt/hooks/qemu`), which admits a domain at
  start only if it fits the partition and refuses every live migration, and the
  agent's domain XML hook, which places each domain in the partition;
- `guest.cpu.mode=host-passthrough` for the agent: VMs never live-migrate, so
  hosts need not present a common CPU model.

The hook records the domains it admits in a ledger under `/run`, and knows
nothing of domains that were already running when it was installed: install it
on a host without running guests (stop or move them first). libvirtd restarts
at the end of the run to pick the hook up; running guests survive that.

In check mode the partition is rendered (and printed) only if the renderer
installed on the host is already the one being applied; otherwise every task
derived from it is skipped.

`partition_agent_values` is a rollout switch: only where it is true does the
agent report the partition's reserved CPUs and memory and its GPU host tags.
It is removed once every host reports them.

`render.yaml` renders each host's `partition.json`, kernel arguments and agent
values into `hosts/out/<host>/` from the host's captured topology in
`hosts/tests/fixtures/` for review. A change to a host's `partition.json` on
the host, which the run reports when it writes the file, is followed by
`cloudstack/tools/cs_partition.py register-groups <host>`, so that the
management server places VMs on the cores and GPU groups the host admits.

The GPU passthrough binding is in the initramfs too: `update-initramfs -u -k
all` rebuilds the image of every installed kernel (`linux-version list`) that
has one, and runs whenever one of those images is older than the binding's
files; an image without an installed kernel is ignored. Tasks that edit
`agent.properties` show no diff, because the file also holds the agent's
keystore passphrase.

## Adding a host

Add it to `cloudstack_hosts` in `inventory.yaml` (campus address, MAC and NIC
name if not `eth0`, management overlay address, and its partition: `gpu_type`
and `gpu_positions` of its GPUs, `housekeeping_cores`, `host_reserve_gib`, and
so on) and, if it is reached through a sudo user, to `bacchus_login`. Add its
captured topology (the sysfs and proc files the renderer reads) as
`hosts/tests/fixtures/sysfs-<host>` and name it in `render.yaml`. vfio-pci
claims the PCI ids the catalog lists for its `gpu_type`. Run `site.yaml` for
every host: each host keeps a VXLAN forwarding entry for every other VTEP, so
existing hosts change too.

CloudStack adds a KVM host over SSH and runs its setup with `sudo`, which a
sudo password cannot answer: give the management server's public key
(`cloud@cloudstack-management-0`, in derby's `/root/.ssh/authorized_keys`)
to root on the new host and add it as `root` without a password.

Adding the host installs its certificate. Until then libvirtd keeps Debian's
default (it cannot listen on TLS without the certificate), so run `site.yaml`
on the host once more after CloudStack has added it: libvirtd then listens on
TLS and the agent reports the host secured.
Run `render.yaml` as well: it rewrites `argocd/atrium/cloudstack/overlay-gw/peers`
and the `cloudstack_peers` set of `nodes/atrium/k8s-host-firewall.nft` from the
inventory, so the host list is kept in `inventory.yaml` only.
