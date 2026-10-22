# cloudstack

Host-side configuration for the CloudStack KVM hosts. The management server and
the overlay gateway live in the atrium cluster (`argocd/atrium/cloudstack`); the
zone, offerings and global settings are configured through the CloudStack API
and recorded in the Bacchus howto (`infra/cloudstack.md`).

`auth0-setup.sh` registers the Auth0 applications of the sign-in gate's
Bacchus door and of Warpgate and stores their credentials in Vault; it needs
an Auth0 tenant administrator (usage in the script).

```
hosts/
├── inventory.yaml   # hosts, addresses, overlays, gateway and storage roles
├── site.yaml        # configure the hosts (network files only take effect on reboot)
├── apply.sh         # run site.yaml as it is in a given commit, in the background
├── render.yaml      # render the per-host files into hosts/out/ without connecting, and
│                    # regenerate the atrium-side host lists from the inventory
├── files/           # the agent's domain XML hook (tests in tests/)
└── templates/
```

`python3 -m unittest discover -s hosts/tests` runs the hook's tests.

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

## Adding a host

Add it to `cloudstack_hosts` in `inventory.yaml` (campus address, MAC and NIC
name if not `eth0`, management overlay address, `vfio_pci_ids` of its GPU and
the GPU's audio function) and, if it is reached through a sudo user, to
`bacchus_login`. Run `site.yaml` for every host: each host keeps a VXLAN
forwarding entry for every other VTEP, so existing hosts change too.

The playbook fails on a host that cannot run `guest_cpu_model`: every VM uses
that one CPU model so that it can live-migrate to any host (CloudStack offers
every host of the zone and does not compare CPUs). Lowering it is a decision
for all hosts; it applies to each VM at its next start.

CloudStack adds a KVM host over SSH and runs its setup with `sudo`, which a
sudo password cannot answer: give the management server's public key
(`cloud@cloudstack-management-0`, in derby's `/root/.ssh/authorized_keys`)
to root on the new host and add it as `root` without a password.

Adding the host installs its certificate. Until then libvirtd keeps Debian's
default (it cannot listen on TLS without the certificate), so run `site.yaml`
on the host once more after CloudStack has added it: libvirtd then listens on
TLS and the agent reports the host secured, which live migration needs.
Run `render.yaml` as well: it rewrites `argocd/atrium/cloudstack/overlay-gw/peers`
and the `cloudstack_peers` set of `nodes/atrium/k8s-host-firewall.nft` from the
inventory, so the host list is kept in `inventory.yaml` only.
