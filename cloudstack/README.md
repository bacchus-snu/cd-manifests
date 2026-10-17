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
├── render.yaml      # render the per-host files into hosts/out/ without connecting, and
│                    # regenerate the atrium-side host lists from the inventory
└── templates/
```

## Usage

The hosts are reachable only from the campus network; from outside, jump through
martini, e.g. `-e "ansible_ssh_common_args='-J martini'"` or a `ProxyJump` entry
in `~/.ssh/config` for the names the inventory connects to
(`derby.snucse.org eggnog.snucse.org faust.snucse.org cojito.snucse.org`).
From outside the campus the first SSH connection is refused and the following
ones pass, so retry once (Ansible: `-e ansible_ssh_retries=3`). Work on one host
at a time: dozens of simultaneous connections through martini have had the
source address cut off for minutes.

```console
$ cd hosts
$ ansible-playbook -i inventory.yaml render.yaml            # review hosts/out/<host>/
$ ansible-playbook -i inventory.yaml site.yaml --limit derby --check --diff
$ ansible-playbook -i inventory.yaml site.yaml --limit derby
$ ssh root@derby reboot                                     # network changes apply on reboot
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

Add it to `cloudstack_hosts` in `inventory.yaml` (campus address and MAC,
management overlay address) and run `site.yaml` for every host: each host keeps
a VXLAN forwarding entry for every other VTEP, so existing hosts change too.
Run `render.yaml` as well: it rewrites `argocd/atrium/cloudstack/overlay-gw/peers`
and the `cloudstack_peers` set of `nodes/atrium/k8s-host-firewall.nft` from the
inventory, so the host list is kept in `inventory.yaml` only.
