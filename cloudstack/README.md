# cloudstack

Host-side configuration for the CloudStack KVM hosts. The management server and
the overlay gateway live in the waiter cluster (`argocd/waiter/cloudstack`); the
zone itself is declared with Terraform in `bacchus-snu/infra`.

```
hosts/
├── inventory.yaml   # hosts, addresses, overlays, gateway and storage roles
├── site.yaml        # configure the hosts (network files only take effect on reboot)
├── render.yaml      # render the per-host files into hosts/out/ without connecting
└── templates/
```

## Usage

```console
$ cd hosts
$ ansible-playbook -i inventory.yaml render.yaml            # review hosts/out/<host>/
$ ansible-playbook -i inventory.yaml site.yaml --limit derby
$ ssh root@derby reboot                                     # network changes apply on reboot
```

Network changes are never applied to a live network: the playbook writes
`/etc/network/interfaces` (keeping a backup) and the host is rebooted.

## Adding a host

Add it to `cloudstack_hosts` in `inventory.yaml` (campus address and MAC,
management overlay address) and run `site.yaml` for every host: each host keeps
a VXLAN forwarding entry for every other VTEP, so existing hosts change too.
Add the new host to the `peers` list of the overlay gateway ConfigMap in
`argocd/waiter/cloudstack/overlay-gw.yaml` as well.
