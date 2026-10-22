"""Operator tool for the host partitions, per-host move rates and quota grants.

  cs_partition.py show-config                       live settings, offerings, hosts and GPU cards (read-only)
  cs_partition.py register-groups <host> [--pool-cores]
                                                    register the host's live partition: its pool cores and,
                                                    without --pool-cores, its GPU groups
  cs_partition.py check-groups [<host> ...] [--pool-cores]
                                                    compare the hosts' registration (every KVM host's when none
                                                    is named) with their live partition: the pool cores and,
                                                    without --pool-cores, twice them against the CPUs the agent
                                                    reports and the GPU groups; exits 1 on a difference
  cs_partition.py set-move-rate <host> <mbps>       the host's volume copy rate for move estimates (0 removes it)
  cs_partition.py set-quota <account> [--domain <path>] --cpu <n> --memory <MiB> --storage <GiB>
                            [--gpu <type>=<n> ...] --expiry <yyyy-mm-dd> [--reason <text>]
                                                    enter the quota as a grant and approve it

Zone settings are lines of argocd/atrium/cloudstack/settings.toml, which the sync job applies; this tool sets
none. The API keys come from the cluster secret, as the sync job's do, and are never printed. A host's
partition is read from the host itself (/etc/cloudstack/agent/partition.json) over SSH, as the inventory
reaches it.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SYNC_DIR = REPO / "argocd" / "atrium" / "cloudstack"
INVENTORY = REPO / "cloudstack" / "hosts" / "inventory.yaml"
PARTITION_FILE = "/etc/cloudstack/agent/partition.json"
SSH_JUMP = "martini"  # the hosts are reachable only from the campus network
ADMIN_ACCOUNT_TYPE = 1
SYNC = None  # the sync job's module, once client() has loaded it

GLOBAL_KEYS = [
    "gpu.detach.on.stop", "capacity.skipcounting.hours", "capacity.check.period", "vm.allocation.algorithm",
    "host.capacityType.to.order.clusters", "host.capacityType.to.order.clusters.cputomemoryweight",
    "snapshot.backup.to.secondary", "enable.additional.vm.configuration", "allow.additional.vm.configuration.list.kvm",
    "kvm.incremental.snapshot", "resource.count.running.vms.only", "resource.limit.host.tags",
    "vm.strict.resource.limit.host.tag.check", "pool.storage.capacity.disablethreshold",
    "pool.storage.allocated.capacity.disablethreshold", "job.cancel.threshold.minutes", "copy.volume.wait",
    "enable.storage.migration", "destroy.root.volume.on.vm.destruction", "host.maintenance.local.storage.strategy",
    "system.vm.use.local.storage", "cluster.cpu.allocated.capacity.disablethreshold",
    "cluster.memory.allocated.capacity.disablethreshold", "cpu.overprovisioning.factor", "mem.overprovisioning.factor",
    "cloud.kubernetes.service.enabled", "sharedfs.feature.enabled", "vnf.template.appliance.enabled",
    "backup.framework.enabled", "quota.enable.service", "cloudian.connector.enabled", "allow.user.force.stop.vm",
    "store.download.follow.redirects", "custom.diskoffering.size.min", "custom.diskoffering.size.max",
]
DOMAIN_KEYS = ["gpu.detach.on.stop"]
CLUSTER_KEYS = ["drs.automatic.enable", "cluster.cpu.allocated.capacity.disablethreshold",
                "cluster.memory.allocated.capacity.disablethreshold", "cpu.overprovisioning.factor",
                "mem.overprovisioning.factor"]
POOL_KEYS = ["storage.overprovisioning.factor"]
OFFERING_FIELDS = ["name", "cpunumber", "cpuspeed", "memory", "hosttags", "offerha", "vgpuprofilename", "gpucount",
                   "diskofferingstrictness", "rootdisksize", "iscustomized", "state"]


def config(cs, name, **scope):
    """The value of one setting at a scope, or None when the server does not know the key."""
    for c in cs("listConfigurations", name=name, **scope).get("configuration", []):
        if c["name"] == name:
            return c.get("value")
    return None


def collect(cs):
    """Everything show-config prints, read from the API only."""
    data = {"global": {k: config(cs, k) for k in GLOBAL_KEYS}}
    data["max_account"] = {c["name"]: c.get("value")
                           for c in cs("listConfigurations", keyword="max.account.").get("configuration", [])
                           if c["name"].startswith("max.account.")}
    domains = cs("listDomains", listall="true").get("domain", [])
    data["domain"] = {d["path"]: {k: config(cs, k, domainid=d["id"]) for k in DOMAIN_KEYS} for d in domains}
    clusters = cs("listClusters").get("cluster", [])
    data["cluster"] = {c["name"]: {k: config(cs, k, clusterid=c["id"]) for k in CLUSTER_KEYS} for c in clusters}
    pools = cs("listStoragePools").get("storagepool", [])
    data["pool"] = {p["name"]: dict({k: config(cs, k, storageid=p["id"]) for k in POOL_KEYS},
                                    scope=p.get("scope"), type=p.get("type"))
                    for p in pools}
    vms = cs("listVirtualMachines", listall="true").get("virtualmachine", [])
    vms += cs("listVirtualMachines", listall="true", projectid=-1).get("virtualmachine", [])
    per_offering = {}
    for vm in {v["id"]: v for v in vms}.values():
        per_offering[vm.get("serviceofferingname")] = per_offering.get(vm.get("serviceofferingname"), 0) + 1
    data["offerings"] = [dict({f: o.get(f) for f in OFFERING_FIELDS}, vms=per_offering.get(o.get("name"), 0))
                         for o in cs("listServiceOfferings", isrecursive="true", listall="true").get("serviceoffering", [])]
    data["hosts"] = [{"name": h["name"], "cpuspeed": h.get("cpuspeed"), "cpunumber": h.get("cpunumber"),
                      "state": h.get("state"), "resourcestate": h.get("resourcestate")}
                     for h in cs("listHosts", type="Routing").get("host", [])]
    data["gpucards"] = [{f: c.get(f) for f in ("name", "id", "vendorid", "deviceid", "vendorname", "devicename")}
                        for c in cs("listGpuCards").get("gpucard", [])]
    pool_by_id = {p["id"]: p for p in pools}
    sysvms = [(s["name"], s["id"]) for s in cs("listSystemVms").get("systemvm", [])]
    sysvms += [(r["name"], r["id"]) for r in cs("listRouters", listall="true").get("router", [])]
    data["system_vm_roots"] = []
    names = dict(sysvms)
    # system VM volumes are listed only on request
    for v in cs("listVolumes", listsystemvms="true", type="ROOT", listall="true").get("volume", []):
        if v.get("vmname") in names:
            pool = pool_by_id.get(v.get("storageid"), {})
            data["system_vm_roots"].append({"vm": v["vmname"], "pool": v.get("storage"), "scope": pool.get("scope")})
    return data


def render(data):
    """show-config's text, one setting or object per line."""
    out = [f"global {k} = {v}" for k, v in data["global"].items()]
    out += [f"global {k} = {v}" for k, v in sorted(data["max_account"].items())]
    for path, keys in sorted(data["domain"].items()):
        out += [f"domain {path} {k} = {v}" for k, v in keys.items()]
    for name, keys in sorted(data["cluster"].items()):
        out += [f"cluster {name} {k} = {v}" for k, v in keys.items()]
    for name, keys in sorted(data["pool"].items()):
        out.append(f"pool {name} " + " ".join(f"{k}={v}" for k, v in keys.items()))
    for o in data["offerings"]:
        out.append("offering " + " ".join(f"{k}={v}" for k, v in o.items()))
    for h in data["hosts"]:
        out.append("host " + " ".join(f"{k}={v}" for k, v in h.items()))
    speeds = [int(h["cpuspeed"]) for h in data["hosts"] if h.get("cpuspeed")]
    out.append(f"min host cpuspeed = {min(speeds) if speeds else None}")
    for c in data["gpucards"]:
        out.append("gpucard " + " ".join(f"{k}={v}" for k, v in c.items()))
    for r in data["system_vm_roots"]:
        out.append(f"system vm root {r['vm']} pool={r['pool']} scope={r['scope']}")
    return "\n".join(out)


def load_inventory():
    import yaml
    with open(INVENTORY) as f:
        return yaml.safe_load(f)


def ssh_destination(host, inventory):
    """user@address of a host as the inventory reaches it: its ansible_user and ansible_host, merged as
    Ansible does (the groups that hold it from the outermost in, then the host's own variables)."""
    groups, listing = {}, []

    def walk(name, group, ancestors):
        group = group or {}
        chain = [*ancestors, (len(ancestors), name, group)]
        if host in (group.get("hosts") or {}):
            groups.update({g[1]: g for g in chain})
            listing.append(group)
        for child_name, child in (group.get("children") or {}).items():
            walk(child_name, child, chain)

    walk("all", inventory.get("all"), [])
    if not listing:
        raise ValueError(f"{host} is not in the inventory")
    merged = {}
    for _, _, group in sorted(groups.values(), key=lambda g: g[:2]):
        merged.update(group.get("vars") or {})
    for group in listing:
        merged.update(group["hosts"][host] or {})
    user, address = merged.get("ansible_user"), merged.get("ansible_host", host)
    return f"{user}@{address}" if user else address


def read_partition(host):
    """The partition the host runs on: its live partition.json, never a local render."""
    argv = ["ssh", "-o", "BatchMode=yes", "-J", SSH_JUMP, ssh_destination(host, load_inventory()), "cat", PARTITION_FILE]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"cannot read {PARTITION_FILE}: {result.stderr.strip() or f'ssh exited {result.returncode}'}")
    return json.loads(result.stdout)


def gpu_groups(partition):
    """The updateHostGpuGroups rule of a partition, its groups as bus addresses; None for a host without GPUs."""
    if not partition.get("gpu_type"):
        return None
    rule = partition["group_rule"]
    if rule != "partitions":
        return {"rule": rule}
    bus = {u["position"]: u["bus"] for u in partition["units"]}
    return {"rule": rule, "groups": [[bus[p] for p in group] for group in partition["groups"]]}


def routing_host(cs, name):
    hosts = [h for h in cs("listHosts", type="Routing", name=name).get("host", []) if h["name"] == name]
    if len(hosts) != 1:
        raise ValueError(f"{name}: {len(hosts)} KVM hosts of that name")
    return hosts[0]


def register_groups(cs, args):
    host = routing_host(cs, args.host)
    partition = read_partition(args.host)
    cs("updateHostPoolCores", post=True, hostid=host["id"], cores=json.dumps(partition["pool_cores"]))
    print(f"{args.host}: {len(partition['pool_cores'])} pool cores registered")
    if args.pool_cores:
        return 0
    rule = gpu_groups(partition)
    if rule is None:
        print(f"{args.host}: no GPUs, no GPU groups to register")
        return 0
    cs("updateHostGpuGroups", post=True, hostid=host["id"], groups=json.dumps(rule))
    print(f"{args.host}: GPU groups registered ({rule['rule']}, {len(rule.get('groups', []))} groups)")
    return 0


def _group_set(rule):
    if not rule:
        return None
    return rule["rule"], sorted(sorted(b.lower() for b in g) for g in rule.get("groups") or [])


def host_differences(cs, host, partition, pool_cores_only):
    differences = []
    registered = {(c["node"], tuple(c["threads"])) for c in cs("listHostPoolCores", hostid=host["id"]).get("hostpoolcore", [])}
    wanted = {(c["node"], tuple(c["threads"])) for c in partition["pool_cores"]}
    if registered != wanted:
        differences.append(f"pool cores registered {sorted(registered)}, partition has {sorted(wanted)}")
    if pool_cores_only:
        return differences
    if int(host.get("cpunumber") or 0) != 2 * len(wanted):
        differences.append(f"the agent reports {host.get('cpunumber')} CPUs, twice the {len(wanted)} pool cores is "
                           f"{2 * len(wanted)}")
    listed = cs("listHostGpuGroups", hostid=host["id"]).get("hostgpugroups", [])
    have = _group_set(listed[0]) if listed else None
    want = _group_set(gpu_groups(partition))
    if have != want:
        differences.append(f"GPU groups registered {have or 'none'}, partition has {want or 'none'}")
    return differences


def check_groups(cs, args):
    hosts = {h["name"]: h for h in cs("listHosts", type="Routing").get("host", [])}
    status = 0
    for name in args.hosts or sorted(hosts):
        try:
            if name not in hosts:
                raise ValueError("not a KVM host of the zone")
            differences = host_differences(cs, hosts[name], read_partition(name), args.pool_cores)
        except (OSError, RuntimeError, ValueError, KeyError) as e:
            differences = [str(e)]
        for d in differences:
            print(f"{name}: {d}")
            status = 1
    if status == 0:
        print(f"{', '.join(args.hosts) if args.hosts else 'every host'}: the registration matches the partition")
    return status


def set_move_rate(cs, args):
    host = routing_host(cs, args.host)
    cs("updateHostMoveRate", hostid=host["id"], mbps=args.mbps)
    print(f"{args.host}: move rate {args.mbps} Mbps")
    return 0


def gpu_count(text):
    tag, _, count = text.partition("=")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", tag) or not count.isdigit():
        raise argparse.ArgumentTypeError(f"{text!r} is not <type>=<count>")
    return tag, int(count)


def set_quota(cs, args):
    accounts = [a for a in cs("listAccounts", name=args.account, listall="true").get("account", [])
                if a["name"] == args.account]
    if args.domain:
        domains = {d["path"]: d["id"] for d in cs("listDomains", listall="true").get("domain", [])}
        accounts = [a for a in accounts if a.get("domainid") == domains.get(args.domain)]
    if len(accounts) != 1:
        print(f"{args.account}: {len(accounts)} accounts of that name; name its domain with --domain")
        return 1
    account = accounts[0]
    # an Admin-type account's limits are always unlimited, and it cannot hold a grant
    if int(account.get("accounttype", -1)) == ADMIN_ACCOUNT_TYPE:
        print(f"{args.account}: Admin-type account, skipped")
        return 0
    params = {"account": account["name"], "domainid": account["domainid"], "cpu": args.cpu, "memory": args.memory,
              "storage": args.storage, "expiry": args.expiry}
    for i, (tag, count) in enumerate(args.gpu):
        params[f"gpu[{i}].type"] = tag
        params[f"gpu[{i}].count"] = count
    if args.reason:
        params["reason"] = args.reason
    request = cs("createResourceLimitRequest", post=True, **params)["resourcelimitrequest"]
    cs("approveResourceLimitRequest", post=True, id=request["id"])
    print(f"{args.account}: grant {request['id']} approved until {args.expiry}")
    return 0


def show_config(cs, args):
    print(render(collect(cs)))
    return 0


def parser():
    p = argparse.ArgumentParser(prog="cs_partition.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("show-config").set_defaults(run=show_config)
    r = sub.add_parser("register-groups")
    r.add_argument("host")
    r.add_argument("--pool-cores", action="store_true", help="register the pool cores only")
    r.set_defaults(run=register_groups)
    c = sub.add_parser("check-groups")
    c.add_argument("hosts", nargs="*", help="the hosts to check; every KVM host when none is named")
    c.add_argument("--pool-cores", action="store_true", help="compare the pool cores only")
    c.set_defaults(run=check_groups)
    m = sub.add_parser("set-move-rate")
    m.add_argument("host")
    m.add_argument("mbps", type=int)
    m.set_defaults(run=set_move_rate)
    q = sub.add_parser("set-quota")
    q.add_argument("account")
    q.add_argument("--domain", help="the account's domain path, when its name is not unique")
    q.add_argument("--cpu", type=int, required=True, help="vCPUs of instances without a GPU")
    q.add_argument("--memory", type=int, required=True, help="MiB of instances without a GPU")
    q.add_argument("--storage", type=int, required=True, help="GiB of volumes and snapshots together")
    q.add_argument("--gpu", type=gpu_count, action="append", default=[], help="<GPU type tag>=<GPUs>")
    q.add_argument("--expiry", required=True, help="the grant's last day, yyyy-mm-dd")
    q.add_argument("--reason")
    q.set_defaults(run=set_quota)
    return p


def client(read_only):
    """The sync job's signed API client with the admin user's keys from the cluster secret."""
    import base64
    import os
    import time
    import urllib.error

    def secret(key):
        out = subprocess.run(["kubectl", "--context", "bacchus-atrium", "-n", "cloudstack", "get", "secret",
                              "cloudstack-api", "-o", f"jsonpath={{.data.{key}}}"],
                             capture_output=True, text=True, check=True).stdout
        return base64.b64decode(out).decode()

    os.environ["CLOUDSTACK_API_URL"] = "https://cloud.snucse.org/client/api"
    os.environ["CLOUDSTACK_API_KEY"] = secret("api_key")
    os.environ["CLOUDSTACK_SECRET_KEY"] = secret("secret_key")
    sys.path.insert(0, str(SYNC_DIR))
    import sync
    global SYNC
    SYNC = sync

    def cs(command, post=False, **params):
        if not command.startswith("list"):
            if read_only:
                raise ValueError(f"{command}: this command only reads")
            return sync.cloudstack(command, post=post, **params)
        # reads are retried: the campus network refuses some first connections
        for attempt in range(4):
            try:
                return sync.cloudstack(command, post=post, **params)
            except (TimeoutError, urllib.error.URLError):
                if attempt == 3:
                    raise
                time.sleep(5)
    return cs


def main(argv, cs=None):
    args = parser().parse_args(argv)
    if cs is None:
        cs = client(read_only=args.command in ("show-config", "check-groups"))
    try:
        return args.run(cs, args)
    except (OSError, RuntimeError, ValueError, KeyError) as e:
        print(f"error: {SYNC.api_failure(e) if SYNC else e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
