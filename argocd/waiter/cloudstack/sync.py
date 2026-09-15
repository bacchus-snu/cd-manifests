"""Reconcile state that follows CloudStack: the console proxy endpoints in
Kubernetes, the users, roles and targets of the Warpgate bastion, and the
user data that makes templates trust the bastion. Runs once per invocation;
the CronJob provides the cadence."""

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

API_URL = os.environ["CLOUDSTACK_API_URL"]
API_KEY = os.environ["CLOUDSTACK_API_KEY"].strip()
SECRET_KEY = os.environ["CLOUDSTACK_SECRET_KEY"].strip()
CONSOLE_SERVICE = os.environ.get("CONSOLE_SERVICE", "console-proxy")
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
# "BASTION_" rather than "WARPGATE_": Kubernetes injects WARPGATE_PORT and friends
# for the Service of that name
WARPGATE_HOST = os.environ.get("BASTION_HOST")  # service name; unset: skip the bastion
WARPGATE_PORT = int(os.environ.get("BASTION_PORT", "8888"))
WARPGATE_TLS_NAME = os.environ.get("BASTION_TLS_NAME")  # name on Warpgate's certificate
WARPGATE_TOKEN = (os.environ.get("BASTION_TOKEN") or "").strip()
WARPGATE_SSO = os.environ.get("BASTION_SSO", "snucse")
# what Warpgate logs in as on the guests: the templates' default user
GUEST_USER = os.environ.get("GUEST_USER", "ubuntu")
# CloudStack's built-in accounts, never mirrored
BUILTIN_ACCOUNTS = {"system", "baremetal-system-account"}
ADMINS_ROLE = "admins"  # Warpgate role of CloudStack root administrators: every target
MANAGED = "cloudstack:"  # description prefix of the Warpgate objects this job owns
GUEST_TAG_PREFIX = "ssh.account."  # VM tag: <prefix><linux username> = comma-separated user names
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
USERDATA_PREFIX = "warpgate-ssh"  # user data objects with this name prefix are managed here


def cloudstack(command, **params):
    params.update(command=command, response="json", apikey=API_KEY)
    query = "&".join(
        f"{k}={urllib.parse.quote(str(v), safe='-_.*')}"
        for k, v in sorted(params.items(), key=lambda kv: kv[0].lower())
    )
    digest = hmac.new(SECRET_KEY.encode(), query.lower().encode(), hashlib.sha1).digest()
    signature = urllib.parse.quote(base64.b64encode(digest).decode(), safe="")
    with urllib.request.urlopen(f"{API_URL}?{query}&signature={signature}", timeout=30) as resp:
        body = json.load(resp)
    return body[f"{command.lower()}response"]


def kube(method, path, body=None):
    with open(f"{SA_DIR}/token") as f:
        token = f.read()
    ctx = ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt")
    url = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ['KUBERNETES_SERVICE_PORT']}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def sync_console_endpoints():
    with open(f"{SA_DIR}/namespace") as f:
        namespace = f.read()
    proxies = cloudstack("listSystemVms", systemvmtype="consoleproxy", state="Running").get("systemvm", [])
    addresses = sorted(p["publicip"] for p in proxies if p.get("publicip"))

    path = f"/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices/{CONSOLE_SERVICE}"
    status, current = kube("GET", path)
    have = sorted(a for e in current.get("endpoints", []) for a in e["addresses"]) if status == 200 else None
    if have == addresses:
        return
    desired = {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": CONSOLE_SERVICE,
            "namespace": namespace,
            "labels": {
                "kubernetes.io/service-name": CONSOLE_SERVICE,
                "endpointslice.kubernetes.io/managed-by": "cloudstack-sync",
            },
        },
        "addressType": "IPv4",
        "ports": [
            {"name": "http", "protocol": "TCP", "port": 80},
            {"name": "websocket", "protocol": "TCP", "port": 8080},
        ],
        "endpoints": [{"addresses": [a], "conditions": {"ready": True}} for a in addresses],
    }
    if status == 200:
        desired["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
        status, body = kube("PUT", path, desired)
    else:
        status, body = kube("POST", path.rsplit("/", 1)[0], desired)
    if status not in (200, 201):
        raise RuntimeError(f"endpointslice update failed: {status} {body.get('message')}")
    print(f"console proxy endpoints: {have} -> {addresses}")


class _WarpgateConnection(http.client.HTTPSConnection):
    """Reached by its service name but verified against the public name on its
    certificate, so the connection is fully checked."""

    def connect(self):
        raw = http.client.socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=WARPGATE_TLS_NAME)


def warpgate(method, path, body=None):
    """Warpgate admin API. Returns (status, json or None). 409 (exists) is not an error."""
    conn = _WarpgateConnection(WARPGATE_HOST, WARPGATE_PORT, timeout=30, context=ssl.create_default_context())
    conn.request(method, f"/@warpgate/admin/api{path}", body=json.dumps(body) if body is not None else None, headers={
        "X-Warpgate-Token": WARPGATE_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    if resp.status == 409:
        return resp.status, None
    if resp.status >= 400:
        raise RuntimeError(f"warpgate {method} {path}: {resp.status} {raw[:200]!r}")
    return resp.status, (json.loads(raw) if raw else None)


def close_sessions(target_id, usernames=None):
    """End live sessions on a target once the right to it is gone; role removal
    alone only stops new logins."""
    sessions = warpgate("GET", "/sessions?active_only=true&limit=1000")[1] or {}
    for s in sessions.get("items", []):
        if s.get("target_id") != target_id:
            continue
        if usernames is not None and s.get("username") not in usernames:
            continue
        warpgate("POST", f"/sessions/{s['id']}/close", {})
        print(f"warpgate session {s['id']} ({s.get('username')}) closed")


def guest_accounts(vm):
    """Linux username -> SNUCSE IDs allowed to log in as it, from the VM's tags.
    Only the shape is checked: which accounts a co-owner opens is their call."""
    result = {}
    for tag in vm.get("tags", []):
        key = tag.get("key", "")
        if not key.startswith(GUEST_TAG_PREFIX):
            continue
        username = key[len(GUEST_TAG_PREFIX):]
        if not USERNAME_RE.match(username):
            print(f"vm {vm.get('name')}: tag {key} ignored: invalid username")
            continue
        ids = []
        for part in (tag.get("value") or "").split(","):
            name = part.strip().lower()
            if name and name not in ids:
                ids.append(name)
        if ids:
            result[username] = ids
    return result


def render_trust_script(public_keys):
    """First-boot script that makes every local account accept the bastion's
    key: an absolute AuthorizedKeysFile without a %u token applies to all users.
    Which accounts the bastion connects to is decided by its targets, not here."""
    keys = "\n".join(sorted(public_keys))
    return (
        "#!/bin/sh\n"
        "set -e\n"
        f"cat > /etc/ssh/warpgate_keys <<'EOF'\n{keys}\nEOF\n"
        "chmod 644 /etc/ssh/warpgate_keys\n"
        "mkdir -p /etc/ssh/sshd_config.d\n"
        "printf 'AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/warpgate_keys\\n' > /etc/ssh/sshd_config.d/50-warpgate.conf\n"
        "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true\n"
    )


def userdata_name(script):
    return f"{USERDATA_PREFIX}-{hashlib.sha256(script.encode()).hexdigest()[:8]}"


def plan_targets(vms, members, guest_user=GUEST_USER):
    """Warpgate targets a set of VMs should have, and the roles that reach each.
    One target per VM for its co-owners (the account, or every member account
    of the owning project) plus one per tagged guest account, reachable only
    by the tagged names. VM names are unique across the zone, so the VM name
    is the target name; the colon form selects the guest account."""
    wanted, reach = {}, {}
    for vm in vms:
        ip = next((n["ipaddress"] for n in vm.get("nic", []) if n.get("ipaddress")), None)
        if not ip:
            continue
        name = vm["name"].lower()
        if vm.get("projectid"):
            owners = {f"account-{a}" for a in members.get(vm["projectid"], set())}
        else:
            owners = {f"account-{vm['account']}"}

        def spec(target, username, description):
            return {
                "name": target,
                "description": description,
                "options": {"kind": "Ssh", "host": ip, "port": 22, "username": username,
                            "auth": {"kind": "PublicKey", "key_id": None}},
            }

        wanted[name] = spec(name, guest_user, f"{MANAGED}vm:{vm['id']}")
        reach[name] = owners
        for username, ids in guest_accounts(vm).items():
            target = f"{name}:{username}"
            wanted[target] = spec(target, username, f"{MANAGED}vm:{vm['id']}:guest:{username}")
            reach[target] = {f"account-{i}" for i in ids}
    return wanted, reach


def sync_warpgate():
    """Role per CloudStack account, user per CloudStack user (SSO credential =
    the user's e-mail, which the sign-in gate keeps equal to the identity
    provider's claim), target per VM plus one per guest account a co-owner has
    tagged on it. A VM is reachable by its account, or by every member account
    of the project that owns it; a guest target only by the tagged accounts;
    root administrators reach every target. Objects created here carry a
    'cloudstack:' description and are removed when their source disappears."""
    users = [u for u in cloudstack("listUsers", listall="true").get("user", [])
             if u.get("state") == "enabled" and u["account"] not in BUILTIN_ACCOUNTS and u.get("email")]
    # project-owned VMs are only listed when asked for explicitly
    vms = cloudstack("listVirtualMachines", listall="true").get("virtualmachine", [])
    vms += cloudstack("listVirtualMachines", listall="true", projectid=-1).get("virtualmachine", [])
    vms = list({vm["id"]: vm for vm in vms}.values())
    per_account, users_of_role = {}, {}
    for u in users:
        per_account.setdefault(u["account"], []).append(u["username"])
        users_of_role.setdefault(f"account-{u['account']}", set()).add(u["username"])
    for account, names in per_account.items():
        if len(names) > 1:  # roles are per account: every user of it would share access
            print(f"warning: account {account} has {len(names)} users: {sorted(names)}")
    members = {}  # project id -> member account names
    for p in cloudstack("listProjects", listall="true").get("project", []):
        members[p["id"]] = {m["account"] for m in cloudstack("listProjectAccounts", projectid=p["id"]).get("projectaccount", [])}

    wanted, reach = plan_targets(vms, members)
    guests = {i for vm in vms for ids in guest_accounts(vm).values() for i in ids}
    # accounts that have someone who can log in or something to log in to
    relevant = {u["account"] for u in users} | {vm["account"] for vm in vms if not vm.get("projectid")}
    relevant |= set().union(*members.values()) if members else set()
    relevant |= guests
    accounts = {a["name"]: a for a in cloudstack("listAccounts", listall="true").get("account", [])
                if a["name"] in relevant}

    roles = {r["name"]: r for r in warpgate("GET", "/roles")[1]}
    for name in accounts:
        role = f"account-{name}"
        if role not in roles:
            warpgate("POST", "/roles", {"name": role, "description": f"{MANAGED}account:{accounts[name]['id']}"})
            print(f"warpgate role {role} created")
    if ADMINS_ROLE not in roles:
        warpgate("POST", "/roles", {"name": ADMINS_ROLE, "description": f"{MANAGED}admins"})
        print(f"warpgate role {ADMINS_ROLE} created")
    roles = {r["name"]: r for r in warpgate("GET", "/roles")[1]}

    wg_users = {u["username"]: u for u in warpgate("GET", "/users")[1]}
    for u in users:
        if u["username"] not in wg_users:
            warpgate("POST", "/users", {"username": u["username"], "description": f"{MANAGED}user:{u['id']}"})
            print(f"warpgate user {u['username']} created")
    wg_users = {u["username"]: u for u in warpgate("GET", "/users")[1]}
    for u in users:
        wu = wg_users.get(u["username"])
        if not wu:
            continue
        email = u["email"]  # as the identity provider presents it: Warpgate compares verbatim
        creds = warpgate("GET", f"/users/{wu['id']}/credentials/sso")[1]
        for c in creds:  # the address may change: keep exactly one, current credential
            if c.get("provider") in (None, WARPGATE_SSO) and c["email"] != email:
                warpgate("DELETE", f"/users/{wu['id']}/credentials/sso/{c['id']}")
        if not any(c["email"] == email and c.get("provider") in (None, WARPGATE_SSO) for c in creds):
            warpgate("POST", f"/users/{wu['id']}/credentials/sso", {"provider": WARPGATE_SSO, "email": email})
            print(f"warpgate user {u['username']}: sso credential {email}")
        wanted_roles = {f"account-{u['account']}"}
        if u.get("accounttype") == 1:
            wanted_roles.add(ADMINS_ROLE)
        have = {r["name"] for r in warpgate("GET", f"/users/{wu['id']}/roles")[1]}
        for name in wanted_roles - have:
            warpgate("POST", f"/users/{wu['id']}/roles/{roles[name]['id']}", {})
            print(f"warpgate user {u['username']}: role {name}")
        for name in (have & {ADMINS_ROLE}) - wanted_roles:
            warpgate("DELETE", f"/users/{wu['id']}/roles/{roles[name]['id']}")
            print(f"warpgate user {u['username']}: role {name} removed")

    wg_targets = {t["name"]: t for t in warpgate("GET", "/targets")[1]}
    for name, spec in wanted.items():
        t = wg_targets.get(name)
        if t is None:
            status, t = warpgate("POST", "/targets", spec)
            print(f"warpgate target {name} -> {spec['options']['host']} created")
        elif (t["options"].get("host") != spec["options"]["host"]
              or t["options"].get("username") != spec["options"]["username"]):
            warpgate("PUT", f"/targets/{t['id']}", spec)
            print(f"warpgate target {name} -> {spec['options']['host']} updated")
        if t is not None:
            wanted_roles = {r for r in reach[name] if r in roles} | {ADMINS_ROLE}
            have = {r["name"]: r for r in warpgate("GET", f"/targets/{t['id']}/roles")[1]}
            for rname in wanted_roles - have.keys():
                warpgate("POST", f"/targets/{t['id']}/roles/{roles[rname]['id']}", {})
                print(f"warpgate target {name}: role {rname}")
            for rname, r in have.items():  # membership that ended, e.g. someone left the project
                if rname not in wanted_roles and (r.get("description") or "").startswith(MANAGED):
                    warpgate("DELETE", f"/targets/{t['id']}/roles/{r['id']}")
                    print(f"warpgate target {name}: role {rname} removed")
                    close_sessions(t["id"], users_of_role.get(rname, set()))
    for name, t in wg_targets.items():
        if (t.get("description") or "").startswith(MANAGED) and name not in wanted:
            close_sessions(t["id"])
            warpgate("DELETE", f"/targets/{t['id']}")
            print(f"warpgate target {name} removed")
    live_users = {u["username"] for u in users}
    for name, wu in wg_users.items():
        if (wu.get("description") or "").startswith(MANAGED) and name not in live_users:
            for s in (warpgate("GET", f"/sessions?active_only=true&limit=1000&username={urllib.parse.quote(name)}")[1] or {}).get("items", []):
                warpgate("POST", f"/sessions/{s['id']}/close", {})
                print(f"warpgate session {s['id']} ({name}) closed")
            warpgate("DELETE", f"/users/{wu['id']}")
            print(f"warpgate user {name} removed")
    live_roles = {f"account-{a}" for a in accounts} | {ADMINS_ROLE}
    for name, r in roles.items():
        if (r.get("description") or "").startswith(MANAGED) and name not in live_roles:
            warpgate("DELETE", f"/roles/{r['id']}")
            print(f"warpgate role {name} removed")


def sync_template_userdata():
    """Every user template gets the bastion trust script as appended user data,
    so a VM from any template accepts the bastion without anyone copying keys.
    A template that links some other user data is someone's deliberate choice
    and is left alone. Stale managed scripts are removed once unlinked."""
    keys = warpgate("GET", "/ssh/own-keys")[1] or []
    public = [k["public_key"] for k in keys if k.get("is_default")] or [k["public_key"] for k in keys]
    if not public:
        print("warning: warpgate has no client keys; template user data not managed")
        return
    script = render_trust_script(public)
    name = userdata_name(script)

    existing = {u["name"]: u for u in cloudstack("listUserData", listall="true").get("userdata", [])}
    if name not in existing:
        cloudstack("registerUserData", name=name, userdata=base64.b64encode(script.encode()).decode())
        print(f"cloudstack user data {name} registered")
        existing = {u["name"]: u for u in cloudstack("listUserData", listall="true").get("userdata", [])}
    current = existing[name]["id"]

    linked = set()
    for t in cloudstack("listTemplates", templatefilter="all", listall="true").get("template", []):
        if t.get("templatetype") != "USER":
            continue
        have, have_name = t.get("userdataid"), t.get("userdataname") or ""
        if have == current:
            linked.add(have)
            continue
        if have and not have_name.startswith(USERDATA_PREFIX):
            print(f"template {t['name']}: links user data {have_name}, left alone")
            linked.add(have)
            continue
        cloudstack("linkUserDataToTemplate", templateid=t["id"], userdataid=current, userdatapolicy="APPEND")
        print(f"template {t['name']}: user data {name} linked (append)")
    for uname, u in existing.items():
        if uname.startswith(USERDATA_PREFIX) and uname != name and u["id"] not in linked:
            try:
                cloudstack("deleteUserData", id=u["id"])
                print(f"cloudstack user data {uname} removed")
            except urllib.error.HTTPError as e:  # still referenced by a VM: retry next run
                print(f"cloudstack user data {uname}: not removed: {e}")


def main():
    sync_console_endpoints()
    if WARPGATE_HOST and WARPGATE_TLS_NAME and WARPGATE_TOKEN:
        sync_warpgate()
        sync_template_userdata()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # one line per failure, exit non-zero for the Job
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
