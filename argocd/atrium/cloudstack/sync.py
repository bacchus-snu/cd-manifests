"""Reconcile state that follows CloudStack: the console proxy endpoints in
Kubernetes and the certificate the console proxies serve, the users, roles
and targets of the Warpgate bastion, and the user data that brings guests
from the templates onto the network and makes them trust the bastion. It also
drops the records of management servers that are gone. Runs once per
invocation; the CronJob provides the cadence."""

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, time as daytime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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
# CloudStack domain path -> Warpgate SSO provider its users sign in with, e.g.
# "ROOT=bacchus,ROOT/snucse=snucse"; users of other domains are not mirrored
WARPGATE_SSO = os.environ.get("BASTION_SSO", "")
# what Warpgate logs in as on the guests: the templates' default user
GUEST_USER = os.environ.get("GUEST_USER", "ubuntu")
# CloudStack's built-in accounts, never mirrored
BUILTIN_ACCOUNTS = {"system", "baremetal-system-account"}
ADMINS_ROLE = "admins"  # Warpgate role of CloudStack root administrators: every target
# Users sign in with their identity provider only, so a password set on one's
# Warpgate profile must open nothing: SSH does not offer password
# authentication, and the web login of mirrored users requires SSO. SSH keeps
# accepting any one credential (a registered key or the browser approval).
WARPGATE_PARAMETERS = {"ssh_client_auth_password": False, "password_login_mode": "Minimized"}
USER_CREDENTIAL_POLICY = {"http": ["Sso"]}
MANAGED = "cloudstack:"  # description prefix of the Warpgate objects this job owns
GUEST_TAG_PREFIX = "ssh.account."  # VM tag: <prefix><linux username> = comma-separated user names
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
USERDATA_PREFIX = "warpgate-ssh"  # user data objects with this name prefix are managed here
PASSWORD_SCRIPT = "/var/lib/cloud/scripts/per-boot/cloudstack-password"
NETWORK_FALLBACK_CFG = "/etc/cloud/cloud.cfg.d/90-network-fallback.cfg"
USERDATA_BOUNDARY = "==cloudstack-user-data=="
CATALOG_PATH = os.environ.get("TEMPLATE_CATALOG", "/opt/sync/templates.toml")
ROLES_PATH = os.environ.get("ROLE_CATALOG", "/opt/sync/roles.toml")
ROLE_TYPES = ("Admin", "ResourceAdmin", "DomainAdmin", "User")
PROVIDERS_PATH = os.environ.get("IDP_CATALOG", "/opt/sync/idps.toml")
# certificate (leaf, then intermediates) and key that every running console
# proxy must serve; cert-manager renews them in place
CONSOLE_TLS_DIR = os.environ.get("CONSOLE_TLS_DIR", "/etc/console-tls")
CONSOLE_CERT_DOMAIN = "console-proxy.cloud.snucse.org"
# every upload reboots the secondary storage VMs and resets the console proxies
CONSOLE_CERT_UPLOAD_INTERVAL = timedelta(minutes=60)
CONSOLE_CERT_ZONE = timezone(timedelta(hours=9))
CONSOLE_CERT_WINDOW = (daytime(4, 0), daytime(6, 0))
CONSOLE_PROBE_RETRY = 30  # seconds
CONSOLE_PROXY_STATE = "consoleproxy.management.state"
LIST_PAGE_SIZE = 500  # default.page.size, the largest page the server accepts
PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def cloudstack(command, *, post=False, **params):
    params.update(command=command, response="json", apikey=API_KEY)
    query = "&".join(
        f"{k}={urllib.parse.quote(str(v), safe='-_.*')}"
        for k, v in sorted(params.items(), key=lambda kv: kv[0].lower())
    )
    digest = hmac.new(SECRET_KEY.encode(), query.lower().encode(), hashlib.sha1).digest()
    signature = urllib.parse.quote(base64.b64encode(digest).decode(), safe="")
    if post:  # parameters that must never appear in a URL, such as private keys
        request = urllib.request.Request(
            API_URL, data=f"{query}&signature={signature}".encode(), method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
    else:
        request = f"{API_URL}?{query}&signature={signature}"
    with urllib.request.urlopen(request, timeout=30) as resp:
        body = json.load(resp)
    return body[f"{command.lower()}response"]


def cloudstack_list(command, key, **params):
    """Every item of a list command. Unpaged, the server returns only its first default.page.size items."""
    items, page = [], 1
    while True:
        batch = cloudstack(command, page=page, pagesize=LIST_PAGE_SIZE, **params).get(key, [])
        items += batch
        if len(batch) < LIST_PAGE_SIZE:
            return items
        page += 1


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
    # an empty endpoint list is stored as null, not []
    have = sorted(a for e in (current.get("endpoints") or []) for a in e["addresses"]) if status == 200 else None
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
            {"name": "https", "protocol": "TCP", "port": 443},
            {"name": "websocket", "protocol": "TCP", "port": 8443},
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


def wait_for_job(jobid, timeout=300, interval=2):
    deadline = time.monotonic() + timeout
    while True:
        result = cloudstack("queryAsyncJobResult", jobid=jobid)
        if result.get("jobstatus") == 1:
            return result
        if result.get("jobstatus") == 2:
            raise RuntimeError(f"job {jobid} failed: {(result.get('jobresult') or {}).get('errortext')}")
        if time.monotonic() > deadline:
            raise RuntimeError(f"job {jobid} still running after {timeout}s")
        time.sleep(interval)


def restore_console_proxy_state():
    """A server certificate upload sets the console proxy management state to
    ResetSuspending so that the proxies restart with it. The state is read once
    per management server process, though: the running server never acts on
    it, and a server started while it is set stops every proxy for good.
    Nothing else sets it, so it is put back to Auto and the proxies are
    restarted by the caller instead."""
    for s in cloudstack("listConfigurations", name=CONSOLE_PROXY_STATE).get("configuration", []):
        if s.get("name") == CONSOLE_PROXY_STATE and s.get("value") == "ResetSuspending":
            cloudstack("updateConfiguration", name=CONSOLE_PROXY_STATE, value="Auto")
            print("console proxy management state: ResetSuspending -> Auto")


def prune_management_servers():
    """A management server is known by the MAC address of its interface, so
    every restart of the server's pod registers a new one and leaves the old
    record Down for good. Down records are removed while a server is Up."""
    servers = cloudstack("listManagementServers").get("managementserver", [])
    if not any(m.get("state") == "Up" for m in servers):
        return
    for m in servers:
        if m.get("state") == "Down":
            cloudstack("removeManagementServer", id=m["id"])
            print(f"management server record {m.get('serviceip')} (Down) removed")


def presented_certificate(address, port=443):
    """DER of the certificate the peer presents, unverified. b"" when the port
    refuses or the handshake fails: the peer serves no certificate. None when
    the peer cannot be reached at all: nothing is known about it."""
    try:
        return ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate((address, port), timeout=10))
    except (ConnectionRefusedError, ssl.SSLError):
        return b""
    except OSError:
        return None


def pem_blocks(bundle):
    return [m.group(0) + "\n" for m in PEM_CERT_RE.finditer(bundle)]


def last_certificate_upload():
    events = cloudstack_list("listEvents", "event", type="UPLOAD.CUSTOM.CERTIFICATE", listall="true")
    return max((datetime.strptime(e["created"], "%Y-%m-%dT%H:%M:%S%z") for e in events if e.get("created")),
               default=None)


def sync_console_certificate(now=None):
    """Makes the console proxies serve the mounted certificate. The proxies are
    observed rather than CloudStack's stored copy, which the API does not
    expose. An upload restarts the proxies and the secondary storage VMs, so a
    renewed certificate waits for the nightly window while the old one is still
    valid, a proxy that serves nothing is fixed at once, uploads are at least
    an interval apart, and nothing happens while any proxy cannot be observed."""
    try:
        with open(f"{CONSOLE_TLS_DIR}/tls.crt") as f:
            chain = pem_blocks(f.read())
        with open(f"{CONSOLE_TLS_DIR}/tls.key") as f:
            key = f.read()
    except FileNotFoundError:
        return
    if not chain:
        return
    settings = cloudstack("listConfigurations", name="consoleproxy.sslEnabled").get("configuration", [])
    if not any(s.get("name") == "consoleproxy.sslEnabled" and s.get("value") == "true" for s in settings):
        return
    proxies = [p for p in cloudstack("listSystemVms", systemvmtype="consoleproxy", state="Running").get("systemvm", [])
               if p.get("publicip")]
    if not proxies:
        return
    # a proxy is handed its keystore when its agent connects and starts serving
    # a moment later: an agent that is not up tells nothing, and an empty answer
    # is only believed when it repeats
    presented = {p["name"]: presented_certificate(p["publicip"]) if p.get("agentstate") == "Up" else None
                 for p in proxies}
    if b"" in presented.values():
        time.sleep(CONSOLE_PROBE_RETRY)
        for p in proxies:
            if presented[p["name"]] == b"":
                presented[p["name"]] = presented_certificate(p["publicip"])
    unknown = sorted(name for name, der in presented.items() if der is None)
    if unknown:
        print(f"console certificate: {unknown} cannot be observed, not compared")
        return
    leaf = ssl.PEM_cert_to_DER_cert(chain[0])
    if all(der == leaf for der in presented.values()):
        return
    now = now or datetime.now(timezone.utc)
    start, end = CONSOLE_CERT_WINDOW
    if all(presented.values()) and not start <= now.astimezone(CONSOLE_CERT_ZONE).time() < end:
        print("console certificate: renewed, replacement deferred to the window")
        return
    last = last_certificate_upload()
    if last and now - last < CONSOLE_CERT_UPLOAD_INTERVAL:
        print(f"console certificate: last upload at {last.isoformat()}, waiting")
        return
    # the chain goes in top-down, under fixed aliases so later uploads replace it;
    # each upload is stored by its job, so the next step waits for it
    for index, cert in enumerate(reversed(chain[1:]), start=1):
        wait_for_job(cloudstack("uploadCustomCertificate", post=True, certificate=cert, id=index,
                                name=f"console-chain-{index}", domainsuffix=CONSOLE_CERT_DOMAIN)["jobid"])
    wait_for_job(cloudstack("uploadCustomCertificate", post=True, certificate=chain[0], privatekey=key,
                            domainsuffix=CONSOLE_CERT_DOMAIN)["jobid"])
    restore_console_proxy_state()
    # a proxy loads the keystore when its agent connects, so a reboot brings the new one
    for p in proxies:
        cloudstack("rebootSystemVm", id=p["id"])
    print(f"console certificate: uploaded, rebooting {sorted(p['name'] for p in proxies)}")


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
        if not any(t.get("target_id") == target_id and not t.get("ended") for t in s.get("target_sessions", [])):
            continue
        if usernames is not None and s.get("username") not in usernames:
            continue
        warpgate("POST", f"/sessions/{s['id']}/close", {})
        print(f"warpgate session {s['id']} ({s.get('username')}) closed")


def sync_user_roles(user, wanted, roles):
    """Grant the wanted roles and withdraw root-administrator rights no longer
    held; returns the roles withdrawn. A revoked or expired assignment stays
    listed, inactive, and granting it again reactivates it."""
    active = {r["name"] for r in warpgate("GET", f"/users/{user['id']}/roles")[1] if r["is_active"]}
    for name in sorted(wanted - active):
        warpgate("POST", f"/users/{user['id']}/roles/{roles[name]['id']}", {})
        print(f"warpgate user {user['username']}: role {name}")
    revoked = (active & {ADMINS_ROLE}) - wanted
    for name in sorted(revoked):
        warpgate("DELETE", f"/users/{user['id']}/roles/{roles[name]['id']}")
        print(f"warpgate user {user['username']}: role {name} removed")
    return revoked


def sync_warpgate_parameters():
    current = warpgate("GET", "/parameters")[1] or {}
    drift = {k: v for k, v in WARPGATE_PARAMETERS.items() if current.get(k) != v}
    if drift:  # fields left out of the update keep their values
        warpgate("PUT", "/parameters", drift)
        print(f"warpgate parameters: {drift}")


def sync_user_policy(user):
    """The update replaces every field of the user, so the others are sent back
    as they are."""
    current = {k: v for k, v in (user.get("credential_policy") or {}).items() if v}
    if current == USER_CREDENTIAL_POLICY:
        return
    warpgate("PUT", f"/users/{user['id']}", {
        "username": user["username"], "description": user.get("description") or "",
        "credential_policy": USER_CREDENTIAL_POLICY,
        "rate_limit_bytes_per_second": user.get("rate_limit_bytes_per_second"),
        "allowed_ip_ranges": user.get("allowed_ip_ranges"),
    })
    print(f"warpgate user {user['username']}: credential policy {USER_CREDENTIAL_POLICY}")


def close_demoted_sessions(demoted, targets, reach):
    """End the sessions former root administrators (username -> own account
    role) hold on managed targets their own account does not reach."""
    for name, roles in reach.items():
        lost = {who for who, own in demoted.items() if own not in roles}
        if lost and name in targets:
            close_sessions(targets[name]["id"], lost)


def guest_accounts(vm):
    """Linux username -> account names allowed to log in as it, from the VM's tags.
    A tag value holds at most 8192 characters, so a long list continues in
    tags whose key carries a numeric suffix (name, name.1, name.2, ...); the
    username itself cannot contain a dot, so the split is unambiguous. Only
    the shape is checked: which accounts a co-owner opens is their call."""
    parts = {}  # username -> [(sequence, ids)]
    for tag in vm.get("tags", []):
        key = tag.get("key", "")
        if not key.startswith(GUEST_TAG_PREFIX):
            continue
        username, _, suffix = key[len(GUEST_TAG_PREFIX):].partition(".")
        if not USERNAME_RE.match(username) or (suffix and not suffix.isdigit()):
            print(f"vm {vm.get('name')}: tag {key} ignored: invalid username")
            continue
        ids = [part.strip().lower() for part in (tag.get("value") or "").split(",")]
        parts.setdefault(username, []).append((int(suffix) if suffix else 0, [i for i in ids if i]))
    result = {}
    for username, chunks in parts.items():
        ids = []
        for _, chunk in sorted(chunks, key=lambda c: c[0]):
            for name in chunk:
                if name not in ids:
                    ids.append(name)
        if ids:
            result[username] = ids
    return result


def render_password_script():
    """Applies a password set through CloudStack, at deployment or by a reset,
    from the config drive the hypervisor attaches. cloud-init sets the first
    one from the drive's vendor data but only once per instance, so a reset
    would never reach the account. The drive keeps the password, so the one
    applied is remembered by its hash and not applied again: a password the
    user has changed since stays. The hash is readable by root only, who can
    read the drive anyway; to anyone else it would be an offline guessing
    target. The account is cloud-init's default user."""
    return (
        "#!/bin/sh\n"
        "umask 077\n"
        "state=/var/lib/cloud/cloudstack-password.sha256\n"
        "dev=$(blkid 2>/dev/null | grep 'LABEL=\"config-2\"' | head -n 1 | cut -d: -f1)\n"
        "[ -n \"$dev\" ] || exit 0\n"
        "mnt=$(mktemp -d) || exit 0\n"
        "pw=\n"
        "if mount -o ro \"$dev\" \"$mnt\" 2>/dev/null; then\n"
        "  pw=$(cat \"$mnt/cloudstack/password/vm_password.txt\" 2>/dev/null)\n"
        "  umount \"$mnt\"\n"
        "fi\n"
        "rmdir \"$mnt\"\n"
        "[ -n \"$pw\" ] || exit 0\n"
        "sum=$(printf '%s' \"$pw\" | sha256sum | cut -d' ' -f1)\n"
        "[ \"$sum\" != \"$(cat \"$state\" 2>/dev/null)\" ] || exit 0\n"
        "user=$(python3 -c 'import yaml; print(yaml.safe_load(open(\"/etc/cloud/cloud.cfg\"))[\"system_info\"][\"default_user\"][\"name\"])' 2>/dev/null)\n"
        "[ -n \"$user\" ] || user=$(getent passwd 1000 | cut -d: -f1)\n"
        "[ -n \"$user\" ] || exit 0\n"
        "printf '%s:%s\\n' \"$user\" \"$pw\" | chpasswd && printf '%s\\n' \"$sum\" > \"$state\" && chmod 600 \"$state\"\n"
    )


def render_trust_script(public_keys):
    """First-boot script that makes every local account accept the bastion's
    key: an absolute AuthorizedKeysFile without a %u token applies to all users.
    Which accounts the bastion connects to is decided by its targets, not here.
    The password script is installed for later boots and run once now, as the
    per-boot hook has already fired on this one. It stays a shell script rather
    than a cloud-config: CloudStack appends template user data to the
    instance's own part by part and concatenates parts of one type as text,
    so a cloud-config here would override keys of a user's cloud-config."""
    keys = "\n".join(sorted(public_keys))
    # a subshell, so that set -e does not reach a script appended after this one
    return (
        "#!/bin/sh\n"
        "(\n"
        "set -e\n"
        f"cat > /etc/ssh/warpgate_keys <<'EOF'\n{keys}\nEOF\n"
        "chmod 644 /etc/ssh/warpgate_keys\n"
        "mkdir -p /etc/ssh/sshd_config.d\n"
        "if [ -f /etc/ssh/sshd_config ] && ! grep -qs '^Include /etc/ssh/sshd_config.d/' /etc/ssh/sshd_config; then sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config; fi\n"
        "printf 'AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/warpgate_keys\\n' > /etc/ssh/sshd_config.d/50-warpgate.conf\n"
        "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || rc-service sshd reload 2>/dev/null || true\n"
        f"mkdir -p {os.path.dirname(PASSWORD_SCRIPT)}\n"
        f"cat > {PASSWORD_SCRIPT} <<'EOF'\n{render_password_script()}EOF\n"
        f"chmod 755 {PASSWORD_SCRIPT}\n"
        f"{PASSWORD_SCRIPT} || true\n"
        ")\n"
    )


NETWORK_FALLBACK_PY = """\
import ipaddress, json, os, subprocess, time
from cloudinit import stages, util

init = stages.Init()
init.read_cfg()
ds = init.fetch(existing="trust")
described = getattr(ds, "network_json", "absent")
if not isinstance(described, (dict, type(None))):
    raise SystemExit
if described:
    if os.path.exists(path):
        os.remove(path)
    raise SystemExit
distro = init.distro
cfg = distro.generate_fallback_config()
if not cfg:
    raise SystemExit
try:
    addr = ipaddress.ip_address(util.mount_cb(ds.source, lambda d: open(
        os.path.join(d, "cloudstack/metadata/local-ipv4.txt")).read().strip()))
except Exception:
    addr = None
mtu = next((m for c, m in mtus.items() if addr and addr in ipaddress.ip_network(c)), None)
if mtu:
    for dev in cfg.get("ethernets", {}).values():
        dev["mtu"] = mtu
want = {"network": cfg}
try:
    with open(path) as f:
        if json.load(f) == want:
            raise SystemExit
except (OSError, ValueError):
    pass
with open(path, "w") as f:
    json.dump(want, f)


def routed(seconds):
    for _ in range(seconds):
        with open("/proc/net/route") as f:
            if any(line.split()[1:2] == ["00000000"] for line in f):
                return True
        time.sleep(1)
    return False


if distro.apply_network_config(cfg, bring_up=True) or not routed(30):
    for name in cfg.get("ethernets", {}):
        try:
            subprocess.call(["ifup", name])
        except OSError:
            pass
    routed(60)
print("network: applied cloud-init's fallback " + json.dumps(cfg))
"""


def render_network_hook(mtus):
    """Boot hook for a config drive that does not describe the network.
    cloud-init takes the empty description CloudStack writes when the drive
    serves neither DHCP nor DNS as "configure nothing" and skips its DHCP
    fallback; with no description at all, the network's MTU still reaches only
    DHCP clients that ask for it. The hook renders cloud-init's fallback with
    the MTU of the network (CIDR -> MTU) holding the drive's address, brings it
    up and keeps it in cloud-init's system configuration, which outranks the
    drive whenever the network is rendered again. cloud-init picks an
    activator by what is installed, not by its renderer, and reports neither
    a mismatch nor a failure; so when no default route follows, ifup brings
    the interface up from the rendered files. On every boot a current kept fallback is left alone, a
    stale one (a copied disk) is replaced, and it is removed once the drive
    describes the network. The interpreter runs isolated, since a directory
    in the working directory named like a module would shadow it."""
    py = f"path = {NETWORK_FALLBACK_CFG!r}\nmtus = {json.dumps(mtus, sort_keys=True)}\n" + NETWORK_FALLBACK_PY
    return (
        "#!/bin/sh\n"
        "(\n"
        "py=$(sed -n '1s/^#! *//p' \"$(command -v cloud-init)\" 2>/dev/null)\n"
        "[ -z \"$py\" ] || $py -I - <<'PY'\n"
        f"{py}"
        "PY\n"
        ")\n"
    )


def render_userdata(public_keys, mtus):
    """Template user data: the network hook as a boot hook, which cloud-init
    runs before its configuration modules and any user script, so those find
    the network up, and the trust script. The MIME boundary is fixed because
    the user data is named after a hash of its text."""
    msg = MIMEMultipart(boundary=USERDATA_BOUNDARY)
    msg.attach(MIMEText(render_network_hook(mtus), "cloud-boothook"))
    msg.attach(MIMEText(render_trust_script(public_keys), "x-shellscript"))
    return msg.as_string()


def network_mtus(networks):
    """CIDR -> MTU of the guest networks that state both; a CIDR used by
    networks with different MTUs gets the smallest, which fits all of them."""
    mtus = {}
    for n in networks:
        if n.get("cidr") and n.get("privatemtu"):
            mtus[n["cidr"]] = min(mtus.get(n["cidr"], int(n["privatemtu"])), int(n["privatemtu"]))
    return mtus


def userdata_name(script):
    return f"{USERDATA_PREFIX}-{hashlib.sha256(script.encode()).hexdigest()[:8]}"


def load_catalog(path=CATALOG_PATH):
    """Operator-provided templates: name, display text, pinned image URL and
    checksum, guest OS type, the guest's default user (what the bastion logs
    in as) and whether it is the featured pick. No file means nothing managed."""
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f).get("template", [])
    except FileNotFoundError:
        return []
    catalog = []
    for entry in raw:
        missing = [k for k in ("name", "display", "url", "checksum", "ostype", "user") if not entry.get(k)]
        if missing:
            raise ValueError(f"template {entry.get('name', '?')}: missing {missing}")
        catalog.append({**entry, "featured": bool(entry.get("featured", False))})
    return catalog


LEASE_EXPIRY_ACTIONS = ("STOP", "DESTROY")


def offering_lease(spec):
    """The lease a compute offering gives each session of its instances, from a
    catalog GPU type or the cpu_only section: createServiceOffering /
    updateServiceOffering parameters, or {} for a spec without lease_hours."""
    hours = spec.get("lease_hours")
    if hours is None:
        return {}
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 1:
        raise ValueError(f"{spec.get('name', '?')}: lease_hours must be a whole number of hours of 1 or more, not {hours!r}")
    action = spec.get("lease_expiry_action", "STOP")
    if action not in LEASE_EXPIRY_ACTIONS:
        raise ValueError(f"{spec.get('name', '?')}: lease_expiry_action must be one of {LEASE_EXPIRY_ACTIONS}, not {action!r}")
    return {"leasehours": str(hours), "leaseexpiryaction": action}


def offering_lease_update(live, spec):
    """The updateServiceOffering parameters that bring a live offering's lease to
    the spec's, in place (running instances keep theirs until their next start or
    renewal); {} when it is in step, leasehours 0 when the spec no longer has one."""
    wanted = offering_lease(spec)
    if not wanted:
        return {"leasehours": "0"} if live.get("leasehours") is not None else {}
    if live.get("leasehours") is not None and str(live["leasehours"]) == wanted["leasehours"] \
            and live.get("leaseexpiryaction", "STOP") == wanted["leaseexpiryaction"]:
        return {}
    return wanted


def sync_templates(catalog):
    """Register catalogued templates that are missing, keep their public and
    featured flags, and hide user templates that are not in the catalog.
    Returns template id -> guest user for the catalogued ones. Templates are
    never deleted here: an old one may still back a VM's reinstall."""
    def user_templates():
        return [t for t in cloudstack_list("listTemplates", "template", templatefilter="all", listall="true")
                if t.get("templatetype") == "USER"]
    templates = user_templates()
    by_name = {t["name"]: t for t in templates}
    ostypes = {o["description"]: o["id"] for o in cloudstack("listOsTypes").get("ostype", [])}
    zone = cloudstack("listZones").get("zone", [{}])[0].get("id")
    users = {}
    for entry in catalog:
        t = by_name.get(entry["name"])
        featured = "true" if entry["featured"] else "false"
        if t is None:
            if entry["ostype"] not in ostypes:
                print(f"template {entry['name']}: unknown OS type {entry['ostype']!r}, skipped")
                continue
            cloudstack("registerTemplate", name=entry["name"], displaytext=entry["display"], url=entry["url"], checksum=entry["checksum"],
                       format="QCOW2", hypervisor="KVM", zoneid=zone, ostypeid=ostypes[entry["ostype"]], passwordenabled="true",
                       requireshvm="true", isextractable="false", ispublic="true", isfeatured=featured)
            print(f"template {entry['name']} registered from {entry['url']}")
            by_name = {t["name"]: t for t in user_templates()}
            t = by_name.get(entry["name"])
        elif (bool(t.get("ispublic")), bool(t.get("isfeatured"))) != (True, entry["featured"]):
            cloudstack("updateTemplatePermissions", id=t["id"], ispublic="true", isfeatured=featured)
            print(f"template {entry['name']}: public, featured={featured}")
        if t and entry["ostype"] in ostypes and t.get("ostypeid") != ostypes[entry["ostype"]]:
            # the OS type picks the virtual hardware (virtio or IDE and e1000) of new instances
            cloudstack("updateTemplate", id=t["id"], ostypeid=ostypes[entry["ostype"]])
            print(f"template {entry['name']}: OS type {entry['ostype']}")
        if t:
            users[t["id"]] = entry["user"]
    names = {e["name"] for e in catalog}
    for t in templates:
        if t["name"] not in names and (t.get("ispublic") or t.get("isfeatured")):
            cloudstack("updateTemplatePermissions", id=t["id"], ispublic="false", isfeatured="false")
            print(f"template {t['name']}: not in the catalog, hidden")
    return users


def load_roles(path=ROLES_PATH):
    """Custom roles: name, type, description and the ordered (rule, permission)
    pairs. No file means nothing managed."""
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f).get("role", [])
    except FileNotFoundError:
        return []
    roles, seen = [], set()
    for entry in raw:
        name = entry.get("name")
        if not name or name in seen:
            raise ValueError(f"role {name!r}: missing or repeated name")
        if entry.get("type") not in ROLE_TYPES:
            raise ValueError(f"role {name}: type {entry.get('type')!r} is not one of {ROLE_TYPES}")
        rules = [tuple(r) for r in entry.get("rules", [])]
        if not rules or any(len(r) != 2 or not r[0] or r[1] not in ("allow", "deny") for r in rules):
            raise ValueError(f"role {name}: rules must be non-empty [rule, allow|deny] pairs")
        seen.add(name)
        roles.append({"name": name, "type": entry["type"], "description": entry.get("description", ""), "rules": rules})
    return roles


def role_rules(role_id):
    return [(p["rule"], p["permission"])
            for p in cloudstack("listRolePermissions", roleid=role_id).get("rolepermission", [])]


def sync_roles(catalog):
    """Create catalogued roles that are missing and re-import those whose rules
    or description drifted. importRole with forced=true replaces the rules in
    one transaction and keeps the role id, so accounts keep the role. Rule
    order decides, so the result is read back and a mismatch fails the run."""
    live = {r["name"]: r for r in cloudstack("listRoles").get("role", [])}
    for entry in catalog:
        role = live.get(entry["name"])
        if role is not None:
            if role.get("isdefault"):
                print(f"role {entry['name']}: built-in, not managed")
                continue
            if role.get("type") != entry["type"]:  # importRole would create a second role of the new type
                print(f"role {entry['name']}: type is {role.get('type')}, catalog says {entry['type']}; left alone")
                continue
            if (role.get("description") or "") == entry["description"] and role_rules(role["id"]) == entry["rules"]:
                continue
        params = {}
        for i, (rule, permission) in enumerate(entry["rules"]):
            params[f"rules[{i}].rule"] = rule
            params[f"rules[{i}].permission"] = permission
        imported = cloudstack("importRole", post=True, name=entry["name"], type=entry["type"],
                              description=entry["description"], forced="true", **params)["role"]
        if role_rules(imported["id"]) != entry["rules"]:
            raise RuntimeError(f"role {entry['name']}: rules read back in a different order")
        print(f"role {entry['name']} {'updated' if role else 'created'} ({len(entry['rules'])} rules)")


PROVIDER_NAME_RE = re.compile(r"[a-z][a-z0-9]{0,63}")
PROVIDER_REQUIRED = ("name", "label", "issuer", "username_claim", "username_pattern", "groups_claim", "allowed_groups",
                     "domain", "role")
PROVIDER_FIELDS = PROVIDER_REQUIRED + ("scopes", "authorize_params", "lowercase_username", "require_verified_email",
                                       "subject_prefix", "refusal", "jit", "end_session_url", "end_session_label",
                                       "ca_certificate", "membership_source", "enabled")
# what the job last wrote of the providers' write-only secrets, as digests keyed with its own API secret
SYNC_STATE = "cloudstack-sync-state"


def load_providers(path=PROVIDERS_PATH):
    """OpenID providers people sign in with: for each, the createOidcProvider
    parameters it is reconciled to, the domain path and role name of its
    accounts and its optional membership source. Client credentials and the
    membership source's secret come from the environment, never from the
    file. No file means nothing managed."""
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f).get("provider", [])
    except FileNotFoundError:
        return []
    providers, seen = [], set()
    for entry in raw:
        name = entry.get("name", "")
        if not isinstance(name, str) or not PROVIDER_NAME_RE.fullmatch(name) or name in seen:
            raise ValueError(f"provider {name!r}: names are unique lowercase letters and digits, starting with a letter")
        missing = [k for k in PROVIDER_REQUIRED if not entry.get(k)]
        unknown = sorted(set(entry) - set(PROVIDER_FIELDS))
        if missing or unknown:
            raise ValueError(f"provider {name}: missing {missing}, unknown {unknown}")
        if bool(entry.get("end_session_url")) != bool(entry.get("end_session_label")):
            raise ValueError(f"provider {name}: end_session_url and end_session_label go together")
        admission = {"groups_claim": entry["groups_claim"], "allowed_groups": list(entry["allowed_groups"])}
        if entry.get("subject_prefix"):
            admission["subject_prefix"] = entry["subject_prefix"]
        params = {
            "label": entry["label"],
            "issuer": entry["issuer"],
            "scopes": entry.get("scopes", "openid profile email"),
            "authorizeparams": dict(entry.get("authorize_params", {})),
            "usernameclaim": entry["username_claim"],
            "lowercaseusername": bool(entry.get("lowercase_username", False)),
            "usernamepattern": entry["username_pattern"],
            "requireverifiedemail": bool(entry.get("require_verified_email", False)),
            "admission": admission,
            "refusal": entry.get("refusal", ""),
            "jit": bool(entry.get("jit", True)),
            "endsessionurl": entry.get("end_session_url", ""),
            "endsessionlabel": entry.get("end_session_label", ""),
            "cacertificate": entry.get("ca_certificate", ""),
            "enabled": bool(entry.get("enabled", True)),
        }
        seen.add(name)
        providers.append({"name": name, "domain": entry["domain"], "role": entry["role"], "params": params,
                          "membership_source": dict(entry.get("membership_source", {}))})
    return providers


def api_value(value):
    """A provider parameter as the API takes it; an empty value removes an optional one."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":"), sort_keys=True) if value else ""
    return value


def provider_drift(live, params):
    """The parameters whose value in the detailed listing differs from the wanted one."""
    drift = {}
    for key, want in params.items():
        have = live.get(key)
        if isinstance(want, bool):
            same = (have is True) == want
        elif isinstance(want, dict):
            same = (json.loads(have) if have else {}) == want
        else:
            same = str(have or "").strip() == str(want).strip()
        if not same:
            drift[key] = want
    return drift


def secret_digest(name, kind, value):
    return hmac.new(SECRET_KEY.encode(), f"{name}\0{kind}\0{value}".encode(), hashlib.sha256).hexdigest()


def sync_state_path():
    with open(f"{SA_DIR}/namespace") as f:
        return f"/api/v1/namespaces/{f.read()}/configmaps/{SYNC_STATE}"


def sync_oidc_providers(catalog=None, env=os.environ):
    """Create catalogued OpenID providers that are missing, write back the
    parameters that drifted, and disable providers the catalog does not list:
    a provider decides who gets an account in which domain and role, so only
    the catalog (and root) define providers. Secrets are write-only: one is
    written when its provider is created, when the client changes, or when it
    differs from the digest kept of the last one written. A provider without
    client credentials in the environment is not created. The catalog is
    idps.toml's unless one is given. Returns what could not be reconciled; one
    provider's failure holds back none of the others, and a catalog that cannot
    be read fails this step only."""
    failed = []
    try:
        if catalog is None:
            catalog = load_providers(PROVIDERS_PATH)
        live = cloudstack("listOidcProviders").get("oidcprovider", [])
        if any("issuer" not in p for p in live):
            raise RuntimeError("listOidcProviders shows no configuration: the job's API key is not a root administrator's")
        live = {p["name"]: p for p in live}
        if not catalog and not live:
            return failed
        domains = {d["path"]: d["id"] for d in cloudstack_list("listDomains", "domain", listall="true")}
        roles = {}
        for r in cloudstack("listRoles").get("role", []):
            roles.setdefault(r["name"], []).append(r["id"])
        status, state = kube("GET", sync_state_path())
        if status != 200:
            raise RuntimeError(f"configmap {SYNC_STATE}: {status} {state.get('message')}")
    except (OSError, RuntimeError, ValueError, KeyError) as e:
        print(f"error: OpenID providers: {api_failure(e)}")
        return ["providers"]
    digests = dict(state.get("data") or {})
    for entry in catalog:
        name = entry["name"]
        prefix = f"OIDC_{name.upper()}_"
        client_id = (env.get(prefix + "CLIENT_ID") or "").strip()
        client_secret = (env.get(prefix + "CLIENT_SECRET") or "").strip()
        membership_secret = (env.get(prefix + "MEMBERSHIP_SECRET") or "").strip()
        keys = {"clientsecret": f"oidc.{name}.clientsecret", "membershipsecret": f"oidc.{name}.membershipsecret"}
        try:
            domainid = domains.get(entry["domain"])
            roleids = roles.get(entry["role"], [])
            if domainid is None or len(roleids) != 1:
                raise RuntimeError(f"domain {entry['domain']} or role {entry['role']} is missing or not unique")
            wanted = {**entry["params"], "domainid": domainid, "roleid": roleids[0]}
            current = live.get(name)
            if current is None:
                if not (client_id and client_secret):
                    print(f"OpenID provider {name}: no {prefix}CLIENT_ID and {prefix}CLIENT_SECRET; not created")
                    continue
                changes = {**wanted, "clientid": client_id, "clientsecret": client_secret}
            else:
                changes = provider_drift(current, wanted)
                secret_changed = digests.get(keys["clientsecret"]) != secret_digest(name, "clientsecret", client_secret)
                if client_id and client_secret and (current.get("clientid") != client_id or secret_changed):
                    changes.update(clientid=client_id, clientsecret=client_secret)
            have_source = json.loads(current["membershipsource"]) if current and current.get("membershipsource") else {}
            source = entry["membership_source"]
            if source and membership_secret:
                digest = secret_digest(name, "membershipsecret", membership_secret)
                if have_source != source or digests.get(keys["membershipsecret"]) != digest:
                    changes.update(membershipsource=source, membershipsecret=membership_secret)
            elif source and have_source != source:
                print(f"OpenID provider {name}: its membership source waits for {prefix}MEMBERSHIP_SECRET")
            elif not source and have_source:
                changes.update(membershipsource={}, membershipsecret="")
            if not changes:
                continue
            params = {k: api_value(v) for k, v in changes.items()}
            if current is None:
                cloudstack("createOidcProvider", post=True, name=name, **{k: v for k, v in params.items() if v != ""})
                print(f"OpenID provider {name} created ({entry['domain']}, {entry['role']})")
            else:
                cloudstack("updateOidcProvider", post=True, id=current["id"], **params)
                print(f"OpenID provider {name} updated: {', '.join(sorted(changes))}")
            for kind in keys:
                if changes.get(kind):
                    digests[keys[kind]] = secret_digest(name, kind, changes[kind])
                elif changes.get(kind) == "":
                    digests.pop(keys[kind], None)
        except (OSError, RuntimeError, ValueError, KeyError) as e:
            print(f"error: OpenID provider {name}: {api_failure(e)}")
            failed.append(name)
    catalogued = {entry["name"] for entry in catalog}
    for name, p in live.items():
        if name not in catalogued and p.get("enabled"):
            try:
                cloudstack("updateOidcProvider", post=True, id=p["id"], enabled="false")
                print(f"OpenID provider {name}: not in the catalog, disabled")
            except OSError as e:
                print(f"error: OpenID provider {name}: {api_failure(e)}")
                failed.append(name)
    if digests != (state.get("data") or {}):
        status, answer = kube("PUT", sync_state_path(), {**state, "data": digests})
        if status != 200:
            print(f"error: configmap {SYNC_STATE}: {status} {answer.get('message')}; the secrets are written again next run")
            failed.append(SYNC_STATE)
    return failed


def sso_providers(spec=None):
    """Parses "domain path=provider,..." (default: BASTION_SSO) into a dict."""
    providers = {}
    for item in (WARPGATE_SSO if spec is None else spec).split(","):
        if item.strip():
            path, _, provider = item.partition("=")
            if not path.strip() or not provider.strip():
                raise ValueError(f"BASTION_SSO: {item!r} is not <domain path>=<provider>")
            providers[path.strip()] = provider.strip()
    return providers


def api_failure(e):
    """A failed call as one log line; the server's error text names the parameter it refused."""
    if isinstance(e, urllib.error.HTTPError):
        return f"{e} {e.read()[:300]!r}"
    return str(e)


SETTINGS_PATH = os.environ.get("SETTINGS_CATALOG", "/opt/sync/settings.toml")
COMPUTE_CATALOG_PATH = os.environ.get("COMPUTE_CATALOG", "/opt/sync/compute-catalog.json")
SETTING_FIELDS = {"key", "scope", "target", "value", "value_env"}
# scope -> the listConfigurations / updateConfiguration parameter of its object, and how its objects are listed
SETTING_SCOPES = {
    "global": None,
    "zone": ("zoneid", "listZones", "zone", "name", {}),
    "cluster": ("clusterid", "listClusters", "cluster", "name", {}),
    "storagepool": ("storageid", "listStoragePools", "storagepool", "name", {}),
    "domain": ("domainid", "listDomains", "domain", "path", {"listall": "true"}),
    "account": ("accountid", "listAccounts", "account", "name", {"listall": "true"}),
}
# the list of host tags that carry resource limits has one source, the compute catalog
HOST_TAGS_SETTING = "resource.limit.host.tags"


def load_settings(path=SETTINGS_PATH):
    """The [[setting]] entries of settings.toml as written. No file means none."""
    try:
        with open(path, "rb") as f:
            return tomllib.load(f).get("setting", [])
    except FileNotFoundError:
        return []


def load_compute_catalog(path=COMPUTE_CATALOG_PATH):
    """The compute catalog: the GPU types and the CPU-only offering. No file means nothing managed (None)."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def resource_limit_host_tags(catalog):
    """The host tags with resource limits: the CPU-only offering's tag, which every host carries, then each GPU type's."""
    tags = [(catalog.get("cpu_only") or {}).get("tag", "cpu")]
    tags += [t["tag"] for t in catalog.get("gpu_types", []) if t["tag"] not in tags]
    return ",".join(tags)


def setting_value(value):
    """A settings.toml value as CloudStack stores it."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    raise ValueError(f"value {value!r} is not a string, number or boolean")


def same_setting_value(live, wanted):
    if (live or "") == wanted:
        return True
    try:
        return float(live) == float(wanted)
    except (TypeError, ValueError):
        return False


def checked_setting(entry, env):
    """(key, scope, target, value, environment variable or None) of a settings.toml entry; ValueError says what
    is wrong with it."""
    if not isinstance(entry, dict):
        raise ValueError("an entry is a [[setting]] table")
    unknown = sorted(set(entry) - SETTING_FIELDS)
    key, scope, target = entry.get("key"), entry.get("scope", "global"), entry.get("target")
    if unknown:
        raise ValueError(f"unknown fields {unknown}")
    if not isinstance(key, str) or not key:
        raise ValueError("no key")
    if key == HOST_TAGS_SETTING:
        raise ValueError("written from the compute catalog (the CPU tag and every GPU type's), so an entry is refused")
    if scope not in SETTING_SCOPES:
        raise ValueError(f"scope {scope!r} is not one of {', '.join(SETTING_SCOPES)}")
    if (scope == "global") != (target is None) or not (target is None or isinstance(target, str) and target):
        raise ValueError("a global setting has no target; any other names its object, or * for every one")
    if ("value" in entry) == ("value_env" in entry):
        raise ValueError("give either value or value_env")
    if "value_env" in entry:
        name = entry["value_env"]
        if not isinstance(name, str) or name not in env:
            raise ValueError(f"the environment variable {name!r} of its value is not set")
        return key, scope, target, env[name], name
    return key, scope, target, setting_value(entry["value"]), None


def setting_label(key, scope, target):
    return key if scope == "global" else f"{key} ({scope} {target})"


def management_server_starts():
    """When each running management server last started, in seconds since the epoch."""
    from datetime import datetime
    return [datetime.strptime(s["lastserverstart"], "%Y-%m-%dT%H:%M:%S%z").timestamp()
            for s in cloudstack("listManagementServers").get("managementserver", []) if s.get("state") == "Up"]


def sync_settings(settings=None, catalog=None, env=os.environ):
    """Reconcile CloudStack's settings with settings.toml, and resource.limit.host.tags with the compute catalog.
    A setting is written only where its value at its object (the global value, or a zone's, a cluster's, a
    storage pool's, a domain's or an account's; * is every object of the scope) differs. A key the running
    management server does not know is skipped, as the file may name the settings of patches not deployed yet.
    A changed key that is not dynamic is reported as restart required at every run until each running
    management server has started after the change; nothing here restarts. A value from the environment is
    never printed, and one stored encrypted is compared by the digest of what this job last wrote. The written
    keys awaiting a restart and those digests are kept in the job's state ConfigMap. The entries are
    settings.toml's and the catalog compute-catalog.json's unless given. Returns what could not be applied; one
    entry's failure holds back none of the others."""
    failed = []

    def fail(label, reason):
        print(f"error: setting {label}: {reason}")
        if label not in failed:
            failed.append(label)

    if settings is None:
        try:
            settings = load_settings(SETTINGS_PATH)
        except (OSError, ValueError) as e:
            fail("settings.toml", e)
            settings = []
    if catalog is None:
        try:
            catalog = load_compute_catalog(COMPUTE_CATALOG_PATH)
        except (OSError, ValueError) as e:
            fail(HOST_TAGS_SETTING, f"compute catalog: {e}")
    entries = []  # (key, scope, target, value, environment variable), and why the entry cannot be applied
    for entry in settings:
        try:
            entries.append((checked_setting(entry, env), None))
        except ValueError as e:
            entry = entry if isinstance(entry, dict) else {}
            entries.append(((entry.get("key") or "?", entry.get("scope", "global"), entry.get("target"), None, None), e))
    if catalog:
        try:
            entries.append(((HOST_TAGS_SETTING, "global", None, resource_limit_host_tags(catalog), None), None))
        except (AttributeError, KeyError, TypeError) as e:
            fail(HOST_TAGS_SETTING, f"compute catalog: {e!r}")
    declared = [e[:3] for e, error in entries if error is None]
    objects, listings, state, written = {}, {}, {}, {}

    def listing(param, object_id):
        if (param, object_id) not in listings:
            scoped = {param: object_id} if param else {}
            listings[param, object_id] = {c["name"]: c for c in cloudstack_list("listConfigurations", "configuration", **scoped)}
        return listings[param, object_id]

    def scope_objects(scope, target):
        param, command, key, field, params = SETTING_SCOPES[scope]
        if scope not in objects:
            objects[scope] = [(o["id"], o[field]) for o in cloudstack_list(command, key, **params)]
        named = objects[scope] if target == "*" else [o for o in objects[scope] if o[1] == target]
        if target != "*" and len(named) != 1:
            raise ValueError(f"{len(named)} {scope} objects are named {target}")
        return param, named

    def stored():
        if not state:
            status, current = kube("GET", sync_state_path())
            if status != 200:
                raise RuntimeError(f"configmap {SYNC_STATE}: {status} {current.get('message')}")
            state.update(current)
        return state.get("data") or {}

    for (key, scope, target, value, from_env), error in entries:
        label = setting_label(key, scope, target)
        if error is not None:
            fail(label, error)
            continue
        if declared.count((key, scope, target)) > 1:
            fail(label, "declared more than once in settings.toml")
            continue
        if target not in (None, "*") and (key, scope, "*") in declared:
            fail(label, f"the entry for every {scope} sets it already")
            continue
        try:
            param, targets = (None, [(None, None)]) if scope == "global" else scope_objects(scope, target)
        except (OSError, RuntimeError, ValueError, KeyError) as e:
            fail(label, api_failure(e))
            continue
        for object_id, object_name in targets:
            where = setting_label(key, scope, object_name)
            try:
                live = listing(param, object_id).get(key)
                if live is None:
                    if param is None or key not in listing(None, None):
                        print(f"setting {where}: unknown to this management server, skipped")
                        continue
                    raise ValueError(f"not a {scope} setting")
                # an encrypted value is listed encrypted anew each time
                encrypted = live.get("category") in ("Secure", "Hidden")
                if encrypted:
                    digest_key = f"setting.{key}" if param is None else f"setting.{param}.{object_id}.{key}"
                    digest = secret_digest(f"setting:{param}:{object_id}", key, value)
                    if stored().get(digest_key) == digest:
                        continue
                elif same_setting_value(live.get("value"), value):
                    continue
                cloudstack("updateConfiguration", post=True, name=key, value=value,
                           **({param: object_id} if param else {}))
                if encrypted:
                    written[digest_key] = digest
                if from_env or encrypted:
                    print(f"setting {where}: written (value from {from_env or 'settings.toml'})")
                else:
                    print(f"setting {where}: {live.get('value')!r} -> {value!r}")
                if not live.get("isdynamic", True):
                    written[f"restart.{key}"] = str(int(time.time()))
            except (OSError, RuntimeError, ValueError, KeyError) as e:
                fail(label, api_failure(e))
    try:
        data = {**stored(), **written}
        waiting = {name: int(when) for name, when in data.items() if name.startswith("restart.")}
        if waiting:
            starts = management_server_starts()
            for name, when in sorted(waiting.items()):
                if starts and min(starts) > when:
                    del data[name]
                else:
                    print(f"restart required: {name[len('restart.'):]}")
        if data != (state.get("data") or {}):
            status, answer = kube("PUT", sync_state_path(), {**state, "data": data})
            if status != 200:
                raise RuntimeError(f"configmap {SYNC_STATE}: {status} {answer.get('message')}")
    except (OSError, RuntimeError, ValueError, KeyError) as e:
        fail("settings state", f"{api_failure(e)}; what is not kept is written or reported again next run")
    return failed


OFFERING_INVARIANTS = {"storagetype": "local", "offerha": "false", "dynamicscalingenabled": "false",
                       "diskofferingstrictness": "true"}


def sync_gpu_cards(catalog):
    """Create the GPU card of each catalogued type that discovery has not created yet, so that its offerings can
    exist before a host of the type joins; createGpuCard also creates the card's passthrough profile, and
    discovery later takes both over by the card's vendor and device id. Returns the types whose card could not
    be created."""
    failed = []
    try:
        cards = {(c.get("vendorid", "").lower(), c.get("deviceid", "").lower())
                 for c in cloudstack_list("listGpuCards", "gpucard")}
    except OSError as e:
        print(f"error: GPU cards: {api_failure(e)}")
        return ["gpu cards"]
    for t in catalog.get("gpu_types", []):
        try:
            card = t["card"]
            if (card["vendor_id"].lower(), card["device_id"].lower()) in cards:
                continue
            cloudstack("createGpuCard", vendorid=card["vendor_id"], deviceid=card["device_id"],
                       vendorname=card["vendor_name"], devicename=card["device_name"], name=card["name"])
            print(f"GPU card {card['name']} created")
        except (OSError, KeyError, AttributeError) as e:
            print(f"error: GPU card of {t.get('tag')}: {api_failure(e)}")
            failed.append(str(t.get("tag")))
    return failed


def gpu_offerings(gpu_type):
    """(name, GPU count, host tags) of a GPU type's offerings: <tag>-1, keyed by the card alone, and for each
    class every count from the class's keyed_min_count (2 by default) up, keyed by the class as well; a smaller
    count is keyed by the card alone."""
    tag = gpu_type["tag"]
    offerings = [(f"{tag}-1", 1, tag)]
    for name, cls in gpu_type.get("classes", {}).items():
        keyed = cls.get("keyed_min_count", 2)
        if isinstance(keyed, bool) or not isinstance(keyed, int) or keyed < 1:
            raise ValueError(f"class {name}: keyed_min_count must be a whole number of 1 or more, not {keyed!r}")
        for n in cls.get("counts", []):
            offering = (f"{tag}-{name}-{n}", n, f"{tag},{tag}-{name}") if n >= keyed else (f"{tag}-{n}", n, tag)
            if offering not in offerings:
                offerings.append(offering)
    return offerings


def offering_properties(params):
    """What makes an offering, as strings: the createServiceOffering parameters but its name, display text and
    lease. A GPU offering's speed is left out: no host check of an instance with a vGPU profile reads it."""
    props = {k: str(v) for k, v in params.items() if k not in ("name", "displaytext", "leasehours", "leaseexpiryaction")}
    if props["customized"] == "false":
        props.pop("cpuspeed")
    props["hosttags"] = ",".join(sorted(props["hosttags"].split(",")))
    props.setdefault("vgpuprofileid", "")
    props.setdefault("gpucount", "")
    props["rootdisksize"] = "0"
    return props


def listed_offering_properties(live, keys):
    def flag(name):
        return "true" if live.get(name) else "false"
    details = live.get("serviceofferingdetails") or {}
    have = {"customized": flag("iscustomized"), "offerha": flag("offerha"),
            "dynamicscalingenabled": flag("dynamicscalingenabled"), "diskofferingstrictness": flag("diskofferingstrictness"),
            "storagetype": live.get("storagetype"), "hosttags": ",".join(sorted((live.get("hosttags") or "").split(","))),
            "rootdisksize": str(live.get("rootdisksize") or 0), "vgpuprofileid": live.get("vgpuprofileid") or "",
            "gpucount": str(live["gpucount"]) if live.get("gpucount") else "",
            **{k: str(live.get(k)) for k in ("cpuspeed", "cpunumber", "memory")},
            **{k: details.get(k) for k in ("mincpunumber", "maxcpunumber", "minmemory", "maxmemory")}}
    return {k: have.get(k) for k in keys}


def sync_offerings(catalog):
    """Create the catalogued compute offerings that are missing: the CPU-only offering of the cpu_only section
    and, for each GPU type with a unit size, the offerings of gpu_offerings(), each n units of the type with its
    card's passthrough profile. Every offering has a compute-only root whose size the user gives, local storage,
    no HA and no dynamic scaling; the CPU-only one is customized within fixed bounds at a speed the user never
    sets, the lowest of the KVM hosts, so that every host passes the speed check: a speed at or below the lowest
    is in step. CloudStack changes no offering's CPU, memory or tags in place, so a live
    offering whose properties differ is renamed <name>-v<k> and deactivated, its instances keeping it, and a new
    one is created; only the lease (the catalog's lease_hours and lease_expiry_action) is reconciled in place.
    Nothing is deleted and offerings outside the catalog are left alone. Returns what could not be reconciled."""
    failed = []
    try:
        speeds = [int(h["cpuspeed"]) for h in cloudstack_list("listHosts", "host", type="Routing") if h.get("cpuspeed")]
        if not speeds:
            raise RuntimeError("no KVM host reports its CPU speed")
        speed = min(speeds)
        live = cloudstack_list("listServiceOfferings", "serviceoffering", state="all", listall="true", isrecursive="true")
        cards = {(c.get("vendorid", "").lower(), c.get("deviceid", "").lower()): c["id"]
                 for c in cloudstack_list("listGpuCards", "gpucard")}
    except (OSError, RuntimeError, ValueError, KeyError) as e:
        print(f"error: offerings: {api_failure(e)}")
        return ["offerings"]
    wanted = []
    section = catalog.get("cpu_only")
    if section is None:
        print("error: offering cpu: the compute catalog has no cpu_only section, so there is no CPU-only offering")
        failed.append("cpu")
    else:
        try:
            wanted.append(({"name": section["name"], "displaytext": section["name"], "customized": "true",
                            "cpuspeed": speed, "mincpunumber": section["min_vcpu"], "maxcpunumber": section["max_vcpu"],
                            "minmemory": section["min_memory_mib"], "maxmemory": section["max_memory_mib"],
                            "hosttags": section["tag"], **OFFERING_INVARIANTS}, section))
        except KeyError as e:
            print(f"error: offering cpu: the cpu_only section has no {e}")
            failed.append("cpu")
    for t in catalog.get("gpu_types", []):
        tag = t["tag"]
        if t.get("unit_vcpu") is None or t.get("unit_ram_gib") is None:
            print(f"GPU type {tag}: no unit size yet, no offerings")
            continue
        try:
            card = cards.get((t["card"]["vendor_id"].lower(), t["card"]["device_id"].lower()))
            if card is None:
                raise RuntimeError("its GPU card does not exist")
            profiles = [p["id"] for p in cloudstack("listVgpuProfiles", gpucardid=card).get("vgpuprofile", [])
                        if p.get("name") == "passthrough"]
            if len(profiles) != 1:
                raise RuntimeError(f"its card has {len(profiles)} passthrough profiles")
            for name, n, hosttags in gpu_offerings(t):
                wanted.append(({"name": name, "displaytext": name, "customized": "false", "cpunumber": n * t["unit_vcpu"],
                                "cpuspeed": speed, "memory": n * t["unit_ram_gib"] * 1024, "hosttags": hosttags,
                                "vgpuprofileid": profiles[0], "gpucount": n, **OFFERING_INVARIANTS}, {**t, "name": tag}))
        except (OSError, RuntimeError, ValueError, KeyError) as e:
            print(f"error: GPU type {tag}: {api_failure(e)}")
            failed.append(tag)
    names = {o["name"] for o in live}
    # an active offering wins over an inactive one of the same name
    by_name = {o["name"]: o for o in sorted(live, key=lambda o: o.get("state") == "Active")}
    for params, lease_spec in wanted:
        name = params["name"]
        try:
            lease = offering_lease(lease_spec)
            current = by_name.get(name)
            if current is not None:
                props = offering_properties(params)
                drift = sorted(k for k, v in listed_offering_properties(current, props).items() if v != props[k]
                               and not (k == "cpuspeed" and int(current.get("cpuspeed") or 0) <= speed))
                if not drift:
                    update = offering_lease_update(current, lease_spec)
                    if update:
                        cloudstack("updateServiceOffering", id=current["id"], **update)
                        print(f"offering {name}: lease {', '.join(f'{k} {v}' for k, v in update.items())}")
                    continue
                versions = [int(m.group(1)) for n in names if (m := re.fullmatch(re.escape(name) + r"-v(\d+)", n))]
                old = f"{name}-v{max(versions, default=0) + 1}"
                cloudstack("updateServiceOffering", id=current["id"], name=old, state="Inactive")
                names.add(old)
                print(f"offering {name}: {', '.join(drift)} changed; the previous one is {old}, inactive")
            cloudstack("createServiceOffering", **params, **lease)
            print(f"offering {name} created")
        except (OSError, RuntimeError, ValueError, KeyError) as e:
            print(f"error: offering {name}: {api_failure(e)}")
            failed.append(name)
    return failed


def sync_compute_catalog(path=COMPUTE_CATALOG_PATH):
    """The GPU cards, then the compute offerings, of the compute catalog; returns what could not be reconciled."""
    try:
        catalog = load_compute_catalog(path)
    except (OSError, ValueError) as e:
        print(f"error: compute catalog: {e}")
        return ["compute catalog"]
    if catalog is None:
        return []
    return sync_gpu_cards(catalog) + sync_offerings(catalog)


def plan_targets(vms, members, user_by_template=None, guest_user=GUEST_USER, root_by_vm=None):
    """Warpgate targets a set of VMs should have, and the roles that reach each.
    One target per VM for its co-owners (the account, or every member account
    of the owning project), logging in as the template's default user, plus
    one per tagged guest account, reachable only by the tagged names. The
    target name is the VM's SSH name (its account's prefix and its visible
    name, unique across the service), or the VM name for VMs from before SSH
    names; the colon form selects the guest account. The VM's root volume id rides in the
    owner target's description: a reinstall replaces the volume, and with it
    the guest's SSH host key."""
    wanted, reach = {}, {}
    user_by_template = user_by_template or {}
    root_by_vm = root_by_vm or {}
    vms = [vm for vm in vms if any(n.get("ipaddress") for n in vm.get("nic", []))]
    holders = {}
    for vm in vms:
        holders.setdefault((vm.get("sshname") or vm["name"]).lower(), []).append(vm["id"])
    # a name two VMs claim would let one tenant's target point at the other's VM
    shared = {name: ids for name, ids in holders.items() if len(ids) > 1}
    for name, ids in sorted(shared.items()):
        print(f"warning: vms {', '.join(sorted(ids))} share the target name {name}; none of them is reachable by it")
    for vm in vms:
        ip = next(n["ipaddress"] for n in vm.get("nic", []) if n.get("ipaddress"))
        name = (vm.get("sshname") or vm["name"]).lower()
        if name in shared:
            continue
        if vm.get("projectid"):
            owners = {f"account-{a}" for a in members.get(vm["projectid"], set())}
        else:
            owners = {f"account-{vm['account']}"}

        def spec(target, username, description):
            return {
                "name": target,
                "description": description,
                "options": {"kind": "Ssh", "host": ip, "port": 22, "username": username,
                            "allow_insecure_algos": False,
                            "auth": {"kind": "PublicKey", "key_id": None}},
                # access comes from the roles reconciled here only: no ticket
                # requests, and approval if someone ever turns them on
                "ticket_requests_disabled": True,
                "ticket_require_approval": True,
                "require_approval": False,
            }

        root = f":root:{root_by_vm[vm['id']]}" if vm["id"] in root_by_vm else ""
        wanted[name] = spec(name, user_by_template.get(vm.get("templateid"), guest_user), f"{MANAGED}vm:{vm['id']}{root}")
        reach[name] = owners
        for username, ids in guest_accounts(vm).items():
            target = f"{name}:{username}"
            wanted[target] = spec(target, username, f"{MANAGED}vm:{vm['id']}:guest:{username}")
            reach[target] = {f"account-{i}" for i in ids}
    return wanted, reach


def target_identity(description):
    """The VM, and guest account, a managed target stands for: its description without the root volume."""
    return re.sub(r":root:[^:]*$", "", description or "")


def target_renames(wanted, targets):
    """Wanted target name -> the existing managed target to rename to it: the
    same VM (and guest account) under its new name. A target whose current
    name is still wanted keeps that name, and only names no target holds are
    given, so a rename never collides."""
    by_identity = {target_identity(t.get("description")): t for name, t in targets.items()
                   if name not in wanted and (t.get("description") or "").startswith(MANAGED)}
    return {name: by_identity[key] for name, spec in wanted.items()
            if name not in targets and (key := target_identity(spec["description"])) in by_identity}


def stale_known_hosts(known, targets, refreshed):
    """Warpgate pins a guest's SSH host key on first contact and refuses a
    changed one. Entries to drop: those of addresses no SSH target uses, and
    those of addresses whose instance was created or reinstalled since the
    last run (a fresh disk means fresh host keys), so the next connection
    pins the new key. Address takeover by another tenant is what the guest
    network's anti-spoofing rules prevent, not this pinning."""
    in_use = {(t["options"].get("host"), t["options"].get("port", 22))
              for t in targets if (t.get("options") or {}).get("kind") == "Ssh"}
    return [k for k in known if (k["host"], k["port"]) not in in_use or (k["host"], k["port"]) in refreshed]


def sync_warpgate():
    """Role per CloudStack account, user per enabled user of an enabled account (SSO credential =
    the user's e-mail, which sign-in keeps equal to the identity
    provider's claim, at the provider of the user's domain), target per VM plus
    one per guest account a co-owner has tagged on it. A VM is reachable by its
    account, or by every member account of the project that owns it; a guest
    target only by the tagged accounts; root administrators reach every target.
    Objects created here carry a 'cloudstack:' description and are removed when
    their source disappears."""
    providers = sso_providers()
    if not providers:  # with no mapping every user would be removed, with their keys
        raise ValueError("BASTION_SSO is empty")
    sync_warpgate_parameters()
    paths = {d["id"]: d["path"] for d in cloudstack_list("listDomains", "domain", listall="true")}
    all_accounts = cloudstack_list("listAccounts", "account", listall="true")
    # disabling or locking an account leaves its users' own state enabled
    enabled_accounts = {(a.get("domainid"), a["name"]) for a in all_accounts if a.get("state") == "enabled"}
    provider_of = {}
    users = []
    for u in cloudstack_list("listUsers", "user", listall="true"):
        if (u.get("state") != "enabled" or (u.get("domainid"), u["account"]) not in enabled_accounts
                or u["account"] in BUILTIN_ACCOUNTS or not u.get("email")):
            continue
        provider = providers.get(paths.get(u.get("domainid")))
        if provider is None:
            continue
        provider_of[u["username"]] = provider
        users.append(u)
    # usernames are unique per CloudStack domain only, Warpgate has one namespace
    names = [u["username"] for u in users]
    clashing = {n for n in names if names.count(n) > 1}
    for name in sorted(clashing):
        print(f"warning: user name {name} exists in several domains; not mirrored")
    users = [u for u in users if u["username"] not in clashing]
    # project-owned VMs are only listed when asked for explicitly
    vms = cloudstack_list("listVirtualMachines", "virtualmachine", listall="true")
    vms += cloudstack_list("listVirtualMachines", "virtualmachine", listall="true", projectid=-1)
    vms = list({vm["id"]: vm for vm in vms}.values())
    per_account, users_of_role = {}, {}
    for u in users:
        per_account.setdefault(u["account"], []).append(u["username"])
        users_of_role.setdefault(f"account-{u['account']}", set()).add(u["username"])
    for account, names in per_account.items():
        if len(names) > 1:  # roles are per account: every user of it would share access
            print(f"warning: account {account} has {len(names)} users: {sorted(names)}")
    members = {}  # project id -> member account names
    for p in cloudstack_list("listProjects", "project", listall="true"):
        members[p["id"]] = {m["account"] for m in cloudstack("listProjectAccounts", projectid=p["id"]).get("projectaccount", [])}

    user_by_template = sync_templates(load_catalog())
    volumes = cloudstack_list("listVolumes", "volume", type="ROOT", listall="true")
    volumes += cloudstack_list("listVolumes", "volume", type="ROOT", listall="true", projectid=-1)
    root_by_vm = {v["virtualmachineid"]: v["id"] for v in volumes if v.get("virtualmachineid")}
    wanted, reach = plan_targets(vms, members, user_by_template, root_by_vm=root_by_vm)
    guests = {i for vm in vms for ids in guest_accounts(vm).values() for i in ids}
    # accounts that have someone who can log in or something to log in to
    relevant = {u["account"] for u in users} | {vm["account"] for vm in vms if not vm.get("projectid")}
    relevant |= set().union(*members.values()) if members else set()
    relevant |= guests
    accounts = {a["name"]: a for a in all_accounts if a["name"] in relevant}

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
    demoted = {}
    for u in users:
        wu = wg_users.get(u["username"])
        if not wu:
            continue
        sync_user_policy(wu)
        email = u["email"]  # as the identity provider presents it: Warpgate compares verbatim
        provider = provider_of[u["username"]]
        creds = warpgate("GET", f"/users/{wu['id']}/credentials/sso")[1]
        # keep exactly one credential: the address may change, and one without a
        # provider would match the same address at every provider
        for c in creds:
            if c.get("provider") in (None, *providers.values()) and (c.get("provider"), c["email"]) != (provider, email):
                warpgate("DELETE", f"/users/{wu['id']}/credentials/sso/{c['id']}")
        if not any((c.get("provider"), c["email"]) == (provider, email) for c in creds):
            warpgate("POST", f"/users/{wu['id']}/credentials/sso", {"provider": provider, "email": email})
            print(f"warpgate user {u['username']}: sso credential {email} ({provider})")
        wanted_roles = {f"account-{u['account']}"}
        if u.get("accounttype") == 1:
            wanted_roles.add(ADMINS_ROLE)
        if sync_user_roles(wu, wanted_roles, roles):
            demoted[u["username"]] = f"account-{u['account']}"

    wg_targets = {t["name"]: t for t in warpgate("GET", "/targets")[1]}
    renames = target_renames(wanted, wg_targets)
    close_demoted_sessions(demoted, {**wg_targets, **renames}, reach)
    refreshed = set()  # (host, port) of instances created or reinstalled: their host keys are new
    for name, spec in wanted.items():
        t = wg_targets.get(name)
        renamed = renames.get(name) if t is None else None
        current = t or renamed
        owner = ":guest:" not in spec["description"]
        changed = current is not None and (current["options"].get("host") != spec["options"]["host"]
                                           or current["options"].get("username") != spec["options"]["username"]
                                           or (current.get("description") or "") != spec["description"])
        wanted_roles = {r for r in reach[name] if r in roles} | {ADMINS_ROLE}
        kept = None
        if current is not None:
            # memberships that ended go before the target points anywhere new: a name taken over by another
            # VM must never be reachable by its previous owner
            have = {r["name"]: r for r in warpgate("GET", f"/targets/{current['id']}/roles")[1]}
            for rname, r in have.items():
                if rname not in wanted_roles and (r.get("description") or "").startswith(MANAGED):
                    warpgate("DELETE", f"/targets/{current['id']}/roles/{r['id']}")
                    print(f"warpgate target {name}: role {rname} removed")
                    close_sessions(current["id"], users_of_role.get(rname, set()))
            kept = have.keys() & wanted_roles
        if renamed is not None:
            warpgate("PUT", f"/targets/{renamed['id']}", spec)
            print(f"warpgate target {renamed['name']} renamed {name}")
            if owner and changed:
                refreshed.add((spec["options"]["host"], 22))
            del wg_targets[renamed["name"]]
            t = wg_targets[name] = {**renamed, **spec}
        elif t is None:
            status, t = warpgate("POST", "/targets", spec)
            print(f"warpgate target {name} -> {spec['options']['host']} created")
            if owner:
                refreshed.add((spec["options"]["host"], 22))
        elif changed:
            warpgate("PUT", f"/targets/{t['id']}", spec)
            print(f"warpgate target {name} -> {spec['options']['host']} updated")
            if owner:
                refreshed.add((spec["options"]["host"], 22))
        if t is not None:
            if kept is None:
                kept = {r["name"] for r in warpgate("GET", f"/targets/{t['id']}/roles")[1]}
            for rname in wanted_roles - kept:
                warpgate("POST", f"/targets/{t['id']}/roles/{roles[rname]['id']}", {})
                print(f"warpgate target {name}: role {rname}")
    for name, t in wg_targets.items():
        if (t.get("description") or "").startswith(MANAGED) and name not in wanted:
            close_sessions(t["id"])
            warpgate("DELETE", f"/targets/{t['id']}")
            print(f"warpgate target {name} removed")
    known = warpgate("GET", "/ssh/known-hosts")[1] or []
    for k in stale_known_hosts(known, warpgate("GET", "/targets")[1] or [], refreshed):
        warpgate("DELETE", f"/ssh/known-hosts/{k['id']}")
        print(f"warpgate host key of {k['host']}:{k['port']} forgotten")
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
            warpgate("DELETE", f"/role/{r['id']}")  # single-role routes are singular
            print(f"warpgate role {name} removed")


def sync_template_userdata():
    """Every user template gets the managed user data appended, so a VM from
    any template reaches the network and accepts the bastion without anyone
    copying keys. A template that links some other user data is someone's
    deliberate choice and is left alone. Stale managed user data is removed
    once unlinked."""
    keys = warpgate("GET", "/ssh/own-keys")[1] or []
    public = [k["public_key"] for k in keys if k.get("is_default")] or [k["public_key"] for k in keys]
    if not public:
        print("warning: warpgate has no client keys; template user data not managed")
        return
    networks = cloudstack_list("listNetworks", "network", listall="true")
    script = render_userdata(public, network_mtus(networks))
    name = userdata_name(script)

    existing = {u["name"]: u for u in cloudstack_list("listUserData", "userdata", listall="true")}
    if name not in existing:
        cloudstack("registerUserData", post=True, name=name, userdata=base64.b64encode(script.encode()).decode())
        print(f"cloudstack user data {name} registered")
        existing = {u["name"]: u for u in cloudstack_list("listUserData", "userdata", listall="true")}
    current = existing[name]["id"]

    linked = set()
    for t in cloudstack_list("listTemplates", "template", templatefilter="all", listall="true"):
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
    prune_management_servers()
    sync_roles(load_roles())
    unreconciled = sync_oidc_providers()
    unapplied = sync_settings()
    unsynced = sync_compute_catalog()
    if WARPGATE_HOST and WARPGATE_TLS_NAME and WARPGATE_TOKEN:
        sync_warpgate()
        sync_template_userdata()
    # last: a failed upload fails the run without holding back the rest
    restore_console_proxy_state()
    sync_console_certificate()
    if unreconciled:
        raise RuntimeError(f"OpenID providers not reconciled: {', '.join(unreconciled)}")
    if unapplied:
        raise RuntimeError(f"settings not applied: {', '.join(unapplied)}")
    if unsynced:
        raise RuntimeError(f"compute catalog not reconciled: {', '.join(unsynced)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # one line per failure, exit non-zero for the Job
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
