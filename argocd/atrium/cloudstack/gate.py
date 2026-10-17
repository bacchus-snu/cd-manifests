"""Sign-in gate: the only way into CloudStack.

Each door (gate.toml) is an OIDC identity provider together with the group that
admits people, the CloudStack domain and role their accounts get and the claim
their username comes from. The gate logs the person in at the door's provider,
creates or updates their account, gives the CloudStack user a fresh random
password, logs in to CloudStack with it and hands the session to the browser
with the cookies CloudStack's own SAML login sets. Nobody learns the password
and the next login replaces it, so every session starts with the provider's
word and the group check. Nothing here can list members: someone who leaves a
group is stopped at their next login.
"""

import base64
import hashlib
import hmac
import html
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

EXTERNAL_URL = os.environ["EXTERNAL_URL"].rstrip("/")  # this service, as seen by browsers
GATE_PATH = urllib.parse.urlsplit(EXTERNAL_URL).path.rstrip("/")
CLIENT_PATH = os.environ.get("CLIENT_PATH", "/client").rstrip("/")  # the CloudStack UI, same origin
API_URL = os.environ["CLOUDSTACK_API_URL"]
API_KEY = os.environ["CLOUDSTACK_API_KEY"].strip()
SECRET_KEY = os.environ["CLOUDSTACK_SECRET_KEY"].strip()
DOORS_PATH = os.environ.get("GATE_DOORS", "/opt/gate/gate.toml")
CONTACT = os.environ.get("CONTACT", "Bacchus")
DOCS_URL = os.environ.get("DOCS_URL", "").strip()  # user documentation; unset: not mentioned
# where the SSH bastion comes from, as the instances see it; unset: no SSH rule
SSH_SOURCE_CIDR = os.environ.get("SSH_SOURCE_CIDR", "").strip()
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
MANAGED = "gate"  # accountdetails key marking accounts this service owns
# every countable resource except projects: users create those themselves, and a
# new project starts with the (zero) global project limits
ZERO_LIMIT_TYPES = [0, 2, 3, 4, 6, 7, 8, 9, 10, 11, 16]
STATE_TTL = 600
NONCE_COOKIE = "gate_nonce"
# what the UI keeps of a session in local storage (vue-ls, prefix primate__);
# it prefers a stored session key and API list to the new session's
UI_SESSION_KEYS = ["Access-Token", "APIS", "ZONES", "CURRENT_PROJECT", "HEADER_NOTICES", "DOMAIN_STORE",
                   "MS_ID", "PASSWORD_CHANGE_REQUIRED", "SHOW_SECURITY_GROUPS"]
DOOR_DEFAULTS = {"scope": "openid profile email", "authorize_params": {}, "lowercase_username": False,
                 "require_verified_email": False, "subject_prefix": "", "zero_limits": False, "refusal": ""}
DOOR_KEYS = ("label", "issuer", "groups_claim", "allowed_groups", "username_claim", "username_pattern", "domain", "role")


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- CloudStack

def cloudstack(command, *, post=False, **params):
    params.update(command=command, response="json", apikey=API_KEY)
    query = "&".join(
        f"{k}={urllib.parse.quote(str(v), safe='-_.*')}"
        for k, v in sorted(params.items(), key=lambda kv: kv[0].lower())
    )
    digest = hmac.new(SECRET_KEY.encode(), query.lower().encode(), hashlib.sha1).digest()
    signature = urllib.parse.quote(base64.b64encode(digest).decode(), safe="")
    if post:  # passwords never go into a URL
        request = urllib.request.Request(
            API_URL, data=f"{query}&signature={signature}".encode(), method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
    else:
        request = f"{API_URL}?{query}&signature={signature}"
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"cloudstack {command}: {e.code} {e.read()[:300]!r}")
    return body[f"{command.lower()}response"]


class LoginRefused(Exception):
    pass


def cloudstack_login(username, password, domainid):
    """CloudStack's own password login: the session (login response and its
    JSESSIONID) of that user."""
    data = urllib.parse.urlencode({"command": "login", "username": username, "password": password,
                                   "domainid": domainid, "response": "json"}).encode()
    request = urllib.request.Request(API_URL, data=data, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            body = json.load(resp)
            set_cookies = resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise LoginRefused(f"{username}: {e.read()[:300]!r}")
        raise RuntimeError(f"cloudstack login: {e.code} {e.read()[:300]!r}")
    jsessionid = next((c.split(";", 1)[0].split("=", 1)[1] for c in set_cookies if c.startswith("JSESSIONID=")), None)
    if not jsessionid:
        raise RuntimeError("cloudstack login: no JSESSIONID")
    return body["loginresponse"], jsessionid


def session_cookies(login, jsessionid):
    """Set-Cookie values that make the UI take over a session started
    elsewhere, as CloudStack's SAML login does: the session key twice (readable
    by the UI, which sends it as a parameter, and HttpOnly for the API path,
    the server wanting both), the identity the UI reads from cookies, and
    isSAML, which makes the UI discover its APIs instead of waiting for its
    own login form."""
    attrs = "; Secure; SameSite=Lax"
    cookies = [
        f"JSESSIONID={jsessionid}; Path={CLIENT_PATH}; HttpOnly{attrs}",
        f"sessionkey={login['sessionkey']}; Path={CLIENT_PATH}/api; HttpOnly{attrs}",
        f"sessionkey={login['sessionkey']}; Path={CLIENT_PATH}{attrs}",
    ]
    values = [
        ("userid", login.get("userid")), ("domainid", login.get("domainid")), ("role", login.get("type")),
        ("username", login.get("username")), ("account", login.get("account")),
        ("userfullname", f"{login.get('firstname', '')} {login.get('lastname', '')}".strip()),
        ("timezone", login.get("timezone")), ("managementserverid", login.get("managementserverid")),
        ("twoFaEnabled", str(login.get("is2faenabled", "false")).lower()),
        ("twoFaProvider", login.get("providerfor2fa")), ("isSAML", "true"),
    ]
    for name, value in values:
        if value:
            cookies.append(f"{name}={urllib.parse.quote(str(value), safe='')}; Path={CLIENT_PATH}{attrs}")
    return cookies


def handoff_page():
    target = json.dumps(f"{CLIENT_PATH}/")
    keys = json.dumps(UI_SESSION_KEYS)
    return (f'<script>for (const k of {keys}) localStorage.removeItem("primate__" + k); location.replace({target});</script>'
            f'<noscript><meta http-equiv="refresh" content="0;url={html.escape(CLIENT_PATH)}/"></noscript>'
            f'<p><a href="{html.escape(CLIENT_PATH)}/">SNUCSE Cloud로 이동</a></p>')


class Provisioner:
    def __init__(self):
        self._locks = {}
        self._locks_guard = threading.Lock()

    def lock(self, key):
        with self._locks_guard:
            return self._locks.setdefault(key, threading.Lock())

    def domain_id(self, path):
        """The domain with that path ("ROOT", "ROOT/snucse"), created if missing."""
        domains = {d["path"]: d["id"] for d in cloudstack("listDomains", listall="true").get("domain", [])}
        parts = path.split("/")
        if parts[0] != "ROOT" or "ROOT" not in domains:
            raise RuntimeError(f"domain {path}: not below ROOT")
        for i in range(1, len(parts)):
            here = "/".join(parts[:i + 1])
            if here not in domains:
                cloudstack("createDomain", name=parts[i], parentdomainid=domains["/".join(parts[:i])])
                domains = {d["path"]: d["id"] for d in cloudstack("listDomains", listall="true").get("domain", [])}
                log(f"domain {here} created")
        return domains[path]

    def role_id(self, name):
        for r in cloudstack("listRoles", name=name).get("role", []):
            if r["name"] == name:
                return r["id"]
        raise RuntimeError(f"role {name}: not found")

    def ensure(self, door, domainid, username, email, name):
        """Create or update the account named after the user. Returns a
        message for the user when the login cannot proceed, else None."""
        role = self.role_id(door["role"])
        accounts = cloudstack("listAccounts", name=username, domainid=domainid, listall="true").get("account", [])
        account = next((a for a in accounts if a["name"] == username), None)
        if account is None:
            others = cloudstack("listUsers", username=username, domainid=domainid, listall="true").get("user", [])
            if any(u["username"] == username for u in others):
                log(f"{door['name']}: {username}: user exists in another account, not creating")
                return "같은 이름의 사용자가 이미 다른 계정에 있습니다. 관리자에게 문의하세요."
            cloudstack("createAccount", post=True, username=username, account=username, email=email,
                       firstname=name, lastname="-", password=secrets.token_urlsafe(32),
                       roleid=role, domainid=domainid, **{f"accountdetails[0].{MANAGED}": "true"})
            if door["zero_limits"]:
                for t in ZERO_LIMIT_TYPES:
                    try:
                        cloudstack("updateResourceLimit", resourcetype=t, max=0, account=username, domainid=domainid)
                    except RuntimeError as e:
                        log(f"{door['name']}: {username}: limit type {t}: {e}")
            log(f"{door['name']}: {username}: account created ({door['role']})")
            self.ensure_default_rules(domainid, username)
            return None

        details = account.get("accountdetails") or {}
        if account["state"] != "enabled":
            if details.get(MANAGED) == "true" and details.get("disabledby") == MANAGED:
                # updateAccount replaces the whole detail map: keep our marker, drop the reason
                cloudstack("updateAccount", id=account["id"], **{f"accountdetails[0].{MANAGED}": "true"})
                cloudstack("enableAccount", id=account["id"])
                log(f"{door['name']}: {username}: account re-enabled")
            else:
                return "계정이 비활성화되어 있습니다. 관리자에게 문의하세요."
        if account.get("roleid") != role:
            cloudstack("updateAccount", id=account["id"], roleid=role)
            log(f"{door['name']}: {username}: role -> {door['role']}")
        user = self.user(domainid, username)
        if user is None or user.get("account") != username:
            return "계정에 로그인 사용자가 없습니다. 관리자에게 문의하세요."
        if user.get("state") != "enabled":
            return "사용자가 비활성화되어 있습니다. 관리자에게 문의하세요."
        if (user.get("email") or "") != email:
            cloudstack("updateUser", id=user["id"], email=email)
            log(f"{door['name']}: {username}: email updated")
        self.ensure_default_rules(domainid, username)
        return None

    def user(self, domainid, username):
        users = cloudstack("listUsers", username=username, domainid=domainid, listall="true").get("user", [])
        return next((u for u in users if u["username"] == username), None)

    def ensure_default_rules(self, domainid, username):
        """The account's default security group is fixed policy, not user
        configuration: the SSH bastion may reach the instances, and the
        account's own instances may reach each other on any port; nothing else
        gets in. Idempotent, and never blocks the login: the group is created
        with the account, and a rule that is still missing is added at the next
        login."""
        try:
            groups = cloudstack("listSecurityGroups", account=username, domainid=domainid,
                                securitygroupname="default").get("securitygroup", [])
            if not groups:
                log(f"{username}: no default security group yet")
                return
            rules = groups[0].get("ingressrule", [])
            if SSH_SOURCE_CIDR and not any((r.get("protocol"), r.get("startport"), r.get("endport"), r.get("cidr"))
                                           == ("tcp", 22, 22, SSH_SOURCE_CIDR) for r in rules):
                cloudstack("authorizeSecurityGroupIngress", securitygroupname="default", account=username,
                           domainid=domainid, protocol="tcp", startport=22, endport=22, cidrlist=SSH_SOURCE_CIDR)
                log(f"{username}: ssh from {SSH_SOURCE_CIDR} allowed")
            if not any(r.get("protocol") == "all" and r.get("account") == username and r.get("securitygroupname") == "default"
                       for r in rules):
                cloudstack("authorizeSecurityGroupIngress", securitygroupname="default", account=username,
                           domainid=domainid, protocol="all",
                           **{"usersecuritygrouplist[0].account": username, "usersecuritygrouplist[0].group": "default"})
                log(f"{username}: traffic between own instances allowed")
        except RuntimeError as e:
            log(f"{username}: security group rules: {e}")

    def release_stale(self, domainid, username, email):
        """The identity provider verified that the address belongs to this user
        now; any other user of the domain still carrying it holds a stale value
        that would make the bastion's lookup by address ambiguous. Park it
        until that user logs in."""
        for u in cloudstack("listUsers", domainid=domainid, listall="true").get("user", []):
            if u["username"] != username and (u.get("email") or "").lower() == email.lower():
                cloudstack("updateUser", id=u["id"], email=f"{u['username']}@stale.invalid")
                log(f"{u['username']}: stale email {email} released to {username}")

    def revoke(self, domainid, username):
        """The person lost the group: keep the account and its data, stop it."""
        accounts = cloudstack("listAccounts", name=username, domainid=domainid, listall="true").get("account", [])
        account = next((a for a in accounts if a["name"] == username), None)
        if account is None:
            return
        details = account.get("accountdetails") or {}
        if details.get(MANAGED) == "true" and account["state"] == "enabled":
            cloudstack("updateAccount", id=account["id"],
                       **{f"accountdetails[0].{MANAGED}": "true", "accountdetails[0].disabledby": MANAGED})
            cloudstack("disableAccount", id=account["id"], lock="false")
            log(f"{username}: account disabled (left the group)")

    def start_session(self, domainid, username):
        """Replace the user's password with a fresh random one and log in with
        it. Another login of the same user in between replaces it again, so a
        refused login is retried once."""
        with self.lock((domainid, username)):
            for attempt in (1, 2):
                user = self.user(domainid, username)
                password = secrets.token_urlsafe(32)
                cloudstack("updateUser", post=True, id=user["id"], password=password)
                try:
                    return cloudstack_login(username, password, domainid)
                except LoginRefused:
                    if attempt == 2:
                        raise


# ---------------------------------------------------------------- OIDC

def load_doors(path=DOORS_PATH, env=os.environ):
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    doors = {}
    for name, entry in raw.items():
        if not re.fullmatch(r"[a-z][a-z0-9]*", name):
            raise ValueError(f"door {name!r}: name must be lowercase letters and digits")
        missing = [k for k in DOOR_KEYS if not entry.get(k)]
        if missing:
            raise ValueError(f"door {name}: missing {missing}")
        client_id = (env.get(f"{name.upper()}_CLIENT_ID") or "").strip()
        client_secret = (env.get(f"{name.upper()}_CLIENT_SECRET") or "").strip()
        # a door whose client is not registered yet stays closed; the others work
        doors[name] = {**DOOR_DEFAULTS, **entry, "name": name,
                       "username_re": re.compile(entry["username_pattern"]),
                       "client_id": client_id, "client_secret": client_secret,
                       "open": bool(client_id and client_secret)}
    if not doors:
        raise ValueError(f"{path}: no doors")
    return doors


class Discovery:
    """OpenID configuration per issuer, fetched on first use and again after a
    failure, so that one provider being down does not close the other doors."""

    def __init__(self):
        self._cache = {}

    def get(self, issuer):
        if issuer not in self._cache:
            with urllib.request.urlopen(f"{issuer.rstrip('/')}/.well-known/openid-configuration", timeout=15) as resp:
                self._cache[issuer] = json.load(resp)
        return self._cache[issuer]


def state_key(doors):
    return hashlib.sha256(b"\0".join(sorted(d["client_secret"].encode() for d in doors.values() if d["open"]))).digest()


def sign_state(key, payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    mac = hmac.new(key, raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac + raw).decode().rstrip("=")


def verify_state(key, state, now=None):
    try:
        blob = base64.urlsafe_b64decode(state + "=" * (-len(state) % 4))
        mac, raw = blob[:32], blob[32:]
        if not hmac.compare_digest(mac, hmac.new(key, raw, hashlib.sha256).digest()):
            return None
        payload = json.loads(raw)
        if (now or time.time()) - payload.get("t", 0) > STATE_TTL:
            return None
        return payload
    except Exception:
        return None


def jwt_claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def id_token_claims(token, issuer, audience, now=None):
    """Claims of an ID token received straight from the token endpoint over
    TLS, which stands in for the signature check (OpenID Connect Core 3.1.3.7);
    issuer, audience and expiry are still checked."""
    claims = jwt_claims(token)
    aud = claims.get("aud")
    if claims.get("iss") != issuer or audience not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError("id_token: wrong issuer or audience")
    if claims.get("exp", 0) < (now or time.time()) - 60:
        raise ValueError("id_token: expired")
    return claims


def exchange_code(door, oidc, code):
    """The person's claims: the ID token's, then the userinfo endpoint's."""
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": f"{EXTERNAL_URL}/{door['name']}/callback",
    }).encode()
    basic = base64.b64encode(f"{door['client_id']}:{door['client_secret']}".encode()).decode()
    req = urllib.request.Request(oidc["token_endpoint"], data=data, method="POST", headers={
        "Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        token = json.load(resp)
    claims = id_token_claims(token["id_token"], oidc["issuer"], door["client_id"]) if token.get("id_token") else {}
    if oidc.get("userinfo_endpoint") and token.get("access_token"):
        req = urllib.request.Request(oidc["userinfo_endpoint"], headers={"Authorization": f"Bearer {token['access_token']}"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            info = json.load(resp)
        if claims.get("sub") and info.get("sub") != claims["sub"]:
            raise ValueError("userinfo: subject differs from the ID token")
        claims.update(info)
    return claims


def identity(door, claims):
    """(username, email, display name, groups), or a message for the user."""
    username = str(claims.get(door["username_claim"]) or "").strip()
    if door["lowercase_username"]:
        username = username.lower()
    email = str(claims.get("email") or "").strip()  # kept as presented: the bastion compares it verbatim
    if not username or not email:
        return "계정 정보를 읽지 못했습니다. 관리자에게 문의하세요."
    if not door["username_re"].fullmatch(username):
        log(f"{door['name']}: refused username {username!r}")
        return "이 로그인으로 쓸 수 없는 계정 이름입니다. 관리자에게 문의하세요."
    if door["require_verified_email"] and claims.get("email_verified") is not True:
        return "확인되지 않은 이메일 주소입니다."
    if not str(claims.get("sub") or "").startswith(door["subject_prefix"]):
        log(f"{door['name']}: refused subject {claims.get('sub')!r}")
        return "이 로그인으로 쓸 수 없는 계정입니다."
    groups = claims.get(door["groups_claim"]) or []
    if isinstance(groups, str):
        groups = [groups]
    return username, email, str(claims.get("name") or username), set(groups)


# ---------------------------------------------------------------- HTTP

def request_cookie(header, name):
    """A cookie from the request's Cookie header. Parsed leniently: the
    browser also sends the UI's cookies, and one value that a strict parser
    rejects must not hide the others."""
    for part in header.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            return value
    return None


PAGE = """<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:sans-serif;max-width:40em;margin:4em auto;padding:0 1em;line-height:1.6}}
a.door{{display:block;margin:.5em 0;padding:.6em 1em;border:1px solid #1890ff;border-radius:4px;text-decoration:none;text-align:center}}</style></head>
<body><h1>{title}</h1>{body}</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "cloudstack-gate"

    def log_message(self, fmt, *args):  # one line per request on stderr, without the query (codes, state)
        log(f"{self.address_string()} {fmt % args}".replace(self.path, self.path.split("?", 1)[0]))

    def send_page(self, status, title, body, cookies=()):
        data = PAGE.format(title=html.escape(title), body=body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, url, cookies=()):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Cache-Control", "no-store")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(url.query, keep_blank_values=True))
        path = url.path.rstrip("/")
        parts = path[len(GATE_PATH):].strip("/").split("/") if path.startswith(GATE_PATH) else None
        try:
            if parts == ["healthz"]:
                self.send_page(200, "ok", "<p>ok</p>")
            elif parts == [""]:
                self.send_doors()
            elif parts and len(parts) == 2 and parts[0] in self.server.doors and parts[1] in ("login", "callback"):
                door = self.server.doors[parts[0]]
                if not door["open"]:
                    self.send_page(503, f"{door['label']} 로그인은 아직 준비 중입니다",
                                   f"<p>{html.escape(CONTACT)}에 문의하세요.</p>")
                elif parts[1] == "login":
                    self.begin_login(door)
                else:
                    self.complete_login(door, query)
            else:
                self.send_page(404, "Not found", "<p>Not found</p>")
        except Exception as e:
            log(f"error: {e!r}")
            self.send_page(500, "로그인 처리 중 오류", "<p>잠시 후 다시 시도하세요. 계속되면 관리자에게 문의하세요.</p>")

    def send_doors(self):
        links = "".join(f'<a class="door" href="{html.escape(GATE_PATH)}/{name}/login">{html.escape(d["label"])}로 로그인</a>'
                        for name, d in self.server.doors.items() if d["open"])
        self.send_page(200, "SNUCSE Cloud 로그인", links)

    def begin_login(self, door):
        oidc = self.server.discovery.get(door["issuer"])
        nonce = secrets.token_urlsafe(16)
        state = sign_state(self.server.state_key, {"d": door["name"], "n": nonce, "t": int(time.time())})
        params = urllib.parse.urlencode({
            **door["authorize_params"],
            "client_id": door["client_id"], "redirect_uri": f"{EXTERNAL_URL}/{door['name']}/callback",
            "response_type": "code", "scope": door["scope"], "state": state,
        })
        # the state is only accepted back in the browser that started the login
        cookie = f"{NONCE_COOKIE}={nonce}; Path={GATE_PATH}/{door['name']}; Max-Age={STATE_TTL}; HttpOnly; Secure; SameSite=Lax"
        self.redirect(f"{oidc['authorization_endpoint']}?{params}", [cookie])

    def complete_login(self, door, query):
        clear = f"{NONCE_COOKIE}=; Path={GATE_PATH}/{door['name']}; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
        again = f'<p><a href="{html.escape(GATE_PATH)}/{door["name"]}/login">다시 로그인</a>하세요.</p>'
        payload = verify_state(self.server.state_key, query.get("state", ""))
        nonce = request_cookie(self.headers.get("Cookie", ""), NONCE_COOKIE)
        if (payload is None or payload.get("d") != door["name"] or nonce is None
                or not hmac.compare_digest(nonce, str(payload.get("n", "")))):
            self.send_page(400, "로그인 시간이 지났습니다", again, [clear])
            return
        if "code" not in query:
            log(f"{door['name']}: provider answered {query.get('error')!r}")
            self.send_page(400, "로그인하지 않았습니다", again, [clear])
            return
        claims = exchange_code(door, self.server.discovery.get(door["issuer"]), query["code"])
        who = identity(door, claims)
        if isinstance(who, str):
            self.send_page(403, "로그인할 수 없습니다", f"<p>{html.escape(who)}</p>", [clear])
            return
        username, email, name, groups = who
        provisioner = self.server.provisioner
        domainid = provisioner.domain_id(door["domain"])
        if not groups & set(door["allowed_groups"]):
            provisioner.revoke(domainid, username)
            docs = f'<p>자세한 내용은 <a href="{html.escape(DOCS_URL)}">사용 안내</a>를 보세요.</p>' if DOCS_URL else ""
            self.send_page(403, "아직 사용할 수 없는 계정입니다",
                           door["refusal"].format(contact=html.escape(CONTACT)) + docs, [clear])
            return
        provisioner.release_stale(domainid, username, email)
        problem = provisioner.ensure(door, domainid, username, email, name)
        if problem:
            self.send_page(403, "로그인할 수 없습니다", f"<p>{html.escape(problem)}</p>", [clear])
            return
        login, jsessionid = provisioner.start_session(domainid, username)
        log(f"{door['name']}: {username}: signed in")
        self.send_page(200, "로그인 중", handoff_page(), [clear, *session_cookies(login, jsessionid)])


def main():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    server.doors = load_doors()
    server.state_key = state_key(server.doors)
    server.discovery = Discovery()
    server.provisioner = Provisioner()
    log(f"gate listening on {LISTEN_PORT}; doors: " + ", ".join(
        f"{n} ({d['allowed_groups']} -> {d['domain']}, {d['role']}{'' if d['open'] else '; closed: no client credentials'})"
        for n, d in server.doors.items()))
    server.serve_forever()


if __name__ == "__main__":
    main()
