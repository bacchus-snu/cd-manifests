"""Sign-in gate: provisions the CloudStack account of the person who is logging
in, then hands the login over to the identity provider.

CloudStack's "keycloak" OAuth provider sends the browser to an arbitrary
authorize URL. Pointed here, the gate first logs the user in itself (its own
OIDC client, so it only ever sees that user's claims), checks the group that
grants access, creates or updates the CloudStack account, and finally redirects
to the identity provider's real authorize endpoint with CloudStack's original
request. The provider already holds the session, so the code goes straight
back to CloudStack and its own login completes. Nothing here can list members.
"""

import base64
import hashlib
import hmac
import html
import http.server
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ISSUER = os.environ["OIDC_ISSUER"].rstrip("/")
CLIENT_ID = os.environ["OIDC_CLIENT_ID"].strip()
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"].strip()
EXTERNAL_URL = os.environ["EXTERNAL_URL"].rstrip("/")  # this service, as seen by browsers
API_URL = os.environ["CLOUDSTACK_API_URL"]
API_KEY = os.environ["CLOUDSTACK_API_KEY"].strip()
SECRET_KEY = os.environ["CLOUDSTACK_SECRET_KEY"].strip()
# identity provider groups that grant access, and the ones that make an
# administrator (administrators are admitted regardless of the former)
ALLOWED_GROUPS = {g for g in os.environ.get("ALLOWED_GROUPS", "").split(",") if g}
ADMIN_GROUPS = {g for g in os.environ.get("ADMIN_GROUPS", "").split(",") if g}
ROLE_USER = os.environ.get("ROLE_USER", "User")
ROLE_ADMIN = os.environ.get("ROLE_ADMIN", "Root Admin")
IDP_NAME = os.environ.get("IDP_NAME", "SNUCSE ID")
IDP_URL = os.environ.get("IDP_URL", "https://id.snucse.org")
CONTACT = os.environ.get("CONTACT", "Bacchus")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
MANAGED = "gate"  # accountdetails key marking accounts this service owns
ZERO_LIMIT_TYPES = [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16]  # every countable resource
STATE_KEY = hashlib.sha256(CLIENT_SECRET.encode()).digest()


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- CloudStack

def cloudstack(command, **params):
    params.update(command=command, response="json", apikey=API_KEY)
    query = "&".join(
        f"{k}={urllib.parse.quote(str(v), safe='-_.*')}"
        for k, v in sorted(params.items(), key=lambda kv: kv[0].lower())
    )
    digest = hmac.new(SECRET_KEY.encode(), query.lower().encode(), hashlib.sha1).digest()
    signature = urllib.parse.quote(base64.b64encode(digest).decode(), safe="")
    try:
        with urllib.request.urlopen(f"{API_URL}?{query}&signature={signature}", timeout=30) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"cloudstack {command}: {e.code} {e.read()[:300]!r}")
    return body[f"{command.lower()}response"]


class Provisioner:
    def __init__(self):
        domains = cloudstack("listDomains", level=0)["domain"]
        self.root_domain = domains[0]["id"]
        self.roles = {r["name"]: r["id"] for r in cloudstack("listRoles")["role"]}

    def ensure(self, username, email, name, admin):
        """Create or update the account named after the user. Returns a
        message for the user when the login cannot proceed, else None."""
        role = self.roles[ROLE_ADMIN if admin else ROLE_USER]
        accounts = cloudstack("listAccounts", name=username, domainid=self.root_domain, listall="true").get("account", [])
        account = accounts[0] if accounts else None
        if account is None:
            others = cloudstack("listUsers", username=username, domainid=self.root_domain, listall="true").get("user", [])
            if others:
                log(f"{username}: user exists in account {others[0]['account']}, not creating")
                return "같은 이름의 사용자가 이미 다른 계정에 있습니다. 관리자에게 문의하세요."
            cloudstack("createAccount", username=username, account=username, email=email,
                       firstname=name, lastname="-", password=secrets.token_urlsafe(24),
                       roleid=role, domainid=self.root_domain,
                       **{f"accountdetails[0].{MANAGED}": "true"})
            if not admin:
                for t in ZERO_LIMIT_TYPES:
                    try:
                        cloudstack("updateResourceLimit", resourcetype=t, max=0, account=username, domainid=self.root_domain)
                    except RuntimeError as e:
                        log(f"{username}: limit type {t}: {e}")
            log(f"{username}: account created ({'admin' if admin else 'user'})")
            return None

        details = account.get("accountdetails") or {}
        if account["state"] != "enabled":
            if details.get(MANAGED) == "true" and details.get("disabledby") == MANAGED:
                # updateAccount replaces the whole detail map: keep our marker, drop the reason
                cloudstack("updateAccount", id=account["id"], **{f"accountdetails[0].{MANAGED}": "true"})
                cloudstack("enableAccount", id=account["id"])
                log(f"{username}: account re-enabled")
            else:
                return "계정이 비활성화되어 있습니다. 관리자에게 문의하세요."
        if account.get("roleid") != role:
            cloudstack("updateAccount", id=account["id"], roleid=role)
            log(f"{username}: role -> {'admin' if admin else 'user'}")
        users = cloudstack("listUsers", account=username, domainid=self.root_domain, listall="true").get("user", [])
        user = next((u for u in users if u["username"] == username), None)
        if user is None:
            return "계정에 로그인 사용자가 없습니다. 관리자에게 문의하세요."
        if (user.get("email") or "").lower() != email.lower():
            cloudstack("updateUser", id=user["id"], email=email)
            log(f"{username}: email updated")
        return None

    def release_stale(self, username, email):
        """The identity provider verified that the address belongs to this user
        now; any other user still carrying it holds a stale value that would
        make the address match two users. Park it until that user logs in."""
        for u in cloudstack("listUsers", domainid=self.root_domain, listall="true").get("user", []):
            if u["username"] != username and (u.get("email") or "").lower() == email.lower():
                cloudstack("updateUser", id=u["id"], email=f"{u['username']}@stale.invalid")
                log(f"{u['username']}: stale email {email} released to {username}")

    def revoke(self, username):
        """The person lost the group: keep the account and its data, stop it."""
        accounts = cloudstack("listAccounts", name=username, domainid=self.root_domain, listall="true").get("account", [])
        if not accounts:
            return
        account = accounts[0]
        details = account.get("accountdetails") or {}
        if details.get(MANAGED) == "true" and account["state"] == "enabled":
            cloudstack("updateAccount", id=account["id"],
                       **{f"accountdetails[0].{MANAGED}": "true", "accountdetails[0].disabledby": MANAGED})
            cloudstack("disableAccount", id=account["id"], lock="false")
            log(f"{username}: account disabled (left the group)")


# ---------------------------------------------------------------- OIDC

def discovery():
    with urllib.request.urlopen(f"{ISSUER}/.well-known/openid-configuration", timeout=15) as resp:
        return json.load(resp)


def sign_state(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    mac = hmac.new(STATE_KEY, raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac + raw).decode().rstrip("=")


def verify_state(state):
    try:
        blob = base64.urlsafe_b64decode(state + "=" * (-len(state) % 4))
        mac, raw = blob[:32], blob[32:]
        if not hmac.compare_digest(mac, hmac.new(STATE_KEY, raw, hashlib.sha256).digest()):
            return None
        payload = json.loads(raw)
        if time.time() - payload.get("t", 0) > 600:
            return None
        return payload
    except Exception:
        return None


def exchange_code(oidc, code):
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": f"{EXTERNAL_URL}/callback",
    }).encode()
    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    req = urllib.request.Request(oidc["token_endpoint"], data=data, method="POST", headers={
        "Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        token = json.load(resp)
    req = urllib.request.Request(oidc["userinfo_endpoint"], headers={"Authorization": f"Bearer {token['access_token']}"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.load(resp)


# ---------------------------------------------------------------- HTTP

PAGE = """<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:sans-serif;max-width:40em;margin:4em auto;padding:0 1em;line-height:1.6}}</style></head>
<body><h1>{title}</h1>{body}</body></html>"""

NOT_ELIGIBLE = """<p>SNUCSE 클라우드(cloud.snucse.org)와 SSH 접속(Warpgate)은 <b>{idp}에서 컴퓨터공학부 주전공 인증을 마친 회원</b>만 쓸 수 있습니다.</p>
<ol>
<li><a href="{idp_url}">{idp}</a>에 로그인해 <b>주전공 인증</b>을 진행하세요(SNU 계정으로 학과를 확인합니다).</li>
<li>인증이 끝나면 다시 <a href="{back}">로그인</a>하세요. 첫 로그인에서 계정이 자동으로 만들어집니다.</li>
</ol>
<p>주전공이 아니지만 사용 허가가 필요하면 {contact}에 문의하세요. 허용 그룹에 추가되면 같은 방법으로 로그인할 수 있습니다.</p>"""


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "cloudstack-gate"

    def log_message(self, fmt, *args):  # one line per request on stderr
        log(f"{self.address_string()} {fmt % args}")

    def send_page(self, status, title, body):
        data = PAGE.format(title=html.escape(title), body=body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(url.query, keep_blank_values=True))
        path = url.path.rstrip("/")
        try:
            if path.endswith("/healthz"):
                self.send_page(200, "ok", "<p>ok</p>")
            elif path.endswith("/authorize"):
                self.begin_login(query)
            elif path.endswith("/callback"):
                self.complete_login(query)
            else:
                self.send_page(404, "Not found", "<p>Not found</p>")
        except Exception as e:
            log(f"error: {e!r}")
            self.send_page(500, "로그인 처리 중 오류", "<p>잠시 후 다시 시도하세요. 계속되면 관리자에게 문의하세요.</p>")

    def begin_login(self, query):
        """CloudStack sent the browser here instead of the identity provider."""
        if not query.get("client_id") or not query.get("redirect_uri"):
            self.send_page(400, "잘못된 요청", "<p>로그인 화면에서 다시 시작하세요.</p>")
            return
        state = sign_state({"q": query, "t": int(time.time()), "n": secrets.token_urlsafe(8)})
        params = urllib.parse.urlencode({
            "client_id": CLIENT_ID, "redirect_uri": f"{EXTERNAL_URL}/callback",
            "response_type": "code", "scope": "openid profile email", "state": state,
        })
        self.redirect(f"{self.server.oidc['authorization_endpoint']}?{params}")

    def complete_login(self, query):
        payload = verify_state(query.get("state", ""))
        if payload is None or "code" not in query:
            self.send_page(400, "로그인 시간이 지났습니다", "<p>로그인 화면에서 다시 시작하세요.</p>")
            return
        info = exchange_code(self.server.oidc, query["code"])
        username = (info.get("username") or "").strip()
        email = (info.get("email") or "").strip()  # kept as presented: Warpgate compares it verbatim
        groups = set(info.get("groups") or [])
        if not username or not email:
            self.send_page(500, "로그인 처리 중 오류", "<p>계정 정보를 읽지 못했습니다. 관리자에게 문의하세요.</p>")
            return
        original = urllib.parse.urlencode(payload["q"])
        if not groups & (ALLOWED_GROUPS | ADMIN_GROUPS):
            self.server.provisioner.revoke(username)
            self.send_page(403, "아직 사용할 수 없는 계정입니다", NOT_ELIGIBLE.format(
                idp=html.escape(IDP_NAME), idp_url=html.escape(IDP_URL), contact=html.escape(CONTACT),
                back=html.escape(payload["q"]["redirect_uri"].split("?")[0])))
            return
        self.server.provisioner.release_stale(username, email)
        problem = self.server.provisioner.ensure(username, email, info.get("name") or username, bool(groups & ADMIN_GROUPS))
        if problem:
            self.send_page(403, "로그인할 수 없습니다", f"<p>{html.escape(problem)}</p>")
            return
        self.redirect(f"{self.server.oidc['authorization_endpoint']}?{original}")


def main():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    server.oidc = discovery()
    server.provisioner = Provisioner()
    log(f"gate listening on {LISTEN_PORT}; allowed={sorted(ALLOWED_GROUPS)} admin={sorted(ADMIN_GROUPS)}")
    server.serve_forever()


if __name__ == "__main__":
    main()
