import base64
import importlib
import io
import json
import os
import re
import time
import unittest
import urllib.error
import urllib.parse
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("EXTERNAL_URL", "https://cloud.test/gate")
os.environ.setdefault("CLOUDSTACK_API_URL", "http://cloudstack.test/client/api")
os.environ.setdefault("CLOUDSTACK_API_KEY", "k")
os.environ.setdefault("CLOUDSTACK_SECRET_KEY", "s")
gate = importlib.import_module("gate")

ENV = {"SNUCSE_CLIENT_ID": "cloudstack", "SNUCSE_CLIENT_SECRET": "s1",
       "BACCHUS_CLIENT_ID": "auth0-client", "BACCHUS_CLIENT_SECRET": "s2"}


def doors():
    return gate.load_doors(os.path.join(HERE, "gate.toml"), ENV)


def jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


class DoorsTest(unittest.TestCase):
    def test_repository_doors(self):
        d = doors()
        self.assertEqual(set(d), {"snucse", "bacchus"})
        self.assertEqual((d["snucse"]["domain"], d["snucse"]["role"], d["snucse"]["zero_limits"]),
                         ("ROOT/snucse", "SNUCSE User", True))
        self.assertEqual((d["bacchus"]["domain"], d["bacchus"]["role"], d["bacchus"]["zero_limits"]),
                         ("ROOT", "Bacchus Member", False))
        self.assertEqual(d["bacchus"]["authorize_params"], {"connection": "bacchus-workspace"})
        self.assertEqual(d["bacchus"]["client_id"], "auth0-client")
        self.assertIn("{contact}", d["snucse"]["refusal"])

    def test_username_namespaces_are_disjoint(self):
        d = doors()
        self.assertTrue(d["snucse"]["username_re"].fullmatch("baneling100"))
        self.assertFalse(d["snucse"]["username_re"].fullmatch("whnbaek@bacchus.snucse.org"))
        self.assertTrue(d["bacchus"]["username_re"].fullmatch("whnbaek@bacchus.snucse.org"))
        for name in ("baneling100", "whnbaek@gmail.com", "x@bacchus.snucse.org.evil", "x@sub.bacchus.snucse.org"):
            self.assertFalse(d["bacchus"]["username_re"].fullmatch(name), name)

    def test_door_without_client_credentials_is_closed(self):
        d = gate.load_doors(os.path.join(HERE, "gate.toml"), {"SNUCSE_CLIENT_ID": "x", "SNUCSE_CLIENT_SECRET": "y",
                                                               "BACCHUS_CLIENT_ID": " "})
        self.assertTrue(d["snucse"]["open"])
        self.assertFalse(d["bacchus"]["open"])
        self.assertEqual(gate.state_key(d), gate.state_key({"snucse": d["snucse"]}))

    def test_missing_keys_fail(self):
        path = os.path.join(self.tmp(), "g.toml")
        with open(path, "w") as f:
            f.write('[x]\nlabel = "X"\n')
        with self.assertRaises(ValueError):
            gate.load_doors(path, {"X_CLIENT_ID": "a", "X_CLIENT_SECRET": "b"})

    def tmp(self):
        import tempfile
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return d.name


class RequestCookieTest(unittest.TestCase):
    def test_lenient_parse(self):
        header = 'userfullname=A "B"; bad\\value=1; gate_nonce=abc_-1; x=y'
        self.assertEqual(gate.request_cookie(header, "gate_nonce"), "abc_-1")
        self.assertIsNone(gate.request_cookie("a=b", "gate_nonce"))
        self.assertIsNone(gate.request_cookie("", "gate_nonce"))


class StateTest(unittest.TestCase):
    def test_round_trip_tamper_and_expiry(self):
        key = gate.state_key(doors())
        state = gate.sign_state(key, {"d": "snucse", "n": "abc", "t": 1000})
        self.assertEqual(gate.verify_state(key, state, now=1100)["n"], "abc")
        self.assertIsNone(gate.verify_state(key, state, now=1000 + gate.STATE_TTL + 1))
        self.assertIsNone(gate.verify_state(b"other", state, now=1100))
        self.assertIsNone(gate.verify_state(key, state[:-2] + "AA", now=1100))
        self.assertIsNone(gate.verify_state(key, "garbage", now=1100))


class IdTokenTest(unittest.TestCase):
    def test_checks_issuer_audience_and_expiry(self):
        now = 10_000
        good = {"iss": "https://idp/", "aud": ["a", "b"], "exp": now + 60, "email": "x"}
        self.assertEqual(gate.id_token_claims(jwt(good), "https://idp/", "b", now=now)["email"], "x")
        for bad in ({**good, "iss": "https://other/"}, {**good, "aud": "c"}, {**good, "exp": now - 3600}):
            with self.assertRaises(ValueError):
                gate.id_token_claims(jwt(bad), "https://idp/", "b", now=now)


class IdentityTest(unittest.TestCase):
    def test_bacchus_email_becomes_lowercase_username(self):
        d = doors()["bacchus"]
        who = gate.identity(d, {"sub": "google-apps|WhnBaek@bacchus.snucse.org", "email": "WhnBaek@bacchus.snucse.org",
                                "email_verified": True, "name": "W",
                                "https://bacchus.io/groups": ["regular-members@bacchus.snucse.org"]})
        self.assertEqual(who, ("whnbaek@bacchus.snucse.org", "WhnBaek@bacchus.snucse.org", "W",
                               {"regular-members@bacchus.snucse.org"}))

    def test_refusals(self):
        d = doors()["bacchus"]
        self.assertIsInstance(gate.identity(d, {"sub": "google-apps|x", "email": "x@bacchus.snucse.org"}), str)  # not verified
        self.assertIsInstance(gate.identity(d, {"sub": "auth0|x", "email": "x@bacchus.snucse.org", "email_verified": True}), str)
        self.assertIsInstance(gate.identity(d, {"email": "x@gmail.com", "email_verified": True}), str)
        self.assertIsInstance(gate.identity(d, {}), str)
        s = doors()["snucse"]
        self.assertIsInstance(gate.identity(s, {"username": "a@b", "email": "a@snu.ac.kr"}), str)

    def test_snucse_groups_from_userinfo(self):
        who = gate.identity(doors()["snucse"], {"username": "alice", "email": "a@snu.ac.kr", "groups": "major"})
        self.assertEqual(who, ("alice", "a@snu.ac.kr", "alice", {"major"}))


class CookiesTest(unittest.TestCase):
    def test_session_cookies_match_the_ui(self):
        login = {"sessionkey": "k+e/y=", "userid": "u-1", "domainid": "d-1", "type": "1",
                 "username": "m@bacchus.snucse.org", "account": "m@bacchus.snucse.org",
                 "firstname": "M", "lastname": "-", "is2faenabled": "false", "managementserverid": "ms"}
        cookies = gate.session_cookies(login, "node0abc")
        by_name = {}
        for c in cookies:
            name, rest = c.split("=", 1)
            by_name.setdefault(name, []).append(rest)
        self.assertEqual(by_name["JSESSIONID"], ["node0abc; Path=/client; HttpOnly; Secure; SameSite=Lax"])
        self.assertEqual(sorted(by_name["sessionkey"]), ["k+e/y=; Path=/client/api; HttpOnly; Secure; SameSite=Lax",
                                                         "k+e/y=; Path=/client; Secure; SameSite=Lax"])
        self.assertEqual(by_name["username"], ["m%40bacchus.snucse.org; Path=/client; Secure; SameSite=Lax"])
        self.assertEqual(by_name["isSAML"][0].split(";")[0], "true")
        self.assertEqual(by_name["twoFaEnabled"][0].split(";")[0], "false")
        self.assertEqual(by_name["userfullname"][0].split(";")[0], "M%20-")
        self.assertNotIn("twoFaProvider", by_name)

    def test_handoff_page_clears_the_ui_session_cache(self):
        page = gate.handoff_page()
        self.assertIn('"Access-Token"', page)
        self.assertIn('"APIS"', page)
        self.assertIn('location.replace("/client/")', page)


class CloudStackLoginTest(unittest.TestCase):
    def test_returns_login_response_and_session_id(self):
        class Resp(io.BytesIO):
            headers = mock.Mock()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass
        resp = Resp(json.dumps({"loginresponse": {"sessionkey": "k", "userid": "u"}}).encode())
        resp.headers.get_all.return_value = ["JSESSIONID=node0x;Path=/client;HttpOnly", "sessionkey=k;HttpOnly"]
        seen = {}

        def fake_urlopen(req, timeout):
            seen["data"] = dict(urllib.parse.parse_qsl(req.data.decode()))
            seen["url"] = req.full_url
            return resp
        with mock.patch.object(gate.urllib.request, "urlopen", fake_urlopen):
            login, sid = gate.cloudstack_login("alice", "pw", "d-1")
        self.assertEqual((login["sessionkey"], sid), ("k", "node0x"))
        self.assertEqual(seen["data"], {"command": "login", "username": "alice", "password": "pw",
                                        "domainid": "d-1", "response": "json"})
        self.assertNotIn("pw", seen["url"])

    def test_refused_login(self):
        def fake_urlopen(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 401, "unauthorized", {}, io.BytesIO(b"{}"))
        with mock.patch.object(gate.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(gate.LoginRefused):
                gate.cloudstack_login("alice", "pw", "d-1")


class FakeCloudStack:
    def __init__(self):
        self.calls = []
        self.domains = [{"id": "d-root", "path": "ROOT"}]
        self.accounts = []
        self.users = []

    def __call__(self, command, post=False, **params):
        self.calls.append((command, post, params))
        if command == "listDomains":
            return {"domain": [dict(d) for d in self.domains]}
        if command == "createDomain":
            parent = next(d for d in self.domains if d["id"] == params["parentdomainid"])
            self.domains.append({"id": f"d-{params['name']}", "path": f"{parent['path']}/{params['name']}"})
            return {}
        if command == "listRoles":
            return {"role": [{"id": f"r-{params['name']}", "name": params["name"]}]}
        if command == "listAccounts":
            return {"account": [a for a in self.accounts if a["name"] == params.get("name") and a["domainid"] == params["domainid"]]}
        if command == "listUsers":
            return {"user": [u for u in self.users if u["domainid"] == params["domainid"]
                             and params.get("username") in (None, u["username"])]}
        if command == "createAccount":
            self.accounts.append({"id": f"a-{params['account']}", "name": params["account"], "domainid": params["domainid"],
                                  "state": "enabled", "roleid": params["roleid"], "accountdetails": {"gate": "true"}})
            self.users.append({"id": f"u-{params['username']}", "username": params["username"], "account": params["account"],
                               "domainid": params["domainid"], "email": params["email"], "state": "enabled"})
            return {}
        if command == "listSecurityGroups":
            return {"securitygroup": [{"ingressrule": []}]}
        return {}

    def commands(self, name):
        return [(post, p) for c, post, p in self.calls if c == name]


class ProvisionerTest(unittest.TestCase):
    def setUp(self):
        self.cs = FakeCloudStack()
        p = mock.patch.object(gate, "cloudstack", self.cs)
        p.start()
        self.addCleanup(p.stop)
        self.prov = gate.Provisioner()

    def test_creates_missing_domain_once(self):
        self.assertEqual(self.prov.domain_id("ROOT/snucse"), "d-snucse")
        self.assertEqual(self.prov.domain_id("ROOT/snucse"), "d-snucse")
        self.assertEqual(len(self.cs.commands("createDomain")), 1)
        self.assertEqual(self.prov.domain_id("ROOT"), "d-root")

    def test_student_account_gets_zero_limits_and_the_role(self):
        d = doors()["snucse"]
        self.assertIsNone(self.prov.ensure(d, "d-snucse", "alice", "a@snu.ac.kr", "Alice"))
        ((post, created),) = self.cs.commands("createAccount")
        self.assertTrue(post)  # the initial password stays out of the URL
        self.assertEqual((created["roleid"], created["domainid"]), ("r-SNUCSE User", "d-snucse"))
        self.assertEqual(len(self.cs.commands("updateResourceLimit")), len(gate.ZERO_LIMIT_TYPES))

    def test_member_account_has_no_zero_limits(self):
        d = doors()["bacchus"]
        self.assertIsNone(self.prov.ensure(d, "d-root", "m@bacchus.snucse.org", "m@bacchus.snucse.org", "M"))
        self.assertEqual(self.cs.commands("createAccount")[0][1]["roleid"], "r-Bacchus Member")
        self.assertEqual(self.cs.commands("updateResourceLimit"), [])

    def test_disabled_user_is_refused(self):
        d = doors()["snucse"]
        self.prov.ensure(d, "d-snucse", "alice", "a@snu.ac.kr", "Alice")
        self.cs.users[0]["state"] = "disabled"
        self.assertIsInstance(self.prov.ensure(d, "d-snucse", "alice", "a@snu.ac.kr", "Alice"), str)

    def test_start_session_sets_a_fresh_password_and_retries_once(self):
        self.prov.ensure(doors()["snucse"], "d-snucse", "alice", "a@snu.ac.kr", "Alice")
        attempts = []

        def fake_login(username, password, domainid):
            attempts.append(password)
            if len(attempts) == 1:
                raise gate.LoginRefused("raced")
            return {"sessionkey": "k"}, "sid"
        with mock.patch.object(gate, "cloudstack_login", fake_login):
            self.assertEqual(self.prov.start_session("d-snucse", "alice"), ({"sessionkey": "k"}, "sid"))
        updates = self.cs.commands("updateUser")
        self.assertEqual([p["password"] for _, p in updates], attempts)
        self.assertTrue(all(post for post, _ in updates))
        self.assertNotEqual(attempts[0], attempts[1])
        self.assertGreaterEqual(len(attempts[0]), 40)

    def test_revoke_disables_only_gate_accounts(self):
        self.prov.ensure(doors()["snucse"], "d-snucse", "alice", "a@snu.ac.kr", "Alice")
        self.prov.revoke("d-snucse", "alice")
        self.assertEqual(len(self.cs.commands("disableAccount")), 1)
        self.cs.accounts[0]["accountdetails"] = {}
        self.cs.accounts[0]["state"] = "enabled"
        self.prov.revoke("d-snucse", "alice")
        self.assertEqual(len(self.cs.commands("disableAccount")), 1)


class HandlerTest(unittest.TestCase):
    """The HTTP flow, driven without a socket."""

    def setUp(self):
        self.server = mock.Mock()
        self.server.doors = doors()
        self.server.state_key = gate.state_key(self.server.doors)
        self.server.discovery.get.return_value = {
            "issuer": "https://idp/", "authorization_endpoint": "https://idp/authorize", "token_endpoint": "https://idp/token"}
        self.prov = self.server.provisioner
        self.prov.domain_id.return_value = "d-root"
        self.prov.ensure.return_value = None
        self.prov.start_session.return_value = ({"sessionkey": "k", "userid": "u"}, "sid")

    def request(self, path, cookie=""):
        h = gate.Handler.__new__(gate.Handler)
        h.server, h.path, h.wfile = self.server, path, io.BytesIO()
        h.headers = {"Cookie": cookie}
        h.request_version, h.requestline, h.command, h.client_address = "HTTP/1.1", f"GET {path} HTTP/1.1", "GET", ("1.2.3.4", 1)
        with mock.patch.object(gate, "log"):
            h.do_GET()
        raw = h.wfile.getvalue().decode()
        head, _, body = raw.partition("\r\n\r\n")
        lines = head.split("\r\n")
        status = int(lines[0].split()[1])
        headers = [tuple(line.split(": ", 1)) for line in lines[1:]]
        return status, headers, body

    def begin(self, door):
        status, headers, _ = self.request(f"/gate/{door}/login")
        self.assertEqual(status, 302)
        location = urllib.parse.urlsplit(dict(headers)["Location"])
        params = dict(urllib.parse.parse_qsl(location.query))
        nonce = next(v for k, v in headers if k == "Set-Cookie").split(";")[0]
        return params, nonce

    def test_login_starts_at_the_door_provider(self):
        params, nonce = self.begin("bacchus")
        self.assertEqual(params["connection"], "bacchus-workspace")
        self.assertEqual(params["client_id"], "auth0-client")
        self.assertEqual(params["redirect_uri"], "https://cloud.test/gate/bacchus/callback")
        self.assertTrue(nonce.startswith("gate_nonce="))

    def callback(self, door, claims, with_cookie=True):
        params, nonce = self.begin(door)
        with mock.patch.object(gate, "exchange_code", return_value=claims):
            return self.request(f"/gate/{door}/callback?code=c&state={urllib.parse.quote(params['state'])}",
                                cookie=nonce if with_cookie else "")

    MEMBER = {"sub": "google-apps|m@bacchus.snucse.org", "email": "m@bacchus.snucse.org", "email_verified": True,
              "https://bacchus.io/groups": ["regular-members@bacchus.snucse.org"]}

    def test_member_gets_a_session(self):
        status, headers, body = self.callback("bacchus", self.MEMBER)
        self.assertEqual(status, 200)
        cookies = [v for k, v in headers if k == "Set-Cookie"]
        self.assertTrue(any(c.startswith("JSESSIONID=sid;") for c in cookies))
        self.assertTrue(any(c.startswith("gate_nonce=;") and "Max-Age=0" in c for c in cookies))
        self.assertIn("location.replace", body)
        self.prov.ensure.assert_called_once()
        self.assertEqual(self.prov.ensure.call_args.args[2:4], ("m@bacchus.snucse.org", "m@bacchus.snucse.org"))
        self.prov.start_session.assert_called_once_with("d-root", "m@bacchus.snucse.org")

    def test_callback_from_another_browser_is_refused(self):
        status, _, _ = self.callback("bacchus", self.MEMBER, with_cookie=False)
        self.assertEqual(status, 400)
        self.prov.start_session.assert_not_called()

    def test_state_of_another_door_is_refused(self):
        params, nonce = self.begin("snucse")
        with mock.patch.object(gate, "exchange_code", return_value=self.MEMBER):
            status, _, _ = self.request(f"/gate/bacchus/callback?code=c&state={urllib.parse.quote(params['state'])}", cookie=nonce)
        self.assertEqual(status, 400)

    def test_outside_the_group_is_revoked_and_refused(self):
        status, _, body = self.callback("bacchus", {**self.MEMBER, "https://bacchus.io/groups": ["alumni-members@bacchus.snucse.org"]})
        self.assertEqual(status, 403)
        self.prov.revoke.assert_called_once_with("d-root", "m@bacchus.snucse.org")
        self.prov.start_session.assert_not_called()
        self.assertIn("정회원", body)

    def test_closed_door_says_so(self):
        self.server.doors["bacchus"]["open"] = False
        status, _, body = self.request("/gate/bacchus/login")
        self.assertEqual(status, 503)
        self.assertIn("준비 중", body)
        self.assertEqual(self.request("/gate/bacchus/callback?code=c&state=s")[0], 503)
        self.assertNotIn("/gate/bacchus/login", self.request("/gate/")[2])
        self.assertEqual(self.begin("snucse")[0]["client_id"], "cloudstack")

    def test_unknown_paths(self):
        self.assertEqual(self.request("/gate/nope/login")[0], 404)
        self.assertEqual(self.request("/gate/authorize")[0], 404)
        self.assertEqual(self.request("/gate/healthz")[0], 200)
        status, _, body = self.request("/gate/")
        self.assertEqual(status, 200)
        self.assertIn("/gate/bacchus/login", body)


if __name__ == "__main__":
    unittest.main()
