"""Tests for sign-in, sessions, the update check and version ordering.

Run with:  python -m unittest discover -s tests -v     (stdlib only)
The server tests start the real request handler on a random local port.
"""
import http.client
import importlib.util
import json
import os
import pathlib
import shutil
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gitmirror", ROOT / "gitmirror.py")
gm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gm)
# the page templates get their stylesheet inserted when the program starts; do the same here
for _name in ("PAGE", "ADMIN", "REPO", "MAINT", "SOURCES", "EVENTS", "LOGIN", "SETUP"):
    setattr(gm, _name, getattr(gm, _name).replace("<style>__STYLE__</style>", "<style>" + gm.STYLE + "</style>"))


class PasswordTests(unittest.TestCase):
    def test_round_trip_and_wrong_password(self):
        h = gm.hash_password("correct horse")
        self.assertTrue(h.startswith("scrypt$"))
        self.assertNotIn("correct horse", h)
        self.assertTrue(gm.verify_password("correct horse", h))
        self.assertFalse(gm.verify_password("correct horsf", h))
        self.assertNotEqual(h, gm.hash_password("correct horse"))  # fresh salt every time

    def test_damaged_or_hostile_hashes_never_pass_or_crash(self):
        good = gm.hash_password("pw-pw-pw-pw")
        for bad in ("", "x", "scrypt$1$2", "md5$1$1$1$AA==$AA==", good.replace("$32768$", "$99999999$"), good[:-6], None):
            with self.subTest(bad=bad):
                self.assertFalse(gm.verify_password("pw-pw-pw-pw", bad))

    def test_credential_rules(self):
        gm.check_new_credentials("ed", "12345678")
        gm.check_new_credentials("Ed.K_1@home", "x" * 256)
        for name, pw in (("", "12345678"), ("a b", "12345678"), ("x" * 65, "12345678"), ("ed", "1234567"), ("ed", "x" * 257), (None, "12345678"), ("ed", None)):
            with self.subTest(name=name, pw=pw):
                self.assertRaises(ValueError, gm.check_new_credentials, name, pw)


class ThrottleTests(unittest.TestCase):
    def setUp(self):
        gm.LOGIN_FAILS.clear()

    def test_blocks_after_too_many_failures_then_recovers(self):
        for _ in range(gm.LOGIN_MAX - 1):
            gm.login_failed("1.2.3.4")
        self.assertEqual(gm.login_wait("1.2.3.4"), 0)
        gm.login_failed("1.2.3.4")
        self.assertGreater(gm.login_wait("1.2.3.4"), 0)
        self.assertEqual(gm.login_wait("5.6.7.8"), 0)  # another address is unaffected
        gm.LOGIN_FAILS["1.2.3.4"] = [time.time() - gm.LOGIN_WINDOW - 5] * 20  # old failures expire
        self.assertEqual(gm.login_wait("1.2.3.4"), 0)


class VersionTests(unittest.TestCase):
    def test_semver_ordering(self):
        order = ["0.0.1-alpha", "0.0.1-beta", "0.0.1-beta.2", "0.0.1-beta.11", "0.0.1-rc.1", "0.0.1", "0.0.2-beta", "0.1.0", "1.0.0", "v1.0.1"]
        keys = [gm.version_key(v) for v in order]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), len(keys))

    def test_unparseable_versions(self):
        for bad in ("", "latest", "1.2", "sha-abc1234", "v1.2.x", None):
            self.assertIsNone(gm.version_key(bad))

    def test_latest_release_ignores_noise(self):
        self.assertEqual(gm.latest_release(["v0.0.1-beta", "v0.0.10", "v0.0.9", "junk", "latest"]), "0.0.10")
        self.assertEqual(gm.latest_release(["v1.0.0-rc.1", "v1.0.0"]), "1.0.0")
        self.assertIsNone(gm.latest_release(["junk"]))
        self.assertIsNone(gm.latest_release([]))


class Base(unittest.TestCase):
    """A real server on a random port, with its own data folder."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gitmirror-auth-")
        self.old = (gm.API_TOKEN, gm.Handler.store)
        gm.API_TOKEN = "setup-code"
        gm.LOGIN_FAILS.clear()
        self.start()

    def start(self):
        self.store = gm.Store(self.tmp)
        gm.Handler.store = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), gm.Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def tearDown(self):
        self.stop()
        gm.API_TOKEN, gm.Handler.store = self.old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def req(self, method, path, body=None, cookie=None, headers=None):
        h = dict(headers or {})
        data = None
        if body is not None:
            data, h["Content-Type"] = json.dumps(body), "application/json"
        if cookie:
            h["Cookie"] = "gm_session=" + cookie
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw.decode(errors="replace")
        return r.status, r, parsed

    @staticmethod
    def session_of(resp):
        for k, v in resp.getheaders():
            if k.lower() == "set-cookie" and v.startswith("gm_session="):
                return v.split(";")[0].split("=", 1)[1]
        return None

    def make_account(self, user="ed", pw="correct horse"):
        self.store.auth = {"user": user, "hash": gm.hash_password(pw), "created": time.time()}
        self.store.save_auth()

    def login(self, user="ed", pw="correct horse"):
        status, resp, _ = self.req("POST", "/api/auth/login", {"username": user, "password": pw})
        self.assertEqual(status, 200)
        return self.session_of(resp)


class SetupTests(Base):
    def test_before_an_account_exists(self):
        status, resp, _ = self.req("GET", "/")
        self.assertEqual((status, resp.getheader("Location")), (302, "/setup"))
        self.assertEqual(self.req("GET", "/login")[1].getheader("Location"), "/setup")
        self.assertEqual(self.req("GET", "/setup")[0], 200)
        status, _, body = self.req("GET", "/api/stats")
        self.assertEqual((status, body["setup_required"]), (401, True))
        self.assertEqual(self.req("GET", "/api/auth/status")[2], {"setup_required": True, "setup_code_required": True})

    def test_setup_needs_the_code_and_a_decent_password(self):
        ok = {"username": "ed", "password": "correct horse", "setup_code": "setup-code"}
        self.assertEqual(self.req("POST", "/api/auth/setup", dict(ok, setup_code="nope"))[0], 403)
        self.assertEqual(self.req("POST", "/api/auth/setup", dict(ok, password="short"))[0], 400)
        self.assertEqual(self.req("POST", "/api/auth/setup", dict(ok, username="a b"))[0], 400)
        self.assertEqual(self.store.auth, {})

    def test_setup_creates_account_and_signs_in(self):
        status, resp, _ = self.req("POST", "/api/auth/setup", {"username": "ed", "password": "correct horse", "setup_code": "setup-code"})
        self.assertEqual(status, 200)
        cookie = next(v for k, v in resp.getheaders() if k.lower() == "set-cookie")
        for part in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(part, cookie)
        tok = self.session_of(resp)
        self.assertEqual(self.req("GET", "/api/auth/me", cookie=tok)[2]["user"], "ed")
        self.assertEqual(self.req("GET", "/", cookie=tok)[0], 200)
        # the password is only ever stored hashed, and both files are private to the owner
        with open(self.store.auth_path) as f:
            self.assertNotIn("correct horse", f.read())
        if os.name == "posix":
            for f in (self.store.auth_path, self.store.sessions_path):
                self.assertEqual(os.stat(f).st_mode & 0o077, 0)
        # setup is closed once an account exists
        self.assertEqual(self.req("POST", "/api/auth/setup", {"username": "x", "password": "another one", "setup_code": "setup-code"})[0], 403)
        self.assertEqual(self.req("GET", "/setup")[1].getheader("Location"), "/login")

    def test_no_setup_code_is_asked_for_when_no_token_is_configured(self):
        gm.API_TOKEN = ""
        self.assertFalse(self.req("GET", "/api/auth/status")[2]["setup_code_required"])
        self.assertEqual(self.req("POST", "/api/auth/setup", {"username": "ed", "password": "correct horse"})[0], 200)


class SignInTests(Base):
    def setUp(self):
        super().setUp()
        self.make_account()

    def test_login_rules(self):
        self.assertEqual(self.req("POST", "/api/auth/login", {"username": "ed", "password": "wrong wrong"})[0], 401)
        self.assertEqual(self.req("POST", "/api/auth/login", {"username": "zed", "password": "correct horse"})[0], 401)
        self.assertEqual(self.req("POST", "/api/auth/login", {"username": ["ed"], "password": 5})[0], 401)
        self.assertTrue(self.login("ED"))  # user names ignore case

    def test_everything_else_needs_a_session(self):
        self.assertEqual(self.req("GET", "/api/stats")[0], 401)
        self.assertEqual(self.req("GET", "/")[1].getheader("Location"), "/login")
        self.assertEqual(self.req("GET", "/api/stats", cookie="A" * 43)[0], 401)  # forged cookie
        self.assertEqual(self.req("GET", "/healthz")[0], 200)  # health checks stay open
        self.assertEqual(self.req("GET", "/healthz")[2]["version"], gm.__version__)

    def test_bearer_token_for_scripts_but_not_in_the_url(self):
        self.assertEqual(self.req("GET", "/api/stats", headers={"Authorization": "Bearer setup-code"})[0], 200)
        self.assertEqual(self.req("GET", "/api/stats", headers={"Authorization": "Bearer nope"})[0], 401)
        self.assertEqual(self.req("GET", "/api/stats?token=setup-code")[0], 401)
        gm.API_TOKEN = ""
        self.assertEqual(self.req("GET", "/api/stats", headers={"Authorization": "Bearer "})[0], 401)  # no token configured: nothing matches

    def test_repeated_failures_are_throttled(self):
        codes = [self.req("POST", "/api/auth/login", {"username": "ed", "password": "wrong wrong"})[0] for _ in range(gm.LOGIN_MAX + 2)]
        self.assertEqual(codes[:gm.LOGIN_MAX], [401] * gm.LOGIN_MAX)
        self.assertEqual(codes[gm.LOGIN_MAX:], [429, 429])
        status, resp, _ = self.req("POST", "/api/auth/login", {"username": "ed", "password": "correct horse"})
        self.assertEqual(status, 429)  # even the right password has to wait
        self.assertTrue(resp.getheader("Retry-After"))

    def test_logout_ends_only_that_session(self):
        a, b = self.login(), self.login()
        self.assertEqual(self.req("POST", "/api/auth/logout", {}, cookie=a)[0], 200)
        self.assertEqual(self.req("GET", "/api/stats", cookie=a)[0], 401)
        self.assertEqual(self.req("GET", "/api/stats", cookie=b)[0], 200)

    def test_sessions_survive_a_restart_and_expire(self):
        tok = self.login()
        self.stop()
        self.start()  # a new process reading the same data folder
        self.assertEqual(self.req("GET", "/api/stats", cookie=tok)[0], 200)
        for s in self.store.sessions.values():
            s["exp"] = time.time() - 1
        self.assertEqual(self.req("GET", "/api/stats", cookie=tok)[0], 401)

    def test_change_password(self):
        a, b = self.login(), self.login()
        self.assertEqual(self.req("POST", "/api/auth/password", {"current": "wrong wrong", "new": "brand new pass"}, cookie=a)[0], 403)
        self.assertEqual(self.req("POST", "/api/auth/password", {"current": "correct horse", "new": "short"}, cookie=a)[0], 400)
        self.assertEqual(self.req("POST", "/api/auth/password", {"current": "correct horse", "new": "brand new pass"},
                                  headers={"Authorization": "Bearer setup-code"})[0], 403)  # not with the script token
        status, resp, _ = self.req("POST", "/api/auth/password", {"current": "correct horse", "new": "brand new pass"}, cookie=a)
        self.assertEqual(status, 200)
        fresh = self.session_of(resp)
        self.assertEqual(self.req("GET", "/api/stats", cookie=fresh)[0], 200)
        self.assertEqual(self.req("GET", "/api/stats", cookie=a)[0], 401)  # every older session is gone
        self.assertEqual(self.req("GET", "/api/stats", cookie=b)[0], 401)
        self.assertEqual(self.req("POST", "/api/auth/login", {"username": "ed", "password": "correct horse"})[0], 401)
        self.assertTrue(self.login(pw="brand new pass"))

    def test_cross_site_requests_with_a_valid_cookie_are_refused(self):
        tok = self.login()
        body = {}
        self.assertEqual(self.req("POST", "/api/maintenance/verify", body, cookie=tok, headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/maintenance/verify", body, cookie=tok, headers={"Origin": "null"})[0], 403)
        self.assertEqual(self.req("POST", "/api/maintenance/verify", body, cookie=tok, headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)  # a plain HTML form post
        c.request("POST", "/api/maintenance/verify", body="a=b", headers={"Cookie": "gm_session=" + tok, "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(c.getresponse().status, 415)

    def test_pages_carry_safe_headers_and_the_title_links_to_github(self):
        tok = self.login()
        status, resp, html = self.req("GET", "/", cookie=tok)
        self.assertEqual(status, 200)
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        self.assertIn(f'href="{gm.REPO_URL}"', html)
        self.assertNotIn("?token=", html)


class UpdateCheckTests(Base):
    def setUp(self):
        super().setUp()
        self.make_account()
        self.tok = self.login()
        self.store.settings["update_check"] = True
        os.environ.pop("GITMIRROR_UPDATE_CHECK", None)

    def test_reports_up_to_date_and_update_available(self):
        self.store.update_info = {"checked": time.time(), "latest": gm.__version__, "error": ""}
        v = self.req("GET", "/api/version", cookie=self.tok)[2]
        self.assertEqual((v["version"], v["enabled"], v["update_available"]), (gm.__version__, True, False))
        self.store.update_info = {"checked": time.time(), "latest": "99.0.0", "error": ""}
        v = self.req("GET", "/api/version", cookie=self.tok)[2]
        self.assertTrue(v["update_available"])
        self.assertTrue(v["url"].endswith("/releases/tag/v99.0.0"))

    def test_a_pre_release_counts_as_older_than_its_release(self):
        old, gm.__version__ = gm.__version__, "1.0.0-beta"
        try:
            self.store.update_info = {"checked": time.time(), "latest": "1.0.0", "error": ""}
            self.assertTrue(self.req("GET", "/api/version", cookie=self.tok)[2]["update_available"])
        finally:
            gm.__version__ = old

    def test_can_be_switched_off(self):
        self.store.settings["update_check"] = False
        v = self.req("GET", "/api/version", cookie=self.tok)[2]
        self.assertEqual((v["enabled"], v["version"]), (False, gm.__version__))
        self.assertNotIn("latest", v)
        self.store.settings["update_check"] = True
        os.environ["GITMIRROR_UPDATE_CHECK"] = "0"
        try:
            self.assertFalse(self.req("GET", "/api/version", cookie=self.tok)[2]["enabled"])
        finally:
            os.environ.pop("GITMIRROR_UPDATE_CHECK", None)


if __name__ == "__main__":
    unittest.main()
