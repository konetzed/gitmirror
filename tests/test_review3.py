"""Tests for the fixes from the v0.0.3-beta review: outbound request policy, separate Bearer throttling, malformed-request
handling, the Server header, fast tag cleaning, settings visibility, file:// gating and the API-key touch."""
import http.server
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error

from test_auth import Base, gm


class _Tiny(http.server.BaseHTTPRequestHandler):
    """A local server whose every response is decided by the test: (status, headers, body)."""
    plan = {}
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        _Tiny.seen.append((self.path, dict(self.headers)))
        code, headers, body = self.plan.get(self.path, (404, {}, b"no"))
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Tiny)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class OutboundPolicyTests(unittest.TestCase):
    def setUp(self):
        self.old = gm.ALLOW_LOCAL_HOSTS
        gm.ALLOW_LOCAL_HOSTS = False
        _Tiny.plan, _Tiny.seen = {}, []

    def tearDown(self):
        gm.ALLOW_LOCAL_HOSTS = self.old

    def test_local_addresses_are_always_refused(self):
        for host in ("127.0.0.1", "localhost", "::1", "169.254.169.254", "0.0.0.0", "::ffff:127.0.0.1"):
            with self.subTest(host=host):
                self.assertIn("local", gm.host_problem(host, allow_private=True) or "")

    def test_private_networks_depend_on_who_chose_the_host(self):
        for host in ("10.0.0.1", "192.168.1.5", "172.16.3.4", "fd00::1"):
            with self.subTest(host=host):
                self.assertIsNone(gm.host_problem(host, allow_private=True))      # an operator's LAN forge
                self.assertIn("private", gm.host_problem(host, allow_private=False))  # a third party's link
        self.assertIsNone(gm.host_problem("8.8.8.8", allow_private=False))
        self.assertIn("resolve", gm.host_problem("no-such-host.invalid", True))
        self.assertIn("no host", gm.host_problem("", True))

    def test_the_override_lifts_only_the_local_rule(self):
        gm.ALLOW_LOCAL_HOSTS = True
        self.assertIsNone(gm.host_problem("127.0.0.1", allow_private=False))
        self.assertIn("private", gm.host_problem("10.0.0.1", allow_private=False))

    def test_open_url_refuses_before_connecting(self):
        with self.assertRaises(RuntimeError):
            gm.open_url("http://127.0.0.1:1/x", {}, 2, allow_private=True)
        with self.assertRaises(RuntimeError):
            gm.open_url("ftp://example.org/x", {}, 2, allow_private=True)
        with self.assertRaises(RuntimeError):
            gm.download_asset("http://169.254.169.254/latest/meta-data", os.path.join(tempfile.gettempdir(), "gm-nonexistent", "x"), 1 << 20)

    def test_redirects_are_checked_per_hop_and_drop_the_token_across_hosts(self):
        gm.ALLOW_LOCAL_HOSTS = True  # so the test can use local servers at all
        a, b = serve(), serve()
        try:
            pa, pb = a.server_address[1], b.server_address[1]
            _Tiny.plan = {
                "/same": (302, {"Location": f"http://127.0.0.1:{pa}/landed"}, b""),          # same host: header kept
                "/other": (302, {"Location": f"http://localhost:{pb}/landed"}, b""),         # other host name: header dropped
                "/meta": (302, {"Location": "http://169.254.169.254/latest/meta-data"}, b""),  # never followed
                "/ftp": (302, {"Location": "ftp://example.org/x"}, b""),
                "/landed": (200, {}, b"ok"),
            }
            hdr = {"Authorization": "Bearer secret", "User-Agent": "t"}
            self.assertEqual(gm.open_url(f"http://127.0.0.1:{pa}/same", hdr, 5, True).read(), b"ok")
            self.assertEqual(_Tiny.seen[-1][1].get("Authorization"), "Bearer secret")
            self.assertEqual(gm.open_url(f"http://127.0.0.1:{pa}/other", hdr, 5, True).read(), b"ok")
            self.assertIsNone(_Tiny.seen[-1][1].get("Authorization"))
            for path in ("/meta", "/ftp"):
                with self.subTest(path=path):
                    with self.assertRaises(urllib.error.HTTPError) as cm:
                        gm.open_url(f"http://127.0.0.1:{pa}{path}", hdr, 5, True)
                    self.assertIn("redirect refused", str(cm.exception.msg))
            self.assertEqual([p for p, _ in _Tiny.seen if "meta-data" in p], [])
        finally:
            a.shutdown(); a.server_close(); b.shutdown(); b.server_close()

    def test_api_json_reports_a_refused_redirect_readably(self):
        gm.ALLOW_LOCAL_HOSTS = True
        a = serve()
        try:
            _Tiny.plan = {"/r": (302, {"Location": "http://169.254.169.254/x"}, b"")}
            with self.assertRaises(RuntimeError) as cm:
                gm.api_json(f"http://127.0.0.1:{a.server_address[1]}/r", timeout=5)
            self.assertIn("redirect refused", str(cm.exception))
        finally:
            a.shutdown(); a.server_close()

    def test_release_asset_links_keep_only_http_urls(self):
        self.assertIsNone(gm._http_url("javascript:alert(1)", 2000))
        self.assertEqual(gm._http_url("https://h/a.zip", 2000), "https://h/a.zip")


class BearerThrottleTests(Base):
    def setUp(self):
        super().setUp()
        gm.BEARER_FAILS.clear()
        self.make_account()
        self.tok = self.login()
        self.key = self.req("POST", "/api/keys", {"name": "k", "role": "viewer"}, cookie=self.tok)[2]["key"]

    def tearDown(self):
        gm.BEARER_FAILS.clear()
        super().tearDown()

    def bad_login(self):
        return self.req("POST", "/api/auth/login", {"username": "ed", "password": "nope nope nope"})[0]

    def test_failed_sign_ins_never_block_keys_or_the_script_token(self):
        codes = [self.bad_login() for _ in range(gm.LOGIN_MAX + 1)]
        self.assertEqual(codes[-1], 429)  # sign-in itself is locked for this address ...
        self.assertEqual(self.req("GET", "/api/mirrors", headers={"Authorization": "Bearer " + self.key})[0], 200)    # ... a key still works
        self.assertEqual(self.req("GET", "/api/summary", headers={"Authorization": "Bearer setup-code"})[0], 200)     # ... so does the script token

    def test_wrong_bearers_never_block_sign_in(self):
        for _ in range(gm.BEARER_MAX):
            self.req("GET", "/api/mirrors", headers={"Authorization": "Bearer gm_" + "y" * 43})
        self.assertEqual(self.req("GET", "/api/mirrors", headers={"Authorization": "Bearer " + self.key})[0], 429)
        self.assertEqual(self.req("POST", "/api/auth/login", {"username": "ed", "password": "correct horse"})[0], 200)

    def test_the_global_sign_in_cap_does_not_apply_to_bearers(self):
        gm.LOGIN_FAILS.update({f"10.9.{i // 250}.{i % 250}": [time.time()] for i in range(gm.LOGIN_MAX_ALL)})
        self.assertEqual(self.req("GET", "/api/mirrors", headers={"Authorization": "Bearer " + self.key})[0], 200)
        gm.LOGIN_FAILS.clear()


class RobustnessTests(Base):
    def setUp(self):
        super().setUp()
        self.make_account()
        self.tok = self.login()

    def test_deeply_nested_json_is_a_400_before_sign_in(self):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", "/api/auth/login", body="[" * 100000, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        self.assertEqual(r.status, 400)
        self.assertIn(b"bad json", r.read())
        c.close()

    def test_wrong_types_are_400s_not_dropped_connections(self):
        self.assertEqual(self.req("POST", "/api/mirrors", {"source": ["https://h/x.git"]}, cookie=self.tok)[0], 400)
        self.assertEqual(self.req("PUT", "/api/settings", {"timeout": 1e400}, cookie=self.tok)[0], 400)
        self.assertEqual(self.req("PUT", "/api/settings", {"timeout": None}, cookie=self.tok)[0], 400)
        self.assertEqual(self.req("POST", "/api/import", {"mirrors": "https://h/x.git"}, cookie=self.tok)[0], 400)
        self.assertEqual(self.req("POST", "/api/import", {"sources": {"url": "x"}}, cookie=self.tok)[0], 400)

    def test_an_unexpected_error_is_a_json_500(self):
        real = gm.settings_out
        gm.settings_out = lambda st: 1 / 0
        try:
            status, _, body = self.req("GET", "/api/settings", cookie=self.tok)
        finally:
            gm.settings_out = real
        self.assertEqual((status, body), (500, {"error": "internal error"}))

    def test_server_header_has_no_python_version(self):
        _, resp, _ = self.req("GET", "/healthz")
        self.assertEqual(resp.getheader("Server"), "gitmirror")

    def test_viewers_cannot_read_settings(self):
        self.make_account("v", "viewer pass", role="viewer")
        self.make_account("o", "operator pw", role="operator")
        self.assertEqual(self.req("GET", "/api/settings", cookie=self.login("v", "viewer pass"))[0], 403)
        self.assertEqual(self.req("GET", "/api/settings", cookie=self.login("o", "operator pw"))[0], 200)

    def test_a_key_touch_does_not_rewrite_auth_on_every_address_change(self):
        old = gm.TRUSTED_PROXIES
        gm.TRUSTED_PROXIES = gm.parse_networks("127.0.0.1")
        try:
            key = self.req("POST", "/api/keys", {"name": "k", "role": "viewer"}, cookie=self.tok)[2]["key"]
            for ip in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
                self.req("GET", "/api/mirrors", headers={"Authorization": "Bearer " + key, "X-Forwarded-For": ip})
            self.assertEqual(self.req("GET", "/api/keys", cookie=self.tok)[2][0]["last_ip"], "198.51.100.1")  # first use recorded, then left alone within the minute
        finally:
            gm.TRUSTED_PROXIES = old


class CleanTagsTests(unittest.TestCase):
    def test_huge_lists_fail_fast(self):
        t0 = time.time()
        with self.assertRaises(ValueError):
            gm.clean_tags([f"t{i}" for i in range(100000)])
        self.assertLess(time.time() - t0, 1.0)
        self.assertEqual(gm.clean_tags(["a", "A", "b"] * 1000), ["a", "b"])  # duplicates never count towards the limit


class FileRemoteTests(unittest.TestCase):
    def test_file_urls_are_off_by_default(self):
        old = gm.ALLOW_FILE_REMOTES
        gm.ALLOW_FILE_REMOTES = False
        try:
            with self.assertRaises(ValueError) as cm:
                gm.check_url("file:///srv/git/x.git", "source")
            self.assertIn("GITMIRROR_ALLOW_FILE_REMOTES", str(cm.exception))
            self.assertRaises(ValueError, gm.check_url, "FILE:///srv/git/x.git", "source")
            gm.check_url("file:///srv/git/x.git", "source", admin=True)  # admins may
            gm.ALLOW_FILE_REMOTES = True
            gm.check_url("file:///srv/git/x.git", "source")
        finally:
            gm.ALLOW_FILE_REMOTES = old


if __name__ == "__main__":
    unittest.main()
