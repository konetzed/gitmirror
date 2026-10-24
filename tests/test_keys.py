"""Tests for personal API keys: creation, limits, what a key may do, revocation, usage tracking and abuse handling."""
import json
import time
import unittest

from test_roles import RoleServerBase, gm  # three signed-in users (viewer, operator, admin) on a live server


class KeyTests(RoleServerBase):
    def as_role(self, role, method, path, body=None):
        return self.req(method, path, body, cookie=self.cookies[role])

    def make_key(self, role="admin", name="Chrome laptop", cap="operator", days=0):
        status, _, body = self.as_role(role, "POST", "/api/keys", {"name": name, "role": cap, "expires_days": days})
        self.assertEqual(status, 201, body)
        return body

    def with_key(self, key, method, path, body=None, headers=None):
        return self.req(method, path, body, headers=dict({"Authorization": "Bearer " + key}, **(headers or {})))


class CreateAndListTests(KeyTests):
    def test_create_shows_the_key_once_and_stores_only_a_hash(self):
        made = self.make_key()
        self.assertTrue(made["key"].startswith("gm_") and len(made["key"]) > 40)
        listed = self.as_role("admin", "GET", "/api/keys")[2]
        self.assertEqual([k["name"] for k in listed], ["Chrome laptop"])
        self.assertNotIn(made["key"], json.dumps(listed))  # the list never repeats the key
        self.assertNotIn("hash", json.dumps(listed))
        with open(self.store.auth_path) as f:
            self.assertNotIn(made["key"], f.read())  # nor does the file on disk
        self.assertEqual(listed[0]["prefix"], made["key"][:7])
        self.assertIsNone(listed[0]["last_used"])
        self.assertAlmostEqual(listed[0]["created"], time.time(), delta=30)

    def test_a_user_can_have_several_keys_and_they_are_independent(self):
        a, b = self.make_key(name="Laptop"), self.make_key(name="Home Assistant", cap="viewer")
        self.assertNotEqual(a["key"], b["key"])
        self.assertEqual(len(self.as_role("admin", "GET", "/api/keys")[2]), 2)
        self.assertEqual(self.as_role("admin", "DELETE", "/api/keys/" + a["id"])[0], 200)
        self.assertEqual(self.with_key(a["key"], "GET", "/api/mirrors")[0], 401)  # revoked
        self.assertEqual(self.with_key(b["key"], "GET", "/api/mirrors")[0], 200)  # the other one is unaffected

    def test_people_only_see_and_revoke_their_own_keys(self):
        k = self.make_key(role="operator", name="Olive's key")
        self.assertEqual(self.as_role("viewer", "GET", "/api/keys")[2], [])
        self.assertEqual(self.as_role("viewer", "DELETE", "/api/keys/" + k["id"])[0], 404)
        self.assertEqual(self.with_key(k["key"], "GET", "/api/mirrors")[0], 200)

    def test_rules_for_new_keys(self):
        for bad in ({"name": "", "role": "viewer"}, {"name": "x" * 41, "role": "viewer"}, {"name": "ok", "role": "admin"}, {"name": "ok", "role": "root"},
                    {"name": "ok", "role": "viewer", "expires_days": 7}, {"name": 5, "role": "viewer"}):
            with self.subTest(bad=bad):
                self.assertEqual(self.as_role("admin", "POST", "/api/keys", bad)[0], 400)
        self.assertEqual(self.as_role("viewer", "POST", "/api/keys", {"name": "ro", "role": "operator"})[0], 400)  # no more than you are
        self.assertEqual(self.as_role("viewer", "POST", "/api/keys", {"name": "ro", "role": "viewer"})[0], 201)
        for i in range(gm.MAX_KEYS_PER_USER):
            self.as_role("operator", "POST", "/api/keys", {"name": f"k{i}", "role": "viewer"})
        self.assertEqual(self.as_role("operator", "POST", "/api/keys", {"name": "one too many", "role": "viewer"})[0], 400)

    def test_account_page_is_open_to_every_role(self):
        for role in gm.ROLES:
            status, _, html = self.as_role(role, "GET", "/account")
            self.assertEqual(status, 200)
            self.assertIn("API keys", html)


class WhatAKeyMayDoTests(KeyTests):
    def test_a_key_is_capped_at_operator_even_for_an_admin(self):
        k = self.make_key(role="admin", cap="operator")["key"]
        self.assertEqual(self.with_key(k, "GET", "/api/auth/me")[2]["role"], "operator")
        self.assertNotEqual(self.with_key(k, "POST", "/api/maintenance/verify", {})[0], 403)
        for method, path in (("DELETE", "/api/mirrors/zzz"), ("GET", "/api/users"), ("PUT", "/api/settings"), ("GET", "/api/export")):
            with self.subTest(path=path):
                self.assertEqual(self.with_key(k, method, path, {} if method == "PUT" else None)[0], 403)

    def test_a_read_only_key_cannot_change_anything(self):
        k = self.make_key(role="admin", cap="viewer")["key"]
        self.assertEqual(self.with_key(k, "GET", "/api/summary")[0], 200)
        self.assertEqual(self.with_key(k, "POST", "/api/maintenance/verify", {})[0], 403)

    def test_a_key_cannot_manage_keys_or_passwords(self):
        k = self.make_key(role="admin", cap="operator")
        self.assertEqual(self.with_key(k["key"], "POST", "/api/keys", {"name": "mine", "role": "viewer"})[0], 403)
        self.assertEqual(self.with_key(k["key"], "GET", "/api/keys")[0], 403)
        self.assertEqual(self.with_key(k["key"], "DELETE", "/api/keys/" + k["id"])[0], 403)
        self.assertEqual(self.with_key(k["key"], "POST", "/api/auth/password", {"current": "x", "new": "y" * 9})[0], 403)
        bearer = {"Authorization": "Bearer setup-code"}  # the shared script token can't either
        self.assertEqual(self.req("POST", "/api/keys", {"name": "x", "role": "viewer"}, headers=bearer)[0], 403)

    def test_the_owner_s_role_changes_apply_to_the_key(self):
        k = self.make_key(role="operator", cap="operator")["key"]
        self.assertNotEqual(self.with_key(k, "POST", "/api/maintenance/verify", {})[0], 403)
        self.as_role("admin", "PUT", "/api/users/operator", {"role": "viewer"})
        self.assertEqual(self.with_key(k, "POST", "/api/maintenance/verify", {})[0], 403)  # demoted owner, demoted key
        self.assertEqual(self.with_key(k, "GET", "/api/auth/me")[2]["role"], "viewer")

    def test_disabling_or_deleting_the_owner_kills_the_key(self):
        k = self.make_key(role="operator")["key"]
        self.as_role("admin", "PUT", "/api/users/operator", {"disabled": True})
        self.assertEqual(self.with_key(k, "GET", "/api/mirrors")[0], 401)
        self.as_role("admin", "PUT", "/api/users/operator", {"disabled": False})
        self.assertEqual(self.with_key(k, "GET", "/api/mirrors")[0], 200)
        self.as_role("admin", "DELETE", "/api/users/operator")
        self.assertEqual(self.with_key(k, "GET", "/api/mirrors")[0], 401)

    def test_an_admin_can_revoke_all_of_a_users_keys(self):
        a, b = self.make_key(role="operator", name="a")["key"], self.make_key(role="operator", name="b")["key"]
        users = {u["name"]: u for u in self.as_role("admin", "GET", "/api/users")[2]}
        self.assertEqual(users["operator"]["keys"], 2)
        self.assertEqual(self.as_role("operator", "PUT", "/api/users/operator", {"revoke_keys": True})[0], 403)
        self.assertEqual(self.as_role("admin", "PUT", "/api/users/operator", {"revoke_keys": True})[0], 200)
        for key in (a, b):
            self.assertEqual(self.with_key(key, "GET", "/api/mirrors")[0], 401)
        self.assertEqual(self.as_role("operator", "GET", "/api/mirrors")[0], 200)  # signed-in browsers are not affected

    def test_expiry(self):
        made = self.make_key(role="operator", days=30)
        self.assertAlmostEqual(made["expires"], time.time() + 30 * 86400, delta=60)
        self.assertEqual(self.with_key(made["key"], "GET", "/api/mirrors")[0], 200)
        for u in self.store.users.values():
            for k in u.get("keys", []):
                k["expires"] = time.time() - 1
        self.assertEqual(self.with_key(made["key"], "GET", "/api/mirrors")[0], 401)


class UsageTrackingTests(KeyTests):
    def find(self, key_id):
        return next(k for k in self.store.users["admin"]["keys"] if k["id"] == key_id)

    def test_last_used_and_address_are_recorded_and_not_rewritten_on_every_call(self):
        made = self.make_key()
        self.assertIsNone(self.find(made["id"])["last_used"])
        self.assertEqual(self.with_key(made["key"], "GET", "/api/mirrors")[0], 200)
        first = self.find(made["id"])
        self.assertAlmostEqual(first["last_used"], time.time(), delta=30)
        self.assertEqual(first["last_ip"], "127.0.0.1")
        stamp = first["last_used"]
        self.with_key(made["key"], "GET", "/api/mirrors")
        self.assertEqual(self.find(made["id"])["last_used"], stamp)  # within the minute: not touched
        first["last_used"] = time.time() - 120
        self.with_key(made["key"], "GET", "/api/mirrors")
        self.assertGreater(self.find(made["id"])["last_used"], time.time() - 30)
        listed = self.as_role("admin", "GET", "/api/keys")[2][0]
        self.assertEqual(listed["last_ip"], "127.0.0.1")

    def test_the_activity_log_names_the_key(self):
        made = self.make_key(role="operator", name="Chrome laptop")
        self.with_key(made["key"], "POST", "/api/maintenance/verify", {})
        log = self.as_role("admin", "GET", "/api/audit")[2]
        entry = next(e for e in log if e["what"] == "POST /api/maintenance/verify")
        self.assertEqual((entry["user"], entry["via"]), ("operator", "key 'Chrome laptop'"))
        self.assertNotIn(made["key"], json.dumps(log))
        created = next(e for e in log if e["what"] == "POST /api/keys")
        self.assertIn("Chrome laptop", created["note"])


class HeaderAuthTests(KeyTests):
    def test_a_key_works_from_an_extension_origin_but_a_cookie_does_not(self):
        k = self.make_key(role="operator")["key"]
        ext = {"Origin": "chrome-extension://abcdefghijklmnop"}
        self.assertNotEqual(self.with_key(k, "POST", "/api/maintenance/verify", {}, headers=ext)[0], 403)  # no ambient credentials, no cross-site risk
        self.assertEqual(self.req("POST", "/api/maintenance/verify", {}, cookie=self.cookies["operator"], headers=ext)[0], 403)  # a cookie still is
        both = dict(ext, Authorization="Bearer " + k)
        self.assertEqual(self.req("POST", "/api/maintenance/verify", {}, cookie=self.cookies["operator"], headers=both)[0], 403)  # a cookie present: stay strict

    def test_wrong_keys_are_throttled_like_wrong_passwords(self):
        codes = [self.with_key("gm_" + "x" * 43, "GET", "/api/mirrors")[0] for _ in range(gm.LOGIN_MAX + 2)]
        self.assertEqual(codes[:gm.LOGIN_MAX], [401] * gm.LOGIN_MAX)
        self.assertEqual(codes[gm.LOGIN_MAX:], [429, 429])

    def test_garbage_after_bearer_is_just_unauthorized(self):
        for value in ("Bearer ", "Bearer gm_", "Bearer gm_" + "é" * 5, "Basic abc"):
            with self.subTest(value=value):
                try:
                    status = self.req("GET", "/api/mirrors", headers={"Authorization": value})[0]
                except (UnicodeEncodeError, ValueError):
                    continue  # the client library refused to send it
                self.assertEqual(status, 401)

    def test_old_account_files_without_keys_still_load(self):
        for u in self.store.users.values():
            u.pop("keys", None)
        self.assertEqual(self.as_role("admin", "GET", "/api/keys")[2], [])
        self.assertEqual(self.as_role("admin", "GET", "/api/users")[2][0]["keys"], 0)


if __name__ == "__main__":
    unittest.main()
