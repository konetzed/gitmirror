"""Tests for roles: the permission table, enforcement on a real server, user management, migration and the activity log."""
import json
import os
import time
import unittest

from test_auth import Base, gm  # the server fixture and the loaded module (Base has no tests of its own)


class RuleTests(unittest.TestCase):
    def test_permission_table(self):
        cases = [
            ("GET", "/", "viewer"), ("GET", "/events", "viewer"), ("GET", "/maintenance", "viewer"), ("GET", "/maintenance/size", "viewer"),
            ("GET", "/sources", "viewer"), ("GET", "/source/abc123", "viewer"), ("GET", "/repo/abc123", "viewer"),
            ("GET", "/api/mirrors", "viewer"), ("GET", "/api/mirrors/abc123", "viewer"), ("GET", "/api/mirrors/abc123/log", "viewer"),
            ("GET", "/api/mirrors/abc123/extras", "viewer"), ("GET", "/api/stats", "viewer"), ("GET", "/api/summary", "viewer"),
            ("GET", "/api/history", "viewer"), ("GET", "/api/events", "viewer"), ("GET", "/api/maintenance", "viewer"),
            ("GET", "/api/sources", "viewer"), ("GET", "/api/sources/abc123", "viewer"), ("GET", "/api/settings", "viewer"),
            ("GET", "/api/version", "viewer"), ("GET", "/api/auth/me", "viewer"), ("GET", "/dl/abc123/releases/v1/tool.bin", "viewer"),
            ("GET", "/admin", "admin"), ("GET", "/api/export", "admin"), ("GET", "/api/users", "admin"), ("GET", "/api/audit", "admin"), ("GET", "/account", "viewer"), ("GET", "/api/keys", "viewer"),
            ("POST", "/api/keys", "viewer"), ("DELETE", "/api/keys/abc123", "viewer"),
            ("POST", "/api/auth/logout", "viewer"), ("POST", "/api/auth/password", "viewer"),
            ("POST", "/api/mirrors", "operator"), ("POST", "/api/mirrors/abc123/sync", "operator"), ("POST", "/api/mirrors/abc123/hold", "operator"),
            ("POST", "/api/mirrors/abc123/accept", "operator"), ("POST", "/api/mirrors/abc123/lfs", "operator"),
            ("POST", "/api/sources", "operator"), ("POST", "/api/sources/preview", "operator"), ("POST", "/api/sources/abc123/approve", "operator"),
            ("POST", "/api/maintenance/verify", "operator"), ("POST", "/api/maintenance/optimize", "operator"), ("POST", "/api/version/check", "operator"),
            ("POST", "/api/import", "admin"), ("POST", "/api/users", "admin"),
            ("PUT", "/api/mirrors/abc123", "operator"), ("PUT", "/api/sources/abc123", "operator"),
            ("PUT", "/api/settings", "admin"), ("PUT", "/api/users/ed", "admin"),
            ("DELETE", "/api/mirrors/abc123", "admin"), ("DELETE", "/api/sources/abc123", "admin"), ("DELETE", "/api/users/ed", "admin"),
        ]
        for method, path, want in cases:
            with self.subTest(method=method, path=path):
                self.assertEqual(gm.required_role(method, path), want)

    def test_bulk_depends_on_the_action(self):
        self.assertEqual(gm.required_role("POST", "/api/bulk", {"action": "sync"}), "operator")
        self.assertEqual(gm.required_role("POST", "/api/bulk", {"action": "add_tag"}), "operator")
        self.assertEqual(gm.required_role("POST", "/api/bulk", {"action": "delete"}), "admin")
        self.assertEqual(gm.required_role("POST", "/api/bulk", None), "operator")

    def test_anything_unknown_needs_an_admin(self):
        for method, path in (("GET", "/api/brand-new"), ("POST", "/api/brand-new"), ("PUT", "/api/brand-new"), ("DELETE", "/api/mirrors/abc123/extra"),
                             ("PATCH", "/api/mirrors/abc123"), ("GET", "/api/mirrors/abc123/secret"), ("POST", "/api/mirrors/abc123/unknown-action")):
            with self.subTest(method=method, path=path):
                self.assertEqual(gm.required_role(method, path), "admin")

    def test_rank(self):
        self.assertLess(gm.role_rank("viewer"), gm.role_rank("operator"))
        self.assertLess(gm.role_rank("operator"), gm.role_rank("admin"))
        self.assertEqual(gm.role_rank("root"), -1)  # an unknown role is below everything


class RoleServerBase(Base):
    def setUp(self):
        super().setUp()
        self.cookies = {}
        for role in gm.ROLES:
            self.make_account(role, "pass " + role + " word", role)
            self.cookies[role] = self.login(role, "pass " + role + " word")

    def as_role(self, role, method, path, body=None):
        return self.req(method, path, body, cookie=self.cookies[role])


class EnforcementTests(RoleServerBase):
    CASES = [  # (method, path, body, may viewer, may operator, may admin)
        ("GET", "/api/mirrors", None, 1, 1, 1),
        ("GET", "/api/settings", None, 1, 1, 1),
        ("POST", "/api/maintenance/verify", {}, 0, 1, 1),
        ("POST", "/api/mirrors/zzz/sync", {}, 0, 1, 1),
        ("PUT", "/api/mirrors/zzz", {"name": "x"}, 0, 1, 1),
        ("POST", "/api/bulk", {"ids": [], "action": "sync"}, 0, 1, 1),
        ("POST", "/api/bulk", {"ids": [], "action": "delete"}, 0, 0, 1),
        ("DELETE", "/api/mirrors/zzz", None, 0, 0, 1),
        ("DELETE", "/api/sources/zzz", None, 0, 0, 1),
        ("PUT", "/api/settings", {"theme": "dark"}, 0, 0, 1),
        ("GET", "/api/export", None, 0, 0, 1),
        ("POST", "/api/import", {}, 0, 0, 1),
        ("GET", "/api/users", None, 0, 0, 1),
        ("GET", "/api/audit", None, 0, 0, 1),
        ("POST", "/api/users", {"username": "x", "password": "12345678", "role": "viewer"}, 0, 0, 1),
    ]

    def test_each_role_gets_exactly_its_permissions(self):
        for method, path, body, *allowed in self.CASES:
            for role, may in zip(gm.ROLES, allowed):
                with self.subTest(role=role, request=f"{method} {path} {body or ''}"):
                    status = self.as_role(role, method, path, body)[0]
                    if may:
                        self.assertNotEqual(status, 403)
                    else:
                        self.assertEqual(status, 403)

    def test_admin_page_and_role_marker(self):
        for role, status in (("viewer", 302), ("operator", 302), ("admin", 200)):
            with self.subTest(role=role):
                self.assertEqual(self.as_role(role, "GET", "/admin")[0], status)
        for role in gm.ROLES:
            html = self.as_role(role, "GET", "/")[2]
            self.assertIn(f'r.dataset.role="{role}"', html)  # lets the page hide what this role can't use
        self.assertIn('r.dataset.role="viewer"', self.req("GET", "/login")[2])  # unknown or signed out: least privilege

    def test_me_reports_the_role(self):
        for role in gm.ROLES:
            self.assertEqual(self.as_role(role, "GET", "/api/auth/me")[2]["role"], role)

    def test_everyone_can_change_their_own_password_and_log_out(self):
        for role in gm.ROLES:
            self.assertEqual(self.as_role(role, "POST", "/api/auth/password", {"current": "wrong wrong", "new": "brand new pass"})[0], 403)  # reached the handler
        self.assertEqual(self.as_role("viewer", "POST", "/api/auth/logout", {})[0], 200)

    def test_script_token_is_an_operator_by_default_and_never_an_admin(self):
        bearer = {"Authorization": "Bearer setup-code"}
        self.assertNotEqual(self.req("POST", "/api/maintenance/verify", {}, headers=bearer)[0], 403)
        self.assertEqual(self.req("DELETE", "/api/mirrors/zzz", headers=bearer)[0], 403)
        self.assertEqual(self.req("GET", "/api/users", headers=bearer)[0], 403)
        self.assertEqual(self.req("PUT", "/api/settings", {"theme": "dark"}, headers=bearer)[0], 403)
        self.assertEqual(self.req("GET", "/api/auth/me", headers=bearer)[2]["role"], "operator")

    def test_script_token_can_be_read_only(self):
        old, gm.TOKEN_ROLE = gm.TOKEN_ROLE, "viewer"
        try:
            bearer = {"Authorization": "Bearer setup-code"}
            self.assertEqual(self.req("GET", "/api/summary", headers=bearer)[0], 200)
            self.assertEqual(self.req("POST", "/api/maintenance/verify", {}, headers=bearer)[0], 403)
        finally:
            gm.TOKEN_ROLE = old


class UserManagementTests(RoleServerBase):
    def api(self, method, path, body=None, role="admin"):
        return self.req(method, path, body, cookie=self.cookies[role])

    def test_create_list_and_sign_in_as_the_new_user(self):
        names = [u["name"] for u in self.api("GET", "/api/users")[2]]
        self.assertEqual(sorted(names), ["admin", "operator", "viewer"])
        for bad in ({"username": "a b", "password": "12345678", "role": "viewer"}, {"username": "zoe", "password": "short", "role": "viewer"},
                    {"username": "zoe", "password": "12345678", "role": "root"}):
            with self.subTest(bad=bad):
                self.assertEqual(self.api("POST", "/api/users", bad)[0], 400)
        self.assertEqual(self.api("POST", "/api/users", {"username": "Zoe", "password": "zoe-password", "role": "operator"})[0], 201)
        self.assertEqual(self.api("POST", "/api/users", {"username": "ZOE", "password": "zoe-password", "role": "viewer"})[0], 409)  # names ignore case
        tok = self.login("zoe", "zoe-password")
        self.assertEqual(self.req("GET", "/api/auth/me", cookie=tok)[2], {"user": "Zoe", "role": "operator", "via": "session", "key_name": None})
        self.assertNotIn("hash", json.dumps(self.api("GET", "/api/users")[2]))  # password hashes never leave the server

    def test_a_role_change_applies_to_the_next_request_without_signing_in_again(self):
        self.assertNotEqual(self.as_role("operator", "POST", "/api/maintenance/verify", {})[0], 403)
        self.assertEqual(self.api("PUT", "/api/users/operator", {"role": "viewer"})[0], 200)
        self.assertEqual(self.as_role("operator", "POST", "/api/maintenance/verify", {})[0], 403)  # same cookie, lower role
        self.assertEqual(self.as_role("operator", "GET", "/api/mirrors")[0], 200)

    def test_disabling_signs_the_user_out_and_blocks_sign_in(self):
        self.assertEqual(self.api("PUT", "/api/users/viewer", {"disabled": True})[0], 200)
        self.assertEqual(self.as_role("viewer", "GET", "/api/mirrors")[0], 401)
        self.assertEqual(self.req("POST", "/api/auth/login", {"username": "viewer", "password": "pass viewer word"})[0], 401)
        self.assertEqual(self.api("PUT", "/api/users/viewer", {"disabled": False})[0], 200)
        self.assertTrue(self.login("viewer", "pass viewer word"))

    def test_password_reset_by_an_admin(self):
        self.assertEqual(self.api("PUT", "/api/users/operator", {"password": "short"})[0], 400)
        self.assertEqual(self.api("PUT", "/api/users/operator", {"password": "a fresh password"})[0], 200)
        self.assertEqual(self.as_role("operator", "GET", "/api/mirrors")[0], 401)  # the old session is gone
        self.assertEqual(self.req("POST", "/api/auth/login", {"username": "operator", "password": "pass operator word"})[0], 401)
        self.assertTrue(self.login("operator", "a fresh password"))
        self.assertEqual(self.api("PUT", "/api/users/admin", {"password": "my own new one"})[0], 400)  # your own goes through the Account card

    def test_delete_user(self):
        self.assertEqual(self.api("DELETE", "/api/users/viewer")[0], 200)
        self.assertEqual(self.as_role("viewer", "GET", "/api/mirrors")[0], 401)
        self.assertEqual(self.api("DELETE", "/api/users/viewer")[0], 404)
        self.assertEqual(self.api("DELETE", "/api/users/admin")[0], 409)  # not yourself

    def test_the_last_admin_can_never_be_removed(self):
        for body in ({"role": "operator"}, {"disabled": True}):
            with self.subTest(body=body):
                self.assertEqual(self.api("PUT", "/api/users/admin", body)[0], 409)
        self.assertEqual(self.api("DELETE", "/api/users/admin")[0], 409)
        self.assertEqual(self.api("POST", "/api/users", {"username": "boss", "password": "boss-password", "role": "admin"})[0], 201)
        boss = self.login("boss", "boss-password")
        self.assertEqual(self.api("DELETE", "/api/users/boss")[0], 200)  # a second admin makes room, then it is the last one again
        self.assertEqual(self.api("PUT", "/api/users/admin", {"role": "viewer"})[0], 409)
        self.assertEqual(self.req("GET", "/api/mirrors", cookie=boss)[0], 401)

    def test_an_admin_may_step_down_when_another_admin_exists(self):
        self.assertEqual(self.api("POST", "/api/users", {"username": "boss", "password": "boss-password", "role": "admin"})[0], 201)
        self.assertEqual(self.api("PUT", "/api/users/admin", {"role": "operator"})[0], 200)
        self.assertEqual(self.as_role("admin", "GET", "/api/mirrors")[0], 200)  # still signed in, now an operator
        self.assertEqual(self.as_role("admin", "GET", "/api/users")[0], 403)

    def test_unknown_user_and_awkward_names(self):
        self.assertEqual(self.api("PUT", "/api/users/nobody", {"role": "viewer"})[0], 404)
        self.assertEqual(self.api("POST", "/api/users", {"username": "a.b+c@d", "password": "12345678", "role": "viewer"})[0], 201)
        self.assertEqual(self.api("PUT", "/api/users/a.b%2Bc%40d", {"role": "operator"})[0], 200)
        self.assertEqual(self.store.users["a.b+c@d"]["role"], "operator")

    def test_only_admins_manage_users(self):
        for role in ("viewer", "operator"):
            self.assertEqual(self.api("GET", "/api/users", role=role)[0], 403)
            self.assertEqual(self.api("PUT", "/api/users/admin", {"role": "viewer"}, role=role)[0], 403)
            self.assertEqual(self.api("DELETE", "/api/users/admin", role=role)[0], 403)


class MigrationTests(Base):
    def prepare(self):
        cfg = os.path.join(self.tmp, "configs")
        os.makedirs(cfg)
        h = gm.hash_password("old password")
        with open(os.path.join(cfg, "auth.json"), "w") as f:  # the single-account file written before roles existed
            json.dump({"user": "Ed", "hash": h, "created": 1.0}, f)
        import hashlib
        with open(os.path.join(cfg, "sessions.json"), "w") as f:
            json.dump({hashlib.sha256(b"legacy-cookie").hexdigest(): {"user": "Ed", "created": 1.0, "exp": time.time() + 3600, "agent": ""}}, f)

    def test_the_old_account_becomes_the_admin_and_keeps_working(self):
        self.assertEqual(list(self.store.users), ["ed"])
        self.assertEqual((self.store.users["ed"]["name"], self.store.users["ed"]["role"]), ("Ed", "admin"))
        with open(self.store.auth_path) as f:
            self.assertIn("users", json.load(f))  # rewritten in the new shape
        self.assertEqual(self.req("GET", "/api/auth/me", cookie="legacy-cookie")[2]["role"], "admin")  # an old session survives the upgrade
        self.assertTrue(self.login("ed", "old password"))


class ActivityLogTests(RoleServerBase):
    def entries(self):
        return self.req("GET", "/api/audit", cookie=self.cookies["admin"])[2]

    def test_changes_are_recorded_with_who_and_what_but_reads_and_refusals_are_not(self):
        self.as_role("admin", "GET", "/api/mirrors")
        self.as_role("viewer", "POST", "/api/maintenance/verify", {})  # refused
        self.as_role("operator", "POST", "/api/maintenance/verify", {})
        self.as_role("admin", "PUT", "/api/settings", {"theme": "dark", "github_token": "ghp_SECRET"})
        self.req("POST", "/api/maintenance/verify", {}, headers={"Authorization": "Bearer setup-code"})
        log = self.entries()
        whats = [(e["user"], e["role"], e["what"]) for e in log]
        self.assertIn(("operator", "operator", "POST /api/maintenance/verify"), whats)
        self.assertIn(("admin", "admin", "PUT /api/settings"), whats)
        self.assertIn(("script token", "operator", "POST /api/maintenance/verify"), whats)
        self.assertNotIn("viewer", [e["user"] for e in log])
        self.assertFalse([e for e in log if e["what"].startswith("GET")])
        settings = next(e for e in log if e["what"] == "PUT /api/settings")
        self.assertIn("theme", settings["note"])
        self.assertNotIn("ghp_SECRET", json.dumps(log))  # values of secrets are never written down

    def test_passwords_never_reach_the_log(self):
        self.req("POST", "/api/users", {"username": "zoe", "password": "zoe-very-secret", "role": "viewer"}, cookie=self.cookies["admin"])
        self.req("PUT", "/api/users/zoe", {"password": "another-secret"}, cookie=self.cookies["admin"])
        text = json.dumps(self.entries())
        self.assertNotIn("very-secret", text)
        self.assertNotIn("another-secret", text)
        self.assertIn("zoe", text)

    def test_only_admins_can_read_it_and_it_is_capped(self):
        self.assertEqual(self.as_role("operator", "GET", "/api/audit")[0], 403)
        for i in range(1100):
            self.store.audit.append({"t": i, "user": "x", "role": "operator", "what": "POST /api/x", "target": "", "note": ""})
        gm.audit_add(self.store, {"name": "x", "role": "operator"}, "POST", "/api/x", "", "")
        self.assertLessEqual(len(self.store.audit), 1000)


if __name__ == "__main__":
    unittest.main()
