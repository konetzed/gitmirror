"""Tests for trusted proxy addresses, private data files, interrupted clones and the data format version."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from test_auth import Base, gm

POSIX = os.name == "posix"
GIT = shutil.which("git") is not None


def mode(path):
    return os.stat(path).st_mode & 0o777


class ClientAddressTests(unittest.TestCase):
    T = gm.parse_networks("127.0.0.1")

    def test_a_header_from_a_stranger_is_ignored(self):
        self.assertEqual(gm.client_ip("203.0.113.9", "1.2.3.4", self.T), "203.0.113.9")
        self.assertEqual(gm.client_ip("203.0.113.9", "1.2.3.4", []), "203.0.113.9")  # no trusted proxies configured

    def test_a_trusted_proxy_vouches_for_the_client(self):
        self.assertEqual(gm.client_ip("127.0.0.1", "198.51.100.7", self.T), "198.51.100.7")
        self.assertEqual(gm.client_ip("127.0.0.1", None, self.T), "127.0.0.1")
        self.assertEqual(gm.client_ip("127.0.0.1", "", self.T), "127.0.0.1")

    def test_the_rightmost_untrusted_address_wins_because_the_rest_can_be_made_up(self):
        self.assertEqual(gm.client_ip("127.0.0.1", "6.6.6.6, 198.51.100.7", self.T), "198.51.100.7")
        chain = gm.parse_networks("127.0.0.1, 10.0.0.0/8")
        self.assertEqual(gm.client_ip("127.0.0.1", "198.51.100.7, 10.0.0.5", chain), "198.51.100.7")  # two proxies in a row
        self.assertEqual(gm.client_ip("127.0.0.1", "10.0.0.5, 10.0.0.6", chain), "127.0.0.1")  # nothing but proxies

    def test_garbled_chains_fall_back_to_the_connection(self):
        for bad in ("not-an-ip", "1.2.3.4, banana", "999.1.1.1", ","):
            with self.subTest(bad=bad):
                self.assertEqual(gm.client_ip("127.0.0.1", bad, self.T), "127.0.0.1")

    def test_ipv6_and_mapped_addresses(self):
        v6 = gm.parse_networks("::1")
        self.assertEqual(gm.client_ip("::1", "2001:db8::5", v6), "2001:db8::5")
        self.assertEqual(gm.client_ip("::ffff:127.0.0.1", "198.51.100.7", self.T), "198.51.100.7")

    def test_parse_networks(self):
        self.assertEqual([str(n) for n in gm.parse_networks(" 127.0.0.1, 172.16.0.0/12 ,, nonsense ")], ["127.0.0.1/32", "172.16.0.0/12"])
        self.assertEqual(gm.parse_networks(""), [])
        self.assertEqual(gm.parse_networks(None), [])


class BehindAProxyTests(Base):
    def setUp(self):
        super().setUp()
        self.old_trusted = gm.TRUSTED_PROXIES
        self.make_account()

    def tearDown(self):
        gm.TRUSTED_PROXIES = self.old_trusted
        super().tearDown()

    def wrong(self, xff):
        return self.req("POST", "/api/auth/login", {"username": "ed", "password": "wrong wrong"}, headers={"X-Forwarded-For": xff})[0]

    def test_with_a_trusted_proxy_each_client_has_their_own_limit(self):
        gm.TRUSTED_PROXIES = gm.parse_networks("127.0.0.1")
        for _ in range(gm.LOGIN_MAX):
            self.assertEqual(self.wrong("198.51.100.1"), 401)
        self.assertEqual(self.wrong("198.51.100.1"), 429)  # that client is locked out ...
        status, _, _ = self.req("POST", "/api/auth/login", {"username": "ed", "password": "correct horse"}, headers={"X-Forwarded-For": "198.51.100.2"})
        self.assertEqual(status, 200)  # ... but the next person behind the same proxy is not

    def test_without_trusted_proxies_the_header_cannot_dodge_the_limit(self):
        gm.TRUSTED_PROXIES = []
        codes = [self.wrong(f"198.51.100.{i}") for i in range(gm.LOGIN_MAX + 2)]  # a new "address" every time
        self.assertEqual(codes[-2:], [429, 429])

    def test_an_api_key_records_the_forwarded_address(self):
        gm.TRUSTED_PROXIES = gm.parse_networks("127.0.0.1")
        tok = self.login()
        key = self.req("POST", "/api/keys", {"name": "k", "role": "viewer"}, cookie=tok)[2]["key"]
        self.req("GET", "/api/mirrors", headers={"Authorization": "Bearer " + key, "X-Forwarded-For": "198.51.100.7"})
        self.assertEqual(self.req("GET", "/api/keys", cookie=tok)[2][0]["last_ip"], "198.51.100.7")


@unittest.skipUnless(POSIX, "file modes")
class PrivateDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gitmirror-perm-")
        self.cfg = os.path.join(self.tmp, "configs")
        os.makedirs(self.cfg)
        os.chmod(self.tmp, 0o775)
        for name in ("mirrors.json", "settings.json", "7.log"):  # as an older version would have left them
            with open(os.path.join(self.cfg, name), "w") as f:
                f.write("[]" if name == "mirrors.json" else "{}")
            os.chmod(os.path.join(self.cfg, name), 0o664)

    def tearDown(self):
        os.environ.pop("GITMIRROR_PRIVATE_DATA", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_folders_and_old_files_become_private(self):
        gm.Store(self.tmp)
        self.assertEqual((mode(self.tmp), mode(self.cfg)), (0o700, 0o700))
        for name in ("mirrors.json", "settings.json", "7.log"):
            self.assertEqual(mode(os.path.join(self.cfg, name)), 0o600, name)

    def test_every_file_gitmirror_writes_is_private(self):
        st = gm.Store(self.tmp)
        st.save(); st.save_settings(); st.save_sources(); st.save_history(); st.save_stats(); st.save_auth(); st.save_sessions(); st.save_audit()
        gm.FORGES_PATH = os.path.join(self.cfg, "forges.json")
        gm.save_forges()
        files = sorted(f for f in os.listdir(self.cfg) if f.endswith(".json"))
        self.assertGreaterEqual(len(files), 9)
        for name in files:
            self.assertEqual(mode(os.path.join(self.cfg, name)), 0o600, name)
        self.assertFalse([f for f in os.listdir(self.cfg) if f.endswith(".tmp")])

    def test_the_opt_out_leaves_folder_access_alone(self):
        os.environ["GITMIRROR_PRIVATE_DATA"] = "0"
        gm.Store(self.tmp)
        self.assertEqual(mode(self.tmp), 0o775)
        self.assertEqual(mode(os.path.join(self.cfg, "mirrors.json")), 0o664)


@unittest.skipUnless(GIT, "git is not installed")
class InterruptedCloneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gitmirror-clone-")
        self.origin = os.path.join(self.tmp, "origin")
        env = dict(gm.GIT_ENV, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        subprocess.run(["git", "init", "-q", "-b", "main", self.origin], check=True, env=env)
        subprocess.run(["git", "-C", self.origin, "commit", "-q", "--allow-empty", "-m", "first"], check=True, env=env)
        self.log = open(os.devnull, "w")

    def tearDown(self):
        self.log.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_what_counts_as_needing_a_clone(self):
        missing = os.path.join(self.tmp, "missing.git")
        self.assertTrue(gm.needs_clone(missing))
        empty = os.path.join(self.tmp, "empty.git"); os.makedirs(empty)
        self.assertTrue(gm.needs_clone(empty)); self.assertFalse(os.path.exists(empty))  # an empty leftover is cleared away
        stub = os.path.join(self.tmp, "stub.git"); os.makedirs(os.path.join(stub, "objects", "info")); open(os.path.join(stub, "config"), "w").close()
        self.assertTrue(gm.needs_clone(stub)); self.assertFalse(os.path.exists(stub))  # so is a stub with no objects in it
        good = os.path.join(self.tmp, "good.git")
        gm.clone_mirror("file://" + self.origin, good, self.tmp, self.log, 60)
        self.assertFalse(gm.needs_clone(good)); self.assertTrue(os.path.isdir(good))
        damaged = os.path.join(self.tmp, "damaged.git"); os.makedirs(os.path.join(damaged, "objects", "ab"))
        with open(os.path.join(damaged, "objects", "ab", "cdef"), "w") as f:
            f.write("x")
        self.assertFalse(gm.needs_clone(damaged)); self.assertTrue(os.path.exists(damaged))  # never delete something that holds data

    def test_a_failed_clone_leaves_nothing_behind(self):
        repo = os.path.join(self.tmp, "m.git")
        with self.assertRaises(gm.GitError):
            gm.clone_mirror("file://" + os.path.join(self.tmp, "nope"), repo, self.tmp, self.log, 60)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.startswith("m.git")], [])

    def test_leftovers_from_a_killed_clone_are_cleared(self):
        repo = os.path.join(self.tmp, "m.git")
        os.makedirs(repo + ".partial"); open(os.path.join(repo + ".partial", "junk"), "w").close()
        gm.clone_mirror("file://" + self.origin, repo, self.tmp, self.log, 60)
        self.assertTrue(os.path.exists(os.path.join(repo, "HEAD")))
        self.assertFalse(os.path.exists(repo + ".partial"))

    def sync_once(self, prepare):
        data = os.path.join(self.tmp, "data")
        st = gm.Store(data)
        m = gm.create_mirror(st, "file://" + self.origin, name="t", interval=0, extras={}, start=False)
        prepare(st, m["id"])
        self.assertTrue(gm.sync(st, m["id"]))
        return st, st.get(m["id"])

    def test_sync_recovers_from_an_empty_folder_at_the_mirror_path(self):
        st, m = self.sync_once(lambda st, mid: os.makedirs(st.path(mid)))
        self.assertEqual((m["status"], m["error"]), ("ok", ""))
        self.assertIn("refs/heads/main", gm.ref_snapshot(st.path(m["id"])))

    def test_sync_recovers_from_a_stale_partial_folder(self):
        def leave_junk(st, mid):
            os.makedirs(st.path(mid) + ".partial"); open(os.path.join(st.path(mid) + ".partial", "x"), "w").close()
        st, m = self.sync_once(leave_junk)
        self.assertEqual(m["status"], "ok")
        self.assertFalse(os.path.exists(st.path(m["id"]) + ".partial"))

    def test_deleting_a_mirror_removes_a_partial_folder_too(self):
        st, m = self.sync_once(lambda st, mid: None)
        os.makedirs(st.path(m["id"]) + ".partial")
        self.assertTrue(gm.delete_mirror(st, m["id"]))
        self.assertFalse(os.path.exists(st.path(m["id"]) + ".partial"))


class DataFormatVersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gitmirror-schema-")
        self.cfg = os.path.join(self.tmp, "configs")
        self.saved = (gm.SCHEMA_VERSION, dict(gm.MIGRATIONS))

    def tearDown(self):
        gm.SCHEMA_VERSION = self.saved[0]
        gm.MIGRATIONS.clear()
        gm.MIGRATIONS.update(self.saved[1])
        os.environ.pop("GITMIRROR_IGNORE_SCHEMA", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def read(self, name):
        with open(os.path.join(self.cfg, name)) as f:
            return f.read()

    def stamp(self):
        with open(os.path.join(self.cfg, "version.json")) as f:
            return json.load(f)

    def seed(self, schema=None):
        os.makedirs(self.cfg, exist_ok=True)
        with open(os.path.join(self.cfg, "mirrors.json"), "w") as f:
            json.dump([{"id": "abc1234567", "name": "keep me", "source": "https://x/y.git", "status": "ok"}], f)
        if schema is not None:
            with open(os.path.join(self.cfg, "version.json"), "w") as f:
                json.dump({"schema": schema}, f)

    def test_a_new_folder_starts_at_the_current_version(self):
        gm.Store(self.tmp)
        s = self.stamp()
        self.assertEqual((s["schema"], s["written_by"]), (gm.SCHEMA_VERSION, gm.__version__))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "backups")))  # nothing to back up

    def test_data_from_before_versions_existed_is_stamped_and_backed_up(self):
        self.seed()
        st = gm.Store(self.tmp)
        self.assertEqual([m["name"] for m in st.mirrors], ["keep me"])
        self.assertEqual(self.stamp()["schema"], gm.SCHEMA_VERSION)
        backups = os.listdir(os.path.join(self.tmp, "backups"))
        self.assertEqual(len(backups), 1)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "backups", backups[0], "mirrors.json")))

    def test_newer_data_is_refused_and_left_untouched(self):
        self.seed(schema=99)
        before = self.read("mirrors.json")
        with self.assertRaises(gm.SchemaTooNew):
            gm.Store(self.tmp)
        self.assertEqual(self.stamp()["schema"], 99)
        self.assertEqual(self.read("mirrors.json"), before)

    def test_the_program_exits_with_a_clear_message_on_newer_data(self):
        self.seed(schema=99)
        r = subprocess.run([sys.executable, str(gm.__file__), "--data", self.tmp, "--port", "0"], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("newer gitmirror", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_the_override_runs_but_never_lowers_the_stamp(self):
        self.seed(schema=99)
        os.environ["GITMIRROR_IGNORE_SCHEMA"] = "1"
        gm.Store(self.tmp)
        self.assertEqual(self.stamp()["schema"], 99)

    def test_migrations_run_in_order_after_a_backup(self):
        self.seed(schema=1)
        ran = []
        gm.SCHEMA_VERSION = 3
        gm.MIGRATIONS.update({2: lambda st: ran.append(2), 3: lambda st: ran.append(3)})
        gm.Store(self.tmp)
        self.assertEqual(ran, [2, 3])
        self.assertEqual(self.stamp()["schema"], 3)
        self.assertEqual(len(os.listdir(os.path.join(self.tmp, "backups"))), 1)
        ran.clear()
        gm.Store(self.tmp)
        self.assertEqual(ran, [])  # already current: nothing runs twice

    def test_a_damaged_stamp_is_treated_as_old_data_not_a_crash(self):
        self.seed()
        with open(os.path.join(self.cfg, "version.json"), "w") as f:
            f.write("{not json")
        gm.Store(self.tmp)
        self.assertEqual(self.stamp()["schema"], gm.SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
