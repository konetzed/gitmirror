"""Unit tests for gitmirror's pure helpers and its ref-archiving logic.

Run with:  python -m unittest discover -s tests -v      (stdlib only, like gitmirror itself)
or:        pytest tests
The archive tests need git on PATH and are skipped without it.
"""
import importlib.util
import io
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gitmirror", ROOT / "gitmirror.py")
gm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gm)

HAVE_GIT = shutil.which("git") is not None


class IntervalTests(unittest.TestCase):
    def test_units_and_combinations(self):
        self.assertEqual(gm.parse_interval("1W"), 10080)
        self.assertEqual(gm.parse_interval("3D"), 4320)
        self.assertEqual(gm.parse_interval("12H"), 720)
        self.assertEqual(gm.parse_interval("30M"), 30)
        self.assertEqual(gm.parse_interval("1D12H"), 2160)
        self.assertEqual(gm.parse_interval("2h 30m"), 150)   # case and spaces are tolerated
        self.assertEqual(gm.parse_interval("90"), 90)         # bare number = minutes
        self.assertEqual(gm.parse_interval(45), 45)
        self.assertEqual(gm.parse_interval("0"), 0)

    def test_rejects_bad_input(self):
        for bad in ("", "D", "1X", "1H1D", "1H1H", "1.5H", "-5", True, "1" * 41, 525601, "99W"):
            with self.subTest(bad=bad):
                self.assertRaises(ValueError, gm.parse_interval, bad)

    def test_format_roundtrip(self):
        for text in ("1W", "3D", "12H", "30M", "1D12H", "1W2D3H4M", "0"):
            self.assertEqual(gm.format_interval(gm.parse_interval(text)), text)


class MaskTests(unittest.TestCase):
    def test_user_password_keeps_user(self):
        self.assertEqual(gm.mask("https://bob:s3cret@host/o/r.git"), "https://bob:***@host/o/r.git")
        self.assertEqual(gm.mask("https://oauth2:glpat-abc@gitlab.com/g/p.git"), "https://oauth2:***@gitlab.com/g/p.git")

    def test_bare_token_is_hidden(self):
        # GitHub's documented form has no user name: the whole token must go.
        self.assertEqual(gm.mask("https://ghp_abcdef123@github.com/o/r.git"), "https://***@github.com/o/r.git")
        self.assertEqual(gm.mask("https://bob@host/o/r.git"), "https://***@host/o/r.git")

    def test_ssh_user_is_not_a_secret(self):
        # "git@" / "deploy@" identify the account; masking them would also make exported mirrors unrestorable.
        self.assertEqual(gm.mask("ssh://git@github.com/o/r.git"), "ssh://git@github.com/o/r.git")
        self.assertEqual(gm.mask("ssh://deploy@nas.lan:2222/srv/r.git"), "ssh://deploy@nas.lan:2222/srv/r.git")

    def test_plain_urls_untouched(self):
        for u in ("https://github.com/o/r.git", "git@github.com:o/r.git", "file:///srv/repo.git", "", None):
            self.assertEqual(gm.mask(u), u or "")

    def test_mask_inside_git_output(self):
        out = "fatal: unable to access 'https://ghp_abc@github.com/o/r.git/': 403\n$ git clone https://u:p@h/x.git"
        self.assertNotIn("ghp_abc", gm.mask(out))
        self.assertNotIn(":p@", gm.mask(out))


class UrlHelperTests(unittest.TestCase):
    def test_norm_src_identifies_same_repo(self):
        same = ("https://github.com/Org/Repo.git", "https://github.com/org/repo", "https://TOKEN@github.com/org/repo.git/",
                "https://u:p@github.com/org/repo")
        self.assertEqual(len({gm.norm_src(u) for u in same}), 1)
        self.assertNotEqual(gm.norm_src("https://github.com/org/repo"), gm.norm_src("https://github.com/org/repo2"))

    def test_check_url(self):
        for ok in ("https://h/o/r.git", "ssh://git@h/o/r", "git://h/r", "git@h:o/r.git"):
            gm.check_url(ok, "source")
        self.assertRaises(ValueError, gm.check_url, "file:///x", "source")  # off by default
        gm.ALLOW_FILE_REMOTES = True
        try:
            gm.check_url("file:///x", "source")
        finally:
            gm.ALLOW_FILE_REMOTES = False
        for bad in ("-oProxyCommand=evil", "ext::sh -c evil", "ftp://h/r", "/local/path", "h/o/r", "https://h/x --upload-pack=evil"):
            with self.subTest(bad=bad):
                self.assertRaises(ValueError, gm.check_url, bad, "source")

    def test_http_url_filters_schemes(self):
        self.assertEqual(gm._http_url("https://h/x"), "https://h/x")
        self.assertEqual(gm._http_url("http://h/x"), "http://h/x")
        self.assertIsNone(gm._http_url("javascript:alert(1)"))
        self.assertIsNone(gm._http_url("data:text/html,x"))
        self.assertIsNone(gm._http_url(None))
        self.assertIsNone(gm._http_url(123))
        self.assertEqual(len(gm._http_url("https://h/" + "a" * 500, 50)), 50)

    def test_header_filename_is_printable_ascii(self):
        self.assertEqual(gm.header_filename('a"b\r\nSet-Cookie: x'), "a_bSet-Cookie_ x")
        self.assertEqual(gm.header_filename(""), "download")
        self.assertEqual(gm.header_filename("réport.pdf"), "r_port.pdf")

    def test_safe_name(self):
        self.assertNotIn("/", gm.safe_name("../../etc/passwd"))
        self.assertNotIn("\\", gm.safe_name("..\\..\\x"))
        self.assertFalse(gm.safe_name("...").startswith("."))
        self.assertEqual(gm.safe_name("", "asset"), "asset")


class TagAndRetryTests(unittest.TestCase):
    def test_clean_tags(self):
        self.assertEqual(gm.clean_tags("a, b ,A,  c  d "), ["a", "b", "c d"])
        self.assertEqual(gm.clean_tags(None), [])
        self.assertEqual(gm.clean_tags(["x" * 50])[0], "x" * 30)
        self.assertRaises(ValueError, gm.clean_tags, 42)
        self.assertRaises(ValueError, gm.clean_tags, [str(i) for i in range(21)])

    def test_retry_delay_doubles_and_caps(self):
        s = {"retry_delay": 15, "retry_max": 360}
        self.assertEqual([gm.retry_delay_min(s, n) for n in (1, 2, 3, 4, 5, 6, 7)], [15, 30, 60, 120, 240, 360, 360])
        self.assertIsNone(gm.retry_delay_min({"retry_delay": 0, "retry_max": 360}, 1))
        self.assertEqual(gm.retry_delay_min({"retry_delay": 500, "retry_max": 10}, 1), 500)  # max never below base

    def test_next_due(self):
        self.assertEqual(gm.next_due({"status": "new"}), 0)
        self.assertEqual(gm.next_due({"sync_now": True, "interval": 0}), 0)
        self.assertIsNone(gm.next_due({"interval": 0, "status": "ok"}))
        self.assertIsNone(gm.next_due({"interval": 60, "enabled": False}))
        self.assertEqual(gm.next_due({"interval": 60, "last_run": 1000}), 4600)
        self.assertEqual(gm.next_due({"interval": 60, "last_run": 1000, "retry_at": 1200}), 1200)


@unittest.skipUnless(HAVE_GIT, "git is not installed")
class ArchiveTests(unittest.TestCase):
    """archive_changes() and hold_apply() against a real repo: the core takedown-protection logic."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gitmirror-test-")
        self.origin = os.path.join(self.tmp, "origin")
        self.git(["init", "-q", "-b", "main", self.origin], cwd=self.tmp)
        self.git(["config", "user.email", "t@example.com"])
        self.git(["config", "user.name", "t"])
        self.commit("one")
        self.first = self.rev("main")
        self.commit("two")
        self.git(["tag", "v1"])
        self.git(["branch", "feature"])
        self.mirror = os.path.join(self.tmp, "mirror.git")
        self.git(["clone", "-q", "--mirror", self.origin, self.mirror], cwd=self.tmp)
        gm.protect_repo(self.mirror)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.origin, check=True, capture_output=True, text=True, env=gm.GIT_ENV).stdout

    def commit(self, msg):
        with open(os.path.join(self.origin, msg + ".txt"), "w") as f:
            f.write(msg)
        self.git(["add", "."])
        self.git(["commit", "-q", "-m", msg])

    def rev(self, ref, cwd=None):
        return self.git(["rev-parse", ref], cwd=cwd).strip()

    def refs(self, repo):
        return gm.ref_snapshot(repo)

    def test_fast_forward_archives_nothing(self):
        pre = self.refs(self.mirror)
        self.commit("three")
        gm.run_git(["remote", "update", "--prune"], self.mirror, io.StringIO(), 60)
        _, events = gm.archive_changes(self.mirror, pre, self.refs(self.mirror), io.StringIO())
        self.assertEqual(events, [])

    def test_rewrite_and_delete_are_pinned(self):
        pre = self.refs(self.mirror)
        old_main, old_feature = pre["refs/heads/main"], pre["refs/heads/feature"]
        self.git(["reset", "-q", "--hard", self.first])        # history rewritten
        self.git(["branch", "-D", "feature"])                  # branch deleted
        self.git(["tag", "-d", "v1"])                          # tag deleted
        gm.run_git(["remote", "update", "--prune"], self.mirror, io.StringIO(), 60)
        post = self.refs(self.mirror)
        ts, events = gm.archive_changes(self.mirror, pre, post, io.StringIO())
        kinds = {e["ref"]: e["kind"] for e in events}
        self.assertEqual(kinds, {"refs/heads/main": "rewritten", "refs/heads/feature": "deleted", "refs/tags/v1": "deleted"})
        self.assertEqual(self.rev(f"refs/archive/{ts}/heads/main", self.mirror), old_main)
        self.assertEqual(self.rev(f"refs/archive/{ts}/heads/feature", self.mirror), old_feature)
        self.assertEqual(post["refs/heads/main"], self.first)
        # A later prune must leave refs/archive alone (negative refspec from protect_repo).
        gm.run_git(["remote", "update", "--prune"], self.mirror, io.StringIO(), 60)
        self.assertEqual(self.rev(f"refs/archive/{ts}/heads/main", self.mirror), old_main)

    def test_hold_keeps_local_refs(self):
        before = self.refs(self.mirror)
        self.git(["reset", "-q", "--hard", self.first])
        self.git(["branch", "-D", "feature"])
        self.commit("new-after-reset")
        self.git(["branch", "brand-new"])
        gm.run_git(["fetch", "--no-tags", "--prune", "--", self.origin, "+refs/heads/*:refs/incoming/heads/*",
                    "+refs/tags/*:refs/incoming/tags/*"], self.mirror, io.StringIO(), 60)
        held = gm.hold_apply(self.mirror, {}, io.StringIO())
        after = self.refs(self.mirror)
        self.assertEqual(after["refs/heads/main"], before["refs/heads/main"])        # rewrite NOT applied
        self.assertEqual(after["refs/heads/feature"], before["refs/heads/feature"])  # deletion NOT applied
        self.assertIn("refs/heads/brand-new", after)                                 # new branch applied
        self.assertEqual({(h["ref"], h["kind"]) for h in held},
                         {("refs/heads/main", "rewritten"), ("refs/heads/feature", "deleted")})
        # "Keep mine" then suppresses the same changes on the next look.
        ignored = {h["ref"]: h["new"] or "deleted" for h in held}
        self.assertEqual(gm.hold_apply(self.mirror, ignored, io.StringIO()), [])


if __name__ == "__main__":
    unittest.main()
