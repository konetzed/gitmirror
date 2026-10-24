#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# gitmirror - self-hosted git mirroring with a web UI
# Copyright (C) 2026 Edward Konetzko
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""gitmirror - keep local bare mirrors of git repos, with a small web UI.

Stdlib only (needs git; git-lfs and openssh-client are optional).
Run:  python3 gitmirror.py [--host 127.0.0.1] [--port 8080] [--data ./data]   (creates <data>/configs, repos and extras)
The same options can be set with GITMIRROR_HOST, GITMIRROR_PORT and GITMIRROR_DATA.
Send SIGHUP (kill -HUP <pid>) to re-exec with the latest code on disk.
The first visit to the web UI asks you to create a username and password (stored hashed in <data>/configs/auth.json).
GITMIRROR_TOKEN is optional: it is the setup code for that first account and a Bearer token for scripts ("Authorization: Bearer <token>").
"""
import argparse, base64, hashlib, hmac, http.cookies, ipaddress, json, os, re, secrets, shutil, signal, socket, subprocess, sys, threading, time, urllib.parse, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

__version__ = "0.0.3-beta"
REPO_URL = "https://github.com/konetzed/gitmirror"
API_TOKEN = os.environ.get("GITMIRROR_TOKEN", "")  # optional: setup code for the first account, and a Bearer token for scripts
ROLES = ("viewer", "operator", "admin")  # lowest to highest
KEY_PREFIX = "gm_"               # personal API keys look like gm_<43 random characters>
KEY_ROLES = ("viewer", "operator")  # a key is never an admin, whoever owns it
MAX_KEYS_PER_USER = 20
KEY_TOUCH_SECS = 60              # "last used" is written at most this often per key
TOKEN_ROLE = os.environ.get("GITMIRROR_TOKEN_ROLE", "operator").strip().lower()
if TOKEN_ROLE not in ("viewer", "operator"):  # the script token is never an admin
    TOKEN_ROLE = "operator"
URL_RE = re.compile(r"^(https?://|ssh://|git://|file://|[\w.-]+@[\w.-]+:)")
# file:// lets an operator mirror any repository the service account can read on the server itself: off unless asked for
ALLOW_FILE_REMOTES = os.environ.get("GITMIRROR_ALLOW_FILE_REMOTES", "0").lower() in ("1", "true", "yes")
GIT_ENV = {
    **os.environ,
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ALLOW_PROTOCOL": "https:http:git:ssh:file",  # blocks ext:: and friends
    "GIT_SSH_COMMAND": os.environ.get("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new"),
}
LOG_KEEP = 20000


DEFAULTS = {"update_check": os.environ.get("GITMIRROR_UPDATE_CHECK", "1") not in ("0", "false", "no"), "lfs_auto": False, "lfs_auto_max_gb": 5, "github_token": "", "low_disk_gb": 5, "fsck_interval": 30 * 24 * 60, "extras_default": ["wiki"], "release_asset_max_mb": 200, "retry_delay": 15, "retry_max": 360, "max_parallel": 4, "hold_default": False, "theme": "auto", "light_theme": "light", "dark_theme": "dark", "colorblind": False, "default_interval": 3 * 24 * 60, "timeout": int(os.environ.get("GITMIRROR_TIMEOUT", "1800"))}
SETTING_RANGES = {"timeout": (10, 86400), "max_parallel": (1, 32), "low_disk_gb": (0, 100000), "release_asset_max_mb": (0, 102400), "lfs_auto_max_gb": (0, 100000)}
EXTRA_KEYS = ("wiki", "lfs", "releases", "issues")
CFG = {}  # live reference to Store.settings, for helpers that run outside a Store method


def load_json(path, default=None):
    with open(path) as f:
        return json.load(f)


def parse_interval(v):
    """'1W', '3D', '2H30M', '90M' or a bare number (minutes) -> minutes. 0 = manual only."""
    if isinstance(v, bool):
        raise ValueError("bad interval")
    if isinstance(v, int):
        mins = v
    else:
        t = str(v).strip().upper().replace(" ", "")
        bad = ValueError("interval must look like 1W, 3D, 12H, 30M or 1D12H (0 = manual only)")
        if len(t) > 40:
            raise bad
        if t.isascii() and t.isdigit():
            mins = int(t)
        else:
            parts, num = [], ""  # read "<digits><unit>" pairs one character at a time: no regex, one pass
            for ch in t:
                if "0" <= ch <= "9":
                    num += ch
                elif ch in "WDHM" and num:
                    parts.append((num, ch))
                    num = ""
                else:
                    raise bad
            if num or not parts:
                raise bad
            units = [u for _, u in parts]
            if units != sorted(set(units), key="WDHM".index):  # each unit at most once, in W D H M order
                raise bad
            n = {u: int(d) for d, u in parts}
            mins = ((n.get("W", 0) * 7 + n.get("D", 0)) * 24 + n.get("H", 0)) * 60 + n.get("M", 0)
    if not 0 <= mins <= 525600:
        raise ValueError("interval must be between 0 and 1 year")
    return mins


def format_interval(mins):
    if not mins:
        return "0"
    out = ""
    for unit, size in (("W", 10080), ("D", 1440), ("H", 60), ("M", 1)):
        n, mins = divmod(mins, size)
        if n:
            out += f"{n}{unit}"
    return out


def write_private(path, data, indent=None):
    """Write JSON atomically with owner-only permissions (these files hold password hashes, keys and clone-URL tokens)."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=indent)
    os.replace(tmp, path)


def harden_permissions(data_dir, cfg_dir):
    """Make the data folder private to the user running gitmirror, and tighten files written by older versions.
    GITMIRROR_PRIVATE_DATA=0 skips this (for example when a backup tool running as another user has to read the folder)."""
    if os.name != "posix" or os.environ.get("GITMIRROR_PRIVATE_DATA", "1").lower() in ("0", "false", "no"):
        return
    for d in (data_dir, cfg_dir):
        try:
            os.chmod(d, 0o700)
        except OSError:  # not ours to change (a mount owned by someone else): leave it alone
            pass
    for f in os.listdir(cfg_dir):
        if f.endswith((".json", ".log", ".tmp")):
            try:
                os.chmod(os.path.join(cfg_dir, f), 0o600)
            except OSError:
                pass


# ---- data format version: guards against running an older program on newer data, and gives migrations a place to live
SCHEMA_VERSION = 1
MIGRATIONS = {}  # {target version: function(store)}; run in order when older data is opened, after a backup of configs/


class SchemaTooNew(RuntimeError):
    pass


def check_schema(data_dir, cfg_dir):
    """The data format version recorded in the folder (0 = written before versions existed, current for a new folder)."""
    path = os.path.join(cfg_dir, "version.json")
    stored = None
    if os.path.exists(path):
        try:
            stored = int(load_json(path).get("schema", 0))
        except (ValueError, TypeError, OSError):
            stored = 0
    else:
        existing = any(os.path.exists(os.path.join(cfg_dir, f)) for f in ("mirrors.json", "auth.json", "settings.json", "sources.json"))
        stored = 0 if existing else SCHEMA_VERSION
    if stored > SCHEMA_VERSION and os.environ.get("GITMIRROR_IGNORE_SCHEMA", "0").lower() not in ("1", "true", "yes"):
        raise SchemaTooNew(f"This data folder was written by a newer gitmirror (data format {stored}; this version understands up to "
                           f"{SCHEMA_VERSION}). Running an older version on it could damage it. Start the newer version again, or restore a "
                           f"backup. (GITMIRROR_IGNORE_SCHEMA=1 overrides this at your own risk.)")
    return stored


def migrate_schema(store, stored):
    if stored >= SCHEMA_VERSION:
        return
    backup = os.path.join(store.data, "backups", f"configs-before-format-{SCHEMA_VERSION}-{time.strftime('%Y%m%dT%H%M%S')}")
    try:
        shutil.copytree(store.cfg_dir, backup, ignore=shutil.ignore_patterns("*.log", "*.tmp"))
    except OSError:
        pass  # a missing backup must not stop the upgrade; the files are only read by the steps below
    for v in range(stored + 1, SCHEMA_VERSION + 1):
        if MIGRATIONS.get(v):
            MIGRATIONS[v](store)


class Store:
    def __init__(self, data):
        self.data = os.path.abspath(data)
        self.repos_dir = os.path.join(self.data, "repos")
        self.cfg_dir = os.path.join(self.data, "configs")
        self.cfg = os.path.join(self.cfg_dir, "mirrors.json")
        os.makedirs(self.repos_dir, exist_ok=True)
        os.makedirs(self.cfg_dir, exist_ok=True)
        harden_permissions(self.data, self.cfg_dir)
        stored_schema = check_schema(self.data, self.cfg_dir)
        self.lock = threading.Lock()
        self.running = set()
        self.settings_path = os.path.join(self.cfg_dir, "settings.json")
        self.settings = dict(DEFAULTS)
        if os.path.exists(self.settings_path):
            self.settings.update(load_json(self.settings_path))
        CFG.clear()
        CFG["_ref"] = self.settings
        global FORGES_PATH
        FORGES_PATH = os.path.join(self.cfg_dir, "forges.json")
        if os.path.exists(FORGES_PATH):
            FORGES.update(load_json(FORGES_PATH))
        self.stats_path = os.path.join(self.cfg_dir, "stats.json")
        self.stats = {"saved_bytes": 0, "optimized_at": 0}
        if os.path.exists(self.stats_path):
            self.stats.update(load_json(self.stats_path))
        self.opt = {"active": False}
        self.sources_path = os.path.join(self.cfg_dir, "sources.json")
        self.sources = load_json(self.sources_path) if os.path.exists(self.sources_path) else []
        self.scanning = set()
        self.auth_path = os.path.join(self.cfg_dir, "auth.json")
        raw = load_json(self.auth_path) if os.path.exists(self.auth_path) else {}
        if "users" in raw:
            self.users = raw["users"]
        elif raw.get("user") and raw.get("hash"):  # the single account from before roles existed becomes the admin
            self.users = {raw["user"].casefold(): {"name": raw["user"], "hash": raw["hash"], "role": "admin", "created": raw.get("created", time.time())}}
        else:
            self.users = {}
        self.audit_path = os.path.join(self.cfg_dir, "audit.json")
        self.audit = load_json(self.audit_path) if os.path.exists(self.audit_path) else []
        self.sessions_path = os.path.join(self.cfg_dir, "sessions.json")
        self.sessions = load_json(self.sessions_path) if os.path.exists(self.sessions_path) else {}
        if self.users and "users" not in raw:
            self.save_auth()
        self.update_info = {"checked": 0, "latest": None, "error": ""}
        self.heartbeat = time.time()
        self.history_path = os.path.join(self.cfg_dir, "history.json")
        self.history = load_json(self.history_path) if os.path.exists(self.history_path) else []
        self.mirrors = load_json(self.cfg) if os.path.exists(self.cfg) else []
        for m in self.mirrors:  # anything "running" at crash time is not running now
            if m.get("status") == "running":
                m["status"] = "error"
        migrate_schema(self, stored_schema)
        write_private(os.path.join(self.cfg_dir, "version.json"),
                      {"schema": max(stored_schema, SCHEMA_VERSION), "written_by": __version__, "updated": time.time()}, indent=2)

    def save(self):
        self._write_private(self.cfg, self.mirrors, indent=2)

    def _write_private(self, path, data, indent=None):
        write_private(path, data, indent)

    def save_auth(self):
        self._write_private(self.auth_path, {"users": self.users})

    def save_audit(self):
        self._write_private(self.audit_path, self.audit)

    def save_sessions(self):
        self._write_private(self.sessions_path, self.sessions)

    def save_sources(self):
        self._write_private(self.sources_path, self.sources, indent=2)

    def source(self, sid):
        return next((x for x in self.sources if x["id"] == sid), None)

    def save_history(self):
        self._write_private(self.history_path, self.history)

    def save_stats(self):
        self._write_private(self.stats_path, self.stats, indent=2)

    def save_settings(self):
        self._write_private(self.settings_path, self.settings, indent=2)

    def get(self, mid):
        return next((m for m in self.mirrors if m["id"] == mid), None)

    def path(self, mid):
        return os.path.join(self.repos_dir, mid + ".git")

    def wiki_path(self, mid):
        return os.path.join(self.repos_dir, mid + ".wiki.git")

    def extras_dir(self, mid):
        return os.path.join(self.data, "extras", mid)

    def logpath(self, mid):
        return os.path.join(self.cfg_dir, mid + ".log")


def mask(url):
    """Hide credentials in a clone URL: user:password@ keeps the user name, a bare token@ on http(s) is replaced
    entirely. ssh:// user names such as git@ are not secrets and stay visible (they must survive an export)."""
    url = re.sub(r"(://[^/@:]+:)[^@/]+@", r"\1***@", url or "")
    return re.sub(r"(https?://)[^/@:]+@", r"\1***@", url)


class GitError(RuntimeError):
    def __init__(self, msg, out):
        super().__init__(msg)
        self.out = out


# git output that means "the origin is gone / blocked / private" rather than a transient network problem
MISSING_RE = re.compile(r"repository not found|project not found|returned error: (?:404|410|451|403)|could not read username|"
                        r"terminal prompts disabled|dmca|takedown|access blocked|repository unavailable|"
                        r"does not appear to be a git repository|authentication failed", re.I)
HOLD_CONFIG = (("gc.auto", "0"), ("gc.pruneExpire", "never"), ("gc.reflogExpire", "never"))


def run_git(args, cwd, log, timeout):
    log.write("$ git " + mask(" ".join(args)) + "\n")
    log.flush()
    p = subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    out = mask((p.stdout or "") + (p.stderr or ""))
    log.write(out + ("" if out.endswith("\n") or not out else "\n"))
    if p.returncode:
        last = (out.strip().splitlines() or [""])[-1][:200]
        raise GitError(f"git {args[0]} exited {p.returncode}: {last}", out)
    return out


def git_cfg(repo, *a):
    return subprocess.run(["git", "config", *a], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True).stdout


def protect_repo(repo):
    """Make the mirror archive-safe: our refs/archive/* is never fetched over or pruned, and git never gc-prunes objects."""
    if "^refs/archive/*" not in git_cfg(repo, "--get-all", "remote.origin.fetch").split():
        git_cfg(repo, "--add", "remote.origin.fetch", "^refs/archive/*")
    for k, v in HOLD_CONFIG:
        if git_cfg(repo, "--get", k).strip() != v:
            git_cfg(repo, k, v)


def ref_snapshot(repo):
    p = subprocess.run(["git", "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags"],
                       cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
    return {ref: sha for sha, ref in (l.split(" ", 1) for l in p.stdout.splitlines() if " " in l)}


def archive_changes(repo, pre, post, log):
    """Anything in pre that was deleted or rewritten (non fast-forward) upstream is pinned under refs/archive/<ts>/..."""
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    events = []
    for ref, old in pre.items():
        new = post.get(ref)
        if new == old:
            continue
        if new is not None:
            if subprocess.run(["git", "merge-base", "--is-ancestor", old, new], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL).returncode == 0:
                continue  # normal fast-forward, nothing lost
            kind = "rewritten"
        else:
            kind = "deleted"
        dest = f"refs/archive/{ts}/{ref[len('refs/'):]}"
        subprocess.run(["git", "update-ref", dest, old], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True)
        log.write(f"ARCHIVED {kind} {ref} (was {old[:10]}) -> {dest}\n")
        events.append({"kind": kind, "ref": ref, "old": old, "new": new, "archive": dest})
    return ts, events


def hold_apply(repo, ignored, log):
    """Hold mode, after fetching branches/tags into refs/incoming/*: apply new refs and fast-forwards,
    but leave rewritten or deleted refs alone and return them for review."""
    local = ref_snapshot(repo)
    p = subprocess.run(["git", "for-each-ref", "--format=%(objectname) %(refname)", "refs/incoming"],
                       cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
    inc = {"refs/" + ref[len("refs/incoming/"):]: sha for sha, ref in (l.split(" ", 1) for l in p.stdout.splitlines() if " " in l)}
    held = []
    for ref, new in inc.items():
        old = local.get(ref)
        if old == new:
            continue
        if old is None:
            subprocess.run(["git", "update-ref", ref, new], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True)
            log.write(f"NEW {ref} -> {new[:10]}\n")
        elif subprocess.run(["git", "merge-base", "--is-ancestor", old, new], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL).returncode == 0:
            subprocess.run(["git", "update-ref", ref, new, old], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True)
            log.write(f"FAST-FORWARD {ref} {old[:10]} -> {new[:10]}\n")
        elif ignored.get(ref) != new:
            held.append({"ref": ref, "old": old, "new": new, "kind": "rewritten"})
    for ref, old in local.items():
        if ref not in inc and ignored.get(ref) != "deleted":
            held.append({"ref": ref, "old": old, "new": None, "kind": "deleted"})
    for h in held:
        log.write(f"HELD {h['kind']} {h['ref']} (yours {h['old'][:10]}, upstream {(h['new'] or 'gone')[:10]})\n")
    return held


def resolve_held(store, mid, accept):
    """Accept: apply the held changes, pinning the old versions under refs/archive. Keep mine: ignore them until upstream changes again."""
    with store.lock:
        m = store.get(mid)
        if not m or mid in store.running:
            return None
        held = list(m.get("held") or [])
        store.running.add(mid)
    repo, ts, now = store.path(mid), time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), time.time()
    try:
        if accept:
            for h in held:
                dest = f"refs/archive/{ts}/{h['ref'][len('refs/'):]}"
                subprocess.run(["git", "update-ref", dest, h["old"]], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True)
                if h["new"]:
                    subprocess.run(["git", "update-ref", h["ref"], h["new"]], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True)
                else:
                    subprocess.run(["git", "update-ref", "-d", h["ref"]], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True)
    finally:
        size = mirror_size(store, mid)  # walks the repo: do it before taking the lock
        with store.lock:
            store.running.discard(mid)
            m = store.get(mid)
            if m:
                if accept:
                    summary = f"Accepted {len(held)} held change(s). Old versions kept under refs/archive/{ts}/"
                else:
                    m.setdefault("ignored", {}).update({h["ref"]: h["new"] or "deleted" for h in held})
                    summary = f"Kept your versions of {len(held)} ref(s); those upstream changes are ignored."
                m["held"] = []
                m.setdefault("events", []).append({"time": now, "type": "held_accepted" if accept else "held_rejected",
                                                   "alert": False, "summary": summary, "refs": held[:200]})
                m["size"] = size
                store.save()
    return len(held)


def sync(store, mid):
    if disk_info(store)["stopped"]:
        with store.lock:
            m = store.get(mid)
            if m:
                m["error"] = "Not syncing: less than 1 GB free on the data disk."
                store.save()
        return False
    with store.lock:
        m = store.get(mid)
        if not m or mid in store.running:
            return False
        store.running.add(mid)
        m["status"] = "running"
        m["last_run"] = time.time()
        m.pop("sync_now", None)
        src = m["source"]
        hold = bool(m.get("hold"))
        ex = dict(m.get("extras") or {})
        prev_lfs = dict(m.get("lfs_detect") or {})
        prev_extra = json.loads(json.dumps(m.get("extras_state") or {}))
        ignored = dict(m.get("ignored") or {})
        timeout = store.settings["timeout"]
    t0, err, missing, pre, post, held = time.time(), "", False, None, None, None
    repo = store.path(mid)
    ts, changes = "", []
    extra_state, extra_events = {}, []
    lfs_info, lfs_auto_on = None, False
    try:
        with open(store.logpath(mid), "w") as log:
            try:
                if needs_clone(repo):
                    clone_mirror(src, repo, store.repos_dir, log, timeout)
                    protect_repo(repo)
                elif hold:
                    protect_repo(repo)
                    # fetch from the URL, not the "origin" remote: a named remote also opportunistically
                    # force-updates its configured refs/* tracking refs, which would defeat the hold
                    run_git(["fetch", "--no-tags", "--prune", "--", src, "+refs/heads/*:refs/incoming/heads/*",
                             "+refs/tags/*:refs/incoming/tags/*"], repo, log, timeout)
                    held = hold_apply(repo, ignored, log)
                else:
                    protect_repo(repo)
                    pre = ref_snapshot(repo)
                    run_git(["remote", "update", "--prune"], repo, log, timeout)
            except Exception as e:
                err = str(e)
                if isinstance(e, subprocess.TimeoutExpired):
                    err = f"timed out after {timeout}s"
                elif isinstance(e, GitError) and MISSING_RE.search(e.out):
                    missing = True
                    err = ("Origin unavailable (deleted, private, blocked or taken down). "
                           "Your local mirror is untouched. " + err)
            if pre is not None:  # even after a failed fetch: pin whatever the update changed or removed
                post = ref_snapshot(repo)
                ts, changes = archive_changes(repo, pre, post, log)
            if not err and os.path.isdir(repo):
                lfs_info = detect_lfs(repo, prev_lfs)
                cfg = store.settings
                if (lfs_info.get("used") and lfs_info.get("installed") and not ex.get("lfs") and cfg["lfs_auto"]
                        and (lfs_info.get("bytes") or 0) <= cfg["lfs_auto_max_gb"] * 1e9):
                    ex["lfs"], lfs_auto_on = True, True  # fetched in this same sync, below
            if not err and any(ex.values()) and not disk_info(store)["stopped"]:
                try:
                    extra_state, extra_events = run_extras(store, mid, src, ex, repo, timeout, log, prev_extra)
                except Exception as e:  # an extras problem must never fail the sync itself
                    log.write(f"extras failed: {e}\n")
    except Exception as e:
        err = err or str(e)
    now = time.time()
    size = mirror_size(store, mid)  # walks the whole repo tree: never do that while holding the lock
    with store.lock:
        m = store.get(mid)
        store.running.discard(mid)
        if m:
            m["status"] = "error" if err else "ok"
            m["error"] = err
            m["duration"] = round(now - t0, 1)
            if not err:
                m["last_ok"] = now
                m["failures"] = 0
                m.pop("retry_at", None)
            else:  # exponential backoff: retry sooner than the normal interval, but not hammering
                m["failures"] = m.get("failures", 0) + 1
                d = None if missing else retry_delay_min(store.settings, m["failures"])
                iv = m.get("interval", 0)
                if d is not None and iv > 0 and m.get("enabled", True):
                    m["retry_at"] = now + min(d, iv) * 60
                else:
                    m.pop("retry_at", None)
            events = m.setdefault("events", [])
            if extra_state:
                m.setdefault("extras_state", {}).update(extra_state)
                events.extend(extra_events)
            if lfs_info is not None:
                m["lfs_detect"] = lfs_info
            if lfs_auto_on:
                m.setdefault("extras", {})["lfs"] = True
                events.append({"time": now, "type": "lfs_enabled", "alert": False,
                               "summary": f"Git LFS archiving turned on automatically ({lfs_info.get('files')} files, {round((lfs_info.get('bytes') or 0) / 1e6)} MB)."})
            if held is not None:
                prev = {(h["ref"], h["new"]) for h in m.get("held") or []}
                m["held"] = held
                if held and {(h["ref"], h["new"]) for h in held} != prev:
                    events.append({"time": now, "type": "held", "alert": True, "refs": held[:200],
                                   "summary": f"{len(held)} upstream change(s) held for review. Nothing was applied."})
            if changes:
                rew = sum(e["kind"] == "rewritten" for e in changes)
                dele = sum(e["kind"] == "deleted" for e in changes)
                heads_pre = sum(r.startswith("refs/heads/") for r in pre)
                heads_post = sum(r.startswith("refs/heads/") for r in post)
                wiped = (heads_pre > 0 and heads_post == 0) or dele >= max(1, len(pre) // 2)
                summary = f"{rew} ref(s) rewritten, {dele} deleted upstream. Old versions kept under refs/archive/{ts}/"
                if wiped:
                    m["alert"] = "Origin looks wiped or reset: " + summary
                elif rew:
                    m["alert"] = "Origin rewrote history: " + summary
                events.append({"time": now, "type": "history_changed", "alert": wiped or bool(rew),
                               "summary": summary, "refs": changes[:200]})
            if missing and not m.get("origin_missing"):
                m["origin_missing"] = now
                m["alert"] = "Origin is no longer reachable. The local mirror is kept as an archive."
                events.append({"time": now, "type": "origin_missing", "alert": True, "summary": err})
            elif not err and m.get("origin_missing"):
                m.pop("origin_missing")
                if (m.get("alert") or "").startswith("Origin is no longer reachable"):
                    m.pop("alert")
                events.append({"time": now, "type": "origin_back", "alert": False, "summary": "Origin is reachable again."})
            del events[:-100]
            m["size"] = size
            store.save()
    return True


def optimize_one(store, mid):
    """git gc one mirror (repack, nothing is deleted: gc.pruneExpire=never). Returns bytes saved or None if skipped."""
    with store.lock:
        m = store.get(mid)
        if not m or mid in store.running or not os.path.isdir(store.path(mid)):
            return None
        store.running.add(mid)  # blocks a sync from starting on this repo meanwhile
        timeout = store.settings["timeout"]
    repo = store.path(mid)
    before = dir_size(repo)
    try:
        protect_repo(repo)
        subprocess.run(["git", "-c", "repack.writeBitmaps=false", "-c", "gc.writeCommitGraph=false", "gc", "--quiet"], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        pass
    after = dir_size(repo)
    saved = max(0, before - after)
    size = mirror_size(store, mid)
    with store.lock:
        store.running.discard(mid)
        m = store.get(mid)
        if m:
            m["size"] = size
            m["saved"] = m.get("saved", 0) + saved
            m["optimized_at"] = time.time()
        store.stats["saved_bytes"] += saved
        store.stats["optimized_at"] = time.time()
        store.save()
        store.save_stats()
    return saved


def fsck_one(store, mid):
    """git fsck --connectivity-only: finds missing or corrupt objects without re-reading every blob. Returns 1 if it found problems."""
    with store.lock:
        m = store.get(mid)
        if not m or mid in store.running or not os.path.isdir(store.path(mid)):
            return None
        store.running.add(mid)
        timeout = store.settings["timeout"]
    ok, tail = True, ""
    try:
        p = subprocess.run(["git", "fsck", "--connectivity-only", "--no-dangling"], cwd=store.path(mid), env=GIT_ENV, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=timeout)
        ok, tail = p.returncode == 0, (p.stdout + p.stderr).strip()[-600:]
    except subprocess.TimeoutExpired:
        ok, tail = False, f"timed out after {timeout}s"
    except OSError as e:
        ok, tail = False, str(e)
    now = time.time()
    with store.lock:
        store.running.discard(mid)
        m = store.get(mid)
        if m:
            m["fsck"] = {"time": now, "ok": ok, "output": tail}
            ev = m.setdefault("events", [])
            if not ok:
                m["alert"] = "Integrity check failed: " + (tail.splitlines() or ["see the repo page"])[0][:200]
                ev.append({"time": now, "type": "fsck_failed", "alert": True, "summary": tail[:300]})
            elif (m.get("alert") or "").startswith("Integrity check failed"):
                m.pop("alert")
                ev.append({"time": now, "type": "fsck_ok", "alert": False, "summary": "Integrity check passes again."})
            del ev[:-100]
        store.save()
    return 0 if ok else 1


def run_job(store, ids, fn, label):
    """Run fn(store, id) over ids one at a time, with progress in store.opt. Only one such job at a time."""
    with store.lock:
        if store.opt.get("active"):
            return False
        store.opt = {"active": True, "label": label, "total": len(ids), "done": 0, "current": "", "result": 0}
    try:
        for mid in ids:
            with store.lock:
                m = store.get(mid)
                store.opt["current"] = m["name"] if m else ""
            res = fn(store, mid)
            with store.lock:
                store.opt["done"] += 1
                store.opt["result"] += res or 0
    finally:
        with store.lock:
            store.opt["active"] = False
            store.opt["current"] = ""
    return True


def stats_out(store):
    with store.lock:
        di = disk_info(store)
    return {"disk_free": di["free"], "disk_total": di["total"], "low_disk": di["low"], "syncs_paused": di["stopped"],
            "projects": len(store.mirrors), "disk_bytes": sum(m.get("size") or 0 for m in store.mirrors),
                "saved_bytes": store.stats["saved_bytes"], "optimized_at": store.stats["optimized_at"],
                "optimize": dict(store.opt)}


def maint_rows(store, kind, limit):
    with store.lock:
        rows = [public(m, store) for m in store.mirrors]
    if kind == "size":
        rows.sort(key=lambda r: -(r.get("size") or 0))
    elif kind == "oldest":
        rows.sort(key=lambda r: r.get("added") or 0)  # mirrors from before dates were tracked sort first
    elif kind == "lfs":
        rows = [r for r in rows if r.get("lfs_needed")]
        rows.sort(key=lambda r: -((r.get("lfs_detect") or {}).get("bytes") or 0))
    else:
        rows = [r for r in rows if r.get("status") == "error" or r.get("origin_missing") or not r.get("enabled", True) or r.get("alert")]
        rows.sort(key=lambda r: (not r.get("origin_missing"), r.get("status") != "error", r.get("name", "").lower()))
    keep = ("id", "name", "added", "last_ok", "last_run", "size", "status", "enabled", "tags", "error", "alert",
            "origin_missing", "saved", "optimized_at", "running", "lfs_needed", "lfs_detect")
    return {"total": len(rows), "rows": [{k: r.get(k) for k in keep} for r in rows[:limit]]}


def dir_size(p):
    total = 0
    for root, _, files in os.walk(p):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


DISK_STOP_BYTES = 1 << 30  # below this much free space no sync is started: a full disk can corrupt mirrors
HISTORY_EVERY = 6 * 3600


def disk_info(store):
    try:
        u = shutil.disk_usage(store.data)
    except OSError:
        return {"free": None, "total": None, "low": False, "stopped": False}
    low = store.settings["low_disk_gb"] * (1 << 30)
    return {"free": u.free, "total": u.total, "low": bool(low) and u.free < low, "stopped": u.free < DISK_STOP_BYTES}


def summary_out(store):
    now = time.time()
    with store.lock:
        ms = list(store.mirrors)
        d = {"projects": len(ms), "disk_bytes": sum(m.get("size") or 0 for m in ms),
             "failing": sum(1 for m in ms if m.get("status") == "error"),
             "held": sum(len(m.get("held") or []) for m in ms),
             "alerts": sum(1 for m in ms if m.get("alert")),
             "syncing": len(store.running), "paused": sum(1 for m in ms if not m.get("enabled", True)),
             "origin_missing": sum(1 for m in ms if m.get("origin_missing")),
             "lfs_unmirrored": sum(1 for m in ms if (m.get("lfs_detect") or {}).get("used") and not (m.get("extras") or {}).get("lfs")),
             "pending_approval": sum(c["pending"] for c in (src_counts(x) for x in store.sources)),
             "sources": len(store.sources), "saved_bytes": store.stats["saved_bytes"],
             "last_sync_ok": max((m.get("last_ok") or 0 for m in ms), default=0)}
        oks = [m.get("last_ok") or 0 for m in ms if m.get("enabled", True) and m.get("interval")]
        d["stalest_sync_hours"] = round((now - min(oks)) / 3600, 1) if oks and min(oks) else None
    di = disk_info(store)
    d.update(disk_free_bytes=di["free"], disk_total_bytes=di["total"], low_disk=di["low"], syncs_paused_disk_full=di["stopped"])
    return d


def retry_delay_min(settings, failures):
    """Minutes to wait before retry number `failures` (1-based): delay doubles each time, capped. None = retries off."""
    base = settings["retry_delay"]
    if base <= 0:
        return None
    return min(base * 2 ** min(failures - 1, 20), max(settings["retry_max"], base))


def next_due(m):
    if m.get("status") == "new" or m.get("sync_now"):
        return 0  # created in bulk (a Source) and never synced yet
    iv = m.get("interval", 0) * 60
    if iv <= 0 or not m.get("enabled", True):
        return None
    nxt = m.get("last_run", 0) + iv
    if m.get("retry_at"):
        nxt = min(nxt, m["retry_at"])
    return nxt


def scheduler(store):
    while True:
        time.sleep(5)
        now = time.time()
        store.heartbeat = now
        try:
            if not store.history or now - store.history[-1]["t"] >= HISTORY_EVERY:
                with store.lock:
                    store.history.append({"t": now, "disk": sum(m.get("size") or 0 for m in store.mirrors), "n": len(store.mirrors)})
                    del store.history[:-2000]
                    store.save_history()
        except OSError:
            pass
        ui = store.update_info
        if (store.settings.get("update_check") and os.environ.get("GITMIRROR_UPDATE_CHECK", "1") not in ("0", "false", "no")
                and now - ui.get("checked", 0) >= (3600 if ui.get("error") else 6 * 3600)):
            store.update_info = dict(ui, checked=now)  # claim the slot so a slow check isn't started twice
            threading.Thread(target=check_update, args=(store,), daemon=True).start()
        stopped = disk_info(store)["stopped"]
        with store.lock:
            room = 0 if stopped else store.settings["max_parallel"] - len(store.running)
            due = sorted((nd, m["id"]) for m in store.mirrors
                         if m["id"] not in store.running and (nd := next_due(m)) is not None and now >= nd)
            ids = [mid for _, mid in due[:max(room, 0)]]  # most overdue first
        for mid in ids:
            threading.Thread(target=sync, args=(store, mid), daemon=True).start()
        with store.lock:
            scans = [x["id"] for x in store.sources if x.get("rescan", 0) > 0 and x["id"] not in store.scanning
                     and now - x.get("last_scan", 0) >= x["rescan"] * 60]
        for sid in scans:
            threading.Thread(target=scan_source, args=(store, sid), daemon=True).start()
        fi = store.settings["fsck_interval"] * 60
        if fi and not stopped and not store.opt.get("active"):  # integrity checks, one at a time, quietly in the background
            with store.lock:
                due = [(m.get("fsck", {}).get("time") or m.get("added") or 0, m["id"]) for m in store.mirrors
                       if m["id"] not in store.running and m.get("last_ok") and now - (m.get("fsck", {}).get("time") or m.get("added") or 0) >= fi
                       and len(store.running) < store.settings["max_parallel"]]
            if due:
                threading.Thread(target=fsck_one, args=(store, min(due)[1]), daemon=True).start()


def settings_out(store):
    out = dict(store.settings)
    out["github_token_set"] = bool(out.pop("github_token", "") or os.environ.get("GITMIRROR_GITHUB_TOKEN"))
    for k in ("default_interval", "retry_delay", "retry_max", "fsck_interval"):
        out[k + "_text"] = format_interval(store.settings[k])
    return out


def public(m, store, full=False):
    d = dict(m, source=mask(m["source"]), interval_text=format_interval(m.get("interval", 0)))
    d["event_count"] = len(d.get("events") or [])
    d["held_count"] = len(d.get("held") or [])
    d["lfs_needed"] = bool((d.get("lfs_detect") or {}).get("used") and not (d.get("extras") or {}).get("lfs"))
    src = store.source(m.get("source_id")) if m.get("source_id") else None
    if src:
        d["source_name"] = src["name"]
    nd = next_due(m)
    if nd is not None:
        d["next_run"] = nd
    if not full:
        d.pop("events", None)
        d.pop("held", None)
    d["running"] = m["id"] in store.running
    return d


# ---- forge detection: which software runs at a host (GitHub, GitLab, Gitea/Forgejo, GitHub Enterprise)
KNOWN_FORGES = {"github.com": "github", "www.github.com": "github", "codeberg.org": "gitea", "bitbucket.org": "bitbucket"}
FORGES = {}  # "host[:port]" -> {"kind": ..., "t": probe time}; remembered across restarts in configs/forges.json
FORGES_PATH = None
FORGE_LOCK = threading.Lock()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # a probe must never be bounced to some other host


_probe_opener = urllib.request.build_opener(_NoRedirect)

# ---- outbound requests. The server must never be talked into reading something on its own machine or on the link-local
# range (cloud metadata lives at 169.254.169.254). Private networks are fine when an operator chose the host (a forge on the
# LAN) but not when a third party did (a release asset link in a mirrored project). GITMIRROR_ALLOW_LOCAL_HOSTS=1 lifts the
# loopback/link-local rule for development and tests.
ALLOW_LOCAL_HOSTS = os.environ.get("GITMIRROR_ALLOW_LOCAL_HOSTS", "0").lower() in ("1", "true", "yes")


def host_problem(host, allow_private):
    """Why this host must not be contacted, or None. The name is resolved and every address it has must pass."""
    if not host:
        return "no host in URL"
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return f"cannot resolve {host}"
    for info in infos:
        try:
            a = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        if a.is_link_local or a.is_multicast:
            return f"{host} is a local address"  # 169.254.169.254 and friends: no override
        if a.is_loopback or a.is_unspecified:
            if not ALLOW_LOCAL_HOSTS:
                return f"{host} is a local address"
        elif a.is_private and not allow_private:
            return f"{host} is on a private network"
    return None


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to hosts that pass the same policy, and never carry an Authorization header to another host."""

    def __init__(self, allow_private):
        self.allow_private = allow_private

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = urllib.parse.urlparse(newurl)
        why = None if new.scheme in ("http", "https") else "redirect to a non-http URL"
        why = why or host_problem(new.hostname, self.allow_private)
        if why:
            raise urllib.error.HTTPError(newurl, code, "redirect refused: " + why, headers, fp)
        r = super().redirect_request(req, fp, code, msg, headers, newurl)
        if r is not None and (new.hostname or "").lower() != (urllib.parse.urlparse(req.full_url).hostname or "").lower():
            r.remove_header("Authorization")
        return r


def open_url(url, headers, timeout, allow_private):
    """urlopen with the outbound policy applied to the URL and to every redirect hop. Raises RuntimeError when refused."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        raise RuntimeError("not an http(s) URL")
    why = host_problem(p.hostname, allow_private)
    if why:
        raise RuntimeError("refused: " + why)
    return urllib.request.build_opener(_GuardedRedirect(allow_private)).open(urllib.request.Request(url, headers=headers), timeout=timeout)


def save_forges():
    if not FORGES_PATH:
        return
    with FORGE_LOCK:
        write_private(FORGES_PATH, FORGES, indent=2)


def _probe_get(url):
    """(status, parsed json or None). Network failures raise OSError."""
    why = host_problem(urllib.parse.urlparse(url).hostname, allow_private=True)
    if why:
        raise OSError(why)  # treated like an unreachable host
    req = urllib.request.Request(url, headers={"User-Agent": "gitmirror", "Accept": "application/json"})
    try:
        r = _probe_opener.open(req, timeout=3)
        code, raw = r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read(65536)
    try:
        return code, json.loads(raw or b"null")
    except ValueError:
        return code, None


def probe_forge(scheme, hostport):
    """'gitea' | 'gitlab' | 'github' | 'unknown', or None when the host couldn't be reached at all."""
    base = f"{scheme}://{hostport}"
    tests = (
        ("gitea", "/api/v1/version", lambda c, b: isinstance(b, dict) and (
            (c == 200 and "version" in b) or (c in (401, 403) and "/api/swagger" in str(b.get("url", ""))))),
        ("gitlab", "/api/v4/version", lambda c, b: isinstance(b, dict) and (
            (c == 200 and "version" in b) or (c == 401 and "message" in b))),
        ("github", "/api/v3/", lambda c, b: c == 200 and isinstance(b, dict) and "current_user_url" in b),
    )
    unreachable = 0
    for kind, path, ok in tests:
        try:
            code, body = _probe_get(base + path)
        except OSError:
            unreachable += 1
            continue
        if ok(code, body):
            return kind
    return None if unreachable == len(tests) else "unknown"


def forge_kind(scheme, hostport, probe=True):
    h = hostport.lower()
    if h in KNOWN_FORGES:
        return KNOWN_FORGES[h]
    if "gitlab" in h.split(":")[0]:
        return "gitlab"
    c = FORGES.get(h)
    if c and (c["kind"] != "unknown" or time.time() - c["t"] < 3600):
        return c["kind"]
    if not probe or scheme not in ("http", "https"):
        return None
    kind = probe_forge(scheme, h)
    if kind is not None:  # an unreachable host isn't cached, so a later retry can still succeed
        FORGES[h] = {"kind": kind, "t": time.time()}
        save_forges()
    return kind


def normalize_url(u):
    """Turn a forge web page URL into its clone URL; leave anything else alone."""
    m = re.match(r"^(https?)://([^/@]+)(/[^?#]*)", u)
    if not m:
        return u
    scheme, hostport, path = m.groups()
    segs = [x for x in path.split("/") if x]
    if len(segs) < 2:
        return u
    kind = forge_kind(scheme, hostport, probe=not segs[-1].endswith(".git"))  # a .git URL is already a clone URL
    if kind in (None, "unknown"):
        return u
    if kind == "gitlab" and "-" in segs:  # group/sub/repo/-/tree/main
        segs = segs[:segs.index("-")]
    elif kind != "gitlab":
        segs = segs[:2]
    if segs[-1].endswith(".git"):
        segs[-1] = segs[-1][:-4]
    if hostport.lower() in KNOWN_FORGES or "gitlab" in hostport.lower().split(":")[0]:
        scheme = "https"
    return f"{scheme}://{hostport}/{'/'.join(segs)}.git"


def parse_repo(src):
    """(scheme, host[:port], 'group/.../repo', kind) for clone URLs on a recognised forge, else None."""
    for pat, scheme in ((r"^(https?)://([^/@]+)/(.+?)(?:\.git)?/?$", None),
                        (r"^ssh://(?:[\w.-]+@)?([^/:]+)(?::\d+)?/(.+?)(?:\.git)?/?$", "https"),
                        (r"^[\w.-]+@([\w.-]+):(.+?)(?:\.git)?/?$", "https")):
        m = re.match(pat, src)
        if not m:
            continue
        sch, hostport, path = (m.groups() if scheme is None else (scheme, *m.groups()))
        kind = forge_kind(sch, hostport)
        if kind not in (None, "unknown"):
            return sch, hostport, path, kind
    return None


def fetch_meta(src):
    """Best-effort project details from the forge's API. Always returns at least web_url when the host is recognised."""
    pr = parse_repo(src)
    if not pr:
        return {}
    scheme, host, path, kind = pr
    meta = {"web_url": f"{scheme}://{host}/{path}", "fetched": time.time()}
    base = f"{scheme}://{host}"
    q = urllib.parse.quote
    try:
        if kind == "bitbucket":
            return meta
        if kind == "github":
            api = "https://api.github.com" if host.lower() in ("github.com", "www.github.com") else base + "/api/v3"
            url = f"{api}/repos/{q(path, safe='/')}"
        elif kind == "gitlab":
            url = f"{base}/api/v4/projects/{q(path, safe='')}"
        else:  # gitea / forgejo
            url = f"{base}/api/v1/repos/{q(path, safe='/')}"

        def get(u):
            return api_json(u, timeout=10)

        d = get(url)
        meta["platform"] = kind
        if kind == "github":
            meta.update(description=d.get("description"), homepage=d.get("homepage"), stars=d.get("stargazers_count"),
                        forks=d.get("forks_count"), language=d.get("language"), topics=d.get("topics"),
                        default_branch=d.get("default_branch"), archived=d.get("archived"),
                        upstream_updated=d.get("pushed_at"), license=(d.get("license") or {}).get("name"))
        elif kind == "gitlab":
            meta.update(description=d.get("description"), stars=d.get("star_count"), forks=d.get("forks_count"),
                        topics=d.get("topics") or d.get("tag_list"), default_branch=d.get("default_branch"),
                        archived=d.get("archived"), upstream_updated=d.get("last_activity_at"))
        else:
            meta.update(description=d.get("description"), homepage=d.get("website"), stars=d.get("stars_count"),
                        forks=d.get("forks_count"), language=d.get("language"), default_branch=d.get("default_branch"),
                        archived=d.get("archived"), upstream_updated=d.get("updated_at"), topics=d.get("topics"))
            if not meta.get("topics"):  # topics live on their own endpoint in Gitea/Forgejo
                try:
                    meta["topics"] = get(url + "/topics").get("topics")
                except Exception:
                    pass
        # API output is untrusted: coerce types, cap sizes, only allow http(s) links
        for k in ("description", "language", "default_branch", "license", "upstream_updated"):
            meta[k] = str(meta[k])[:500] if meta.get(k) else None
        for k in ("stars", "forks"):
            meta[k] = meta[k] if isinstance(meta.get(k), int) else None
        meta["archived"] = bool(meta.get("archived"))
        hp = meta.get("homepage")
        meta["homepage"] = hp[:300] if isinstance(hp, str) and re.match(r"^https?://", hp) else None
        t = meta.get("topics")
        meta["topics"] = [str(x)[:40] for x in t[:30]] if isinstance(t, list) else []
    except Exception as e:  # network down, 404 on private repo, rate limit...
        meta["fetch_error"] = str(e)[:200]
    return meta


def api_headers(url):
    h = {"User-Agent": "gitmirror", "Accept": "application/json"}
    tok = CFG.get("_ref", {}).get("github_token") or os.environ.get("GITMIRROR_GITHUB_TOKEN")
    if tok and urllib.parse.urlparse(url).hostname == "api.github.com":
        h["Authorization"] = "Bearer " + tok
    return h


def api_json(url, timeout=15, with_headers=False):
    """GET a forge API URL and parse JSON. Raises RuntimeError with a readable message (rate limit hint included)."""
    try:
        r = open_url(url, api_headers(url), timeout, allow_private=True)  # the host was typed by an operator: a LAN forge is fine
        data = json.loads(r.read(8 << 20))
        return (data, r.headers) if with_headers else data
    except urllib.error.HTTPError as e:
        if str(e.msg).startswith("redirect refused"):
            raise RuntimeError(str(e.msg)[:150]) from None
        if e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0":
            raise RuntimeError("GitHub API rate limit reached. Add a GitHub token in Admin.") from None
        raise RuntimeError(f"HTTP {e.code} from {urllib.parse.urlparse(url).netloc}") from None
    except (OSError, ValueError) as e:
        raise RuntimeError(str(e)[:150]) from None


def refresh_meta(store, mid):
    with store.lock:
        m = store.get(mid)
        src = m["source"] if m else None
    if not src:
        return
    meta = fetch_meta(src)
    if not meta:
        return None  # host has no API we know about
    changed = []
    with store.lock:
        m = store.get(mid)
        if m:
            old = m.get("meta") or {}
            if "fetch_error" in meta and old.get("platform"):
                meta = {**old, "fetch_error": meta["fetch_error"]}  # keep last good details on a failed lookup
            else:
                changed = [k for k in meta if k not in ("fetched", "fetch_error") and meta.get(k) != old.get(k)]
            m["meta"] = meta
            store.save()
    return changed


def clean_tags(v):
    if v is None:
        return []
    if isinstance(v, str):
        v = v.split(",")
    if not isinstance(v, list):
        raise ValueError("tags must be a list or comma-separated string")
    out, seen = [], set()
    for t in v:
        t = re.sub(r"\s+", " ", str(t)).strip()[:30]
        if t and t.lower() not in seen:
            if len(out) >= 20:
                raise ValueError("at most 20 tags")
            seen.add(t.lower())
            out.append(t)
    return out


def git_info(store, mid):
    repo = store.path(mid)
    if not os.path.isdir(repo):
        return None

    def g(*a):
        return subprocess.run(["git", *a], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15).stdout

    try:
        refs = g("for-each-ref", "--format=%(refname)").split()
        nb = sum(x.startswith("refs/heads/") for x in refs)
        nt = sum(x.startswith("refs/tags/") for x in refs)
        na = sum(x.startswith("refs/archive/") for x in refs)
        info = {"branches": nb, "tags": nt, "archived_refs": na, "other_refs": len(refs) - nb - nt - na, "head": g("symbolic-ref", "--short", "HEAD").strip()}
        parts = g("log", "-1", "--format=%ct%x09%an%x09%s", "HEAD").rstrip("\n").split("\t", 2)
        if len(parts) == 3 and parts[0].isdigit():
            info["last_commit"] = {"time": int(parts[0]), "author": parts[1], "subject": parts[2]}
        return info
    except (subprocess.SubprocessError, OSError):
        return None


THEME_JS = """<script>(()=>{const D=__THEME_DEFAULTS__,g=k=>{try{return localStorage.getItem('gm-'+k)}catch(e){return null}},
mm=q=>matchMedia(q).matches,r=document.documentElement;
const apply=()=>{let mode=g('theme')||D.mode;if(mode!='light'&&mode!='dark')mode=mm('(prefers-color-scheme:dark)')?'dark':'light';
 const hc=mm('(prefers-contrast:more)'),L=g('light')||(hc&&D.light=='light'?'hc-light':D.light),K=g('dark')||(hc&&D.dark=='dark'?'hc-dark':D.dark),cb=g('cb');
 r.dataset.mode=mode;r.dataset.theme=mode=='dark'?K:L;if(cb===null?D.cb:cb=='1')r.dataset.cb='1';else delete r.dataset.cb;
 return{mode,L,K,cb:r.dataset.cb=='1'}};
window.GM={D,apply,set:(k,v)=>{try{v==null?localStorage.removeItem('gm-'+k):localStorage.setItem('gm-'+k,v)}catch(e){}}};apply();r.dataset.role="__ROLE__"})()</script>
"""


# ---- Sources: follow a whole GitHub/GitLab/Gitea user, org or group
SRC_PAGES = 30
ACCT_CACHE = {}  # url -> (time, acct, repos): the preview and the create step share one listing


def parse_acct_url(url):
    u = (url or "").strip()
    if len(u) > 2000:
        return None
    try:
        p = urllib.parse.urlsplit(u)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.netloc or "@" in p.netloc:
        return None
    return p.scheme, p.netloc, [x for x in p.path.split("/") if x]


def is_account_url(url):
    p = parse_acct_url(url)
    if not p or not p[2]:
        return False
    scheme, host, segs = p
    kind = forge_kind(scheme, host)
    if kind in ("github", "gitea"):
        return len(segs) == 1 or (kind == "github" and len(segs) == 2 and segs[0] == "orgs")
    if kind == "gitlab":
        return segs[0] == "groups" or len(segs) == 1
    return False


def _s(x, n=500):
    return str(x)[:n] if x not in (None, "") else None


def _i(x):
    return x if isinstance(x, int) and not isinstance(x, bool) else None


def _http_url(x, n=300):
    """An http(s) URL from untrusted API output, or None. Keeps javascript: and data: links out of the UI."""
    return x[:n] if isinstance(x, str) and re.match(r"^https?://", x) else None


def account_info(url):
    p = parse_acct_url(url)
    if not p or not p[2]:
        raise ValueError("That doesn't look like an account page (expected https://host/name)")
    scheme, host, segs = p
    kind = forge_kind(scheme, host)
    if kind not in ("github", "gitlab", "gitea"):
        raise ValueError("Only GitHub, GitLab and Gitea/Forgejo accounts are supported")
    q = urllib.parse.quote
    try:
        if kind == "github":
            name = segs[1] if segs[0] == "orgs" and len(segs) > 1 else segs[0]
            base = "https://api.github.com" if host.lower() in ("github.com", "www.github.com") else f"{scheme}://{host}/api/v3"
            info = api_json(f"{base}/users/{q(name)}")
            return {"kind": kind, "scheme": scheme, "hostport": host, "base": base, "name": name, "path": name,
                    "type": "org" if info.get("type") == "Organization" else "user"}
        if kind == "gitlab":
            path = "/".join(segs[1:] if segs[0] == "groups" else segs)
            base = f"{scheme}://{host}/api/v4"
            try:
                g = api_json(f"{base}/groups/{q(path, safe='')}")
                return {"kind": kind, "scheme": scheme, "hostport": host, "base": base, "name": path.split("/")[-1],
                        "path": path, "type": "group", "id": g["id"]}
            except RuntimeError as e:
                if "HTTP 404" not in str(e) or "/" in path:
                    raise
            users = api_json(f"{base}/users?username={q(path)}")
            if not users:
                raise RuntimeError("account not found")
            return {"kind": kind, "scheme": scheme, "hostport": host, "base": base, "name": path, "path": path,
                    "type": "user", "id": users[0]["id"]}
        name = segs[0]
        base = f"{scheme}://{host}/api/v1"
        try:
            api_json(f"{base}/orgs/{q(name)}")
            typ = "org"
        except RuntimeError as e:
            if "HTTP 404" not in str(e):
                raise
            api_json(f"{base}/users/{q(name)}")
            typ = "user"
        return {"kind": kind, "scheme": scheme, "hostport": host, "base": base, "name": name, "path": name, "type": typ}
    except RuntimeError as e:
        raise ValueError(f"Couldn't look up that account: {e}") from None


def list_repos(acct):
    """Every public repo of the account, normalised. Raises on any failure so a partial list is never mistaken for a full one."""
    q, base, kind, name = urllib.parse.quote, acct["base"], acct["kind"], acct["path"]
    if kind == "github":
        url = f"{base}/orgs/{q(name)}/repos?type=public&per_page=100" if acct["type"] == "org" else f"{base}/users/{q(name)}/repos?type=owner&per_page=100"
        per = 100
    elif kind == "gitlab":
        url = (f"{base}/groups/{acct['id']}/projects?include_subgroups=true&per_page=100&order_by=path" if acct["type"] == "group"
               else f"{base}/users/{acct['id']}/projects?per_page=100")
        per = 100
    else:
        url = f"{base}/{'orgs' if acct['type'] == 'org' else 'users'}/{q(name)}/repos?limit=50"
        per = 50
    out = []
    for page in range(1, SRC_PAGES + 1):
        data = api_json(f"{url}&page={page}", timeout=20)
        if not isinstance(data, list):
            raise RuntimeError("unexpected API response")
        for d in data:
            if kind == "github":
                r = dict(path=d.get("full_name"), clone=d.get("clone_url"), html=d.get("html_url"), desc=d.get("description"),
                         stars=d.get("stargazers_count"), forks=d.get("forks_count"), lang=d.get("language"), size=d.get("size"),
                         fork=d.get("fork"), arch=d.get("archived"), topics=d.get("topics"), pushed=d.get("pushed_at"),
                         branch=d.get("default_branch"), wiki=d.get("has_wiki"))
            elif kind == "gitlab":
                r = dict(path=d.get("path_with_namespace"), clone=d.get("http_url_to_repo"), html=d.get("web_url"), desc=d.get("description"),
                         stars=d.get("star_count"), forks=d.get("forks_count"), lang=None, size=None,
                         fork=bool(d.get("forked_from_project")), arch=d.get("archived"), topics=d.get("topics") or d.get("tag_list"),
                         pushed=d.get("last_activity_at"), branch=d.get("default_branch"), wiki=d.get("wiki_enabled"))
            else:
                r = dict(path=d.get("full_name"), clone=d.get("clone_url"), html=d.get("html_url"), desc=d.get("description"),
                         stars=d.get("stars_count"), forks=d.get("forks_count"), lang=d.get("language"), size=d.get("size"),
                         fork=d.get("fork"), arch=d.get("archived"), topics=[], pushed=d.get("updated_at"),
                         branch=d.get("default_branch"), wiki=d.get("has_wiki"))
            if not r["path"] or not isinstance(r["clone"], str) or not URL_RE.match(r["clone"]) or r["clone"].startswith("-"):
                continue
            html = r["html"] if isinstance(r["html"], str) and re.match(r"^https?://", r["html"]) else None
            out.append({"path": str(r["path"])[:300], "name": str(r["path"]).split("/")[-1][:80], "clone": r["clone"], "html": html,
                        "desc": _s(r["desc"]), "stars": _i(r["stars"]), "forks": _i(r["forks"]), "lang": _s(r["lang"], 40),
                        "size_kb": _i(r["size"]), "fork": bool(r["fork"]), "arch": bool(r["arch"]),
                        "topics": [str(t)[:40] for t in (r["topics"] or [])[:30]] if isinstance(r["topics"], list) else [],
                        "pushed": _s(r["pushed"], 40), "branch": _s(r["branch"], 100), "wiki": bool(r["wiki"])})
        if len(data) < per:
            return out
    raise RuntimeError(f"more than {SRC_PAGES * per} repositories; not supported")


def meta_from_repo(repo, kind):
    return {"web_url": repo["html"], "platform": kind, "description": repo["desc"], "homepage": None, "stars": repo["stars"],
            "forks": repo["forks"], "language": repo["lang"], "topics": repo["topics"], "default_branch": repo["branch"],
            "archived": repo["arch"], "upstream_updated": repo["pushed"], "license": None, "fetched": time.time()}


def cached_listing(url, fresh=False):
    c = ACCT_CACHE.get(url)
    if c and not fresh and time.time() - c[0] < 600:
        return c[1], c[2]
    acct = account_info(url)
    try:
        repos = list_repos(acct)
    except RuntimeError as e:
        raise ValueError(f"Couldn't list the repositories: {e}") from None
    ACCT_CACHE[url] = (time.time(), acct, repos)
    return acct, repos


def src_rule(src, repo):
    """'fork' / 'archived' when the Source's filters exclude this repo, else None."""
    if repo["fork"] and not src.get("include_forks"):
        return "fork"
    if repo["arch"] and not src.get("include_archived", True):
        return "archived"
    return None


def src_add_repo(store, src, repo):
    """Mirror one repo of a Source (or link the mirror that already exists). Returns the mirror id."""
    with store.lock:
        m = next((x for x in store.mirrors if norm_src(x["source"]) == norm_src(repo["clone"])), None)
    owner_tag = src["name"]
    if m:
        with store.lock:
            m["source_id"] = src["id"]
            if owner_tag.lower() not in [t.lower() for t in m.get("tags", [])]:
                m.setdefault("tags", []).append(owner_tag)
            store.save()
        return m["id"]
    tags = clean_tags([owner_tag] + list(src.get("tags", [])))
    return create_mirror(store, repo["clone"], repo["name"], tags, src["interval"], src["hold"], src["id"],
                         meta_from_repo(repo, src["kind"]), dict(src["extras"]), start=False)["id"]


def known_entry(repo, state, reason=None, mirror=None):
    return {"state": state, "reason": reason, "mirror": mirror, "name": repo["name"], "clone": repo["clone"], "html": repo["html"],
            "desc": repo["desc"], "stars": repo["stars"], "size_kb": repo["size_kb"], "fork": repo["fork"], "arch": repo["arch"]}


def src_event(src, typ, summary, alert=False):
    src.setdefault("events", []).append({"time": time.time(), "type": typ, "summary": summary, "alert": alert})
    del src["events"][:-100]


def create_source(store, url, selected, opts):
    acct, repos = cached_listing(url)
    sid = uuid.uuid4().hex[:10]
    src = {"id": sid, "url": url, "name": acct["name"], "kind": acct["kind"], "scheme": acct["scheme"], "hostport": acct["hostport"],
           "account_type": acct["type"], "added": time.time(), "last_scan": time.time(), "last_error": "",
           "tags": clean_tags(opts.get("tags")), "interval": opts["interval"], "hold": opts["hold"], "extras": opts["extras"],
           "include_forks": opts["include_forks"], "include_archived": opts["include_archived"], "auto_add": opts["auto_add"],
           "rescan": opts["rescan"], "known": {}, "events": []}
    with store.lock:
        store.sources.append(src)
        store.save_sources()
    chosen = set(selected)
    for repo in repos:
        if repo["path"] in chosen:
            mid = src_add_repo(store, src, repo)
            src["known"][repo["path"]] = known_entry(repo, "added", mirror=mid)
        else:
            src["known"][repo["path"]] = known_entry(repo, "excluded", src_rule(src, repo) or "declined")
    with store.lock:
        src_event(src, "created", f"Added {acct['type']} {acct['name']}: {len(chosen)} of {len(repos)} repositories mirrored.")
        store.save_sources()
    return src


def scan_source(store, sid):
    with store.lock:
        src = store.source(sid)
        if not src or sid in store.scanning:
            return False
        store.scanning.add(sid)
        url = src["url"]
    now, err, added, gone, new_pending = time.time(), "", 0, 0, 0
    try:
        acct, repos = cached_listing(url, fresh=True)
        listed = {r["path"]: r for r in repos}
        to_add, to_mark = [], []
        with store.lock:
            for path, repo in listed.items():
                k = src["known"].get(path)
                rule = src_rule(src, repo)
                if k is None:
                    if any(norm_src(x["source"]) == norm_src(repo["clone"]) for x in store.mirrors):
                        to_add.append(repo)  # already mirrored by hand: just link it to this source
                    elif rule:
                        src["known"][path] = known_entry(repo, "excluded", rule)
                    elif src["auto_add"]:
                        to_add.append(repo)
                    else:
                        src["known"][path] = known_entry(repo, "pending")
                        new_pending += 1
                elif k["state"] == "gone":
                    k["state"] = "added"
                    mm = store.get(k.get("mirror"))
                    if mm:
                        mm.pop("gone_from_source", None)
                        if (mm.get("alert") or "").startswith("No longer listed"):
                            mm.pop("alert")
                elif k["state"] == "excluded" and k.get("reason") in ("fork", "archived") and not rule:
                    (to_add if src["auto_add"] else to_mark).append(repo)
                elif k["state"] == "added":
                    mm = store.get(k.get("mirror"))
                    if mm:  # keep stars/description fresh without spending an API call per repo
                        mm["meta"] = {**(mm.get("meta") or {}), **{kk: v for kk, v in meta_from_repo(repo, src["kind"]).items() if kk != "web_url" or v}}
                if k is not None and k["state"] in ("pending", "excluded"):
                    k.update(desc=repo["desc"], stars=repo["stars"], size_kb=repo["size_kb"])
            for path, k in list(src["known"].items()):
                if path in listed:
                    continue
                if k["state"] == "added":
                    k["state"] = "gone"
                    gone += 1
                    mm = store.get(k.get("mirror"))
                    if mm and not mm.get("gone_from_source"):
                        mm["gone_from_source"] = now
                        mm["alert"] = f"No longer listed in {src['name']}'s account. The mirror is kept as an archive."
                        mm.setdefault("events", []).append({"time": now, "type": "gone_from_source", "alert": True,
                                                            "summary": f"{path} disappeared from {src['name']}'s account."})
                elif k["state"] != "gone":  # "gone" entries stay: they are the record of what vanished
                    del src["known"][path]
        for repo in to_mark:
            with store.lock:
                src["known"][repo["path"]] = known_entry(repo, "pending")
                new_pending += 1
        for repo in to_add:
            mid = src_add_repo(store, src, repo)
            with store.lock:
                src["known"][repo["path"]] = known_entry(repo, "added", mirror=mid)
            added += 1
    except Exception as e:
        err = str(e)
    with store.lock:
        store.scanning.discard(sid)
        src["last_scan"], src["last_error"] = now, err
        live = sum(1 for k in src["known"].values() if k["state"] in ("added", "gone"))
        newly_gone = sum(1 for k in src["known"].values() if k["state"] == "gone")
        if gone:
            src["alert"] = f"{gone} repositor{'y' if gone == 1 else 'ies'} vanished from this account." + (" Most of the account is gone." if live and newly_gone * 2 >= live else "")
            src_event(src, "gone", src["alert"], True)
        if added or new_pending:
            src_event(src, "scan", f"{added} added automatically, {new_pending} waiting for approval.")
        if err:
            src_event(src, "scan_failed", err, True)
        store.save_sources()
        store.save()
    return True


def src_counts(src):
    c = {"added": 0, "pending": 0, "excluded": 0, "gone": 0}
    for k in src["known"].values():
        c[k["state"]] = c.get(k["state"], 0) + 1
    return c


def src_public(src, full=False):
    d = {k: v for k, v in src.items() if k not in ("known", "events")}
    d["counts"] = src_counts(src)
    d["interval_text"] = format_interval(src["interval"])
    d["rescan_text"] = format_interval(src["rescan"])
    if full:
        d["known"] = src["known"]
        d["events"] = src.get("events", [])
    return d


def collect_events(store, limit, alerts_only, before):
    rows = []
    with store.lock:
        for m in store.mirrors:
            for e in m.get("events", []):
                rows.append({"time": e.get("time", 0), "type": e.get("type"), "summary": e.get("summary", ""), "alert": bool(e.get("alert")),
                             "mirror": m["name"], "mirror_id": m["id"], "refs": len(e.get("refs") or [])})
        for x in store.sources:
            for e in x.get("events", []):
                rows.append({"time": e.get("time", 0), "type": "source_" + str(e.get("type")), "summary": e.get("summary", ""),
                             "alert": bool(e.get("alert")), "source": x["name"], "source_id": x["id"], "refs": 0})
    if alerts_only:
        rows = [e for e in rows if e["alert"]]
    if before:
        rows = [e for e in rows if e["time"] < before]
    rows.sort(key=lambda e: -e["time"])
    return {"total": len(rows), "events": rows[:limit]}


def delete_mirror(store, mid):
    """Remove a mirror and everything stored for it. False if a sync/job is using it right now."""
    with store.lock:
        m = store.get(mid)
        if not m:
            return True
        if mid in store.running:
            return False
        store.mirrors.remove(m)
        for src in store.sources:  # the account still lists it, so remember that the user doesn't want it
            for k in src["known"].values():
                if k.get("mirror") == mid:
                    k.update(state="excluded", reason="declined", mirror=None)
        store.save()
        store.save_sources()
    for d in (store.path(mid), store.wiki_path(mid), store.extras_dir(mid), store.path(mid) + ".partial", store.wiki_path(mid) + ".partial"):
        shutil.rmtree(d, ignore_errors=True)
    try:
        os.remove(store.logpath(mid))
    except OSError:
        pass
    return True


def canon_acct_url(url):
    url = (url or "").strip()
    if url and "://" not in url:
        url = "https://" + url
    p = parse_acct_url(url)
    if not p or not p[2]:
        raise ValueError("Enter an account page URL like https://github.com/name")
    segs = p[2]
    if segs and segs[-1].endswith(".git"):
        raise ValueError("That is a repository URL, not an account")
    return f"{p[0]}://{p[1]}/{'/'.join(segs)}"


# ---- extras: wiki, LFS objects, releases and issues
ASSET_NAME_RE = re.compile(r"[^\w.+\- ]")


def safe_name(n, default="file"):
    return (ASSET_NAME_RE.sub("_", str(n)).strip(" .")[:120]) or default


def header_filename(name):
    """File name for a Content-Disposition header: printable ASCII only, so no header injection is possible."""
    return re.sub(r"[^A-Za-z0-9._+ -]", "_", str(name).replace("\r", "").replace("\n", ""))[:120] or "download"


def needs_clone(repo):
    """True when there is no usable repository at this path. An empty or stub folder left by an interrupted clone is removed;
    a damaged repository that still holds objects is left alone (nothing is deleted that might be worth recovering)."""
    if not os.path.isdir(repo):
        return True
    if os.path.exists(os.path.join(repo, "HEAD")):
        return False
    for _, _, files in os.walk(os.path.join(repo, "objects")):
        if files:
            return False
    shutil.rmtree(repo, ignore_errors=True)
    return True


def clone_mirror(url, repo, parent, log, timeout):
    """git clone --mirror into <repo>.partial and rename it when finished, so a crash never leaves a half repository under the real name."""
    part = repo + ".partial"
    shutil.rmtree(part, ignore_errors=True)
    try:
        run_git(["clone", "--mirror", "--", url, part], parent, log, timeout)
        os.replace(part, repo)
    finally:
        shutil.rmtree(part, ignore_errors=True)


def mirror_size(store, mid):
    return sum(dir_size(d) for d in (store.path(mid), store.wiki_path(mid), store.extras_dir(mid)))


def mirror_update(repo, url, parent, log, timeout):
    """Create or refresh a bare mirror, pinning anything the origin deleted or rewrote under refs/archive. -> (created, changes)"""
    if needs_clone(repo):
        clone_mirror(url, repo, parent, log, timeout)
        protect_repo(repo)
        return True, []
    protect_repo(repo)
    pre = ref_snapshot(repo)
    try:
        run_git(["remote", "update", "--prune"], repo, log, timeout)
    finally:
        _, changes = archive_changes(repo, pre, ref_snapshot(repo), log)
    return False, changes


def sync_wiki(store, mid, src, timeout, log, prev):
    url = (src[:-4] if src.endswith(".git") else src.rstrip("/")) + ".wiki.git"
    repo, now = store.wiki_path(mid), time.time()
    if prev.get("state") == "none" and now - prev.get("time", 0) < 86400 and not os.path.isdir(repo):
        return dict(prev), []  # no wiki last time: look again once a day, not on every sync
    log.write("--- wiki\n")
    try:
        created, changes = mirror_update(repo, url, store.repos_dir, log, timeout)
    except GitError as e:
        if not os.path.isdir(repo) and re.search(r"not found|does not appear|404|no such|could not read username", e.out, re.I):
            return {"state": "none", "time": now, "msg": "This repository has no wiki."}, []
        return {"state": "error", "time": now, "msg": str(e)[:200], "size": dir_size(repo)}, []
    except Exception as e:
        return {"state": "error", "time": now, "msg": str(e)[:200]}, []
    ev = [{"time": now, "type": "wiki_history_changed", "alert": False, "refs": changes[:100],
           "summary": f"{len(changes)} wiki ref(s) rewritten or deleted upstream; old versions kept."}] if changes else []
    return {"state": "ok", "time": now, "size": dir_size(repo)}, ev


def detect_lfs(repo, prev):
    """Does this repo (any branch, any commit) contain Git LFS pointers? -> {used, files, bytes, installed, time}"""
    now = time.time()
    if prev and not prev.get("used") and now - prev.get("time", 0) < 21600:
        return prev  # looked within the last 6 hours and found nothing
    installed = bool(shutil.which("git-lfs"))
    try:
        if installed:
            p = subprocess.run(["git", "lfs", "ls-files", "--all", "--size"], cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
            lines = [l for l in p.stdout.splitlines() if l.strip()]
            total = 0
            for l in lines:
                m = re.search(r"\(([\d.]+)\s*([KMGT]?B)\)\s*$", l)
                if m:
                    total += int(float(m.group(1)) * {"B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[m.group(2)])
            return {"time": now, "used": bool(lines), "files": len(lines), "bytes": total, "installed": True}
        g = subprocess.run(["git", "grep", "-q", "filter=lfs", "HEAD", "--", ".gitattributes", "*/.gitattributes"],
                           cwd=repo, env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        return {"time": now, "used": g.returncode == 0, "files": None, "bytes": None, "installed": False}
    except (subprocess.SubprocessError, OSError):
        return dict(prev or {"used": False}, time=now, unknown=True)


def sync_lfs(repo, timeout, log):
    now = time.time()
    if not shutil.which("git-lfs"):
        return {"state": "error", "time": now, "msg": "git-lfs is not installed on this server."}
    log.write("--- lfs\n")
    try:
        run_git(["lfs", "fetch", "--all"], repo, log, timeout)
    except Exception as e:
        return {"state": "error", "time": now, "msg": str(e)[:200]}
    return {"state": "ok", "time": now, "size": dir_size(os.path.join(repo, "lfs"))}


def forge_repo_api(src):
    """(kind, repo API base URL) for a clone URL on a recognised forge, else None."""
    pr = parse_repo(src)
    if not pr:
        return None
    scheme, host, path, kind = pr
    q = urllib.parse.quote
    if kind == "github":
        api = "https://api.github.com" if host.lower() in ("github.com", "www.github.com") else f"{scheme}://{host}/api/v3"
        return kind, f"{api}/repos/{q(path, safe='/')}"
    if kind == "gitlab":
        return kind, f"{scheme}://{host}/api/v4/projects/{q(path, safe='')}"
    if kind == "gitea":
        return kind, f"{scheme}://{host}/api/v1/repos/{q(path, safe='/')}"
    return None


def paged(url, per, max_pages=30):
    sep = "&" if "?" in url else "?"
    for page in range(1, max_pages + 1):
        data = api_json(f"{url}{sep}page={page}", timeout=30)
        if not isinstance(data, list):
            raise RuntimeError("unexpected API response")
        yield from data
        if len(data) < per:
            return
    raise RuntimeError(f"more than {max_pages * per} items; stopping")


def download_asset(url, dest, cap_bytes, forge_host=None):
    """Stream to dest.part, abort over the cap. -> bytes written.
    The link was written by whoever maintains the mirrored project, so it may only reach the public internet, or the forge the
    mirror came from (forge_host) when that forge is on a private network."""
    if not re.match(r"^https?://", url):
        raise RuntimeError("not an http(s) URL")
    same_forge = bool(forge_host) and (urllib.parse.urlparse(url).hostname or "").lower() == forge_host.lower()
    n = 0
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open_url(url, {"User-Agent": "gitmirror"}, 60, allow_private=same_forge) as r, open(dest + ".part", "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            n += len(chunk)
            if n > cap_bytes:
                f.close()
                os.remove(dest + ".part")
                raise RuntimeError("larger than the size limit")
            f.write(chunk)
    os.replace(dest + ".part", dest)
    return n


def sync_releases(store, mid, src, log):
    now, ed = time.time(), store.extras_dir(mid)
    fr = forge_repo_api(src)
    if not fr:
        return {"state": "error", "time": now, "msg": "Releases need a GitHub, GitLab or Gitea/Forgejo origin."}
    kind, api = fr
    forge_host = urllib.parse.urlparse(api).hostname
    cap = CFG["_ref"]["release_asset_max_mb"] * (1 << 20)
    log.write("--- releases\n")
    try:
        raw = list(paged(f"{api}/releases?per_page=100" if kind != "gitea" else f"{api}/releases?limit=50", 100 if kind != "gitea" else 50, 20))
    except RuntimeError as e:
        return {"state": "error", "time": now, "msg": str(e)[:200]}
    out, dl, skipped, nbytes = [], 0, 0, 0
    for d in raw:
        if not isinstance(d, dict) or not d.get("tag_name"):
            continue
        tag = str(d["tag_name"])[:100]
        if kind == "gitlab":
            links = (d.get("assets") or {}).get("links") or []
            assets = [{"name": a.get("name"), "size": None, "url": a.get("direct_asset_url") or a.get("url")} for a in links if isinstance(a, dict)]
            rel = {"body": d.get("description"), "published": d.get("released_at"), "url": ((d.get("_links") or {}).get("self")),
                   "draft": False, "prerelease": bool(d.get("upcoming_release"))}
        else:
            assets = [{"name": a.get("name"), "size": a.get("size"), "url": a.get("browser_download_url")} for a in (d.get("assets") or []) if isinstance(a, dict)]
            rel = {"body": d.get("body"), "published": d.get("published_at"), "url": d.get("html_url"),
                   "draft": bool(d.get("draft")), "prerelease": bool(d.get("prerelease"))}
        rel.update(tag=tag, name=_s(d.get("name"), 200), body=_s(rel["body"], 100000), published=_s(rel["published"], 40),
                   url=rel["url"] if isinstance(rel["url"], str) and re.match(r"^https?://", rel["url"]) else None, assets=[])
        for a in assets:
            nm, url = safe_name(a.get("name"), "asset"), a.get("url")
            item = {"name": nm, "size": _i(a.get("size")), "url": _http_url(url, 2000), "local": None, "note": None}
            local = os.path.join("releases", safe_name(tag, "tag"), nm)
            full = os.path.join(ed, local)
            if os.path.isfile(full) and (item["size"] is None or os.path.getsize(full) == item["size"]):
                item["local"] = local
                nbytes += os.path.getsize(full)
            elif cap <= 0:
                item["note"] = "download disabled (metadata only)"
            elif item["size"] is not None and item["size"] > cap:
                item["note"] = "skipped: larger than the size limit"
                skipped += 1
            elif disk_info(store)["stopped"]:
                item["note"] = "skipped: disk almost full"
            elif item["url"]:
                try:
                    nbytes += download_asset(item["url"], full, cap, forge_host)
                    item["local"] = local
                    dl += 1
                    log.write(f"downloaded {local}\n")
                except Exception as e:
                    item["note"] = f"download failed: {str(e)[:80]}"
                    skipped += 1
            rel["assets"].append(item)
        out.append(rel)
    os.makedirs(ed, exist_ok=True)
    with open(os.path.join(ed, "releases.json"), "w") as f:
        json.dump(out, f)
    return {"state": "ok", "time": now, "count": len(out), "downloaded": dl, "skipped": skipped, "bytes": nbytes}


def sync_issues(store, mid, src, log, prev):
    now, ed = time.time(), store.extras_dir(mid)
    fr = forge_repo_api(src)
    if not fr:
        return {"state": "error", "time": now, "msg": "Issues need a GitHub, GitLab or Gitea/Forgejo origin."}
    kind, api = fr
    path = os.path.join(ed, "issues.json")
    try:
        db = load_json(path)
    except (OSError, ValueError):
        db = {"since": None, "issues": {}}
    since = db.get("since")
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 300))
    q = urllib.parse.quote
    log.write("--- issues\n")
    try:
        if kind == "github":
            url = f"{api}/issues?state=all&per_page=100&sort=updated&direction=asc" + (f"&since={q(since)}" if since else "")
            items, per = list(paged(url, 100)), 100
        elif kind == "gitea":
            url = f"{api}/issues?state=all&type=issues&limit=50" + (f"&since={q(since)}" if since else "")
            items, per = list(paged(url, 50)), 50
        else:
            url = f"{api}/issues?scope=all&per_page=100" + (f"&updated_after={q(since)}" if since else "")
            items, per = list(paged(url, 100)), 100
        for d in items:
            if not isinstance(d, dict):
                continue
            num = d.get("number") if kind != "gitlab" else d.get("iid")
            if not isinstance(num, int):
                continue
            user = d.get("user") or d.get("author") or {}
            old = db["issues"].get(str(num), {})
            db["issues"][str(num)] = {
                "number": num, "title": _s(d.get("title"), 300), "state": _s(d.get("state"), 20), "author": _s(user.get("login") or user.get("username"), 80),
                "created": _s(d.get("created_at"), 40), "updated": _s(d.get("updated_at"), 40), "closed": _s(d.get("closed_at"), 40),
                "body": _s(d.get("body") if kind != "gitlab" else d.get("description"), 100000),
                "labels": [str((l.get("name") if isinstance(l, dict) else l))[:60] for l in (d.get("labels") or [])][:30],
                "is_pr": bool(d.get("pull_request")), "url": _http_url(d.get("html_url") or d.get("web_url"), 300),
                "comments": old.get("comments", [])}
        ncom = 0
        if kind in ("github", "gitea"):
            curl = f"{api}/issues/comments?" + ("per_page=100" if kind == "github" else "limit=50") + (f"&since={q(since)}" if since else "")
            for c in paged(curl, 100 if kind == "github" else 50):
                m = re.search(r"/issues/(\d+)$", str(c.get("issue_url", "")))
                if not m or m.group(1) not in db["issues"]:
                    continue
                lst = db["issues"][m.group(1)].setdefault("comments", [])
                rec = {"id": c.get("id"), "author": _s((c.get("user") or {}).get("login"), 80), "created": _s(c.get("created_at"), 40),
                       "body": _s(c.get("body"), 100000)}
                for i, ex in enumerate(lst):
                    if ex.get("id") == rec["id"]:
                        lst[i] = rec
                        break
                else:
                    lst.append(rec)
                ncom += 1
        db["since"] = started
        os.makedirs(ed, exist_ok=True)
        with open(path + ".tmp", "w") as f:
            json.dump(db, f)
        os.replace(path + ".tmp", path)
    except RuntimeError as e:
        return {"state": "error", "time": now, "msg": str(e)[:200], "count": len(db["issues"])}
    note = "" if kind != "gitlab" else "Comments are not archived for GitLab."
    return {"state": "ok", "time": now, "count": len(db["issues"]), "msg": note}


def run_extras(store, mid, src, ex, repo, timeout, log, prev):
    state, events = {}, []
    if ex.get("wiki"):
        state["wiki"], events = sync_wiki(store, mid, src, timeout, log, prev.get("wiki", {}))
    if ex.get("lfs"):
        state["lfs"] = sync_lfs(repo, timeout, log)
    if ex.get("releases"):
        state["releases"] = sync_releases(store, mid, src, log)
    if ex.get("issues"):
        state["issues"] = sync_issues(store, mid, src, log, prev.get("issues", {}))
    return state, events


def default_extras(store):
    return {k: k in store.settings["extras_default"] for k in EXTRA_KEYS}


def create_mirror(store, src, name="", tags=None, interval=None, hold=None, source_id=None, meta=None, extras=None, start=True):
    mid = uuid.uuid4().hex[:10]
    name = (name or "").strip() or re.sub(r"(\.git)?/?$", "", mask(src)).rsplit("/", 1)[-1].rsplit(":", 1)[-1] or mid
    m = {"id": mid, "name": name[:80], "source": src,
         "interval": store.settings["default_interval"] if interval is None else interval,
         "enabled": True, "status": "new", "error": "", "last_run": 0, "added": time.time(),
         "tags": tags or [], "meta": meta or {},
         "hold": bool(store.settings["hold_default"] if hold is None else hold),
         "extras": extras if extras is not None else default_extras(store)}
    if source_id:
        m["source_id"] = source_id
    with store.lock:
        store.mirrors.append(m)
        store.save()
    if start:
        threading.Thread(target=sync, args=(store, mid), daemon=True).start()
        if not meta:
            threading.Thread(target=refresh_meta, args=(store, mid), daemon=True).start()
    return m


def norm_src(u):
    """Comparable form of a clone URL, so the same repo is recognised however it was typed."""
    u = re.sub(r"^(https?://)[^/@]+@", r"\1", (u or "").strip().lower()[:2000])
    u = u.rstrip("/")
    return u[:-4] if u.endswith(".git") else u


def check_url(u, label, admin=False):
    if not u:
        return
    if u.startswith("-") or not URL_RE.match(u) or re.search(r"\s", u):
        raise ValueError(f"{label}: must be an http(s)://, ssh://, git://, file:// or user@host:path URL")
    if u.lower().startswith("file://") and not (ALLOW_FILE_REMOTES or admin):
        raise ValueError(f"{label}: file:// remotes need an admin (or GITMIRROR_ALLOW_FILE_REMOTES=1 for everyone who can add mirrors)")


# ---- accounts, sessions, login throttling
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
SESSION_SECS = 30 * 24 * 3600
USER_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,64}$")
LOGIN_WINDOW, LOGIN_MAX, LOGIN_MAX_ALL = 600, 8, 60
LOGIN_FAILS = {}    # address -> times of failed password or setup-code attempts
BEARER_MAX = 30     # wrong keys or tokens per address per window; separate from passwords so a bad sign-in never blocks scripts
BEARER_FAILS = {}
THROTTLE_LOCK = threading.Lock()


def _b64(b):
    return base64.b64encode(b).decode()


def hash_password(pw, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, maxmem=128 * n * r * 2 + (1 << 20), dklen=32)
    return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(h)}"


def verify_password(pw, stored):
    try:
        scheme, n, r, p, salt, want = stored.split("$")
        n, r, p = int(n), int(r), int(p)
        if scheme != "scrypt" or n > 2 ** 17 or r > 16 or p > 4 or n < 2 or n & (n - 1):
            return False
        got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=n, r=r, p=p, maxmem=128 * n * r * 2 + (1 << 20), dklen=32)
        return hmac.compare_digest(got, base64.b64decode(want))
    except (ValueError, TypeError, AttributeError):
        return False


def check_new_credentials(username, password):
    if not isinstance(username, str) or not USER_RE.match(username):
        raise ValueError("Username: 1 to 64 letters, digits or . _ @ + -")
    check_new_password(password)


def check_new_password(password):
    if not isinstance(password, str) or not 8 <= len(password) <= 256:
        raise ValueError("Password must be 8 to 256 characters")


def _wait(bucket, ip, limit, global_limit):
    now = time.time()
    with THROTTLE_LOCK:
        mine = [t for t in bucket.get(ip, []) if now - t < LOGIN_WINDOW]
        bucket[ip] = mine
        if len(mine) >= limit:
            return int(LOGIN_WINDOW - (now - mine[0])) + 1
        if global_limit:
            allf = [t for lst in bucket.values() for t in lst if now - t < LOGIN_WINDOW]
            if len(allf) >= global_limit:
                return int(LOGIN_WINDOW - (now - min(allf))) + 1
    return 0


def _failed(bucket, ip):
    now = time.time()
    with THROTTLE_LOCK:
        bucket.setdefault(ip, []).append(now)
        if len(bucket) > 2000:  # never let a flood of addresses grow this without bound
            for k in [k for k, v in bucket.items() if not v or now - v[-1] > LOGIN_WINDOW]:
                bucket.pop(k, None)


def login_wait(ip):
    """Seconds this client must wait before another password or setup-code attempt (0 = go ahead)."""
    return _wait(LOGIN_FAILS, ip, LOGIN_MAX, LOGIN_MAX_ALL)


def login_failed(ip):
    _failed(LOGIN_FAILS, ip)


def bearer_wait(ip):
    """Seconds before this address may present another API key or script token. Keys are 256 random bits, so the limit is
    generous, per address only, and untouched by failed sign-ins: a stranger guessing passwords can't take the API down."""
    return _wait(BEARER_FAILS, ip, BEARER_MAX, None)


def bearer_failed(ip):
    _failed(BEARER_FAILS, ip)


_DUMMY_HASH = []


def dummy_hash():
    """A real hash to check against when the user name is unknown, so timing doesn't reveal which names exist."""
    if not _DUMMY_HASH:
        _DUMMY_HASH.append(hash_password("not a real password"))
    return _DUMMY_HASH[0]


def role_rank(role):
    return ROLES.index(role) if role in ROLES else -1


def required_role(method, path, body=None):
    """The lowest role allowed to make this request. Anything not listed here needs an admin (deny by default)."""
    if method == "GET":
        if re.fullmatch(r"/|/events|/account|/maintenance(/\w+)?|/sources|/source/\w+|/repo/\w+", path):
            return "viewer"
        if path == "/api/settings":
            return "operator"  # retry, timeout and LFS policy: not needed to read the mirrors
        if re.fullmatch(r"/api/(mirrors|stats|summary|history|events|maintenance|sources|version|keys|auth/me)|"
                        r"/api/mirrors/\w+(/(log|extras))?|/api/sources/\w+|/dl/\w+/releases/[^/]+/[^/]+", path):
            return "viewer"
        return "admin"  # /admin, /api/export, /api/users, /api/audit and anything unknown
    if method == "POST":
        if path in ("/api/auth/logout", "/api/auth/password", "/api/keys"):
            return "viewer"  # acts on your own session, password and keys
        if path == "/api/bulk":
            return "admin" if (body or {}).get("action") == "delete" else "operator"
        if re.fullmatch(r"/api/(mirrors|sources|sources/preview|maintenance/(verify|optimize)|version/check)|"
                        r"/api/mirrors/\w+/(sync|toggle|meta|ack|hold|accept|reject|verify|lfs)|"
                        r"/api/sources/\w+/(rescan|approve|skip|ack)", path):
            return "operator"
        return "admin"  # /api/import, /api/users and anything unknown
    if method == "PUT":
        if re.fullmatch(r"/api/(mirrors|sources)/\w+", path):
            return "operator"
        return "admin"  # /api/settings, /api/users/<name>
    if method == "DELETE" and re.fullmatch(r"/api/keys/\w+", path):
        return "viewer"  # revoke one of your own keys
    return "admin"  # DELETE and anything else: removing mirrors, sources or users


AUDIT_SKIP = ("/api/auth/logout", "/api/version/check")


def audit_target(store, path, body):
    m = re.match(r"^/api/mirrors/(\w+)", path)
    if m:
        mm = store.get(m.group(1))
        return mm["name"] if mm else m.group(1)
    m = re.match(r"^/api/sources/(\w+)", path)
    if m:
        src = store.source(m.group(1))
        return src["name"] if src else m.group(1)
    m = re.match(r"^/api/users/([^/]+)", path)
    if m:
        return urllib.parse.unquote(m.group(1))
    if path == "/api/users" and isinstance(body, dict):
        return str(body.get("username", ""))[:64]
    return ""


def audit_note(path, body):
    if not isinstance(body, dict):
        return ""
    if path == "/api/bulk":
        return f"{body.get('action')} on {len(body.get('ids') or [])} mirrors"
    if path == "/api/settings":
        return "changed: " + ", ".join(sorted(k for k in body if k not in ("github_token",)))[:200] + (", github_token" if "github_token" in body else "")
    if path == "/api/keys":
        return f"new key '{str(body.get('name', ''))[:40]}' ({body.get('role')})"
    if path.startswith("/api/users"):
        return ", ".join(f"{k}={body[k]}" for k in ("role", "disabled") if k in body) + (" password reset" if "password" in body else "") + (" keys revoked" if body.get("revoke_keys") else "")
    return ""


def audit_add(store, ident, method, path, target, note):
    entry = {"t": time.time(), "user": ident.get("name") or "script token", "role": ident["role"],
             "via": f"key '{ident['key_name']}'" if ident.get("key_name") else "",
             "what": f"{method} " + re.sub(r"/[0-9a-f]{10}\b", "/:id", path), "target": target, "note": note}
    with store.lock:
        store.audit.append(entry)
        del store.audit[:-1000]
        try:
            store.save_audit()
        except OSError:
            pass


def key_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()  # the key is 256 random bits, so a fast hash is enough


def find_key(store, token):
    h = key_hash(token)
    with store.lock:  # an admin may be adding a user or a key while we iterate
        for ukey, u in store.users.items():
            for k in u.get("keys", []):
                if hmac.compare_digest(k["hash"], h):
                    return ukey, u, k
    return None


def create_key(store, ukey, name, role, days):
    """-> (token shown once, public record). Only the hash is stored."""
    tok = KEY_PREFIX + secrets.token_urlsafe(32)
    now = time.time()
    rec = {"id": secrets.token_hex(4), "name": name, "hash": key_hash(tok), "prefix": tok[:7], "role": role,
           "created": now, "last_used": None, "last_ip": None, "expires": now + days * 86400 if days else None}
    with store.lock:
        store.users[ukey].setdefault("keys", []).append(rec)
        store.save_auth()
    return tok, key_public(rec)


def key_public(k):
    return {f: k.get(f) for f in ("id", "name", "prefix", "role", "created", "last_used", "last_ip", "expires")}


def end_user_sessions(store, key):
    with store.lock:
        store.sessions = {h: x for h, x in store.sessions.items() if str(x.get("user", "")).casefold() != key}
        store.save_sessions()


def active_admins(users, ignore=None):
    return [k for k, u in users.items() if u.get("role") == "admin" and not u.get("disabled") and k != ignore]


def new_session(store, user, agent=""):
    tok = secrets.token_urlsafe(32)
    now = time.time()
    with store.lock:
        store.sessions = {h: s for h, s in store.sessions.items() if s["exp"] > now}
        store.sessions[hashlib.sha256(tok.encode()).hexdigest()] = {"user": user, "created": now, "exp": now + SESSION_SECS, "agent": agent[:80]}
        store.save_sessions()
    return tok


def session_user(store, tok):
    h, now = hashlib.sha256(tok.encode()).hexdigest(), time.time()
    with store.lock:
        s = store.sessions.get(h)
        if not s or s["exp"] <= now:
            return None
        if s["exp"] - now < SESSION_SECS - 5 * 24 * 3600:  # slide the expiry, but write the file at most every few days
            s["exp"] = now + SESSION_SECS
            store.save_sessions()
        return s["user"]


def end_sessions(store, keep=None):
    with store.lock:
        store.sessions = {h: s for h, s in store.sessions.items() if h == keep}
        store.save_sessions()


# ---- version and update check
def version_key(v):
    """Sortable form of a semantic version such as 1.2.3 or v0.0.1-beta (a pre-release sorts before its release)."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?", str(v).strip())
    if not m:
        return None
    pre = tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in m.group(4).split(".")) if m.group(4) else None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 1 if pre is None else 0, pre or ())


def latest_release(tags, stable_only=False):
    best = None
    for t in tags:
        k = version_key(t)
        if k and stable_only and k[3] == 0:  # k[3] is 0 for a pre-release such as 1.0.0-beta
            continue
        if k and (best is None or k > best[0]):
            best = (k, t.lstrip("v"))
    return best[1] if best else None


def check_update(store):
    """Ask GitHub which version tags exist (git ls-remote: no API quota, no login). Never raises."""
    info = {"checked": time.time(), "latest": None, "error": ""}
    try:
        p = subprocess.run(["git", "ls-remote", "--tags", "--refs", REPO_URL + ".git"], env=GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        if p.returncode:
            raise RuntimeError((p.stderr.strip().splitlines() or ["git ls-remote failed"])[-1][:150])
        tags = [l.split("refs/tags/", 1)[1] for l in p.stdout.splitlines() if "refs/tags/" in l]
        info["latest"] = latest_release(tags)
        info["latest_stable"] = latest_release(tags, stable_only=True)
    except (OSError, RuntimeError, subprocess.SubprocessError) as e:
        info["error"] = str(e)[:150]
    store.update_info = info
    return info


def version_out(store):
    cur, enabled = __version__, bool(store.settings.get("update_check")) and os.environ.get("GITMIRROR_UPDATE_CHECK", "1") not in ("0", "false", "no")
    out = {"version": cur, "enabled": enabled, "repo": REPO_URL}
    if enabled:
        i, ck = store.update_info, version_key(cur)
        # Someone on a stable release hears only about stable releases; a pre-release install also hears about newer pre-releases.
        latest = i.get("latest") if (ck is None or ck[3] == 0) else i.get("latest_stable")
        newer = bool(latest) and (version_key(latest) or ()) > (ck or ())
        out.update(checked=i.get("checked"), latest=latest, update_available=newer, error=i.get("error", ""),
                   url=f"{REPO_URL}/releases/tag/v{latest}" if latest else None)
    return out


def parse_networks(text):
    nets = []
    for pos, part in enumerate((text or "").split(","), 1):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            print(f"WARNING: ignoring entry {pos} of GITMIRROR_TRUSTED_PROXIES (not an address or network)", file=sys.stderr, flush=True)
    return nets


TRUSTED_PROXIES = parse_networks(os.environ.get("GITMIRROR_TRUSTED_PROXIES", ""))


def _addr(text):
    a = ipaddress.ip_address(text.strip())
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


def client_ip(peer, forwarded, trusted):
    """The address of the real client. X-Forwarded-For is believed only when the connection comes from a trusted proxy, and then
    the right-most address that is not itself a trusted proxy wins, because anything further left may have been made up by the client."""
    try:
        p = _addr(peer)
    except ValueError:
        return peer
    if not any(p in n for n in trusted):
        return peer
    for hop in reversed([h for h in (forwarded or "").split(",") if h.strip()]):
        try:
            a = _addr(hop)
        except ValueError:
            return str(p)  # a garbled chain: don't guess
        if not any(a in n for n in trusted):
            return str(a)
    return str(p)


class Handler(BaseHTTPRequestHandler):
    timeout = 30  # seconds a client may stall mid-request before its connection is dropped
    store = None
    server_version = "gitmirror"
    sys_version = ""  # don't advertise the Python version
    _role = "viewer"  # role of the current request; pages use it to hide what the user may not do
    _audit = None     # (identity, method, path, target, note) of a change to record once it succeeded

    def log_message(self, *a):
        pass

    def version_string(self):
        return self.server_version  # the default appends sys_version with a space even when it is empty

    def client_ip(self):
        return client_ip(self.client_address[0], self.headers.get("X-Forwarded-For"), TRUSTED_PROXIES)

    def send(self, code, body, ctype="application/json", headers=None):
        if ctype == "text/html":
            cfg = self.store.settings
            body = body.replace("__ROLE__", self._role).replace("__THEME_DEFAULTS__", json.dumps({
                "mode": cfg.get("theme", "auto"), "light": cfg.get("light_theme", "light"),
                "dark": cfg.get("dark_theme", "dark"), "cb": bool(cfg.get("colorblind"))}))
        b = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        if self._audit and code < 400:  # recorded before the client sees the success, so a follow-up request always finds it
            audit_add(self.store, *self._audit)
        self._audit = None
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def cookie(self, name):
        try:
            c = http.cookies.SimpleCookie()
            c.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        m = c.get(name)
        return m.value if m else None

    def session_header(self, tok):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
        age = SESSION_SECS if tok else 0
        return {"Set-Cookie": f"gm_session={tok or ''}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{secure}"}

    def identity(self):
        """{'via': 'token'|'session', 'name', 'key', 'role'} for the Bearer token or a signed-in browser, else None."""
        ah = self.headers.get("Authorization") or ""
        if API_TOKEN and ah.startswith("Bearer ") and hmac.compare_digest(ah[7:].encode(), API_TOKEN.encode()):
            return {"via": "token", "name": None, "key": None, "role": TOKEN_ROLE}
        if ah.startswith("Bearer " + KEY_PREFIX):
            hit = find_key(self.store, ah[7:])
            now = time.time()
            if not hit:
                return None
            ukey, u, k = hit
            if u.get("disabled") or (k.get("expires") and k["expires"] <= now):
                return None
            ip = self.client_ip()
            if not k.get("last_used") or now - k["last_used"] > KEY_TOUCH_SECS:  # time only: an address that flips must not rewrite auth.json per request
                with self.store.lock:
                    k["last_used"], k["last_ip"] = now, ip
                    self.store.save_auth()
            role = min(u["role"], k["role"], key=role_rank)  # never more than the owner has right now, nor more than the key was given
            return {"via": "key", "name": u["name"], "key": ukey, "role": role, "key_id": k["id"], "key_name": k["name"]}
        tok = self.cookie("gm_session")
        key = session_user(self.store, tok) if tok else None
        u = self.store.users.get(str(key).casefold()) if key else None  # the role is read fresh every time, so a change applies at once
        if u and not u.get("disabled"):
            return {"via": "session", "name": u["name"], "key": str(key).casefold(), "role": u["role"]}
        return None

    def route(self, method):
        try:
            self._route(method)
        except Exception as e:  # never a traceback to the log per request, never a dropped connection: one line and a JSON 500
            print(f"ERROR {method} {urlparse(self.path).path}: {type(e).__name__}: {str(e)[:200]}", file=sys.stderr, flush=True)
            try:
                self.send(500, {"error": "internal error"})
            except Exception:
                pass

    def _route(self, method):
        if urlparse(self.path).path == "/healthz":  # for Docker / uptime checks, so it needs no login
            ok = time.time() - self.store.heartbeat < 90 and os.access(self.store.data, os.W_OK)
            return self.send(200 if ok else 503, {"ok": ok, "version": __version__})
        path = urlparse(self.path).path.rstrip("/") or "/"
        st = self.store
        if method != "GET":  # CSRF: browsers can't send JSON content-type cross-origin without preflight
            if "application/json" not in self.headers.get("Content-Type", "") and (self.headers.get("Content-Length") or "0") != "0":
                return self.send(415, {"error": "json only"})
            org = self.headers.get("Origin")
            header_only = (self.headers.get("Authorization") or "").startswith("Bearer ") and not self.cookie("gm_session")
            if org and urlparse(org).netloc != self.headers.get("Host") and not header_only:  # a key or token header can't be forged cross-site
                return self.send(403, {"error": "bad origin"})
        body = {}
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self.send(400, {"error": "bad content-length"})
        if n < 0:
            return self.send(400, {"error": "bad content-length"})
        if n:
            try:
                body = json.loads(self.rfile.read(min(n, 1 << 20)))
            except (ValueError, RecursionError):  # RecursionError: thousands of nested brackets
                return self.send(400, {"error": "bad json"})
            if not isinstance(body, dict):
                return self.send(400, {"error": "body must be a JSON object"})

        # ---- sign-in: the only routes that work without being logged in
        ip = self.client_ip()
        self._role, self._audit = "viewer", None
        if method == "GET" and path in ("/login", "/setup"):
            if path == "/login" and self.identity():
                return self.redirect("/")
            if (path == "/setup") != (not st.users):
                return self.redirect("/setup" if not st.users else "/login")
            return self.send(200, LOGIN if path == "/login" else SETUP, "text/html")
        if method == "GET" and path == "/api/auth/status":
            return self.send(200, {"setup_required": not st.users, "setup_code_required": bool(API_TOKEN) and not st.users})
        if method == "POST" and path == "/api/auth/setup":
            wait = login_wait(ip)
            if wait:
                return self.send(429, {"error": f"Too many attempts. Try again in {wait} seconds."}, headers={"Retry-After": str(wait)})
            if st.users:
                return self.send(403, {"error": "An account already exists. Sign in instead."})
            if API_TOKEN and not hmac.compare_digest(str(body.get("setup_code", "")).encode(), API_TOKEN.encode()):
                login_failed(ip)
                return self.send(403, {"error": "Wrong setup code. It is the GITMIRROR_TOKEN value the server was started with."})
            try:
                name, pw = body.get("username"), body.get("password")
                check_new_credentials(name, pw)
            except ValueError as e:
                return self.send(400, {"error": str(e)})
            digest = hash_password(pw)
            with st.lock:
                if st.users:
                    return self.send(409, {"error": "An account was just created. Sign in instead."})
                st.users = {name.casefold(): {"name": name, "hash": digest, "role": "admin", "created": time.time()}}  # the first user is always an admin
                st.save_auth()
            return self.send(200, {"ok": True}, headers=self.session_header(new_session(st, name.casefold(), self.headers.get("User-Agent", ""))))
        if method == "POST" and path == "/api/auth/login":
            if not st.users:
                return self.send(409, {"error": "No account yet. Open /setup first."})
            wait = login_wait(ip)
            if wait:
                return self.send(429, {"error": f"Too many failed attempts. Try again in {wait} seconds."}, headers={"Retry-After": str(wait)})
            name, pw = body.get("username"), body.get("password")
            name, pw = (name if isinstance(name, str) else ""), (pw if isinstance(pw, str) else "")
            u = st.users.get(name.casefold())
            pw_ok = verify_password(pw[:256], u["hash"] if u else dummy_hash())  # always run the slow hash: timing must not reveal which names exist
            if not (u and pw_ok and not u.get("disabled")):
                login_failed(ip)
                return self.send(401, {"error": "Wrong username or password."})
            LOGIN_FAILS.pop(ip, None)
            return self.send(200, {"ok": True}, headers=self.session_header(new_session(st, name.casefold(), self.headers.get("User-Agent", ""))))

        bearer = (self.headers.get("Authorization") or "").startswith("Bearer ")
        if bearer:
            wait = bearer_wait(ip)
            if wait:
                return self.send(429, {"error": f"Too many failed attempts. Try again in {wait} seconds."}, headers={"Retry-After": str(wait)})
        ident = self.identity()
        if not ident:
            if bearer:
                bearer_failed(ip)
            if method == "GET" and not path.startswith(("/api/", "/dl/")):
                return self.redirect("/setup" if not st.users else "/login")
            return self.send(401, {"error": "unauthorized", "setup_required": not st.users})
        self._role = ident["role"]
        need = required_role(method, path, body)
        if role_rank(ident["role"]) < role_rank(need):
            if method == "GET" and not path.startswith(("/api/", "/dl/")):
                return self.redirect("/")  # a page this role may not open
            return self.send(403, {"error": f"Your role ({ident['role']}) can't do this; it needs {need}."})
        if method != "GET" and path not in AUDIT_SKIP:
            self._audit = (ident, method, path, audit_target(st, path, body), audit_note(path, body))

        if method == "POST" and path == "/api/auth/logout":
            tok = self.cookie("gm_session")
            if tok:
                with st.lock:
                    st.sessions.pop(hashlib.sha256(tok.encode()).hexdigest(), None)
                    st.save_sessions()
            return self.send(200, {"ok": True}, headers=self.session_header(None))
        if method == "GET" and path == "/api/auth/me":
            return self.send(200, {"user": ident["name"], "role": ident["role"], "via": ident["via"], "key_name": ident.get("key_name")})
        if method == "POST" and path == "/api/auth/password":
            if ident["via"] != "session":
                return self.send(403, {"error": "Change the password from a signed-in browser."})
            wait = login_wait(ip)
            if wait:
                return self.send(429, {"error": f"Too many failed attempts. Try again in {wait} seconds."}, headers={"Retry-After": str(wait)})
            me = st.users[ident["key"]]
            cur, new = body.get("current"), body.get("new")
            if not isinstance(cur, str) or not verify_password(cur[:256], me["hash"]):
                login_failed(ip)
                return self.send(403, {"error": "Current password is wrong."})
            try:
                check_new_password(new)
            except ValueError as e:
                return self.send(400, {"error": str(e)})
            digest = hash_password(new)
            with st.lock:
                me["hash"] = digest
                st.save_auth()
            end_user_sessions(st, ident["key"])  # that user's other browsers have to sign in again
            return self.send(200, {"ok": True}, headers=self.session_header(new_session(st, ident["key"], self.headers.get("User-Agent", ""))))

        # ---- your own API keys (a signed-in browser only: a key or token can't create or revoke keys)
        if method == "GET" and path == "/account":
            return self.send(200, ACCOUNT, "text/html")
        mk = re.match(r"^/api/keys(?:/(\w+))?$", path)
        if mk:
            if ident["via"] != "session":
                return self.send(403, {"error": "Manage API keys from a signed-in browser."})
            me = st.users[ident["key"]]
            if method == "GET" and not mk.group(1):
                return self.send(200, [key_public(k) for k in me.get("keys", [])])
            if method == "POST" and not mk.group(1):
                name, role = body.get("name"), body.get("role", "viewer")
                try:
                    days = int(body.get("expires_days") or 0)
                    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 40:
                        raise ValueError("Give the key a name of 1 to 40 characters")
                    if role not in KEY_ROLES:
                        raise ValueError("A key is read-only (viewer) or operator")
                    if role_rank(role) > role_rank(me["role"]):
                        raise ValueError(f"You are a {me['role']}, so a key can't be more than that")
                    if days not in (0, 30, 90, 365):
                        raise ValueError("Choose never, 30, 90 or 365 days")
                    if len(me.get("keys", [])) >= MAX_KEYS_PER_USER:
                        raise ValueError(f"At most {MAX_KEYS_PER_USER} keys per user: revoke one you no longer use")
                except (ValueError, TypeError) as e:
                    return self.send(400, {"error": str(e)})
                tok, rec = create_key(st, ident["key"], name.strip(), role, days)
                return self.send(201, dict(rec, key=tok))  # the only time the key itself is ever shown
            if method == "DELETE" and mk.group(1):
                with st.lock:
                    keys = me.get("keys", [])
                    if not any(k["id"] == mk.group(1) for k in keys):
                        return self.send(404, {"error": "no such key"})
                    me["keys"] = [k for k in keys if k["id"] != mk.group(1)]
                    st.save_auth()
                return self.send(200, {"ok": True})

        # ---- users and the activity log (admins only; required_role denies everything else by default)
        mu = re.match(r"^/api/users(?:/([^/]+))?$", path)
        if mu:
            key = urllib.parse.unquote(mu.group(1)).casefold() if mu.group(1) else None
            if key is None and method == "GET":
                with st.lock:
                    now = time.time()
                    return self.send(200, [{"name": u["name"], "key": k, "role": u["role"], "disabled": bool(u.get("disabled")), "created": u.get("created"),
                                            "signed_in": sum(1 for x in st.sessions.values() if str(x.get("user", "")).casefold() == k and x["exp"] > now),
                                            "keys": len(u.get("keys", []))}
                                           for k, u in sorted(st.users.items())])
            if key is None and method == "POST":
                try:
                    name, pw, role = body.get("username"), body.get("password"), body.get("role", "viewer")
                    check_new_credentials(name, pw)
                    if role not in ROLES:
                        raise ValueError("Role must be viewer, operator or admin")
                except ValueError as e:
                    return self.send(400, {"error": str(e)})
                digest = hash_password(pw)
                with st.lock:
                    if name.casefold() in st.users:
                        return self.send(409, {"error": "That user name is taken"})
                    st.users[name.casefold()] = {"name": name, "hash": digest, "role": role, "created": time.time(), "created_by": ident["name"]}
                    st.save_auth()
                return self.send(201, {"ok": True})
            u = st.users.get(key) if key else None
            if key is None or not u:
                return self.send(404, {"error": "no such user"})
            if method == "PUT":
                new = {}
                try:
                    if "role" in body:
                        if body["role"] not in ROLES:
                            raise ValueError("Role must be viewer, operator or admin")
                        new["role"] = body["role"]
                    if "disabled" in body:
                        new["disabled"] = bool(body["disabled"])
                    if "password" in body:
                        if key == ident["key"]:
                            raise ValueError("Change your own password from the Account card instead")
                        check_new_password(body["password"])
                except ValueError as e:
                    return self.send(400, {"error": str(e)})
                digest = hash_password(body["password"]) if "password" in body else None
                with st.lock:
                    after = dict(st.users, **{key: dict(u, **new)})
                    if not active_admins(after):
                        return self.send(409, {"error": "Keep at least one active admin"})
                    u.update(new)
                    if body.get("revoke_keys"):
                        u["keys"] = []
                    if digest:
                        u["hash"] = digest
                    st.save_auth()
                if new.get("disabled") or digest:
                    end_user_sessions(st, key)  # a disabled or reset account is signed out everywhere; a new role simply applies from the next request
                return self.send(200, {"ok": True})
            if method == "DELETE":
                if key == ident["key"]:
                    return self.send(409, {"error": "You can't delete your own account"})
                with st.lock:
                    if not active_admins(st.users, ignore=key):
                        return self.send(409, {"error": "Keep at least one active admin"})
                    st.users.pop(key)
                    st.save_auth()
                end_user_sessions(st, key)
                return self.send(200, {"ok": True})
        if method == "GET" and path == "/api/audit":
            with st.lock:
                return self.send(200, list(reversed(st.audit[-200:])))

        if method == "GET" and path == "/api/version":
            return self.send(200, version_out(st))
        if method == "POST" and path == "/api/version/check":
            if version_out(st)["enabled"]:
                check_update(st)
            return self.send(200, version_out(st))

        if method == "GET" and path == "/":
            return self.send(200, PAGE, "text/html")
        if method == "GET" and path == "/admin":
            return self.send(200, ADMIN, "text/html")
        if path == "/api/settings" and method == "GET":
            return self.send(200, settings_out(st))
        if path == "/api/settings" and method == "PUT":
            try:
                new = {}
                for k, ok in (("light_theme", ("light", "sepia", "hc-light")), ("dark_theme", ("dark", "oled", "hc-dark"))):
                    if k in body:
                        if body[k] not in ok:
                            raise ValueError(f"{k} must be one of {', '.join(ok)}")
                        new[k] = body[k]
                if "colorblind" in body:
                    new["colorblind"] = bool(body["colorblind"])
                if "theme" in body:
                    if body["theme"] not in ("auto", "light", "dark"):
                        raise ValueError("theme must be auto, light or dark")
                    new["theme"] = body["theme"]
                for k in ("default_interval", "retry_delay", "retry_max", "fsck_interval"):
                    if k in body:
                        new[k] = parse_interval(body[k])
                if "extras_default" in body:
                    ed = body["extras_default"]
                    if not isinstance(ed, list) or any(x not in EXTRA_KEYS for x in ed):
                        raise ValueError("extras_default must be a list of: " + ", ".join(EXTRA_KEYS))
                    new["extras_default"] = [x for x in EXTRA_KEYS if x in ed]
                if body.get("clear_github_token"):
                    new["github_token"] = ""
                elif isinstance(body.get("github_token"), str) and body["github_token"].strip():
                    new["github_token"] = body["github_token"].strip()
                if "hold_default" in body:
                    new["hold_default"] = bool(body["hold_default"])
                if "lfs_auto" in body:
                    new["lfs_auto"] = bool(body["lfs_auto"])
                if "update_check" in body:
                    new["update_check"] = bool(body["update_check"])
                for k, (lo, hi) in SETTING_RANGES.items():
                    if k in body:
                        v = int(body[k])
                        if not lo <= v <= hi:
                            raise ValueError(f"{k} must be between {lo} and {hi}")
                        new[k] = v
            except (ValueError, TypeError, OverflowError) as e:  # OverflowError: 1e400 and friends
                return self.send(400, {"error": str(e)})
            with st.lock:
                st.settings.update(new)
                st.save_settings()
            return self.send(200, settings_out(st))
        if method == "GET" and path == "/api/mirrors":
            with st.lock:
                return self.send(200, [public(m, st) for m in st.mirrors])
        if method == "POST" and path == "/api/mirrors":
            try:
                src = normalize_url(str(body.get("source") or "").strip())
                check_url(src, "source", self._role == "admin")
                if not src:
                    raise ValueError("source is required")
                iv = body.get("interval")
                interval = st.settings["default_interval"] if iv in (None, "") else parse_interval(iv)
                tags = clean_tags(body.get("tags"))
            except (ValueError, TypeError) as e:
                return self.send(400, {"error": str(e)})
            if is_account_url(src):
                return self.send(422, {"error": "That's an account page, not a repository. Opening the Sources page so you can pick which repos to mirror.",
                                       "account_url": src})
            with st.lock:
                dup = next((x for x in st.mirrors if norm_src(x["source"]) == norm_src(src)), None)
            if dup:
                return self.send(409, {"error": f"Already mirrored as \"{dup['name']}\"", "id": dup["id"]})
            m = create_mirror(st, src, body.get("name"), tags, interval, body.get("hold"))
            return self.send(201, public(m, st))

        if method == "GET" and re.match(r"^/maintenance(/(size|oldest|attention|lfs))?$", path):
            return self.send(200, MAINT, "text/html")
        md = re.match(r"^/dl/(\w+)/(releases/[^/]+/[^/]+)$", path)
        if method == "GET" and md:
            base = os.path.realpath(st.extras_dir(md.group(1)))
            full = os.path.realpath(os.path.join(base, urllib.parse.unquote(md.group(2))))
            if not full.startswith(base + os.sep) or not os.path.isfile(full):
                return self.send(404, {"error": "not found"})
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(os.path.getsize(full)))
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % header_filename(os.path.basename(full)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            with open(full, "rb") as f:
                shutil.copyfileobj(f, self.wfile)
            return
        if method == "GET" and path == "/api/summary":
            return self.send(200, summary_out(st))
        if method == "GET" and path == "/api/history":
            with st.lock:
                return self.send(200, st.history[-1000:])
        if method == "GET" and path == "/api/stats":
            return self.send(200, stats_out(st))
        if method == "GET" and path == "/api/maintenance":
            q = parse_qs(urlparse(self.path).query)
            kind = (q.get("kind") or ["size"])[0]
            try:
                limit = max(1, min(int((q.get("limit") or ["5000"])[0]), 5000))
            except ValueError:
                limit = 5000
            if kind not in ("size", "oldest", "attention", "lfs"):
                return self.send(400, {"error": "bad kind"})
            return self.send(200, maint_rows(st, kind, limit))
        if method == "POST" and path == "/api/maintenance/verify":
            with st.lock:
                ids = [m["id"] for m in st.mirrors if os.path.isdir(st.path(m["id"]))]
            if st.opt.get("active") or not ids:
                return self.send(409 if ids else 200, {"started": False})
            threading.Thread(target=run_job, args=(st, ids, fsck_one, "verify"), daemon=True).start()
            return self.send(202, {"started": True, "count": len(ids)})
        if method == "POST" and path == "/api/maintenance/optimize":
            with st.lock:
                known = [m["id"] for m in st.mirrors]
            ids = [i for i in body.get("ids", known) if i in known] if isinstance(body.get("ids", known), list) else known
            if not ids or st.opt.get("active"):
                return self.send(409 if ids else 200, {"started": False})
            threading.Thread(target=run_job, args=(st, ids, optimize_one, "optimize"), daemon=True).start()
            return self.send(202, {"started": True, "count": len(ids)})
        if method == "POST" and path == "/api/bulk":
            ids, action, tag = body.get("ids"), body.get("action"), body.get("tag")
            if not isinstance(ids, list) or len(ids) > 5000 or action not in ("sync", "pause", "resume", "hold_on", "hold_off", "add_tag", "remove_tag", "delete", "optimize", "lfs_on"):
                return self.send(400, {"error": "bad request"})
            try:
                tag = clean_tags([tag])[0] if action in ("add_tag", "remove_tag") else None
            except (ValueError, IndexError):
                return self.send(400, {"error": "a tag name is required"})
            done = skipped = 0
            if action == "optimize":
                known = [i for i in ids if st.get(i)]
                if known and not st.opt.get("active"):
                    threading.Thread(target=run_job, args=(st, known, optimize_one, "optimize"), daemon=True).start()
                    return self.send(200, {"done": len(known), "skipped": len(ids) - len(known)})
                return self.send(409, {"error": "a maintenance job is already running"})
            for mid in [x for x in ids if isinstance(x, str)]:
                with st.lock:
                    mm = st.get(mid)
                    if not mm:
                        skipped += 1
                        continue
                    if action == "delete":
                        pass
                    elif action == "sync":
                        if mid in st.running:
                            skipped += 1
                            continue
                        mm["sync_now"] = True  # the scheduler starts it, respecting the parallel-sync limit
                    elif action == "lfs_on":
                        mm.setdefault("extras", {})["lfs"] = True
                        mm["sync_now"] = True
                    elif action in ("pause", "resume"):
                        mm["enabled"] = action == "resume"
                    elif action in ("hold_on", "hold_off"):
                        mm["hold"] = action == "hold_on"
                        if not mm["hold"]:
                            mm["held"], mm["ignored"] = [], {}
                    elif action == "add_tag":
                        mm["tags"] = clean_tags(list(mm.get("tags", [])) + [tag])
                    elif action == "remove_tag":
                        mm["tags"] = [t for t in mm.get("tags", []) if t.lower() != tag.lower()]
                if action == "delete" and not delete_mirror(st, mid):
                    skipped += 1
                    continue
                done += 1
            with st.lock:
                st.save()
            return self.send(200, {"done": done, "skipped": skipped})
        if method == "GET" and path == "/api/events":
            q = parse_qs(urlparse(self.path).query)
            try:
                limit = max(1, min(int((q.get("limit") or ["100"])[0]), 1000))
                before = float((q.get("before") or ["0"])[0])
            except ValueError:
                return self.send(400, {"error": "bad parameter"})
            return self.send(200, collect_events(st, limit, (q.get("alerts") or ["0"])[0] == "1", before))
        if method == "GET" and path == "/events":
            return self.send(200, EVENTS, "text/html")
        if method == "GET" and path == "/api/export":
            with st.lock:
                out = {"version": 1, "exported": time.time(),
                       "note": "Credentials inside clone URLs are masked as ***; entries with masked URLs are skipped on import.",
                       "mirrors": [{"name": m["name"], "source": mask(m["source"]), "tags": m.get("tags", []), "interval": m.get("interval", 0),
                                    "enabled": m.get("enabled", True), "hold": bool(m.get("hold")), "extras": m.get("extras", {})} for m in st.mirrors],
                       "sources": [{"url": x["url"], "tags": x.get("tags", []), "interval": x["interval"], "hold": x["hold"], "extras": x["extras"],
                                    "include_forks": x["include_forks"], "include_archived": x["include_archived"], "auto_add": x["auto_add"],
                                    "rescan": x["rescan"]} for x in st.sources]}
            return self.send(200, json.dumps(out, indent=2).encode(), headers={"Content-Disposition": "attachment; filename=gitmirror-export.json"})
        if method == "POST" and path == "/api/import":
            res = {"mirrors_added": 0, "mirrors_existing": 0, "skipped": [], "sources_added": 0}
            if not isinstance(body.get("mirrors", []), list) or not isinstance(body.get("sources", []), list):
                return self.send(400, {"error": "mirrors and sources must be lists"})
            with st.lock:
                have = {norm_src(x["source"]) for x in st.mirrors}
                have_src = {x["url"] for x in st.sources}
            for d in (body.get("mirrors") or [])[:5000]:
                try:
                    src = str(d.get("source", "")).strip()
                    if "***" in src:
                        raise ValueError("credentials were masked in the export")
                    check_url(src, "source", self._role == "admin")
                    if not src:
                        raise ValueError("no source")
                    if norm_src(src) in have:
                        res["mirrors_existing"] += 1
                        continue
                    ex = d.get("extras") if isinstance(d.get("extras"), dict) else None
                    m = create_mirror(st, src, d.get("name"), clean_tags(d.get("tags")), parse_interval(d.get("interval", st.settings["default_interval"])),
                                      bool(d.get("hold")), extras={k: bool(ex.get(k)) for k in EXTRA_KEYS} if ex else None, start=False)
                    if d.get("enabled") is False:
                        with st.lock:
                            m["enabled"] = False
                            st.save()
                    have.add(norm_src(src))
                    res["mirrors_added"] += 1
                except (ValueError, TypeError, AttributeError) as e:
                    res["skipped"].append(f"{str(d.get('source', '?'))[:80]}: {e}")
            for d in (body.get("sources") or [])[:200]:
                try:
                    url = canon_acct_url(d.get("url"))
                    if url in have_src:
                        continue
                    acct = account_info(url)
                    ex = d.get("extras") if isinstance(d.get("extras"), dict) else default_extras(st)
                    src = {"id": uuid.uuid4().hex[:10], "url": url, "name": acct["name"], "kind": acct["kind"], "scheme": acct["scheme"],
                           "hostport": acct["hostport"], "account_type": acct["type"], "added": time.time(), "last_scan": 0, "last_error": "",
                           "tags": clean_tags(d.get("tags")), "interval": parse_interval(d.get("interval", st.settings["default_interval"])),
                           "hold": bool(d.get("hold")), "extras": {k: bool(ex.get(k)) for k in EXTRA_KEYS},
                           "include_forks": bool(d.get("include_forks")), "include_archived": d.get("include_archived", True) is not False,
                           "auto_add": bool(d.get("auto_add")), "rescan": parse_interval(d.get("rescan", 1440)), "known": {}, "events": []}
                    with st.lock:
                        st.sources.append(src)
                        st.save_sources()
                    res["sources_added"] += 1  # its first scan runs on the next scheduler tick
                except (ValueError, TypeError, AttributeError) as e:
                    res["skipped"].append(f"source {str(d.get('url', '?'))[:80]}: {e}")
            return self.send(200, res)
        if method == "GET" and re.match(r"^/(sources|source/\w+)$", path):
            return self.send(200, SOURCES, "text/html")
        if path == "/api/sources" and method == "GET":
            with st.lock:
                return self.send(200, [src_public(x) for x in st.sources])
        if path == "/api/sources/preview" and method == "POST":
            try:
                url = canon_acct_url(body.get("url"))
                acct, repos = cached_listing(url, fresh=bool(body.get("fresh")))
            except ValueError as e:
                return self.send(400, {"error": str(e)})
            with st.lock:
                have = {norm_src(x["source"]): x["id"] for x in st.mirrors}
                existing = next((x["id"] for x in st.sources if x["url"] == url), None)
            rows = [dict(r, mirrored=have.get(norm_src(r["clone"])), selected=not r["fork"]) for r in repos]
            return self.send(200, {"url": url, "source_id": existing, "account": {k: acct[k] for k in ("kind", "name", "type", "hostport")},
                                   "repos": rows, "settings": {"interval": format_interval(st.settings["default_interval"]),
                                                               "hold": st.settings["hold_default"], "extras": st.settings["extras_default"]}})
        if path == "/api/sources" and method == "POST":
            try:
                url = canon_acct_url(body.get("url"))
                with st.lock:
                    if any(x["url"] == url for x in st.sources):
                        raise ValueError("Already following this account")
                iv, rs = body.get("interval"), body.get("rescan")
                ex = body.get("extras")
                if ex is not None and (not isinstance(ex, list) or any(x not in EXTRA_KEYS for x in ex)):
                    raise ValueError("bad extras")
                opts = {"tags": body.get("tags"), "hold": bool(body.get("hold", st.settings["hold_default"])),
                        "interval": st.settings["default_interval"] if iv in (None, "") else parse_interval(iv),
                        "rescan": 1440 if rs in (None, "") else parse_interval(rs),
                        "extras": {k: (k in ex) for k in EXTRA_KEYS} if ex is not None else default_extras(st),
                        "include_forks": bool(body.get("include_forks")), "include_archived": body.get("include_archived", True) is not False,
                        "auto_add": bool(body.get("auto_add"))}
                sel = body.get("selected")
                if not isinstance(sel, list):
                    raise ValueError("selected must be a list of repository paths")
                src = create_source(st, url, [x for x in sel if isinstance(x, str)], opts)
            except (ValueError, TypeError) as e:
                return self.send(400, {"error": str(e)})
            return self.send(201, src_public(src))
        ms = re.match(r"^/api/sources/(\w+)(?:/(rescan|approve|skip|ack))?$", path)
        if ms:
            sid, act = ms.groups()
            with st.lock:
                src = st.source(sid)
            if not src:
                return self.send(404, {"error": "not found"})
            if method == "GET" and not act:
                with st.lock:
                    return self.send(200, src_public(src, full=True))
            if method == "POST" and act == "rescan":
                started = sid not in st.scanning
                if started:
                    threading.Thread(target=scan_source, args=(st, sid), daemon=True).start()
                return self.send(202, {"started": started})
            if method == "POST" and act == "ack":
                with st.lock:
                    src.pop("alert", None)
                    st.save_sources()
                return self.send(200, src_public(src))
            if method == "POST" and act in ("approve", "skip"):
                paths = body.get("paths")
                with st.lock:
                    if body.get("all"):
                        paths = [pth for pth, k in src["known"].items() if k["state"] == "pending"]
                    paths = [pth for pth in (paths or []) if pth in src["known"] and src["known"][pth]["state"] in ("pending", "excluded")]
                done = 0
                for pth in paths:
                    with st.lock:
                        k = src["known"][pth]
                        repo = {"path": pth, "name": k["name"], "clone": k["clone"], "html": k["html"], "desc": k["desc"], "stars": k["stars"],
                                "forks": None, "lang": None, "size_kb": k["size_kb"], "fork": k["fork"], "arch": k["arch"],
                                "topics": [], "pushed": None, "branch": None, "wiki": True}
                    if act == "approve":
                        mid = src_add_repo(st, src, repo)
                        with st.lock:
                            src["known"][pth].update(state="added", reason=None, mirror=mid)
                    else:
                        with st.lock:
                            src["known"][pth].update(state="excluded", reason="declined")
                    done += 1
                with st.lock:
                    st.save_sources()
                return self.send(200, {"done": done})
            if method == "PUT" and not act:
                try:
                    new = {}
                    if "tags" in body:
                        new["tags"] = clean_tags(body["tags"])
                    for k in ("interval", "rescan"):
                        if k in body:
                            new[k] = parse_interval(body[k])
                    for k in ("hold", "include_forks", "include_archived", "auto_add"):
                        if k in body:
                            new[k] = bool(body[k])
                    if "extras" in body:
                        if not isinstance(body["extras"], list) or any(x not in EXTRA_KEYS for x in body["extras"]):
                            raise ValueError("bad extras")
                        new["extras"] = {k: k in body["extras"] for k in EXTRA_KEYS}
                except (ValueError, TypeError) as e:
                    return self.send(400, {"error": str(e)})
                with st.lock:
                    src.update(new)
                    if body.get("apply_to_members"):
                        for k in src["known"].values():
                            mm = st.get(k.get("mirror")) if k.get("mirror") else None
                            if mm:
                                mm.update(interval=src["interval"], hold=src["hold"], extras=dict(src["extras"]))
                        st.save()
                    st.save_sources()
                if {"include_forks", "include_archived"} & set(new) and sid not in st.scanning:
                    threading.Thread(target=scan_source, args=(st, sid), daemon=True).start()
                return self.send(200, src_public(src))
            if method == "DELETE" and not act:
                with st.lock:
                    members = [k["mirror"] for k in src["known"].values() if k.get("mirror")]
                    st.sources.remove(src)
                    for mid in members:
                        mm = st.get(mid)
                        if mm:
                            mm.pop("source_id", None)
                    st.save_sources()
                    st.save()
                skipped = 0
                if parse_qs(urlparse(self.path).query).get("delete_mirrors") == ["1"]:
                    skipped = sum(not delete_mirror(st, mid) for mid in members)
                return self.send(200, {"ok": True, "busy_not_deleted": skipped})
        if method == "GET" and re.match(r"^/repo/\w+$", path):
            return self.send(200, REPO, "text/html")
        mt = re.match(r"^/api/mirrors/(\w+)(?:/(sync|log|toggle|meta|ack|hold|accept|reject|verify|extras|lfs))?$", path)
        if mt:
            mid, act = mt.groups()
            with st.lock:
                m = st.get(mid)
            if not m:
                return self.send(404, {"error": "not found"})
            if method == "GET" and not act:
                d = public(m, st, full=True)
                d["git"] = git_info(st, mid)
                d["local_path"] = st.path(mid)
                return self.send(200, d)
            if method == "PUT" and not act:
                try:
                    new = {}
                    if "name" in body:
                        new["name"] = str(body["name"]).strip()[:80]
                        if not new["name"]:
                            raise ValueError("name can't be empty")
                    if "tags" in body:
                        new["tags"] = clean_tags(body["tags"])
                    if "extras" in body:
                        if not isinstance(body["extras"], list) or any(x not in EXTRA_KEYS for x in body["extras"]):
                            raise ValueError("bad extras")
                        new["extras"] = {k: k in body["extras"] for k in EXTRA_KEYS}
                    if "interval" in body:
                        new["interval"] = parse_interval(body["interval"])
                except (ValueError, TypeError) as e:
                    return self.send(400, {"error": str(e)})
                with st.lock:
                    m.update(new)
                    st.save()
                return self.send(200, public(m, st))
            if method == "POST" and act == "hold":
                with st.lock:
                    m["hold"] = not m.get("hold", False)
                    if not m["hold"]:  # normal mirroring resumes on the next sync, so pending holds no longer apply
                        m["held"], m["ignored"] = [], {}
                    st.save()
                return self.send(200, public(m, st))
            if method == "POST" and act in ("accept", "reject"):
                n = resolve_held(st, mid, act == "accept")
                if n is None:
                    return self.send(409, {"error": "sync in progress"})
                return self.send(200, dict(public(m, st), resolved=n))
            if method == "GET" and act == "extras":
                ed, out = st.extras_dir(mid), {"state": m.get("extras_state", {}), "releases": [], "issues": []}
                try:
                    out["releases"] = load_json(os.path.join(ed, "releases.json"))
                except (OSError, ValueError):
                    pass
                try:
                    iss = sorted(load_json(os.path.join(ed, "issues.json"))["issues"].values(), key=lambda i: -i["number"])
                    out["issues"], out["issues_total"] = iss[:500], len(iss)
                except (OSError, ValueError, KeyError):
                    pass
                return self.send(200, out)
            if method == "POST" and act == "lfs":
                with st.lock:
                    m.setdefault("extras", {})["lfs"] = True
                    m["sync_now"] = True  # the scheduler fetches the LFS objects right away
                    st.save()
                return self.send(200, public(m, st))
            if method == "POST" and act == "verify":
                started = mid not in st.running
                if started:
                    threading.Thread(target=fsck_one, args=(st, mid), daemon=True).start()
                return self.send(202, {"started": started})
            if method == "POST" and act == "ack":
                with st.lock:
                    m.pop("alert", None)
                    st.save()
                return self.send(200, public(m, st))
            if method == "POST" and act == "meta":
                changed = refresh_meta(st, mid)
                return self.send(200, dict(public(m, st), changed=changed))
            if method == "GET" and act == "log":
                try:
                    txt = open(st.logpath(mid)).read()[-LOG_KEEP:]
                except OSError:
                    txt = ""
                return self.send(200, txt, "text/plain")
            if method == "POST" and act == "sync":
                started = mid not in st.running
                if started:
                    threading.Thread(target=sync, args=(st, mid), daemon=True).start()
                return self.send(202, {"started": started})
            if method == "POST" and act == "toggle":
                with st.lock:
                    m["enabled"] = not m.get("enabled", True)
                    st.save()
                return self.send(200, public(m, st))
            if method == "DELETE" and not act:
                if not delete_mirror(st, mid):
                    return self.send(409, {"error": "sync in progress"})
                return self.send(200, {"ok": True})
        self.send(404, {"error": "not found"})

    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_DELETE(self): self.route("DELETE")
    def do_PUT(self): self.route("PUT")


STYLE = r"""
:root{--bg:#f6f7f9;--fg:#1c2128;--card:#fff;--mut:#6b7280;--bd:#d8dce2;--ok:#1a7f37;--err:#cf222e;--run:#9a6700;--acc:#2f6feb;--onacc:#fff}
:root{color-scheme:light}
@media(prefers-color-scheme:dark){:root:not([data-theme]){color-scheme:dark;--bg:#0f1318;--fg:#e6e8eb;--card:#181d24;--mut:#8b94a1;--bd:#2c333d;--ok:#3fb950;--err:#f85149;--run:#d29922;--acc:#58a6ff}}
:root[data-mode=dark]{color-scheme:dark}
:root[data-theme=dark]{--bg:#0f1318;--fg:#e6e8eb;--card:#181d24;--mut:#8b94a1;--bd:#2c333d;--ok:#3fb950;--err:#f85149;--run:#d29922;--acc:#58a6ff;--onacc:#fff}
:root[data-theme=oled]{--bg:#000;--fg:#eceff3;--card:#0b0b0d;--mut:#98a1ad;--bd:#2a2d33;--ok:#3fb950;--err:#f85149;--run:#d29922;--acc:#58a6ff;--onacc:#fff}
:root[data-theme=sepia]{--bg:#f4ecd8;--fg:#3b3226;--card:#fbf5e6;--mut:#6f604b;--bd:#d9ccb0;--ok:#3f6b19;--err:#a8261c;--run:#8a5a00;--acc:#8a4b14;--onacc:#fff}
:root[data-theme=hc-light]{--bg:#fff;--fg:#000;--card:#fff;--mut:#333;--bd:#000;--ok:#006400;--err:#a40000;--run:#6b4200;--acc:#0000cc;--onacc:#fff}
:root[data-theme=hc-dark]{--bg:#000;--fg:#fff;--card:#000;--mut:#d6d6d6;--bd:#fff;--ok:#5cff5c;--err:#ff7b7b;--run:#ffd24d;--acc:#6cb6ff;--onacc:#000}
:root[data-cb][data-mode=light]{--ok:#0072b2;--err:#c24e00;--run:#7a5f00}
:root[data-cb][data-mode=dark]{--ok:#56b4e9;--err:#ff8a3d;--run:#f0e442}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.4 system-ui,sans-serif}
main{max-width:900px;margin:0 auto;padding:16px}h1{font-size:20px;margin:8px 0 16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px;margin-bottom:12px}
form{display:grid;grid-template-columns:1fr 1fr;gap:8px}form .full{grid-column:1/-1}
input{width:100%;padding:8px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--fg)}
button{padding:6px 12px;border:1px solid var(--bd);border-radius:6px;background:var(--card);color:var(--fg);cursor:pointer}
button.p{background:var(--acc);border-color:var(--acc);color:var(--onacc)}button:hover{filter:brightness(.95)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.sp{flex:1}.mut{color:var(--mut);font-size:13px;word-break:break-all}
.dot{width:16px;height:16px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;background:var(--mut);color:var(--bg);font-size:10px;font-weight:700;line-height:1;flex:none}
.dot.ok::before{content:"✓"}.dot.error::before{content:"✕"}.dot.running::before{content:"↻"}
.ok{background:var(--ok)}.error{background:var(--err)}.running{background:var(--run);animation:b 1s infinite}@keyframes b{50%{opacity:.3}}
@media(prefers-reduced-motion:reduce){.running{animation:none}.tgl .kn{transition:none}}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
:root[data-theme^=hc] :focus-visible{outline-width:4px}
:root[data-theme^=hc] :is(.card,button,input,select,.chip,.pop){border-width:2px}
[hidden]{display:none!important}
button.icon{padding:2px 8px;font-size:16px;line-height:1.5}
.pop{position:absolute;right:0;top:46px;z-index:5;width:270px;background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px;display:grid;gap:10px;box-shadow:0 6px 20px #0005}
pre{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:8px;overflow:auto;max-height:260px;font-size:12px;white-space:pre-wrap}
.cap{display:block;font-size:13px;color:var(--mut)}.cap input{margin-top:4px;color:var(--fg)}a{color:var(--acc)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
th{color:var(--mut);font-weight:500;white-space:nowrap}td.n{white-space:nowrap}.scroll{overflow-x:auto}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:12px}
.tiles .card{margin:0}.tiles b{font-size:20px;display:block}.tiles span{color:var(--mut);font-size:13px}
.tgl{position:relative;display:inline-block;width:54px;height:26px;flex:none}
.tgl input{position:absolute;inset:0;width:100%;height:100%;margin:0;padding:0;border:0;opacity:0;cursor:pointer;z-index:2}
.tgl .tr{position:absolute;inset:0;border-radius:13px;background:var(--bd);display:flex;align-items:center;justify-content:space-between;padding:0 7px;font-size:13px;line-height:1;user-select:none}
.tgl .kn{position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:var(--card);box-shadow:0 1px 3px #0006;transition:transform .2s}
.tgl input:checked~.kn{transform:translateX(28px)}.tgl input:focus-visible~.tr{outline:2px solid var(--acc);outline-offset:2px}
select{width:100%;padding:8px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--fg);margin-top:4px}
html[data-role=viewer] .op,html[data-role=viewer] .adm,html[data-role=operator] .adm{display:none!important}
html[data-role=viewer] #tags .chip b{display:none}html[data-role=viewer] #exbox{pointer-events:none;opacity:.6}
.brand{color:inherit;text-decoration:none}.brand:hover{text-decoration:underline}
.chip{display:inline-block;padding:1px 9px;border-radius:999px;border:1px solid var(--bd);font-size:12px;background:var(--bg);cursor:pointer}
.chip.on{background:var(--acc);border-color:var(--acc);color:var(--onacc)}.chip b{margin-left:4px;opacity:.6}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0}dt{color:var(--mut)}dd{margin:0;word-break:break-word}
.err{color:var(--err);font-size:13px}@media(max-width:560px){form{grid-template-columns:1fr}}
"""

PAGE = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Git Mirror</title>
<style>__STYLE__</style>
<main><div class=row style="position:relative"><h1><a class=brand href="https://github.com/konetzed/gitmirror" target=_blank rel="noopener noreferrer" title="gitmirror on GitHub">Git Mirror</a></h1><span class=mut id=ver></span><span class=sp></span><a data-nav href="/events">Events</a><a data-nav href="/sources">Sources</a><a data-nav href="/maintenance">Maintenance</a><a class=adm data-nav href="/admin">Admin</a>
<button class=icon id=thbtn title="Theme options" aria-haspopup=true aria-expanded=false>🎨</button>
<label class=tgl title="Light / dark"><input type=checkbox id=themetgl aria-label="Dark mode"><span class=tr><span>☀</span><span>☾</span></span><span class=kn></span></label><a href="/account">Account</a><a href="#" id=logout>Log out</a>
<div class=pop id=thpop hidden>
<label class=cap>☀ Sun (light) theme<select id=thl><option value=light>Light</option><option value=sepia>Sepia</option><option value=hc-light>High contrast light</option></select></label>
<label class=cap>☾ Moon (dark) theme<select id=thd><option value=dark>Dark</option><option value=oled>OLED black</option><option value=hc-dark>High contrast dark</option></select></label>
<label class=row style="gap:8px"><input type=checkbox id=thcb style="width:auto"> Colorblind-safe colours</label>
<button id=threset>Reset to site defaults</button></div></div>
<div class="card op"><form id=f>
<input class=full name=source placeholder="Source URL (https://github.com/org/repo.git)" required>
<label class=cap>Name (optional)<input name=name></label>
<label class=cap>Sync interval (W, D, H, M; 0 = manual sync)<input name=interval value=3D placeholder="3D" title="e.g. 1W, 3D, 12H, 30M, 1D12H; 0 = manual only"></label>
<label class="cap full">Tags (comma separated, optional)<input name=tags placeholder="homeassistant, tools"></label>
<label class="full row cap" style="gap:8px"><input type=checkbox name=hold style="width:auto"> Hold upstream rewrites and deletions for my review</label>
<div class="full row"><span class=sp></span><button class=p>Add mirror</button></div>
<div class="full err" id=e></div></form></div>
<div class="card err" id=diskwarn hidden></div>
<div class=tiles id=stats></div>
<div id=tagbar class=row style="margin-bottom:12px"></div>
<div class=row style="margin-bottom:12px"><input id=q type=search placeholder="Search name, URL, tags, description… (is:lfs = LFS not mirrored)" style="flex:1;min-width:180px" aria-label="Search mirrors">
<select id=sortby style="width:auto;margin:0" aria-label="Sort by"><option value=name>Name</option><option value=added>Newest first</option><option value=oldest>Oldest first</option><option value=size>Largest first</option><option value=synced>Last synced</option><option value=status>Problems first</option></select>
<span class=mut id=count></span></div>
<div class="card row op" id=bulk hidden style="position:sticky;top:8px;z-index:4"><b id=bulkn></b>
<button data-b=sync>Sync</button><button data-b=pause>Pause</button><button data-b=resume>Resume</button><button data-b=hold_on>Hold on</button><button data-b=hold_off>Hold off</button>
<button data-b=add_tag>+ Tag</button><button data-b=remove_tag>− Tag</button><button data-b=lfs_on title="Archive Git LFS files for the selected mirrors">LFS on</button><button data-b=optimize>Optimize</button><button class=adm data-b=delete>Delete</button>
<span class=sp></span><span class=mut id=bulkmsg></span><button data-b=all>Select all shown</button><button data-b=none>Clear</button></div>
<div id=list></div></main>
<script>
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const api=(p,o={})=>fetch('/api'+p,{...o,headers:{'Content-Type':'application/json'}}).then(r=>{if(r.status==401)location='/login';return r});
const ago=t=>{if(!t)return'never';const s=Date.now()/1e3-t;return s<90?Math.round(s)+'s ago':s<5400?Math.round(s/60)+'m ago':s<172800?Math.round(s/3600)+'h ago':Math.round(s/86400)+'d ago'};
const sz=b=>b==null?'':b>1e9?(b/1e9).toFixed(1)+' GB':b>1e6?(b/1e6).toFixed(1)+' MB':Math.round(b/1e3)+' KB';
const open=new Set();let busy=false,filter=(new URLSearchParams(location.search).get('tag')||'').toLowerCase()||null;
const post=(p,b)=>api(p,{method:'POST',body:JSON.stringify(b||{})});
const bytes=b=>!b?'0 B':b>=1e9?(b/1e9).toFixed(1)+' GB':b>=1e6?(b/1e6).toFixed(1)+' MB':b>=1e3?Math.round(b/1e3)+' KB':b+' B';
async function loadStats(){const r=await api('/stats');if(!r.ok)return;const s=await r.json();
 const dw=$('#diskwarn');dw.hidden=!s.low_disk&&!s.syncs_paused;dw.textContent=s.syncs_paused?`⚠ Syncing is paused: only ${bytes(s.disk_free)} left on the data disk (less than 1 GB). Free some space or delete mirrors on the Maintenance page.`:`⚠ Low disk space: ${bytes(s.disk_free)} free on the data disk.`;
 $('#stats').innerHTML=[[s.projects,'projects'],[bytes(s.disk_bytes),'disk space used'],[bytes(s.saved_bytes),'space saved by optimizing']].map(t=>`<div class=card><b>${t[0]}</b><span>${t[1]}</span></div>`).join('')}
const until=t=>{const s=t-Date.now()/1e3;return s<=30?'due now':s<5400?'in '+Math.max(1,Math.round(s/60))+'m':s<172800?'in '+Math.round(s/3600)+'h':'in '+Math.round(s/86400)+'d'};
let cache=[],qtext='',sortby=(()=>{try{return localStorage.getItem('gm-sort')}catch(e){return null}})()||'name';const selected=new Set();
const rank=m=>m.origin_missing?0:m.status=='error'?1:(m.alert||m.held_count)?2:m.enabled?4:3;
const SORTS={name:(a,b)=>a.name.localeCompare(b.name),added:(a,b)=>(b.added||0)-(a.added||0),oldest:(a,b)=>(a.added||0)-(b.added||0),size:(a,b)=>(b.size||0)-(a.size||0),
 synced:(a,b)=>(b.last_ok||0)-(a.last_ok||0),status:(a,b)=>rank(a)-rank(b)||a.name.localeCompare(b.name)};
async function load(){const r=await api('/mirrors');if(!r.ok)return;loadStats();cache=await r.json();render()}
function render(){let ms=cache.slice();
 const counts={};ms.forEach(m=>(m.tags||[]).forEach(t=>{const k=t.toLowerCase();(counts[k]=counts[k]||{n:0,t}).n++}));
 if(filter&&!counts[filter])filter=null;
 $('#tagbar').innerHTML=Object.entries(counts).sort().map(([k,v])=>`<span class="chip ${filter==k?'on':''}" data-tag="${esc(k)}">${esc(v.t)} <b>${v.n}</b></span>`).join('');
 if(filter)ms=ms.filter(m=>(m.tags||[]).some(t=>t.toLowerCase()==filter));
 if(qtext.trim()){const w=qtext.toLowerCase().split(/\s+/).filter(Boolean);
  const lfs=w.includes('is:lfs'),ww=w.filter(x=>x!='is:lfs');
  ms=ms.filter(m=>{if(lfs&&!m.lfs_needed)return false;const h=[m.name,m.source,(m.meta||{}).description,(m.tags||[]).join(' '),m.source_name,m.error,m.alert].join(' ').toLowerCase();return ww.every(x=>h.includes(x))})}
 ms.sort(SORTS[sortby]||SORTS.name);
 for(const id of [...selected])if(!cache.some(m=>m.id==id))selected.delete(id);
 shown=ms.map(m=>m.id);
 $('#count').textContent=ms.length==cache.length?cache.length+' mirrors':ms.length+' of '+cache.length+' mirrors';
 $('#list').innerHTML=ms.map(m=>{const st=m.running?'running':m.status,mt=m.meta||{};return `<div class=card data-id=${m.id}>
 <div class=row><input type=checkbox class="sel op" style="width:auto" aria-label="Select ${esc(m.name)}" ${selected.has(m.id)?'checked':''}><span class="dot ${st}"></span><b><a href="/repo/${m.id}">${esc(m.name)}</a></b>${mt.web_url?` <a class=mut href="${esc(mt.web_url)}" target=_blank rel="noopener noreferrer">origin ↗</a>`:''}${m.source_name?` <a class=mut href="/source/${m.source_id}">from ${esc(m.source_name)}</a>`:''}<span class=sp></span>
 <button class=op data-a=sync ${m.running?'disabled':''}>Sync now</button><button class=op data-a=toggle>${m.enabled?'Pause':'Resume'}</button><button class=op data-a=hold title="Hold upstream rewrites and deletions for review instead of applying them">${m.hold?'Hold: on':'Hold: off'}</button>
 <button data-a=log>Log</button><button class=adm data-a=del>Delete</button><button class=op data-a=edit>Edit</button></div>
 ${mt.description?`<div>${esc(mt.description)}</div>`:''}
 <div class=mut>${esc(m.source)}</div>
 ${(m.tags||[]).length?`<div class=row style="margin-top:4px">${m.tags.map(t=>`<span class=chip data-tag="${esc(t.toLowerCase())}">${esc(t)}</span>`).join('')}</div>`:''}
 <div class=mut>${m.enabled?(m.interval?'every '+m.interval_text:'manual'):'paused'} · last run ${ago(m.last_run)}${m.duration!=null?' ('+m.duration+'s)':''} · ${sz(m.size)}${m.next_run&&!m.running?' · next '+until(m.next_run):''}</div>
 ${m.held_count?`<div style="color:var(--run)">⏸ ${m.held_count} upstream change(s) on hold <a href="/repo/${m.id}">review</a></div>`:''}
 ${m.lfs_needed?`<div style="color:var(--run)">⚠ Uses Git LFS (${m.lfs_detect.files==1?'1 file':(m.lfs_detect.files??'some')+' files'}${m.lfs_detect.bytes?', '+sz(m.lfs_detect.bytes):''}) but the large files aren't being mirrored. ${m.lfs_detect.installed===false?'git-lfs is not installed on this server.':'<button class=op data-a=lfs>Enable LFS</button>'}</div>`:''}
 ${m.failures?`<div class=mut>failed ${m.failures}× in a row${m.retry_at?', retrying '+until(m.retry_at):''}</div>`:''}
 ${m.alert?`<div class=err>⚠ ${esc(m.alert)} <a href="/repo/${m.id}">details</a></div>`:''}
 ${m.error?`<div class=err>${esc(m.error)}</div>`:''}
 ${open.has(m.id)?'<pre id=log-'+m.id+'>…</pre>':''}</div>`}).join('')||'<p class=mut>'+(cache.length?'No mirrors match.':'No mirrors yet.')+'</p>';
 for(const id of open){const el=$('#log-'+id);if(el)api('/mirrors/'+id+'/log').then(r=>r.text()).then(t=>el.textContent=t||'(empty)')}
 bulkbar()}
let shown=[];
function bulkbar(){const n=selected.size;$('#bulk').hidden=!n;$('#bulkn').textContent=n+' selected'}
async function bulk(action,extra){const r=await post('/bulk',{ids:[...selected],action,...extra}),j=await r.json();
 $('#bulkmsg').textContent=r.ok?`${j.done} done${j.skipped?', '+j.skipped+' skipped (busy or missing)':''}`:j.error;if(r.ok&&(action=='delete'))selected.clear();load()}
$('#bulk').onclick=e=>{const b=e.target.closest('button');if(!b)return;const a=b.dataset.b;if(!a)return;
 if(a=='all'){shown.forEach(i=>selected.add(i));render();return}
 if(a=='none'){selected.clear();render();return}
 if(a=='delete'){if(!confirm('Delete '+selected.size+' mirrors and their local copies? Archived history in them is lost too.'))return}
 if(a=='add_tag'||a=='remove_tag'){const t=prompt(a=='add_tag'?'Tag to add to '+selected.size+' mirrors:':'Tag to remove from '+selected.size+' mirrors:');if(!t)return;bulk(a,{tag:t});return}
 bulk(a)};
$('#list').addEventListener('change',e=>{const c=e.target.closest('.sel');if(!c)return;const id=c.closest('.card').dataset.id;c.checked?selected.add(id):selected.delete(id);bulkbar()});
$('#q').oninput=e=>{qtext=e.target.value;render()};
$('#sortby').value=sortby;$('#sortby').onchange=e=>{sortby=e.target.value;try{localStorage.setItem('gm-sort',sortby)}catch(x){}render()};
document.onclick=e=>{const c=e.target.closest('.chip');if(!c)return;const k=c.dataset.tag;filter=filter==k?null:k;render()};
$('#list').onclick=async e=>{const b=e.target.closest('button');if(!b)return;const id=b.closest('.card').dataset.id,a=b.dataset.a;
 if(a=='edit'){location='/repo/'+id;return}
 if(a=='log'){open.has(id)?open.delete(id):open.add(id)}
 else if(a=='del'){if(!confirm('Delete mirror and its local copy?'))return;const r=await api('/mirrors/'+id,{method:'DELETE'});if(!r.ok)alert((await r.json()).error)}
 else await api('/mirrors/'+id+'/'+a,{method:'POST'});load()};
$('#f').onsubmit=async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.target));d.hold=e.target.elements.hold.checked;
 const r=await api('/mirrors',{method:'POST',body:JSON.stringify(d)});
 if(r.ok){e.target.reset();$('#e').textContent='';load()}else{const j=await r.json();
  if(r.status==422&&j.account_url){$('#e').textContent=j.error;setTimeout(()=>location='/sources?add='+encodeURIComponent(j.account_url),1200)}else $('#e').textContent=j.error}};
api('/auth/me').then(r=>r.json()).then(m=>{if(m.user)$('#logout').title='Signed in as '+m.user+' ('+m.role+')'});
$('#logout').onclick=async e=>{e.preventDefault();await fetch('/api/auth/logout',{method:'POST',headers:{'Content-Type':'application/json'}});location='/login'};
async function loadVer(){const v=await (await api('/version')).json(),el=$('#ver');
 if(!v.enabled){el.textContent='v'+v.version;return}
 if(!v.checked){el.textContent='v'+v.version+' · checking for updates…';setTimeout(loadVer,8000);return}
 if(v.update_available)el.innerHTML='v'+esc(v.version)+' · <a href="'+esc(v.url)+'" target=_blank rel="noopener noreferrer">update available: v'+esc(v.latest)+'</a>';
 else if(v.latest)el.textContent='v'+v.version+' · up to date ✓';
 else el.textContent='v'+v.version+(v.error?' · could not check for updates':'')}
loadVer();
const tg=$('#themetgl'),pop=$('#thpop');
const sync=()=>{const s=GM.apply();tg.checked=s.mode=='dark';$('#thl').value=s.L;$('#thd').value=s.K;$('#thcb').checked=s.cb};sync();
tg.onchange=()=>{GM.set('theme',tg.checked?'dark':'light');sync()};
$('#thl').onchange=e=>{GM.set('light',e.target.value);sync()};$('#thd').onchange=e=>{GM.set('dark',e.target.value);sync()};
$('#thcb').onchange=e=>{GM.set('cb',e.target.checked?'1':'0');sync()};
$('#threset').onclick=()=>{['theme','light','dark','cb'].forEach(k=>GM.set(k,null));sync()};
$('#thbtn').onclick=e=>{e.stopPropagation();pop.hidden=!pop.hidden;e.currentTarget.setAttribute('aria-expanded',!pop.hidden)};
pop.onclick=e=>e.stopPropagation();
document.addEventListener('click',()=>{pop.hidden=true;$('#thbtn').setAttribute('aria-expanded','false')});
document.addEventListener('keydown',e=>{if(e.key=='Escape'){pop.hidden=true;$('#thbtn').focus()}});

api('/settings').then(r=>r.ok?r.json():null).then(s=>{if(!s)return;const i=document.querySelector('[name=interval]');i.defaultValue=i.value=s.default_interval_text;const h=document.querySelector('[name=hold]');h.defaultChecked=h.checked=!!s.hold_default});
load();setInterval(load,3000);
</script></html>"""

ADMIN = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Git Mirror Admin</title>
<style>__STYLE__</style>
<main><div class=row><h1>Admin</h1><span class=sp></span><a href="/">Back to mirrors</a></div>
<div class=card><form id=f>
<label class=cap>Default sync interval (W, D, H, M; 0 = manual sync)<input name=default_interval placeholder="3D" required></label>
<label class=cap>Default theme<select name=theme><option value=auto>Auto (follow the visitor's system)</option><option value=light>Light</option><option value=dark>Dark</option></select><span class=mut>Visitors can override these with the sun/moon switch and 🎨 menu on the main page.</span></label>
<label class=cap>Sun (light) theme<select name=light_theme><option value=light>Light</option><option value=sepia>Sepia</option><option value=hc-light>High contrast light</option></select></label>
<label class=cap>Moon (dark) theme<select name=dark_theme><option value=dark>Dark</option><option value=oled>OLED black</option><option value=hc-dark>High contrast dark</option></select></label>
<label class="cap full"><span class=row style="gap:8px"><input type=checkbox name=colorblind style="width:auto"> Colorblind-safe colours for status (blue / orange instead of green / red)</span></label>
<label class=cap>Retry a failed sync after (0 = no retries)<input name=retry_delay placeholder="15M" required><span class=mut>Doubles after each failure, never later than the sync interval.</span></label>
<label class=cap>Longest retry delay<input name=retry_max placeholder="6H" required></label>
<label class=cap>Syncs running at once (max)<input name=max_parallel type=number min=1 max=32 required></label>
<label class="cap full"><span class=row style="gap:8px"><input type=checkbox name=hold_default style="width:auto"> Hold upstream rewrites and deletions for review on new mirrors</span></label>
<label class=cap>Integrity check every (0 = never)<input name=fsck_interval placeholder="30D" required></label>
<label class=cap>Warn when free disk is below (GB, 0 = off)<input name=low_disk_gb type=number min=0 required><span class=mut>Syncing also stops automatically below 1 GB.</span></label>
<div class=full><span class=cap>Also archive for new mirrors</span><div class=row><label class=row style="gap:4px"><input type=checkbox style="width:auto" name=extras_default value=wiki> Wiki</label>
<label class=row style="gap:4px"><input type=checkbox style="width:auto" name=extras_default value=lfs> Git LFS files</label>
<label class=row style="gap:4px"><input type=checkbox style="width:auto" name=extras_default value=releases> Releases</label>
<label class=row style="gap:4px"><input type=checkbox style="width:auto" name=extras_default value=issues> Issues</label></div></div>
<label class="cap full"><span class=row style="gap:8px"><input type=checkbox name=lfs_auto style="width:auto"> Turn on Git LFS archiving automatically when a repo uses it</span></label>
<label class=cap>...but only if its LFS files total under (GB)<input name=lfs_auto_max_gb type=number min=0 required></label>
<label class="cap full"><span class=row style="gap:8px"><input type=checkbox name=update_check style="width:auto"> Check GitHub for new gitmirror releases (a version tag lookup every few hours; nothing else is sent)</span><span class=mut id=verline></span></label>
<label class=cap>Largest release file to download (MB, 0 = list only)<input name=release_asset_max_mb type=number min=0 required></label>
<label class=cap>GitHub token <span class=mut id=tokstate></span><input name=github_token type=password autocomplete=off placeholder="leave blank to keep"><span class=mut>Lifts the 60 requests/hour limit. Needs no scopes for public data. Never shown again.</span></label>
<label class=cap>Sync timeout (seconds)<input name=timeout type=number min=10 max=86400 required></label>
<div class="full row"><span class="mut" id=ok></span><span class=sp></span><button class=p>Save</button></div>
<div class="full err" id=e></div></form></div>
<div class=card><b>Users</b> <span class=mut>viewer: read only. operator: add, sync and edit mirrors. admin: everything, including settings, deleting and users.</span>
<div class=scroll><table id=utab></table></div>
<form id=uf style="margin-top:10px"><label class=cap>New user name<input name=username autocomplete=off required pattern="[A-Za-z0-9_.@+\-]{1,64}"></label>
<label class=cap>Starting password (8 or more characters)<input name=password type=password autocomplete=new-password minlength=8 required></label>
<label class=cap>Role<select name=role><option value=viewer>viewer</option><option value=operator>operator</option><option value=admin>admin</option></select></label>
<div class="full row"><span class=mut id=umsg></span><span class=sp></span><button class=p>Add user</button></div><div class="full err" id=uerr></div></form></div>
<div class=card><b>Your account</b> <span class=mut id=whoami></span>
<div class=mut style="margin-top:4px">Your password and your API keys are on <a href="/account">your account page</a>, which every user can open. Lost the admin password? Stop gitmirror, delete <code>configs/auth.json</code> in the data folder and start it again to create a new first admin.</div></div>
<div class=card><b>Recent activity</b> <span class=mut>changes made by signed-in users and by the script token</span>
<div class=scroll><table id=atab></table></div></div>
<div class=card><b>Backup and restore the mirror list</b>
<div class=mut style="margin:2px 0 8px">Exports the list of mirrors and followed accounts (not the repository data). Credentials inside clone URLs are masked, so those entries can't be restored from the file.</div>
<div class=row><a id=exp href="/api/export" download><button type=button>Download export</button></a><input type=file id=impf accept=".json,application/json" style="width:auto"><button id=imp>Import</button></div>
<div class=mut id=impmsg style="margin-top:6px"></div></div></main>
<script>
const api=(p,o={})=>fetch('/api'+p,{...o,headers:{'Content-Type':'application/json'}}).then(r=>{if(r.status==401)location='/login';return r});
const f=document.querySelector('#f'),show=s=>{if(s.extras_default)document.querySelectorAll('[name=extras_default]').forEach(c=>c.checked=s.extras_default.includes(c.value));document.querySelector('#tokstate').textContent=s.github_token_set?'(set)':'(not set)';f.elements.github_token.value='';for(const k in s){const e=f.elements[k];if(k=='extras_default'||k=='github_token')continue;if(!e)continue;if(e.type=='checkbox')e.checked=!!s[k];else e.value=s[k+'_text']??s[k]}};

api('/settings').then(r=>r.json()).then(show);
let ME=null;
api('/auth/me').then(r=>r.json()).then(m=>{ME=m;if(m.user)document.querySelector('#whoami').textContent='signed in as '+m.user+' ('+m.role+')';loadUsers()});
const ago=t=>{const s=Date.now()/1e3-t;return s<90?Math.round(s)+'s ago':s<5400?Math.round(s/60)+'m ago':s<172800?Math.round(s/3600)+'h ago':Math.round(s/86400)+'d ago'};
const esc2=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function loadUsers(){const us=await (await api('/users')).json();
 document.querySelector('#utab').innerHTML='<tr><th>User</th><th>Role</th><th>Status</th><th>Keys</th><th></th></tr>'+us.map(u=>{const me=ME&&u.name.toLowerCase()==(ME.user||'').toLowerCase();
  return `<tr data-k="${esc2(u.key)}"><td>${esc2(u.name)}${me?' <span class=mut>(you)</span>':''}</td>
  <td><select data-f=role style="width:auto;margin:0">${['viewer','operator','admin'].map(r=>`<option ${r==u.role?'selected':''}>${r}</option>`).join('')}</select></td>
  <td>${u.disabled?'<span class=err>disabled</span>':'active'}${u.signed_in?` <span class=mut>${u.signed_in} signed in</span>`:''}</td>
  <td>${u.keys||0}${u.keys?` <button data-a=rk>Revoke</button>`:''}</td>
  <td class=n>${me?'':`<button data-a=pw>Reset password</button> <button data-a=dis>${u.disabled?'Enable':'Disable'}</button> <button data-a=del>Delete</button>`}</td></tr>`}).join('');
 const au=await (await api('/audit')).json();
 document.querySelector('#atab').innerHTML='<tr><th>When</th><th>Who</th><th>What</th><th>On</th></tr>'+(au.slice(0,60).map(a=>`<tr><td class=n>${ago(a.t)}</td><td>${esc2(a.user)} <span class=mut>${esc2(a.role)}${a.via?' via '+esc2(a.via):''}</span></td><td>${esc2(a.what)}${a.note?` <span class=mut>${esc2(a.note)}</span>`:''}</td><td>${esc2(a.target)}</td></tr>`).join('')||'<tr><td class=mut colspan=4>Nothing yet.</td></tr>')}
document.querySelector('#utab').onchange=async e=>{const tr=e.target.closest('tr');if(!tr||e.target.dataset.f!='role')return;const r=await api('/users/'+encodeURIComponent(tr.dataset.k),{method:'PUT',body:JSON.stringify({role:e.target.value})});if(!r.ok)alert((await r.json()).error);loadUsers()};
document.querySelector('#utab').onclick=async e=>{const b=e.target.closest('button'),tr=e.target.closest('tr');if(!b||!tr)return;const k=encodeURIComponent(tr.dataset.k),name=tr.firstElementChild.firstChild.textContent;let r;
 if(b.dataset.a=='pw'){const pw=prompt('New password for '+name+' (8 or more characters). They will be signed out everywhere.');if(!pw)return;r=await api('/users/'+k,{method:'PUT',body:JSON.stringify({password:pw})})}
 else if(b.dataset.a=='rk'){if(!confirm('Revoke all API keys of '+name+'? Anything using them stops working.'))return;r=await api('/users/'+k,{method:'PUT',body:JSON.stringify({revoke_keys:true})})}
 else if(b.dataset.a=='dis'){r=await api('/users/'+k,{method:'PUT',body:JSON.stringify({disabled:b.textContent=='Disable'})})}
 else if(b.dataset.a=='del'){if(!confirm('Delete the user '+name+'?'))return;r=await api('/users/'+k,{method:'DELETE'})}
 if(r&&!r.ok)alert((await r.json()).error);loadUsers()};
document.querySelector('#uf').onsubmit=async ev=>{ev.preventDefault();const g=ev.target.elements,ue=document.querySelector('#uerr'),um=document.querySelector('#umsg');ue.textContent='';um.textContent='';
 const r=await api('/users',{method:'POST',body:JSON.stringify({username:g.username.value,password:g.password.value,role:g.role.value})}),j=await r.json();
 if(r.ok){um.textContent='User added';ev.target.reset();loadUsers()}else ue.textContent=j.error};
api('/version').then(r=>r.json()).then(v=>{document.querySelector('#verline').textContent='This is v'+v.version+(v.enabled&&v.latest?(v.update_available?'; v'+v.latest+' is available.':'; that is the newest release.'):'')});


document.querySelector('#imp').onclick=async()=>{const f=document.querySelector('#impf').files[0],m=document.querySelector('#impmsg');if(!f){m.textContent='Choose an export file first.';return}
 let body;try{body=JSON.parse(await f.text())}catch(e){m.textContent='That file is not valid JSON.';return}
 const r=await api('/import',{method:'POST',body:JSON.stringify(body)}),j=await r.json();
 m.textContent=r.ok?`Added ${j.mirrors_added} mirrors (${j.mirrors_existing} already existed) and ${j.sources_added} followed accounts.${j.skipped.length?' Skipped: '+j.skipped.join('; '):''}`:j.error};
f.onsubmit=async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(f));d.timeout=+d.timeout;d.max_parallel=+d.max_parallel;d.release_asset_max_mb=+d.release_asset_max_mb;d.update_check=f.elements.update_check.checked;d.lfs_auto=f.elements.lfs_auto.checked;d.lfs_auto_max_gb=+d.lfs_auto_max_gb;d.extras_default=[...document.querySelectorAll('[name=extras_default]:checked')].map(x=>x.value);if(!d.github_token)delete d.github_token;d.low_disk_gb=+d.low_disk_gb;d.hold_default=f.elements.hold_default.checked;d.colorblind=f.elements.colorblind.checked;
 const r=await api('/settings',{method:'PUT',body:JSON.stringify(d)}),j=await r.json();
 document.querySelector('#e').textContent=r.ok?'':j.error;document.querySelector('#ok').textContent=r.ok?'Saved':'';if(r.ok)show(j)};
</script></html>"""

REPO = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Mirror details</title>
<style>__STYLE__</style>
<main><div class=row><h1 id=title>…</h1><span class=sp></span><a id=back href="/">All mirrors</a></div>
<div class=card><div class=row><span id=dot class=dot></span><span id=state class=mut></span><span class=sp></span>
<button class=op data-a=sync>Sync now</button><button class=op data-a=toggle id=tg>Pause</button><button class=op data-a=hold id=hd title="Hold upstream rewrites and deletions for review instead of applying them">Hold: off</button><button class=op data-a=meta>Refresh details</button><button class=op data-a=verify title="git fsck: check the stored objects for corruption">Verify</button><button class=adm data-a=del>Delete</button></div>
<div class=err id=err></div><div class=mut id=amsg></div></div>
<div class=card id=heldcard style="display:none;border-color:var(--run)"><b>⏸ Upstream changes on hold</b>
<div class=mut style="margin:4px 0">Your mirror still has the versions below. Nothing upstream has been applied to them.</div><pre id=heldlist></pre>
<div class="row op"><button class=p id=accept>Accept changes</button><button id=reject>Keep mine</button><span class=mut>Accepting applies them and archives your old versions. Keep mine ignores these changes until upstream changes again.</span></div></div>
<div class=card id=alertcard style="display:none;border-color:var(--err)"><div class=row><b class=err>⚠ Alert</b><span class=sp></span><button class=op id=ack>Dismiss</button></div><div id=alerttxt style="margin-top:6px"></div></div>
<div class=card><dl id=info></dl></div>
<div class=card><b>Archive history</b> <span class=mut>(origin deletions, rewrites and outages; old versions are kept)</span><div id=evs style="margin-top:8px"></div></div>
<div class=card><b>Also archive</b> <span class=mut>(more than the git history; refreshed on every sync)</span>
<div class=row id=exbox style="margin:8px 0"></div><div id=exinfo></div></div>
<div class=card><b>Tags</b><div class=row id=tags style="margin:8px 0"></div>
<div class="row op"><input id=newtag placeholder="Add a tag" style="max-width:240px"><button id=addtag>Add</button><span class=mut id=tagmsg></span></div></div>
<div class="card op"><form id=f>
<label class=cap>Name<input id=nm></label><label class=cap>Sync interval (W, D, H, M; 0 = manual sync)<input id=iv placeholder="3D"></label>
<div class="full row"><span class=sp></span><span class=mut id=fmsg></span><button class=p>Save</button></div></form></div>
<div class=card><b>Last sync log</b><pre id=log>…</pre></div></main>
<script>
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const id=location.pathname.split('/').pop();
const api=(p,o={})=>fetch('/api'+p,{...o,headers:{'Content-Type':'application/json'}}).then(r=>{if(r.status==401)location='/login';return r});
const when=t=>t?new Date(t*1000).toLocaleString():'—';
const ago=t=>{if(!t)return'never';const s=Date.now()/1e3-t;return s<90?Math.round(s)+'s ago':s<5400?Math.round(s/60)+'m ago':s<172800?Math.round(s/3600)+'h ago':Math.round(s/86400)+'d ago'};
const until=t=>{const s=t-Date.now()/1e3;return s<=30?'due now':s<5400?'in '+Math.max(1,Math.round(s/60))+'m':s<172800?'in '+Math.round(s/3600)+'h':'in '+Math.round(s/86400)+'d'};
const sz=b=>b==null?'—':b>1e9?(b/1e9).toFixed(1)+' GB':b>1e6?(b/1e6).toFixed(1)+' MB':Math.round(b/1e3)+' KB';
const link=u=>`<a href="${esc(u)}" target=_blank rel="noopener noreferrer">${esc(u)}</a>`;
$('#back').href='/';
let m=null,tags=[];
function render(){const mt=m.meta||{},g=m.git||{},st=m.running?'running':m.status;
 document.title=m.name+' · Git Mirror';$('#title').textContent=m.name;
 $('#dot').className='dot '+st;$('#state').textContent=st+(m.enabled?'':' (paused)');$('#tg').textContent=m.enabled?'Pause':'Resume';
 $('#err').textContent=m.error||'';
 $('#hd').textContent=m.hold?'Hold: on':'Hold: off';
 $('#heldcard').style.display=(m.held||[]).length?'':'none';
 $('#heldlist').textContent=(m.held||[]).map(h=>`${h.kind.padEnd(9)} ${h.ref}  yours ${h.old.slice(0,10)}  upstream ${h.new?h.new.slice(0,10):'(gone)'}`).join('\n');
 $('#alertcard').style.display=m.alert?'':'none';
 loadExtras();$('#alerttxt').textContent=m.alert||'';
 $('#evs').innerHTML=(m.events||[]).slice().reverse().map(e=>`<details ${e.alert?'open':''} style="margin-bottom:8px"><summary class="${e.alert?'err':''}">${when(e.time)} · ${esc(e.type.replace('_',' '))} <span class=mut>— ${esc(e.summary).slice(0,160)}</span></summary>
  ${(e.refs||[]).length?`${e.refs.some(r=>r.archive)?`<div class=mut style="margin:6px 0">Get one back: <code>git -C ${esc(m.local_path)} branch RESTORED-NAME &lt;old commit&gt;</code></div>`:''}<pre>${e.refs.map(r=>esc(`${r.kind.padEnd(9)} ${r.ref}  was ${r.old.slice(0,12)}  ${r.archive?'kept as '+r.archive:(r.new?'upstream now '+r.new.slice(0,12)+', not applied':'deleted upstream, not applied')}`)).join('\n')}</pre>`:''}</details>`).join('')||'<span class=mut>Nothing has been removed or rewritten upstream.</span>';
 const rows=[
  ['Origin',mt.web_url?link(mt.web_url):'—'],
  ['Description',mt.description?esc(mt.description):'—'],
  ['Website',mt.homepage?link(mt.homepage):null],
  ['Clone URL',esc(m.source)],
  ['Added',m.added?when(m.added):'unknown (added before tracking)'],
  ['Last sync',m.last_run?`${when(m.last_run)} (${ago(m.last_run)}${m.duration!=null?', took '+m.duration+'s':''})`:'never'],
  ['Last successful sync',m.last_ok?`${when(m.last_ok)} (${ago(m.last_ok)})`:'never'],
  ['Sync interval',m.interval?'every '+m.interval_text:'manual only'],
  ['Next sync',m.next_run&&!m.running?until(m.next_run):null],
  ['Failures',m.failures?`${m.failures} in a row${m.retry_at?', retrying '+until(m.retry_at):''}`:null],
  ['Integrity',m.fsck?`${m.fsck.ok?'passed':'<span class=err>FAILED</span>'} ${ago(m.fsck.time)}${m.fsck.ok?'':'<pre>'+esc(m.fsck.output)+'</pre>'}`:'not checked yet'],
  ['Hold',m.hold?'on: upstream rewrites and deletions wait for your review':'off: upstream changes are applied and old versions archived'],
  ['Local size',sz(m.size)],
  ['Branches / tags',g.branches!=null?`${g.branches} / ${g.tags}${g.other_refs?` (+${g.other_refs} other refs)`:''}`:'—'],
  ['Archived refs',g.archived_refs?String(g.archived_refs):null],
  ['Default branch',esc(g.head||mt.default_branch||'—')],
  ['Latest commit',g.last_commit?`${esc(g.last_commit.subject)} <span class=mut>— ${esc(g.last_commit.author)}, ${when(g.last_commit.time)}</span>`:'—'],
  ['Platform',mt.platform?esc(mt.platform):null],
  ['Platform stats',mt.platform?`★ ${mt.stars??'?'} · forks ${mt.forks??'?'}${mt.language?' · '+esc(mt.language):''}${mt.license?' · '+esc(mt.license):''}${mt.archived?' · archived':''}`:null],
  ['Upstream activity',mt.upstream_updated?esc(mt.upstream_updated):null],
  ['Topics',(mt.topics||[]).length?mt.topics.map(t=>`<span class=chip style="cursor:default">${esc(t)}</span>`).join(' '):null],
  ['Local path',`<code>${esc(m.local_path)}</code>`],
  ['Details fetched',mt.fetched?ago(mt.fetched)+(mt.fetch_error?` <span class=err>(${esc(mt.fetch_error)})</span>`:''):'never']];
 $('#info').innerHTML=rows.filter(r=>r[1]!=null).map(r=>`<dt>${r[0]}</dt><dd>${r[1]}</dd>`).join('');
 api('/mirrors/'+id+'/log').then(r=>r.text()).then(t=>$('#log').textContent=t||'(empty)')}
function renderTags(){$('#tags').innerHTML=tags.map((t,i)=>`<span class=chip data-i=${i}>${esc(t)}<b>×</b></span>`).join('')||'<span class=mut>No tags yet.</span>'}
async function load(first){const r=await api('/mirrors/'+id);
 if(r.status==404){document.body.innerHTML=`<main><p>Mirror not found. <a href="/">Back to all mirrors</a></p></main>`;return}
 if(!r.ok)return;m=await r.json();render();
 if(first){tags=[...(m.tags||[])];renderTags();$('#nm').value=m.name;$('#iv').value=m.interval_text}}
async function saveTags(){const r=await api('/mirrors/'+id,{method:'PUT',body:JSON.stringify({tags})}),j=await r.json();
 $('#tagmsg').textContent=r.ok?'Saved':j.error;if(r.ok){tags=j.tags;renderTags()}}
const EXN=[['wiki','Wiki'],['lfs','Git LFS files'],['releases','Releases'],['issues','Issues']];
let exsig='';
function drawExtras(){const ex=m.extras||{};
 $('#exbox').innerHTML=EXN.map(e=>`<label class=row style="gap:4px"><input type=checkbox style="width:auto" data-ex=${e[0]} ${ex[e[0]]?'checked':''}> ${e[1]}</label>`).join(' ');
 document.querySelectorAll('[data-ex]').forEach(c=>c.onchange=async()=>{const on=[...document.querySelectorAll('[data-ex]:checked')].map(x=>x.dataset.ex);
  await api('/mirrors/'+id,{method:'PUT',body:JSON.stringify({extras:on})});exsig='';load()})}
async function loadExtras(){const sig=JSON.stringify(m.extras_state||{})+JSON.stringify(m.extras||{})+JSON.stringify(m.lfs_detect||{});if(sig==exsig)return;exsig=sig;drawExtras();
 const j=await (await api('/mirrors/'+id+'/extras')).json(),st=j.state||{},ex=m.extras||{};let h='';
 const line=(k,t)=>ex[k]?`<div class=${st[k]&&st[k].state=='error'?'err':'mut'}>${t}</div>`:'';
 const S=k=>st[k]||{};
 const ld=m.lfs_detect;if(ld&&ld.used)h+=`<div class="${m.lfs_needed?'err':'mut'}">Git LFS: this repo stores ${ld.files==1?'1 large file':(ld.files??'some')+' large files'}${ld.bytes?' ('+sz(ld.bytes)+')':''}${m.lfs_needed?(ld.installed===false?' and git-lfs is not installed on this server, so they are not being mirrored.':' and they are not being mirrored. <button class=op id=lfson>Enable LFS</button>'):'.'}</div>`;
 h+=line('wiki',S('wiki').state=='ok'?`Wiki: mirrored (${sz(S('wiki').size)}) at <code>${esc(m.local_path.replace(/\.git$/,'.wiki.git'))}</code>`:S('wiki').state=='none'?'Wiki: this repository has none':S('wiki').state=='error'?'Wiki: '+esc(S('wiki').msg):'Wiki: not fetched yet');
 h+=line('lfs',S('lfs').state=='ok'?`Git LFS: fetched (${sz(S('lfs').size)})`:S('lfs').state=='error'?'Git LFS: '+esc(S('lfs').msg):'Git LFS: not fetched yet');
 h+=line('releases',S('releases').state=='ok'?`Releases: ${S('releases').count} saved, ${S('releases').downloaded} new files downloaded${S('releases').skipped?', '+S('releases').skipped+' skipped (size limit or failed)':''}, ${sz(S('releases').bytes)} on disk`:S('releases').state=='error'?'Releases: '+esc(S('releases').msg):'Releases: not fetched yet');
 h+=line('issues',S('issues').state=='ok'?`Issues: ${S('issues').count} saved${S('issues').msg?' ('+esc(S('issues').msg)+')':''}`:S('issues').state=='error'?'Issues: '+esc(S('issues').msg):'Issues: not fetched yet');
 if((j.releases||[]).length)h+=`<details style="margin-top:8px"><summary><b>Releases (${j.releases.length})</b></summary>${j.releases.map(r=>`<details style="margin:6px 0 6px 12px"><summary>${esc(r.tag)}${r.name&&r.name!=r.tag?' · '+esc(r.name):''}${r.prerelease?' <span class=chip style="cursor:default">pre-release</span>':''} <span class=mut>${esc((r.published||'').slice(0,10))}</span></summary>
  ${r.body?`<pre>${esc(r.body)}</pre>`:''}${(r.assets||[]).map(a=>`<div>${a.local?`<a href="/dl/${id}/${a.local.split('/').map(encodeURIComponent).join('/')}">${esc(a.name)}</a>`:esc(a.name)} <span class=mut>${a.size!=null?sz(a.size):''} ${a.local?'':esc(a.note||'')}</span></div>`).join('')}</details>`).join('')}</details>`;
 if((j.issues||[]).length)h+=`<details style="margin-top:8px"><summary><b>Issues (${j.issues_total}${j.issues_total>j.issues.length?', newest '+j.issues.length+' shown':''})</b></summary>${j.issues.map(i=>`<details style="margin:6px 0 6px 12px"><summary>#${i.number} ${esc(i.title)} <span class=mut>${esc(i.state)}${i.is_pr?' · PR':''} · ${(i.comments||[]).length} comments</span></summary>
  <div class=mut>${esc(i.author||'?')} opened ${esc((i.created||'').slice(0,10))}${i.url?` · <a href="${esc(i.url)}" target=_blank rel="noopener noreferrer">origin ↗</a>`:''}</div>${i.body?`<pre>${esc(i.body)}</pre>`:''}
  ${(i.comments||[]).map(c=>`<div style="margin:6px 0 0 12px"><span class=mut>${esc(c.author||'?')} · ${esc((c.created||'').slice(0,10))}</span><pre>${esc(c.body||'')}</pre></div>`).join('')}</details>`).join('')}</details>`;
 $('#exinfo').innerHTML=h||'<span class=mut>Nothing extra is enabled.</span>';
 const lb=$('#lfson');if(lb)lb.onclick=async()=>{lb.disabled=true;await api('/mirrors/'+id+'/lfs',{method:'POST'});exsig='';load()}}
$('#accept').onclick=async()=>{if(!confirm('Apply these upstream changes? Your old versions stay archived.'))return;await api('/mirrors/'+id+'/accept',{method:'POST'});load()};
$('#reject').onclick=async()=>{await api('/mirrors/'+id+'/reject',{method:'POST'});load()};
$('#ack').onclick=async()=>{await api('/mirrors/'+id+'/ack',{method:'POST'});load()};
$('#tags').onclick=e=>{const c=e.target.closest('.chip');if(!c)return;tags.splice(+c.dataset.i,1);renderTags();saveTags()};
const add=()=>{const v=$('#newtag').value.trim();if(!v)return;tags=[...tags,...v.split(',')];$('#newtag').value='';renderTags();saveTags()};
$('#addtag').onclick=add;$('#newtag').onkeydown=e=>{if(e.key=='Enter')add()};
$('#f').onsubmit=async e=>{e.preventDefault();
 const r=await api('/mirrors/'+id,{method:'PUT',body:JSON.stringify({name:$('#nm').value,interval:$('#iv').value})}),j=await r.json();
 $('#fmsg').textContent=r.ok?'Saved':j.error;if(r.ok){$('#iv').value=j.interval_text;load()}};
document.querySelector('.card .row').onclick=async e=>{const b=e.target.closest('button');if(!b)return;const a=b.dataset.a;
 if(a=='del'){if(!confirm('Delete mirror and its local copy?'))return;const r=await api('/mirrors/'+id,{method:'DELETE'});
  if(r.ok)location='/';else $('#err').textContent=(await r.json()).error;return}
 b.disabled=true;const r=await api('/mirrors/'+id+'/'+a,{method:'POST'});b.disabled=false;
 if(a=='meta'&&r.ok){const j=await r.json(),e=(j.meta||{}).fetch_error;
  $('#amsg').textContent=j.changed==null?'No API details available for this host.':e?'Lookup failed, kept previous details: '+e:j.changed.length?'Updated from origin: '+j.changed.join(', '):'Checked origin just now: nothing has changed.'}
 load()};
load(true);setInterval(load,4000);
</script></html>"""

MAINT = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Git Mirror Maintenance</title>
<style>__STYLE__</style>
<main><div class=row><h1 id=title>Maintenance</h1><span class=sp></span><a id=back href="/">All mirrors</a></div>
<div id=top></div>
<div class=card id=optcard><div class=row><div><b>Optimize storage</b><div class=mut>Runs <code>git gc</code> on each mirror: repacks objects to save disk. Nothing is deleted, so archived history stays.</div></div><span class=sp></span><button class=op id=verall title="git fsck on every mirror">Verify all</button><button class="p op" id=optall>Optimize all</button></div><div class=mut id=optmsg style="margin-top:6px"></div></div>
<div class=card><b>Disk used over time</b><div id=chart class=mut style="margin-top:6px">Loading…</div></div>
<div id=lists></div></main>
<script>
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=(p,o={})=>fetch('/api'+p,{...o,headers:{'Content-Type':'application/json'}}).then(r=>{if(r.status==401)location='/login';return r});
const bytes=b=>!b?'0 B':b>=1e9?(b/1e9).toFixed(1)+' GB':b>=1e6?(b/1e6).toFixed(1)+' MB':b>=1e3?Math.round(b/1e3)+' KB':b+' B';
const day=t=>t?new Date(t*1000).toLocaleDateString():'unknown';
const ago=t=>{if(!t)return'never';const s=Date.now()/1e3-t;return s<5400?Math.round(s/60)+'m ago':s<172800?Math.round(s/3600)+'h ago':Math.round(s/86400)+'d ago'};
const kinds={size:['Largest mirrors','Biggest disk users first. Delete or optimize to reclaim space.'],
 oldest:['Oldest mirrors','Longest-kept first. Mirrors added before dates were tracked show as unknown and sort first.'],
 lfs:['LFS not mirrored','These repos use Git LFS but their large files are not being archived. Enable LFS to protect them.'],
 attention:['Needs attention','Failing syncs, missing origins, alerts and paused mirrors: candidates for cleanup.']};
const only=location.pathname.split('/')[2]||null;
$('#back').href=only?'/maintenance':'/';$('#back').textContent=only?'Back to maintenance':'All mirrors';
if(only){$('#title').textContent=kinds[only][0];document.title=kinds[only][0]+' · Git Mirror'}
const status=m=>m.origin_missing?'<span class=err>origin missing</span>':m.status=='error'?'<span class=err>error</span>':esc(m.status)+(m.enabled?'':' (paused)');
const table=rows=>rows.length?`<div class=scroll><table><tr><th>Name</th><th>Added</th><th>Last good sync</th><th>Size</th><th>Status</th><th>Tags</th><th></th></tr>${rows.map(m=>`<tr data-id=${m.id}>
 <td><a href="/repo/${m.id}">${esc(m.name)}</a>${m.lfs_needed&&m.lfs_detect?` <span class=mut>LFS: ${m.lfs_detect.files==1?'1 file':(m.lfs_detect.files??'?')+' files'}, ${bytes(m.lfs_detect.bytes)}</span>`:''}</td><td class=n>${day(m.added)}</td><td class=n>${ago(m.last_ok)}</td><td class=n>${bytes(m.size)}</td><td>${status(m)}</td>
 <td>${(m.tags||[]).map(t=>`<span class=chip style="cursor:default">${esc(t)}</span>`).join(' ')}</td>
 <td class=n>${m.lfs_needed?'<button class=op data-a=lfs>Enable LFS</button> ':''}<button class=op data-a=opt>Optimize</button> <button class=adm data-a=del>Delete</button></td></tr>`).join('')}</table></div>`:'<p class=mut>Nothing here.</p>';
async function loadLists(){const ks=only?[only]:Object.keys(kinds);
 const res=await Promise.all(ks.map(k=>api('/maintenance?kind='+k+(only?'':'&limit=10')).then(r=>r.json())));
 $('#lists').innerHTML=ks.map((k,i)=>(!only&&k=='lfs'&&!res[i].total)?'':`<div class=card><div class=row><b>${esc(kinds[k][0])}</b>${only?` <span class=mut>(${res[i].total})</span>`:''}<span class=sp></span>${!only&&res[i].total>10?`<a href="/maintenance/${k}">View full list (${res[i].total}) →</a>`:''}</div>
  <div class=mut style="margin:2px 0 8px">${esc(kinds[k][1])}${only?'':' Top 10.'}</div>${table(res[i].rows)}</div>`).join('')}
async function loadStats(){const r=await api('/stats');if(!r.ok)return;const s=await r.json(),o=s.optimize||{};
 $('#top').innerHTML='<div class=tiles>'+[[s.projects,'projects'],[bytes(s.disk_bytes),'disk space used'],[bytes(s.saved_bytes),'space saved by optimizing'],[s.disk_free==null?'?':bytes(s.disk_free),'free on the data disk'+(s.low_disk?' (low)':'')],[s.optimized_at?ago(s.optimized_at):'never','last optimized']].map(t=>`<div class=card><b>${t[0]}</b><span>${t[1]}</span></div>`).join('')+'</div>';
 $('#optall').disabled=$('#verall').disabled=!!o.active;
 const v=o.label=='verify',res=v?`${o.result} problem(s) found`:`saved ${bytes(o.result)}`;
 $('#optmsg').textContent=o.active?`${v?'Verifying':'Optimizing'} ${o.done}/${o.total}${o.current?': '+o.current:''}… ${res} so far`:o.total?`Last ${v?'verification':'optimize run'}: ${o.done}/${o.total} mirrors, ${res}.`:'';
 return o.active}
$('#optall').onclick=async()=>{await api('/maintenance/optimize',{method:'POST',body:'{}'});tick()};
$('#verall').onclick=async()=>{await api('/maintenance/verify',{method:'POST',body:'{}'});tick()};
$('#lists').onclick=async e=>{const b=e.target.closest('button');if(!b)return;const tr=b.closest('tr'),id=tr.dataset.id,name=tr.querySelector('a').textContent;
 if(b.dataset.a=='lfs'){await api('/mirrors/'+id+'/lfs',{method:'POST'});loadLists();return}
 if(b.dataset.a=='del'){if(!confirm('Delete "'+name+'" and its local copy? Archived history in it is lost too.'))return;
  const r=await api('/mirrors/'+id,{method:'DELETE'});if(!r.ok)alert((await r.json()).error);loadLists();loadStats()}
 else{await api('/maintenance/optimize',{method:'POST',body:JSON.stringify({ids:[id]})});tick()}};
async function chart(){const h=await (await api('/history')).json(),el=$('#chart');
 if(h.length<2){el.textContent='Collecting data: one point is recorded every 6 hours, so a graph appears after the first day.';return}
 const W=700,H=160,P=34,xs=h.map(p=>p.t),ys=h.map(p=>p.disk),x0=xs[0],x1=xs[xs.length-1]||x0+1,y1=Math.max(...ys,1);
 const X=t=>P+(W-P-8)*(t-x0)/Math.max(1,x1-x0),Y=v=>H-22-(H-34)*v/y1;
 const pts=h.map(p=>X(p.t).toFixed(1)+','+Y(p.disk).toFixed(1)).join(' ');
 el.innerHTML=`<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto" role=img aria-label="Disk used over time"><line x1=${P} y1=${H-22} x2=${W-8} y2=${H-22} stroke="var(--bd)"/>
  <text x=${P} y=12 fill="var(--mut)" font-size=11>${bytes(y1)}</text><text x=${P} y=${H-6} fill="var(--mut)" font-size=11>${new Date(x0*1000).toLocaleDateString()}</text>
  <text x=${W-8} y=${H-6} fill="var(--mut)" font-size=11 text-anchor=end>${new Date(x1*1000).toLocaleDateString()}</text>
  <polyline points="${pts}" fill=none stroke="var(--acc)" stroke-width=2 /></svg>`}
let timer=null;async function tick(){clearTimeout(timer);const active=await loadStats();loadLists();timer=active?setTimeout(tick,1500):null}
tick();chart();setInterval(()=>{if(!timer)loadStats()},10000);
</script></html>"""

SOURCES = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Git Mirror Sources</title>
<style>__STYLE__</style>
<main><div class=row><h1 id=title>Sources</h1><span class=sp></span><a id=back href="/">All mirrors</a></div>
<div id=view></div></main>
<script>
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=(p,o={})=>fetch('/api'+p,{...o,headers:{'Content-Type':'application/json'}}).then(r=>{if(r.status==401)location='/login';return r});
const post=(p,b)=>api(p,{method:'POST',body:JSON.stringify(b||{})});
const kb=n=>n==null?'?':n>=1048576?(n/1048576).toFixed(1)+' GB':n>=1024?(n/1024).toFixed(1)+' MB':n+' KB';
const ago=t=>{if(!t)return'never';const s=Date.now()/1e3-t;return s<90?Math.round(s)+'s ago':s<5400?Math.round(s/60)+'m ago':s<172800?Math.round(s/3600)+'h ago':Math.round(s/86400)+'d ago'};
const EX=[['wiki','Wiki'],['lfs','Git LFS files'],['releases','Releases'],['issues','Issues']];
const exBoxes=(sel,name)=>EX.map(e=>`<label class=row style="gap:4px;font-size:13px"><input type=checkbox style="width:auto" name="${name}" value=${e[0]} ${sel.includes(e[0])?'checked':''}> ${e[1]}</label>`).join(' ');
const parts=location.pathname.split('/').filter(Boolean),sid=parts[0]=='source'?parts[1]:null;
$('#back').href=sid?'/sources':'/';$('#back').textContent=sid?'All sources':'All mirrors';
let preview=null;

/* ---------- list page ---------- */
async function list(){
 const ss=await (await api('/sources')).json();
 $('#view').innerHTML=`<div class="card op"><b>Follow a user, org or group</b>
  <div class=mut style="margin:2px 0 8px">Paste an account page, e.g. https://github.com/name. You'll choose which repositories to mirror before anything is added.</div>
  <form id=pf class=row style="flex-wrap:nowrap"><input id=purl placeholder="https://github.com/name" required><button class=p>Preview</button></form><div class=err id=perr></div></div>
  <div id=prev></div>
  ${ss.map(x=>`<div class=card><div class=row><b><a href="/source/${x.id}">${esc(x.name)}</a></b><span class=mut>${esc(x.kind)} ${esc(x.account_type)} · ${esc(x.hostport)}</span><span class=sp></span>
   <a href="/?tag=${encodeURIComponent(x.name.toLowerCase())}">view mirrors</a></div>
   <div class=mut>${x.counts.added} mirrored · ${x.counts.pending?`<b style="color:var(--run)">${x.counts.pending} waiting for approval</b>`:'0 waiting'} · ${x.counts.excluded} skipped · ${x.counts.gone?`<span class=err>${x.counts.gone} gone from account</span>`:'0 gone'} · scanned ${ago(x.last_scan)}${x.last_error?` · <span class=err>${esc(x.last_error)}</span>`:''}</div>
   ${x.alert?`<div class=err>⚠ ${esc(x.alert)}</div>`:''}</div>`).join('')||'<p class=mut>No sources yet.</p>'}`;
 $('#pf').onsubmit=async e=>{e.preventDefault();$('#perr').textContent='';$('#prev').innerHTML='<p class=mut>Looking up the account…</p>';
  const r=await post('/sources/preview',{url:$('#purl').value}),j=await r.json();
  if(!r.ok){$('#prev').innerHTML='';$('#perr').textContent=j.error;return}
  preview=j;renderPreview()};
 const u=new URLSearchParams(location.search).get('add');if(u){$('#purl').value=u;$('#pf').requestSubmit()}
}
function renderPreview(){const j=preview,a=j.account;
 if(j.source_id){$('#prev').innerHTML=`<div class=card>You already follow this account. <a href="/source/${j.source_id}">Open it</a>.</div>`;return}
 const tot=j.repos.reduce((n,r)=>n+(r.size_kb||0),0);
 $('#prev').innerHTML=`<div class=card><div class=row><b>${esc(a.name)}</b><span class=mut>${esc(a.kind)} ${esc(a.type)} · ${j.repos.length} repositories · ${j.repos.filter(r=>r.fork).length} fork${j.repos.filter(r=>r.fork).length==1?'':'s'} · ${j.repos.filter(r=>r.arch).length} archived · about ${kb(tot)} on the host</span></div>
  <div class=scroll><table><tr><th><input type=checkbox id=all style="width:auto"></th><th>Repository</th><th>Size</th><th>Stars</th><th></th></tr>
  ${j.repos.map((r,i)=>`<tr><td><input type=checkbox style="width:auto" data-i=${i} ${r.selected&&!r.mirrored?'checked':''}></td>
   <td><b>${esc(r.name)}</b> ${r.fork?'<span class=chip style="cursor:default">fork</span>':''}${r.arch?'<span class=chip style="cursor:default">archived</span>':''}${r.mirrored?'<span class=chip style="cursor:default">already mirrored</span>':''}<div class=mut>${esc(r.desc||'')}</div></td>
   <td class=n>${kb(r.size_kb)}</td><td class=n>${r.stars??'—'}</td><td></td></tr>`).join('')}</table></div>
  <form id=cf style="margin-top:10px">
   <label class=cap>Sync interval (W, D, H, M)<input name=interval value="${esc(j.settings.interval)}"></label>
   <label class=cap>Extra tags (comma separated)<input name=tags placeholder="${esc(a.name)} is added automatically"></label>
   <div class=full><span class=cap>Also archive</span><div class=row>${exBoxes(j.settings.extras,'extras')}</div></div>
   <label class="full row cap" style="gap:8px"><input type=checkbox name=hold style="width:auto" ${j.settings.hold?'checked':''}> Hold upstream rewrites and deletions for review</label>
   <label class="full row cap" style="gap:8px"><input type=checkbox name=auto_add style="width:auto"> Add new repositories automatically (otherwise they wait for your approval)</label>
   <label class="full row cap" style="gap:8px"><input type=checkbox name=include_forks style="width:auto"> Include forks in future scans</label>
   <div class="full row"><span class=mut id=sel></span><span class=sp></span><button class=p>Mirror selected</button></div><div class="full err" id=cerr></div></form></div>`;
 const boxes=()=>[...document.querySelectorAll('#prev [data-i]')],upd=()=>{const c=boxes().filter(b=>b.checked);
  $('#sel').textContent=`${c.length} selected, about ${kb(c.reduce((n,b)=>n+(j.repos[b.dataset.i].size_kb||0),0))} on the host`};
 $('#all').onchange=e=>{boxes().forEach(b=>b.checked=e.target.checked);upd()};boxes().forEach(b=>b.onchange=upd);upd();
 $('#cf').onsubmit=async e=>{e.preventDefault();const f=e.target.elements;
  const body={url:j.url,selected:boxes().filter(b=>b.checked).map(b=>j.repos[b.dataset.i].path),interval:f.interval.value,tags:f.tags.value,
   extras:[...document.querySelectorAll('#cf [name=extras]:checked')].map(x=>x.value),hold:f.hold.checked,auto_add:f.auto_add.checked,include_forks:f.include_forks.checked};
  $('#cerr').textContent='';const r=await post('/sources',body),k=await r.json();
  if(r.ok)location='/source/'+k.id;else $('#cerr').textContent=k.error}}

/* ---------- detail page ---------- */
async function detail(){
 const r=await api('/sources/'+sid);if(!r.ok){$('#view').innerHTML='<p>Not found.</p>';return}
 const x=await r.json(),ms=await (await api('/mirrors')).json(),mine=ms.filter(m=>m.source_id==sid);
 const byId=Object.fromEntries(ms.map(m=>[m.id,m])),ent=Object.entries(x.known);
 $('#title').textContent=x.name;document.title=x.name+' · Source';
 const rows=st=>ent.filter(([p,k])=>k.state==st);
 const pend=rows('pending'),gone=rows('gone'),skip=rows('excluded');
 $('#view').innerHTML=`
 <div class=card><div class=row><span class=mut>${esc(x.kind)} ${esc(x.account_type)} · ${esc(x.hostport)} · scanned ${ago(x.last_scan)} · rescans every ${esc(x.rescan_text)}</span><span class=sp></span>
  <a href="/?tag=${encodeURIComponent(x.name.toLowerCase())}">view mirrors on main page</a><button class=op id=rescan>Rescan now</button><button class=adm id=del>Remove source</button></div>
  ${x.last_error?`<div class=err>${esc(x.last_error)}</div>`:''}${x.alert?`<div class=row><span class=err>⚠ ${esc(x.alert)}</span><button class=op id=ack>Dismiss</button></div>`:''}</div>
 ${pend.length?`<div class=card style="border-color:var(--run)"><div class=row><b>⏸ ${pend.length} new repositor${pend.length==1?'y':'ies'} waiting for approval</b><span class=sp></span><button class="p op" id=appall>Mirror all</button></div>
  <div class=scroll><table>${pend.map(([p,k])=>`<tr data-p="${esc(p)}"><td><b>${esc(k.name)}</b>${k.arch?' <span class=chip style="cursor:default">archived</span>':''}<div class=mut>${esc(k.desc||'')}</div></td><td class=n>${kb(k.size_kb)}</td><td class=n><button class=op data-a=approve>Mirror</button> <button class=op data-a=skip>Skip</button></td></tr>`).join('')}</table></div></div>`:''}
 ${gone.length?`<div class=card style="border-color:var(--err)"><b class=err>${gone.length} no longer in the account</b><div class=mut>Still mirrored and kept as archives.</div>
  <div class=scroll><table>${gone.map(([p,k])=>`<tr><td><a href="/repo/${k.mirror}">${esc(k.name)}</a></td><td class=mut>${esc(p)}</td></tr>`).join('')}</table></div></div>`:''}
 <div class=card><b>Mirrored (${mine.length})</b><div class=scroll><table><tr><th>Name</th><th>Status</th><th>Last good sync</th><th>Size</th><th>Tags</th></tr>
  ${mine.map(m=>`<tr><td><a href="/repo/${m.id}">${esc(m.name)}</a></td><td>${m.status=='error'?'<span class=err>error</span>':esc(m.status)}${m.gone_from_source?' <span class=err>gone</span>':''}</td><td class=n>${ago(m.last_ok)}</td><td class=n>${m.size!=null?kb(Math.round(m.size/1024)):'—'}</td><td>${(m.tags||[]).map(t=>`<span class=chip style="cursor:default">${esc(t)}</span>`).join(' ')}</td></tr>`).join('')||'<tr><td class=mut>Nothing mirrored yet.</td></tr>'}</table></div></div>
 <div class="card op"><b>Settings for this source</b><form id=sf style="margin-top:8px">
  <label class=cap>Interval for new repositories<input name=interval value="${esc(x.interval_text)}"></label>
  <label class=cap>Rescan the account every (0 = manual)<input name=rescan value="${esc(x.rescan_text)}"></label>
  <label class="cap full">Extra tags for new repositories<input name=tags value="${esc((x.tags||[]).join(', '))}"></label>
  <div class=full><span class=cap>Also archive</span><div class=row>${exBoxes(Object.keys(x.extras).filter(k=>x.extras[k]),'extras')}</div></div>
  <label class="full row cap" style="gap:8px"><input type=checkbox name=hold style="width:auto" ${x.hold?'checked':''}> Hold upstream rewrites and deletions for review</label>
  <label class="full row cap" style="gap:8px"><input type=checkbox name=auto_add style="width:auto" ${x.auto_add?'checked':''}> Add new repositories automatically</label>
  <label class="full row cap" style="gap:8px"><input type=checkbox name=include_forks style="width:auto" ${x.include_forks?'checked':''}> Include forks</label>
  <label class="full row cap" style="gap:8px"><input type=checkbox name=include_archived style="width:auto" ${x.include_archived?'checked':''}> Include archived repositories</label>
  <label class="full row cap" style="gap:8px"><input type=checkbox name=apply style="width:auto"> Also apply interval, hold and extras to the ${mine.length} existing mirrors</label>
  <div class="full row"><span class=mut id=smsg></span><span class=sp></span><button class=p>Save</button></div><div class="full err" id=serr></div></form></div>
 <div class=card><b>History</b><div style="margin-top:6px">${(x.events||[]).slice().reverse().map(e=>`<div class="${e.alert?'err':''}">${new Date(e.time*1000).toLocaleString()} · ${esc(e.summary)}</div>`).join('')||'<span class=mut>Nothing yet.</span>'}</div></div>`;
 $('#rescan').onclick=async()=>{$('#rescan').disabled=true;await post('/sources/'+sid+'/rescan');setTimeout(detail,2500)};
 $('#del').onclick=async()=>{const all=confirm('Remove this source?\n\nOK = remove the source only; its mirrors stay and keep syncing.\nCancel = go back.');if(!all)return;
  const del=confirm('Also delete the '+mine.length+' mirrors it created and their local copies?\n\nOK = delete them too. Cancel = keep the mirrors.');
  await api('/sources/'+sid+(del?'?delete_mirrors=1':''),{method:'DELETE'});location='/sources'};
 const ack=$('#ack');if(ack)ack.onclick=async()=>{await post('/sources/'+sid+'/ack');detail()};
 const aa=$('#appall');if(aa)aa.onclick=async()=>{aa.disabled=true;await post('/sources/'+sid+'/approve',{all:true});detail()};
 document.querySelectorAll('[data-a]').forEach(b=>b.onclick=async()=>{await post('/sources/'+sid+'/'+b.dataset.a,{paths:[b.closest('tr').dataset.p]});detail()});
 $('#sf').onsubmit=async e=>{e.preventDefault();const f=e.target.elements;
  const body={interval:f.interval.value,rescan:f.rescan.value,tags:f.tags.value,hold:f.hold.checked,auto_add:f.auto_add.checked,include_forks:f.include_forks.checked,
   include_archived:f.include_archived.checked,apply_to_members:f.apply.checked,extras:[...document.querySelectorAll('#sf [name=extras]:checked')].map(z=>z.value)};
  const r=await api('/sources/'+sid,{method:'PUT',body:JSON.stringify(body)}),j=await r.json();
  $('#serr').textContent=r.ok?'':j.error;$('#smsg').textContent=r.ok?'Saved':'';if(r.ok)setTimeout(detail,1200)}
}
sid?detail():list();
</script></html>"""

EVENTS = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Git Mirror Events</title>
<style>__STYLE__</style>
<main><div class=row><h1>Events</h1><span class=sp></span><a id=back href="/">All mirrors</a></div>
<div class="card row"><label class=row style="gap:6px"><input type=checkbox id=alerts style="width:auto"> Alerts only</label>
<select id=type style="width:auto;margin:0"><option value="">All types</option></select>
<input id=q type=search placeholder="Filter…" style="flex:1;min-width:160px"><span class=mut id=count></span></div>
<div class=card><div class=scroll><table id=tb></table></div><div class=row style="margin-top:8px"><button id=more hidden>Load older</button></div></div></main>
<script>
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=(p,o={})=>fetch('/api'+p,{...o,headers:{'Content-Type':'application/json'}}).then(r=>{if(r.status==401)location='/login';return r});
$('#back').href='/';
let rows=[],total=0;
const NAMES={history_changed:'history rewritten',origin_missing:'origin missing',origin_back:'origin back',held:'held',held_accepted:'hold accepted',held_rejected:'hold: kept mine',gone_from_source:'gone from account',
 fsck_failed:'integrity failed',fsck_ok:'integrity ok',source_created:'source added',source_scan:'source scan',source_gone:'vanished from account',source_scan_failed:'scan failed'};
async function load(more){const before=more&&rows.length?rows[rows.length-1].time:0;
 const r=await api('/events?limit=200'+($('#alerts').checked?'&alerts=1':'')+(before?'&before='+before:''));if(!r.ok)return;const j=await r.json();
 rows=more?rows.concat(j.events):j.events;total=j.total;draw()}
function draw(){const t=$('#type').value,w=$('#q').value.toLowerCase().split(/\s+/).filter(Boolean);
 const types=[...new Set(rows.map(e=>e.type))].sort(),cur=$('#type').value;
 $('#type').innerHTML='<option value="">All types</option>'+types.map(x=>`<option value="${esc(x)}" ${x==cur?'selected':''}>${esc(NAMES[x]||x)}</option>`).join('');
 const v=rows.filter(e=>(!t||e.type==t)&&w.every(x=>(e.summary+' '+(e.mirror||e.source)+' '+e.type).toLowerCase().includes(x)));
 $('#count').textContent=v.length+' shown';
 $('#tb').innerHTML='<tr><th>When</th><th>Where</th><th>What</th><th>Details</th></tr>'+(v.map(e=>`<tr class="${e.alert?'err':''}"><td class=n>${new Date(e.time*1000).toLocaleString()}</td>
  <td>${e.mirror?`<a href="/repo/${e.mirror_id}">${esc(e.mirror)}</a>`:`<a href="/source/${e.source_id}">${esc(e.source)}</a> <span class=mut>(source)</span>`}</td>
  <td class=n>${esc(NAMES[e.type]||e.type)}</td><td>${esc(e.summary)}${e.refs?` <span class=mut>(${e.refs} refs)</span>`:''}</td></tr>`).join('')||'<tr><td class=mut colspan=4>No events.</td></tr>');
 $('#more').hidden=rows.length>=total}
$('#alerts').onchange=()=>load();$('#type').onchange=draw;$('#q').oninput=draw;$('#more').onclick=()=>load(true);load();
</script></html>"""

LOGIN = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Sign in · Git Mirror</title>
<style>__STYLE__</style><style>.auth{max-width:380px;margin:12vh auto 0}.auth form{grid-template-columns:1fr}</style>
<main class=auth><h1><a class=brand href="https://github.com/konetzed/gitmirror" target=_blank rel="noopener noreferrer">Git Mirror</a></h1>
<div class=card><form id=f>
<label class=cap>Username<input name=username autocomplete=username required autofocus></label>
<label class=cap>Password<input name=password type=password autocomplete=current-password required></label>
<div class=err id=e></div><button class=p>Sign in</button></form></div></main>
<script>
const f=document.querySelector('#f'),e=document.querySelector('#e');
fetch('/api/auth/status').then(r=>r.json()).then(s=>{if(s.setup_required)location='/setup'});
f.onsubmit=async ev=>{ev.preventDefault();e.textContent='';
 const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:f.username.value,password:f.password.value})});
 const j=await r.json();if(r.ok)location='/';else e.textContent=j.error||'Sign-in failed'};
</script></html>"""

SETUP = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Create your account · Git Mirror</title>
<style>__STYLE__</style><style>.auth{max-width:420px;margin:10vh auto 0}.auth form{grid-template-columns:1fr}</style>
<main class=auth><h1><a class=brand href="https://github.com/konetzed/gitmirror" target=_blank rel="noopener noreferrer">Git Mirror</a></h1>
<div class=card><b>Create your account</b>
<div class=mut style="margin:4px 0 10px">Welcome. Choose the username and password you will use to sign in. The password is stored hashed (scrypt) on this server and never leaves it.</div>
<form id=f>
<label class=cap>Username<input name=username autocomplete=username required autofocus pattern="[A-Za-z0-9_.@+\-]{1,64}" title="Letters, digits and . _ @ + -"></label>
<label class=cap>Password (8 or more characters)<input name=password type=password autocomplete=new-password minlength=8 required></label>
<label class=cap>Repeat the password<input name=again type=password autocomplete=new-password minlength=8 required></label>
<label class=cap id=codebox hidden>Setup code<input name=setup_code type=password autocomplete=off><span class=mut>The GITMIRROR_TOKEN value this server was started with. It makes sure only you can create the first account.</span></label>
<div class=err id=e></div><button class=p>Create account</button></form></div></main>
<script>
const f=document.querySelector('#f'),e=document.querySelector('#e');
fetch('/api/auth/status').then(r=>r.json()).then(s=>{if(!s.setup_required)location='/login';document.querySelector('#codebox').hidden=!s.setup_code_required;f.setup_code.required=!!s.setup_code_required});
f.onsubmit=async ev=>{ev.preventDefault();e.textContent='';
 if(f.password.value!==f.again.value){e.textContent='The two passwords differ.';return}
 const r=await fetch('/api/auth/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:f.username.value,password:f.password.value,setup_code:f.setup_code.value})});
 const j=await r.json();if(r.ok)location='/';else e.textContent=j.error||'Could not create the account'};
</script></html>"""

ACCOUNT = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Your account · Git Mirror</title>
<style>__STYLE__</style>
<main><div class=row><h1>Your account</h1><span class=sp></span><a href="/">All mirrors</a></div>
<div class=card><b id=who>…</b> <span class=mut id=role></span></div>
<div class=card><b>API keys</b> <span class=mut>For scripts and the browser extension. A key can do what you can, up to the access you pick, and you can revoke it at any time. Keys can't create other keys or change passwords.</span>
<div id=newkey hidden style="border:1px solid var(--ok);border-radius:8px;padding:10px;margin:10px 0"><b>Your new key</b> <span class=mut>This is the only time it is shown. Copy it now.</span>
<div class=row style="margin-top:6px"><code id=keytext style="word-break:break-all"></code><button id=copy>Copy</button></div></div>
<div class=scroll><table id=ktab></table></div>
<form id=kf style="margin-top:10px"><label class=cap>Name<input name=name maxlength=40 required placeholder="Chrome on my laptop" autocomplete=off></label>
<label class=cap>Access<select name=role></select></label>
<label class=cap>Expires<select name=days><option value=0>Never</option><option value=30>In 30 days</option><option value=90>In 90 days</option><option value=365>In 1 year</option></select></label>
<div class="full row"><span class=mut id=kmsg></span><span class=sp></span><button class=p>Create key</button></div><div class="full err" id=kerr></div></form></div>
<div class=card><b>Change password</b>
<form id=pf style="margin-top:8px"><label class=cap>Current password<input type=password name=current autocomplete=current-password required></label>
<label class=cap>New password (8 or more characters)<input type=password name=new autocomplete=new-password minlength=8 required></label>
<label class=cap>Repeat the new password<input type=password name=again autocomplete=new-password minlength=8 required></label>
<div class="full row"><span class=mut id=pmsg></span><span class=sp></span><button class=p>Change password</button></div><div class="full err" id=perr></div></form>
<div class=mut>Changing your password signs you out of every other browser. Your API keys keep working.</div></div></main>
<script>
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=(p,o={})=>fetch('/api'+p,{...o,headers:{'Content-Type':'application/json'}}).then(r=>{if(r.status==401)location='/login';return r});
const ago=t=>{if(!t)return'never';const s=Date.now()/1e3-t;return s<90?'just now':s<5400?Math.round(s/60)+'m ago':s<172800?Math.round(s/3600)+'h ago':Math.round(s/86400)+'d ago'};
const day=t=>new Date(t*1000).toLocaleDateString();
const NAMES={viewer:'Read only',operator:'Operator'};let ME=null;
async function load(){const keys=await (await api('/keys')).json();
 $('#ktab').innerHTML=keys.length?'<tr><th>Name</th><th>Access</th><th>Created</th><th>Last used</th><th>Expires</th><th></th></tr>'+keys.map(k=>{const dead=k.expires&&k.expires<Date.now()/1e3;
  return `<tr data-id="${esc(k.id)}"><td><b>${esc(k.name)}</b> <span class=mut>${esc(k.prefix)}…</span></td><td>${esc(NAMES[k.role]||k.role)}</td><td class=n>${day(k.created)}</td>
  <td class=n>${k.last_used?esc(ago(k.last_used))+(k.last_ip?` <span class=mut>from ${esc(k.last_ip)}</span>`:''):'<span class=mut>never</span>'}</td>
  <td class=n>${k.expires?(dead?'<span class=err>expired</span>':day(k.expires)):'never'}</td><td class=n><button>Revoke</button></td></tr>`}).join(''):'<tr><td class=mut>No keys yet.</td></tr>'}
(async()=>{ME=await (await api('/auth/me')).json();$('#who').textContent=ME.user;$('#role').textContent='role: '+ME.role;
 $('#kf').elements.role.innerHTML=['viewer','operator'].filter(r=>['viewer','operator','admin'].indexOf(r)<=['viewer','operator','admin'].indexOf(ME.role)).map(r=>`<option value=${r}>${NAMES[r]}</option>`).join('');
 load()})();
$('#kf').onsubmit=async e=>{e.preventDefault();const f=e.target.elements;$('#kerr').textContent='';
 const r=await api('/keys',{method:'POST',body:JSON.stringify({name:f.name.value,role:f.role.value,expires_days:+f.days.value})}),j=await r.json();
 if(!r.ok){$('#kerr').textContent=j.error;return}
 $('#keytext').textContent=j.key;$('#newkey').hidden=false;e.target.reset();load()};
$('#copy').onclick=async()=>{const t=$('#keytext').textContent;try{await navigator.clipboard.writeText(t);$('#copy').textContent='Copied'}catch(x){const r=document.createRange();r.selectNodeContents($('#keytext'));const s=getSelection();s.removeAllRanges();s.addRange(r);$('#copy').textContent='Press Ctrl+C'}};
$('#ktab').onclick=async e=>{const b=e.target.closest('button'),tr=e.target.closest('tr');if(!b||!tr)return;
 if(!confirm('Revoke this key? Anything using it stops working.'))return;
 const r=await api('/keys/'+tr.dataset.id,{method:'DELETE'});if(!r.ok)alert((await r.json()).error);load()};
$('#pf').onsubmit=async ev=>{ev.preventDefault();const g=ev.target.elements;$('#perr').textContent='';$('#pmsg').textContent='';
 if(g.new.value!==g.again.value){$('#perr').textContent='The two new passwords differ.';return}
 const r=await api('/auth/password',{method:'POST',body:JSON.stringify({current:g.current.value,new:g.new.value})}),j=await r.json();
 if(r.ok){$('#pmsg').textContent='Password changed';ev.target.reset()}else $('#perr').textContent=j.error};
</script></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.environ.get("GITMIRROR_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("GITMIRROR_PORT", "8080")))
    ap.add_argument("--data", default=os.environ.get("GITMIRROR_DATA") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    a = ap.parse_args()
    global PAGE, ADMIN, REPO, MAINT, SOURCES, EVENTS, LOGIN, SETUP, ACCOUNT
    PAGE, ADMIN, REPO, MAINT, SOURCES, EVENTS, LOGIN, SETUP, ACCOUNT = (x.replace("<style>__STYLE__</style>", THEME_JS + "<style>" + STYLE + "</style>") for x in (PAGE, ADMIN, REPO, MAINT, SOURCES, EVENTS, LOGIN, SETUP, ACCOUNT))
    try:
        Handler.store = Store(a.data)
    except SchemaTooNew as e:
        sys.exit(str(e))
    except OSError as e:
        sys.exit(f"gitmirror can't use its data directory ({e.filename or a.data}): {e.strerror}.\n"
                 f"It is running as uid {os.getuid() if hasattr(os, 'getuid') else '?'}. The directory must exist and that user needs read and write access\n"
                 f"(on TrueNAS: make the dataset owned by the app user, uid 568; in Docker: chown the folder to 1000).")
    threading.Thread(target=scheduler, args=(Handler.store,), daemon=True).start()
    if TRUSTED_PROXIES:
        print(f"Trusting X-Forwarded-For from {len(TRUSTED_PROXIES)} configured proxy network(s)", flush=True)
    if not Handler.store.users:
        where = f"http://{'localhost' if a.host in ('0.0.0.0', '::') else a.host}:{a.port}/setup"
        print(f"No account yet: open {where} to create the admin account." + (" You will need the GITMIRROR_TOKEN value as the setup code." if API_TOKEN else ""), flush=True)
        if a.host not in ("127.0.0.1", "localhost", "::1") and not API_TOKEN:
            print("WARNING: listening on a non-loopback address with no GITMIRROR_TOKEN; whoever opens the page first can create the account. "
                  "Set GITMIRROR_TOKEN to require a setup code.", flush=True)
    print(f"gitmirror on http://{a.host}:{a.port}  data={Handler.store.data}")
    httpd = ThreadingHTTPServer((a.host, a.port), Handler)
    reloading = threading.Event()

    def reload_self():
        # Refuse to restart into code that doesn't compile; keep serving the old version instead.
        try:  # compile in memory: no __pycache__ write, so it also works from a read-only install directory
            with open(os.path.abspath(__file__)) as f:
                compile(f.read(), __file__, "exec")
        except (SyntaxError, ValueError, OSError) as e:
            print(f"SIGHUP: new code failed to compile, staying on current version:\n{e}", flush=True)
            reloading.clear()
            return
        print("SIGHUP: waiting for running syncs, then restarting...", flush=True)
        httpd.shutdown()
        for _ in range(600):  # up to 5 min so we don't kill a clone mid-way
            if not Handler.store.running:
                break
            time.sleep(0.5)
        httpd.server_close()
        os.execv(sys.executable, [sys.executable, *sys.argv])

    def on_hup(*_):
        if not reloading.is_set():
            reloading.set()
            threading.Thread(target=reload_self, daemon=True).start()

    if hasattr(signal, "SIGHUP"):  # not on Windows; there you just restart the process
        signal.signal(signal.SIGHUP, on_hup)
        print(f"pid {os.getpid()}  (kill -HUP {os.getpid()} to reload code)", flush=True)
    httpd.serve_forever()
    while reloading.is_set():  # serve_forever returned because of shutdown(); let reload_self exec
        time.sleep(1)


if __name__ == "__main__":
    main()
