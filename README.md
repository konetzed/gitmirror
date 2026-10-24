# gitmirror

Keeps local bare mirrors of git repositories (GitHub, GitLab, Gitea/Forgejo, anything git can clone) with a small web UI.
Built to survive takedowns: if an origin rewrites history, deletes branches or disappears, your copy keeps the old versions.

One Python file, standard library only. Needs `git` (and optionally `git-lfs` and `openssh-client`).

## Screenshots

Dark theme, with demo data. There are also light, sepia, OLED and high-contrast themes, picked from the sun/moon switch and the palette button.

**Your mirrors.** Search, sort, tag and act on many at once. Cards show sync health, what is waiting for review, and a warning when a repository uses Git LFS but the large files are not being saved.

![The main page with the mirror list](docs/screenshots/main.png)

**Held changes.** With Hold on, an origin that rewrites history or deletes branches can't touch your copy until you accept the change. Nothing is lost either way.

![A mirror with upstream changes on hold](docs/screenshots/held-changes.png)

**Follow a whole account.** Preview every repository of a user, org or group with its size before anything is added. Forks start unchecked, and a 3.7 GB repository is easy to spot.

![Previewing an organisation before mirroring it](docs/screenshots/sources-preview.png)

**Stay on top of it.** New repositories wait for your approval, and repositories that vanish from an account are flagged and kept.

![A followed account with a new repository and one that vanished](docs/screenshots/source.png)

**Housekeeping.** Disk use over time, integrity checks, the largest and oldest mirrors, and anything that needs LFS.

![The maintenance page](docs/screenshots/maintenance.png)

## Run it with Docker

```bash
cd gitmirror
mkdir -p data && sudo chown 1000:1000 data     # the container runs as uid 1000
export GITMIRROR_TOKEN="$(openssl rand -hex 24)"   # recommended: the setup code for your account, and a token for scripts
docker compose up -d --build
```

Open <http://127.0.0.1:8080>. The first visit asks you to create a username and password; if `GITMIRROR_TOKEN` is set, you also enter it once as the setup code, so only you can create the account. After that you sign in with the username and password, and nothing secret appears in the address bar.

| Setting | How |
|---|---|
| Setup code and script token | `GITMIRROR_TOKEN`: required once to create the first account, and accepted as `Authorization: Bearer <token>` by scripts such as Home Assistant. Optional but recommended |
| What the script token may do | `GITMIRROR_TOKEN_ROLE`: `operator` (default) or `viewer` for read-only sensors. It is never an admin |
| GitHub API token (higher rate limit) | `GITMIRROR_GITHUB_TOKEN`, or the Admin page |
| Outbound requests | Forge lookups and release downloads never reach loopback or link-local addresses, and a release-asset link may only reach the public internet or the forge it came from. `GITMIRROR_ALLOW_LOCAL_HOSTS=1` lifts the loopback rule for development |
| Local repositories | `file://` clone URLs let whoever adds them mirror anything the service account can read, so only admins may add them; `GITMIRROR_ALLOW_FILE_REMOTES=1` extends that to operators. Mirrors created earlier keep syncing |
| Behind a reverse proxy | `GITMIRROR_TRUSTED_PROXIES`: the proxy's address or network (`127.0.0.1`, `172.18.0.0/16`, comma separated). Without it every visitor shares the proxy's address, so the sign-in rate limit locks everyone out together and "last used from" shows the proxy. Only list addresses you control |
| Port / host / data dir | `GITMIRROR_PORT`, `GITMIRROR_HOST`, `GITMIRROR_DATA` (the image sets `8080`, `0.0.0.0`, `/data`) |
| Private repos over HTTPS | put a token in the clone URL: `https://user:TOKEN@host/owner/repo.git` (stored in `mirrors.json`, masked in the UI and exports) |
| Private repos over SSH | mount a key (see the commented line in `docker-compose.yml`) and use `git@host:owner/repo.git` |

The compose file publishes the port on `127.0.0.1` only. To reach it from other machines, front it with a reverse proxy that terminates HTTPS, and keep `GITMIRROR_TOKEN` set.

### Use the published image instead of building it

Every push to `main` is built for amd64 and arm64 and published to GitHub's container registry:

```bash
export GITMIRROR_TOKEN="$(openssl rand -hex 24)"   # note it down; it is the setup code for your account
mkdir -p data && sudo chown 1000:1000 data
docker run -d --name gitmirror --restart unless-stopped \
  -p 127.0.0.1:8080:8080 -e GITMIRROR_TOKEN -v "$PWD/data:/data" \
  ghcr.io/konetzed/gitmirror:0.0.3-beta
```

| Tag | What you get |
|---|---|
| `1.2.3` | exactly that release, forever. Pin this one |
| `1.2`, `1` | the newest patch or minor release of that line |
| `latest` | the newest **stable** release. It never moves for a pre-release or an ordinary commit |
| `0.3.0-beta` | exactly that pre-release; `beta` is always the newest pre-release |
| `edge` | the newest commit on `main`: work in progress that may be broken |
| `sha-<commit>` | the build of one specific commit |

Releases are made by pushing a tag `vX.Y.Z` (or `vX.Y.Z-beta` for a pre-release); a tag without a suffix is a stable release. Until the first stable release exists, `latest` may still point at a beta build, so pin an exact version. The version badge in the page follows the same rule: a stable install is told only about newer stable releases, a pre-release install also hears about newer pre-releases.

### Updating

```bash
docker compose up -d --build     # rebuilds from the current gitmirror.py; your data is in ./data
```

### Data layout (`./data`)

```
configs/   mirrors.json, auth.json (accounts and API key hashes), sessions.json, sources.json, settings.json, stats.json,
           history.json, audit.json, forges.json, version.json and one .log per mirror
repos/     <id>.git bare mirrors, <id>.wiki.git wikis
extras/    <id>/issues.json, releases.json and downloaded release files
backups/   a copy of configs/ taken automatically before an upgrade changes the data format
```

The data folder is made private (mode 700, files 600) because it holds password hashes, API key hashes and tokens that may be part of clone URLs. If a backup tool running as another user has to read it, set `GITMIRROR_PRIVATE_DATA=0`; new files are still written owner-only.

`configs/version.json` records the data format. A gitmirror that finds data written by a *newer* format refuses to start (downgrading could damage it) and tells you so; start the newer version again or restore a backup. `GITMIRROR_IGNORE_SCHEMA=1` overrides that at your own risk.

Back up the whole `data` directory (or just `configs/` plus `repos/`). **Admin > Backup and restore** also exports the list of mirrors and followed accounts as JSON.

## Run on TrueNAS SCALE (24.10 or newer)

SCALE 24.10 and later run apps on Docker, so the published image works as a custom app.

1. **Make a dataset** for gitmirror's data, for example `tank/apps/gitmirror`. Give the `apps` user (uid 568) ownership with read and write access (**Storage**, then the dataset's **Permissions**; the "Apps" ACL preset does this if your version offers it).
2. **Install the app:** **Apps**, **Discover Apps**, the three-dot menu at the top right, **Install via YAML**. Name it `gitmirror`, paste [`deploy/truenas-scale.yaml`](deploy/truenas-scale.yaml), and change the two lines marked `CHANGE`: the token and the dataset path. The wording of the menu varies slightly between releases. If you prefer the form instead, use image `ghcr.io/konetzed/gitmirror`, port `8080`, user and group `568`, the `GITMIRROR_TOKEN` variable, and a host-path volume from your dataset to `/data`.
3. **Open it** at `http://<your-nas>:8080` and create your account: pick a username and password, and enter the `GITMIRROR_TOKEN` from the YAML as the setup code. The app card shows a health status from the image's built-in check.
   If the app stops right away and its log says it can't use its data directory, the dataset's owner isn't `apps` (uid 568) or it is read-only: fix the permissions and start it again.
4. **Update it** by changing the image tag in the app's YAML (for example `:0.0.3-beta` to `:0.0.4-beta`) and saving. Pinning a version tag is more reliable than `latest`, because TrueNAS does not re-pull an unchanged tag.
5. **Back it up** by snapshotting and replicating the dataset: it holds every mirror and all settings.

Keep it on your LAN and keep `GITMIRROR_TOKEN` set (it stops a stranger on the network from creating the account before you do). To reach it from outside, put an HTTPS reverse proxy with its own login in front. Private repositories over SSH work too: put the key in the dataset (`ssh/id_ed25519`, mode 600, owned by the app user) and enable the `GIT_SSH_COMMAND` line in the YAML.

## Running without Docker

```bash
python3 gitmirror.py --data ./data --port 8080
```

`kill -HUP <pid>` re-executes the script with the code on disk (it refuses if the new code doesn't compile). That is for bare installs; in Docker, rebuild instead.

## What it does

- **Mirrors** with a schedule per mirror (`1W`, `3D`, `12H`, `30M`, `0` = manual), retries with exponential backoff, and a limit on parallel syncs.
- **Takedown protection:** deleted or rewritten branches and tags are pinned under `refs/archive/<time>/...`, never pruned; a vanished origin keeps your copy and raises an alert. **Hold** mode queues rewrites and deletions for your approval.
- **Sources:** follow a whole GitHub/GitLab/Gitea user, org or group. You pick repos from a preview (sizes shown), new repos wait for approval or are added automatically, and repos that vanish from the account are flagged and kept.
- **Also archive:** wikis, Git LFS objects (a mirror is checked after every sync; if the repo uses LFS but archiving is off you get a warning and an Enable button, or Admin can turn it on automatically below a size limit), releases (with downloadable files up to a size limit) and issues with comments (GitHub, Gitea/Forgejo; GitLab issues without comments).
- **Users and roles:** viewer, operator and admin accounts, personal API keys, and a record of who changed what.
- **Housekeeping:** search, sort, bulk actions, tags, import/export, a global event log, periodic `git fsck`, low-disk warning (syncing stops under 1 GB free), disk-use history, and `git gc` optimizing.
- **Updates:** the page header shows the running version and whether a newer release tag exists on GitHub (a `git ls-remote` of the version tags every few hours; switch it off in Admin or with `GITMIRROR_UPDATE_CHECK=0`).
- **Themes:** light, dark, sepia, OLED, two high-contrast themes, a colorblind-safe palette.

## Monitoring

- `GET /healthz` needs no sign-in: `200 {"ok": true, "version": ...}` while the scheduler is alive and the data directory is writable. Docker uses it for its health check. Note that this reveals the running version to anyone who can reach the port.
- `GET /api/summary` (send `Authorization: Bearer <token>`: a read-only personal API key from your Account page is enough for a sensor, or `GITMIRROR_TOKEN`, optionally with `GITMIRROR_TOKEN_ROLE=viewer`) returns flat numbers for dashboards: `projects`, `disk_bytes`, `disk_free_bytes`, `failing`, `alerts`, `held`, `origin_missing`, `pending_approval`, `low_disk`, `stalest_sync_hours`, ...

Home Assistant example:

```yaml
rest:
  - resource: http://gitmirror:8080/api/summary
    headers:
      Authorization: !secret gitmirror_bearer      # "Bearer <token>"
    scan_interval: 300
    sensor:
      - name: Gitmirror projects
        value_template: "{{ value_json.projects }}"
      - name: Gitmirror failing
        value_template: "{{ value_json.failing }}"
      - name: Gitmirror disk used
        value_template: "{{ (value_json.disk_bytes / 1e9) | round(2) }}"
        unit_of_measurement: GB
    binary_sensor:
      - name: Gitmirror problem
        device_class: problem
        value_template: "{{ value_json.failing > 0 or value_json.alerts > 0 or value_json.low_disk }}"
```

## Security notes

- **Sign-in:** the first account is created on first use and is always an admin; admins add the others (below). A password is stored only as a salted scrypt hash in `configs/auth.json`, and sessions are random 256-bit tokens kept (hashed) in `configs/sessions.json`; both files are readable by the owner only. The session cookie is `HttpOnly` and `SameSite=Strict`, and also `Secure` when a reverse proxy sets `X-Forwarded-Proto: https`. Changing the password signs every other browser out. After 8 wrong attempts in 10 minutes a client has to wait.
- **Roles:** **viewer** can look at everything (mirrors, events, logs, history, releases) but change nothing. **operator** can also add, sync, pause, tag and edit mirrors, follow accounts, resolve held changes and run maintenance. **admin** can do everything, including delete mirrors and sources, change settings, import and export, and manage users. The server enforces this on every request (an unlisted action needs an admin), and the page hides the buttons you can't use. A role change applies from the next request; disabling a user, resetting a password or deleting a user signs them out. The last active admin can't be removed, demoted or disabled. Admins see who changed what under **Admin > Recent activity** (passwords and tokens are never written to it).
- **API keys:** every user can create several personal keys on their **Account** page (name, access, optional expiry) for scripts and the browser extension. A key is shown once and only its hash is stored. It can do what its owner can, capped at read-only or operator (never admin), and it follows the owner: demote, disable or delete the user and the key follows at once. A key can't create other keys or change passwords. The page lists each key's creation date, last use and the address it last came from, and a key is revoked with one click (admins can revoke all of a user's keys). Send it as `Authorization: Bearer gm_...`; unlike a cookie, a header can't be added by another website, so such requests skip the cross-site check. Wrong keys count towards the same sign-in rate limit.
- **Lost the admin password?** Stop gitmirror, delete `configs/auth.json` and `configs/sessions.json` in the data folder, and start it again: the next visit creates a new first admin (every other account is removed too).
- The old `?token=` address parameter is gone, so no secret ends up in browser history, bookmarks or proxy logs. `GITMIRROR_TOKEN` is now only a setup code and a Bearer token for scripts, with the operator role unless you set `GITMIRROR_TOKEN_ROLE=viewer`.
- Only `http(s)`, `ssh`, `git` and `file` remotes are allowed (git's `ext::` transport is blocked), and clone URLs starting with `-` are rejected.
- State-changing requests must be JSON and same-origin, which blocks cross-site form posts.
- Forge detection and account listing make requests from the server to hosts you paste. That is fine on a private machine; keep `GITMIRROR_TOKEN` set if the UI is reachable by others.
- The release-download endpoint only serves files inside a mirror's own `extras/<id>/releases/` folder.

## License

gitmirror is free software under the **GNU General Public License v3.0 or later** (see [LICENSE](LICENSE)). You may use, study, change and share it; if you distribute a modified version, you must do so under the same license and make the source available.

What changed in each release: [CHANGELOG.md](CHANGELOG.md); how releases are cut and tagged: [RELEASING.md](RELEASING.md). Found a security problem? See [SECURITY.md](SECURITY.md).
