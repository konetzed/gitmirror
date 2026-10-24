# gitmirror

Keeps local bare mirrors of git repositories (GitHub, GitLab, Gitea/Forgejo, anything git can clone) with a small web UI.
Built to survive takedowns: if an origin rewrites history, deletes branches or disappears, your copy keeps the old versions.

One Python file, standard library only. Needs `git` (and optionally `git-lfs` and `openssh-client`).

## Run it with Docker

```bash
cd gitmirror
mkdir -p data && sudo chown 1000:1000 data     # the container runs as uid 1000
export GITMIRROR_TOKEN="$(openssl rand -hex 24)"   # recommended: protects the UI and API
docker compose up -d --build
```

Open <http://127.0.0.1:8080/?token=YOUR_TOKEN> (the token is remembered in the link; keep using that URL, or put a reverse proxy with its own login in front).

| Setting | How |
|---|---|
| Web UI token | `GITMIRROR_TOKEN` (API clients send `Authorization: Bearer <token>`) |
| GitHub API token (higher rate limit) | `GITMIRROR_GITHUB_TOKEN`, or the Admin page |
| Port / host / data dir | `GITMIRROR_PORT`, `GITMIRROR_HOST`, `GITMIRROR_DATA` (the image sets `8080`, `0.0.0.0`, `/data`) |
| Private repos over HTTPS | put a token in the clone URL: `https://user:TOKEN@host/owner/repo.git` (stored in `mirrors.json`, masked in the UI and exports) |
| Private repos over SSH | mount a key (see the commented line in `docker-compose.yml`) and use `git@host:owner/repo.git` |

The compose file publishes the port on `127.0.0.1` only. To reach it from other machines, front it with a reverse proxy that terminates HTTPS, and keep the token set.

### Updating

```bash
docker compose up -d --build     # rebuilds from the current gitmirror.py; your data is in ./data
```

### Data layout (`./data`)

```
configs/   mirrors.json, sources.json, settings.json, stats.json, history.json, forges.json and one .log per mirror
repos/     <id>.git bare mirrors, <id>.wiki.git wikis
extras/    <id>/issues.json, releases.json and downloaded release files
```

Back up the whole `data` directory (or just `configs/` plus `repos/`). **Admin > Backup and restore** also exports the list of mirrors and followed accounts as JSON.

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
- **Housekeeping:** search, sort, bulk actions, tags, import/export, a global event log, periodic `git fsck`, low-disk warning (syncing stops under 1 GB free), disk-use history, and `git gc` optimizing.
- **Themes:** light, dark, sepia, OLED, two high-contrast themes, a colorblind-safe palette.

## Monitoring

- `GET /healthz` needs no token: `200 {"ok": true}` while the scheduler is alive and the data directory is writable. Docker uses it for its health check.
- `GET /api/summary` (token required) returns flat numbers for dashboards: `projects`, `disk_bytes`, `disk_free_bytes`, `failing`, `alerts`, `held`, `origin_missing`, `pending_approval`, `low_disk`, `stalest_sync_hours`, ...

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

- Only `http(s)`, `ssh`, `git` and `file` remotes are allowed (git's `ext::` transport is blocked), and clone URLs starting with `-` are rejected.
- State-changing requests must be JSON and same-origin, which blocks cross-site form posts.
- Forge detection and account listing make requests from the server to hosts you paste. That is fine on a private machine; keep the token set if the UI is reachable by others.
- The release-download endpoint only serves files inside a mirror's own `extras/<id>/releases/` folder.

## License

gitmirror is free software under the **GNU General Public License v3.0 or later** (see [LICENSE](LICENSE)). You may use, study, change and share it; if you distribute a modified version, you must do so under the same license and make the source available.

Found a security problem? See [SECURITY.md](SECURITY.md).
