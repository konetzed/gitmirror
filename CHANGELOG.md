# Changelog

All notable changes to gitmirror are listed here, newest first. Versions follow [semantic versioning](https://semver.org); a `-beta` suffix means the project is still settling and details may change between releases.

## [Unreleased]

- The GitHub token field now says "Token Set" (green) or "No Token Set" (red), with a tick or cross for colour-blind readers.
- Admin has a **Test token** button for the GitHub token: it asks GitHub's rate-limit endpoint (no quota used) whether the saved or just-typed token works, and shows the requests left. The token is never sent back to the browser.

- Docs: a contents line at the top of the README; the TrueNAS section now covers generating the setup code, using personal keys for scripts, and updating with a pinned tag or `pull_policy: always`.

## [0.1.0] - 2026-10-24

First stable release: the `latest` image tag now points at it. It rolls up the 0.0.3-beta review fixes below and the cleared code-scanning alerts.

### Upgrading

- `file://` clone URLs can now be added only by admins, unless `GITMIRROR_ALLOW_FILE_REMOTES=1` extends that to operators. Mirrors that already use one keep syncing.
- The GitHub Enterprise, Gitea and GitLab hosts you point mirrors at may be on your private network as before, but no forge lookup or release download will reach a loopback or link-local address any more. Set `GITMIRROR_ALLOW_LOCAL_HOSTS=1` if you really run a forge on the same machine.

### Fixed

- **Release-asset links could point the server at anything it can reach.** A link in a mirrored project's release (chosen by that project's maintainer, not by you) was downloaded from inside your network, stored, and served back from the download route. Such links may now only reach the public internet or the forge the mirror came from; every redirect hop is checked the same way, and the GitHub token is never sent on to another host.
- **Failed sign-ins no longer lock scripts out.** Wrong keys and tokens are counted separately from wrong passwords (30 per address per 10 minutes), so a stranger guessing passwords behind a shared address can't make Home Assistant or your API keys return 429. The global sign-in limit no longer applies to Bearer requests.
- Malformed requests that used to end the connection with a traceback in the log (deeply nested JSON before sign-in, a non-string `source`, a `1e400` setting, a string where the import expects a list) now get a 400, and anything unexpected gets a JSON 500 with one log line.
- A tag list of tens of thousands of entries no longer keeps a core busy for minutes: the 20-tag limit stops the work at once.
- The `Server` header no longer reveals the Python version.
- Viewers can no longer read `/api/settings` (operator and up); the main page handles that quietly.
- The sign-in and key throttles are protected by a lock, as is the key lookup while an admin edits users.
- A key used from a changing address no longer rewrites `auth.json` on every request; "last used from" is refreshed at most once a minute like "last used".
- Release-asset links from a forge are kept only when they are `http(s)` URLs, like every other link from an API.
- Every `git` subprocess runs with no stdin, which removes a class of environment-dependent clone failures.
- Clone URLs containing whitespace are rejected.
- The container image no longer ships pip, setuptools or wheel (gitmirror never uses them), which clears the urllib3, msgpack and setuptools CVEs Trivy reported from their bundled copies.
- Startup messages no longer echo the `GITMIRROR_TRUSTED_PROXIES` values (CodeQL flagged them as clear-text logging); a bad entry is reported by position.
- Doc fixes: the `docker run` example pins `0.0.3-beta` instead of `latest` (which still points at an old build until the first stable release); `/healthz` is noted as revealing the version. The 0.0.3-beta note "every file gitmirror writes mode 600" applies to the JSON files in `configs/`; per-mirror logs and the extras folder rely on the 700 data folder.

## [0.0.3-beta] - 2026-10-24

### Upgrading

- **Nothing to do for most installs.** On first start the data folder is made private (mode 700, files 600) and `configs/version.json` is written. A copy of your `configs/` is saved to `backups/` first; it is small and safe to delete later.
- If another user on the machine (a backup tool, say) has to read the data folder, set `GITMIRROR_PRIVATE_DATA=0`.
- Behind a reverse proxy? Set `GITMIRROR_TRUSTED_PROXIES` to the proxy's address so sign-in limits and "last used from" see the real client.
- Docker and TrueNAS: change the image tag to `0.0.3-beta`. `latest` does not move for a pre-release and still points at an older build, so use `0.0.3-beta` or `beta`.
- Data written by this version can be opened by 0.0.2-beta, but only 0.0.3-beta and newer check the new data format version: an older program won't warn you.

### Added

- **Personal API keys** for scripts and the browser extension: each user can create several keys on the new **Account** page, with a name, an access level (read-only or operator, never admin) and an optional expiry. A key is shown once and stored only as a hash; the page lists when it was created, when and from which address it was last used, and when it expires, and revokes it with one click. A key follows its owner (demoted, disabled or deleted users take their keys with them), can't create keys or change passwords, and is named in the activity log. Admins see key counts and can revoke all of a user's keys.
- An **Account** page for every user, with the change-password form (it used to be on the Admin page, which only admins can open).
- **`GITMIRROR_TRUSTED_PROXIES`** for installs behind a reverse proxy. `X-Forwarded-For` is believed only when the connection comes from a listed address, and then only its right-most entry that is not itself a proxy. The sign-in rate limit and "last used from" now see the real client instead of the proxy, so one person's failed attempts no longer lock everyone out.
- **A data format version** (`configs/version.json`). When a release changes how data is stored, the old data is copied to `backups/` and migrated. A gitmirror that finds data from a newer format refuses to start rather than risk damaging it.
- **`RELEASING.md`**: version naming, the release steps, and what each tag publishes.

### Changed

- **The data folder is private**: mode 700, files 600 (including `mirrors.json`, `settings.json` and the others, which can hold tokens placed in clone URLs). Older installs are tightened on first start. `GITMIRROR_PRIVATE_DATA=0` opts out.
- Clones are made in `<id>.git.partial` and renamed when finished, so a crash can't leave a half-made repository under the real name. An empty or stub folder left by an interrupted clone is cleared and cloned again instead of failing for ever.
- **Docker tags now mean something.** `latest` moves only when a *stable* release is tagged (`vX.Y.Z`); it no longer follows every commit or any pre-release. New tags: `edge` (newest commit on `main`), `beta` (newest pre-release) and `1` (newest of a major line), next to `1.2.3`, `1.2` and `sha-<commit>`.
- The update badge only suggests stable releases to someone running a stable version.
- Requests that carry only an `Authorization: Bearer` header skip the cross-site origin check, since another website can't add that header; a request that also has a sign-in cookie is still checked.

## [0.0.2-beta] - 2026-10-24

### Upgrading

- **The `?token=` web address no longer works.** The first visit after upgrading shows a page to create your account (a username and a password). If `GITMIRROR_TOKEN` is set, enter it once there as the **setup code**. It stays useful as a Bearer token for scripts (`Authorization: Bearer <token>`), now with the **operator** role, so it can read and change mirrors but can't delete them or touch settings. Set `GITMIRROR_TOKEN_ROLE=viewer` for read-only scripts such as a Home Assistant sensor.
- Nothing changes for your mirrors, tags, settings or archived history. Your data folder is used as it is.
- Docker and TrueNAS: change the image tag to `0.0.2-beta`.

### Added

- **Sign-in with a username and password**, replacing the token in the web address. Passwords are stored only as salted scrypt hashes, sessions are random tokens kept server-side (they survive restarts and last 30 days), failed attempts are rate limited, and there is a Log out link and a change-password form in Admin.
- **Users and roles.** The first account is always an admin. Admins can add more users and give each one a role:
  - **viewer**: read everything, change nothing
  - **operator**: also add, sync, pause, tag and edit mirrors, follow accounts, resolve held changes and run maintenance
  - **admin**: everything, including deleting mirrors and sources, settings, import and export, and user management

  The server checks the role on every request and denies anything it doesn't know; the page hides the buttons a role can't use. The last active admin can't be removed, demoted or disabled. **Admin > Recent activity** shows who changed what.
- **Version badge and update check.** The header shows the running version and says either "up to date" or links to the newer release. It looks at the repository's version tags every few hours (nothing else is sent); turn it off in Admin or with `GITMIRROR_UPDATE_CHECK=0`. `/api/version` and `/healthz` report the version.
- The **"Git Mirror" title links to the GitHub repository.**
- **Tests**: 65 unit and live-server tests (standard library only) covering URL and credential handling, the archive and hold logic, sign-in, roles and the update check, plus a CI job that runs them before an image is built and checks that a release tag matches the version in the code.
- Responses carry `Cache-Control: no-store`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`.

### Changed

- `GITMIRROR_TOKEN` is now a setup code for the first account and a Bearer token for scripts. It is no longer accepted in the address.
- The pinned GitHub Actions in the image workflow use real commit hashes (Dependabot's correction of the `upload-sarif` pin) and `setup-python` is pinned too.

### Fixed

- A token-only HTTPS URL (`https://TOKEN@github.com/...`, GitHub's documented form) was shown, logged and exported unmasked. It is now hidden. SSH user names such as `git@` stay visible, so exported SSH mirrors can still be imported.
- Measuring a mirror's size no longer happens while holding the global lock, so a slow disk can no longer freeze the page and stall the scheduler.
- The access token is compared in constant time.
- Issue links from a forge's API must be `http(s)` URLs, so a hostile server can't plant a `javascript:` link.
- Malformed requests are refused with a clear 400 instead of crashing a worker: a body that is not a JSON object, a non-numeric or negative `Content-Length`. A client that stalls mid-request is dropped after 30 seconds.
- The script starts on Windows (no `SIGHUP` or `os.getuid()` there).
- Config files are read without leaving file handles open.

## [0.0.1-beta] - 2026-10-23

First public release.

- Local bare mirrors of git repositories with a per-mirror schedule (`1W`, `3D`, `12H`, `30M`), retries with backoff, and a limit on parallel syncs.
- **Takedown protection**: deleted or rewritten branches and tags are pinned under `refs/archive/`, a vanished origin keeps your copy and raises an alert, and **Hold** mode queues upstream rewrites and deletions for review.
- **Sources**: follow a whole GitHub, GitLab or Gitea/Forgejo user, org or group, with a preview, approval for new repositories, and a flag for repositories that vanish.
- **Also archive** wikis, Git LFS objects (with detection), releases and issues.
- Search, sort, tags and bulk actions; import and export; a global event log; integrity checks, a low-disk guard and disk-use history; `/healthz` and `/api/summary`.
- Light, dark, sepia, OLED and high-contrast themes with a colorblind-safe palette.
- Docker image for amd64 and arm64 on `ghcr.io/konetzed/gitmirror`, a ready-made TrueNAS SCALE YAML, and GPL-3.0-or-later licensing.

[Unreleased]: https://github.com/konetzed/gitmirror/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/konetzed/gitmirror/compare/v0.0.3-beta...v0.1.0
[0.0.3-beta]: https://github.com/konetzed/gitmirror/compare/v0.0.2-beta...v0.0.3-beta
[0.0.2-beta]: https://github.com/konetzed/gitmirror/compare/v0.0.1-beta...v0.0.2-beta
[0.0.1-beta]: https://github.com/konetzed/gitmirror/releases/tag/v0.0.1-beta
