# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Open this repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub private vulnerability reporting).

Include what you found, how to reproduce it, and which version or commit you tested. I'll acknowledge reports as soon as I can and credit you in the fix if you like.

## Supported versions

Only the latest commit on `main` and the latest Docker image built from it are supported.

## What to keep in mind when running it

gitmirror is meant to run on a machine or network you control.

- The web UI needs a username and password, created on the first visit. Create the account straight away, because until then whoever opens the page first can. Set `GITMIRROR_TOKEN` to require a setup code for that first account, and put the app behind an HTTPS reverse proxy if it leaves your machine. Passwords are stored as scrypt hashes, sessions are server-side, and failed sign-ins are rate limited. Accounts have a role (viewer, operator or admin) that the server checks on every request; give people the lowest role they need. Personal API keys are capped at operator, are stored only as hashes, and can be revoked at any time from the Account page; treat a key like a password, and prefer an expiry for keys that live in a browser.
- Credentials inside clone URLs, and the optional GitHub token, are stored as plain text in the `data/configs` files and in each mirror's git config. gitmirror makes the data folder private (mode 700, files 600); keep it out of backups you share.
- Behind a reverse proxy, set `GITMIRROR_TRUSTED_PROXIES` to the proxy's address so sign-in throttling and "last used from" see the real client. `X-Forwarded-For` is believed only from those addresses, and then only its right-most untrusted entry.
- Forge detection, account listing and release downloads make requests from the server: operators choose the hosts for the first two, and the maintainer of a mirrored project chooses release-asset links. None of them may reach loopback or link-local addresses (where cloud metadata services live), and a release-asset link may only reach the public internet or the forge the mirror came from. Redirects are checked hop by hop and never carry the GitHub token to another host. Names are resolved once before connecting, so a DNS answer that changes between that check and the connection is not caught.
- `file://` clone URLs can be added only by admins (or by operators when `GITMIRROR_ALLOW_FILE_REMOTES=1`), because they read any repository on the server.
- Only `http(s)`, `ssh`, `git` and `file` remotes are accepted; git's `ext::` transport is blocked.
