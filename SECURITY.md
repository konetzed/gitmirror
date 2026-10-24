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

- The web UI needs a username and password, created on the first visit. Create the account straight away, because until then whoever opens the page first can. Set `GITMIRROR_TOKEN` to require a setup code for that first account, and put the app behind an HTTPS reverse proxy if it leaves your machine. Passwords are stored as scrypt hashes, sessions are server-side, and failed sign-ins are rate limited. Accounts have a role (viewer, operator or admin) that the server checks on every request; give people the lowest role they need.
- Credentials inside clone URLs, and the optional GitHub token, are stored as plain text in the `data/configs` files. Keep that directory private and out of backups you share.
- Forge detection, account listing and release downloads make requests from the server to hosts that are typed into the UI.
- Only `http(s)`, `ssh`, `git` and `file` remotes are accepted; git's `ext::` transport is blocked.
