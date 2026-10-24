# Releasing gitmirror

How a version gets from `main` to the container registry, and how tags map to image tags.

## Version names

Versions follow [semantic versioning](https://semver.org). Whether a version is stable is decided by its **suffix**:

| Git tag | Meaning | Image tags it publishes |
|---|---|---|
| `v1.2.3` (no suffix) | stable release | `1.2.3`, `1.2`, `1` and **`latest`** |
| `v1.3.0-beta.1`, `v1.3.0-beta.2` | feature complete, rough edges | `1.3.0-beta.1` and `beta` |
| `v1.3.0-rc.1` | release candidate: ready unless testing finds a problem | `1.3.0-rc.1` and `beta` |
| *(no tag, every push to `main`)* | work in progress | `edge`, `sha-<commit>` |

- Pre-release order is `alpha` < `beta` < `rc` < the plain version. Put a **dot** before the counter (`-beta.2`, `-beta.10`); without it `-beta10` sorts before `-beta2`.
- Never use `-release` or `-dev` as a suffix: any suffix marks a pre-release, so such a tag would never become `latest` and would sort below the plain version.
- A stable release does not have to be 1.0: `v0.1.0` is stable and is the first tag that creates `latest`. Until one exists, `latest` still points at an old beta build, so people should pin an exact version.
- The page header's update badge follows the same rule: someone on a stable version is only told about newer stable releases; someone on a pre-release also hears about newer pre-releases.

## Steps

1. **Finish on `main`.** All work merged, `python3 -m unittest discover -s tests` passing (the same command CI runs).
2. **Pick the version**, say `1.3.0-beta.1`, and bump it in `gitmirror.py`:
   ```python
   __version__ = "1.3.0-beta.1"
   ```
   CI refuses a `v*` tag that does not match this string.
3. **Write the changelog.** In `CHANGELOG.md`, move what is under `## [Unreleased]` into a new `## [1.3.0-beta.1] - YYYY-MM-DD` section (keep an empty Unreleased on top), add an "Upgrading" note if anything needs the user to act, and update the link lines at the bottom.
4. **Point the examples at it** (optional but tidy): the image tag in `deploy/truenas-scale.yaml` and the example in the README.
5. **Commit and push `main`:**
   ```bash
   git commit -am "Release 1.3.0-beta.1"
   git push
   ```
6. **Tag that commit and push the tag:**
   ```bash
   git tag -a v1.3.0-beta.1 -m "gitmirror 1.3.0-beta.1: one-line summary"
   git push origin v1.3.0-beta.1
   ```
7. **Watch the "Docker image" workflow** on the Actions tab. It runs the unit tests and the tag check first, builds amd64 and arm64 images only if they pass, publishes the tags from the table above, then scans the image with Trivy (report only).
8. **Check the result:**
   - the new tags appear on the package page (<https://github.com/konetzed/gitmirror/pkgs/container/gitmirror>), and `latest` moved only if this was a stable release;
   - `docker pull ghcr.io/konetzed/gitmirror:1.3.0-beta.1` works and `docker run` shows the right version on `/healthz`;
   - an older install's badge now says "update available" (it re-checks every six hours; Admin shows the same line).
9. **Optional: a GitHub Release page** for the tag, with the changelog section as its text. Tick *pre-release* for any suffixed version, so GitHub's "Latest" badge stays on the newest stable one.

## From testing to stable

`v1.3.0-rc.1` and `v1.3.0` are different builds. To promote: set `__version__ = "1.3.0"`, move the changelog section's title, commit, push, and tag `v1.3.0`. Only then do `latest`, `1.3` and `1` move.

## Fixes

- **A bug in a published release:** fix it on `main` and cut the next version (`v1.3.1`, or `-beta.2`). Never move or reuse a tag that has already produced an image.
- **The workflow failed on a tag** (tests, or the tag does not match `__version__`): no image was published. Delete the tag, fix, and tag again:
  ```bash
  git tag -d v1.3.0-beta.1 && git push origin :refs/tags/v1.3.0-beta.1
  ```
- **A tag that is wrong but not pushed yet:** `git tag -d <tag>`.
- Container registry tags cannot be removed one at a time: deleting a published image version also removes every tag that shares it. Prefer shipping a new version over cleaning up an old one.
