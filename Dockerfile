FROM python:3.13-slim

LABEL org.opencontainers.image.title="gitmirror" \
      org.opencontainers.image.source="https://github.com/konetzed/gitmirror" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

# git does the mirroring; git-lfs and openssh-client are for LFS objects and ssh:// remotes
RUN apt-get update \
 && apt-get install -y --no-install-recommends git git-lfs openssh-client ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && git lfs install --system \
 && git config --system safe.directory '*'

RUN useradd --create-home --uid 1000 gitmirror && mkdir /data && chown gitmirror:gitmirror /data
# TrueNAS SCALE runs apps as uid 568 ("apps"). ssh refuses to start for a uid without a passwd entry, so give it one.
RUN useradd --uid 568 --no-create-home --home-dir /home/gitmirror --shell /usr/sbin/nologin apps
COPY gitmirror.py LICENSE /app/

ENV GITMIRROR_DATA=/data \
    GITMIRROR_HOST=0.0.0.0 \
    GITMIRROR_PORT=8080 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/gitmirror \
    GIT_SSH_COMMAND="ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/data/known_hosts"

USER gitmirror
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ['GITMIRROR_PORT'], timeout=4)"]

ENTRYPOINT ["tini", "--"]
CMD ["python", "/app/gitmirror.py"]
