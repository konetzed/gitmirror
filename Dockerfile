FROM python:3.13-slim

# git does the mirroring; git-lfs and openssh-client are for LFS objects and ssh:// remotes
RUN apt-get update \
 && apt-get install -y --no-install-recommends git git-lfs openssh-client ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && git lfs install --system \
 && git config --system safe.directory '*'

RUN useradd --create-home --uid 1000 gitmirror && mkdir /data && chown gitmirror:gitmirror /data
COPY gitmirror.py /app/gitmirror.py

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
