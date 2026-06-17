# Squat-scan API webserver + scanner suite
FROM python:3.12-slim

# Run as an unprivileged user with a PINNED UID. Bind mounts keep host
# ownership, so the host must grant this exact UID access to the
# squatting_scanners tree (see run instructions: setfacl for u:10001).
RUN groupadd --gid 10001 scanner && \
    useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin scanner

WORKDIR /app

# Dependencies first for layer caching: scanner deps + webserver deps.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the webserver and scanner code.
# .dockerignore excludes API keys, output/, run_logs/, run_scanners.out:
# secrets must never be baked into image layers, and scan history lives in
# a bind mount so it survives image rebuilds (--compare-previous needs it).
COPY --chown=scanner:scanner . .
RUN chmod +x squatting_scanners/run_scanners.sh

USER scanner

EXPOSE 8000

# Exactly ONE worker: the job registry is in-process memory, and a second
# worker would neither see the first worker's jobs nor share the scanner
# lock. Concurrency comes from threads (fine: handlers are I/O-light, the
# heavy work runs in the app's own background threads).
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--timeout", "120", \
     "--bind", "0.0.0.0:8000", "webserver:app"]
