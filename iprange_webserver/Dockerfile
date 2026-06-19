# IP range scanner / checker
FROM python:3.12-slim

# Port gunicorn binds inside the container. Override with
# --build-arg PORT=NNNN; EXPOSE, the HEALTHCHECK and the gunicorn bind all
# read this one value so they cannot drift.
ARG PORT=8000
ENV PORT=${PORT}

# gunicorn worker timeout in seconds; a single /scan must finish within it or
# the worker is killed. Override at run time via the GUNICORN_TIMEOUT env
# (compose environment) without rebuilding.
ENV GUNICORN_TIMEOUT=120

# iputils-ping for the ICMP follow-up, curl for the container HEALTHCHECK.
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping curl && \
    rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user with a PINNED UID. Bind mounts keep host
# ownership, so the host must grant this exact UID access to the project
# tree (see README: setfacl for u:10001).
RUN groupadd --gid 10001 scanner && \
    useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin scanner

WORKDIR /app

# Dependencies first for layer caching: scanner deps + webserver deps.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the webserver and scanner code.
COPY --chown=scanner:scanner . .

# Writable log dir; a compose bind mount overlays this at runtime.
RUN mkdir -p /app/output && chown scanner:scanner /app/output

USER scanner
EXPOSE ${PORT}

# Liveness probe hits the in-process /health endpoint on the same PORT.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

# sh -c so ${PORT} expands at runtime; exec so gunicorn is PID 1 and gets
# SIGTERM for graceful shutdown.
CMD ["sh", "-c", \
     "exec gunicorn --workers 1 --threads 8 --timeout ${GUNICORN_TIMEOUT} --bind 0.0.0.0:${PORT} webserver:app"]
