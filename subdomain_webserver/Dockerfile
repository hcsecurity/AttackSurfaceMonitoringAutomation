# Recon API webserver + subfinder + puredns (+ massdns).
#
# Two stages: a Debian-based Go/build stage to compile the binaries, then a slim
# Python runtime that carries only those binaries plus the Flask app. Both
# stages are bookworm-based so the C-compiled massdns binary is glibc-compatible
# with the runtime.

# ---- Stage 1: build the binaries -------------------------------------------
FROM golang:1.26-bookworm AS builder

# massdns build dependencies. puredns shells out to the massdns binary.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git make gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# massdns (C). `make` produces ./bin/massdns.
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /build/massdns \
    && make -C /build/massdns

# subfinder (passive subdomain discovery), puredns (DNS bruteforce front-end for
# massdns), and supercronic (container-friendly cron that runs as non-root and
# logs to stdout). go install drops these in /go/bin.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/d3mondev/puredns/v2@latest \
    && go install github.com/aptible/supercronic@latest

# ---- Stage 2: runtime ------------------------------------------------------
FROM python:3.12-slim-bookworm

# Binaries from the builder. /usr/local/bin is on PATH, so puredns finds massdns.
COPY --from=builder /build/massdns/bin/massdns /usr/local/bin/massdns
COPY --from=builder /go/bin/subfinder          /usr/local/bin/subfinder
COPY --from=builder /go/bin/puredns            /usr/local/bin/puredns
COPY --from=builder /go/bin/supercronic        /usr/local/bin/supercronic

# ca-certificates so subfinder can reach its HTTPS data sources.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user with a PINNED UID. Bind mounts keep host ownership, so the
# host must grant this exact UID access to the mounted data dir (see README:
# setfacl for u:10001).
RUN groupadd --gid 10001 recon \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin recon

WORKDIR /app

# Python deps first for layer caching (just Flask + gunicorn).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code. .dockerignore keeps secrets and runtime data OUT of the image
# (provider-config.yaml, resolvers.txt, wordlist.txt, domains.txt, output/);
# those arrive via the bind mount at runtime so nothing sensitive is baked into
# an image layer.
COPY --chown=recon:recon . .
RUN chmod +x /app/entrypoint.sh /app/run_puredns.sh

USER recon

EXPOSE 8001

# Liveness probe against the unauthenticated health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8001/api/health', timeout=3).status==200 else 1)"

# Starts supercronic (weekly puredns cron) + gunicorn.
ENTRYPOINT ["/app/entrypoint.sh"]
