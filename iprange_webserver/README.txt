==============================================================================
IP RANGE SCANNER / CHECKER  (iprange-api)
==============================================================================

Flask/gunicorn REST API that scans IP blocks with the Shodan host API, pings
the hosts Shodan has no data for, and returns a per-IP summary. Built to be
driven by n8n over HTTP. No UI.

Each IP lands in one of three buckets:
  with_data      Shodan returned data; listed with open ports and banners.
  alive_no_data  no Shodan data, but the host answered ICMP echo.
  inactive       no Shodan data and the host did not answer ping.

Every /scan response is also written to OUTPUT_DIR as
scan_<UTC timestamp>.json for logging.

------------------------------------------------------------------------------
1. ENDPOINTS
------------------------------------------------------------------------------
All requests except /health require the X-API-Key header.

  GET  /health
      Liveness probe. Returns {"status": "ok"}. No auth. Used by the
      container HEALTHCHECK.

  POST /scan
      Header: X-API-Key: <WEBSERVER_API_KEY>
      Body:   {"blocks": ["10.11.32.11-124", "10.11.40.5"]}
      The last octet may be a single value or a START-END range.

  Example:
      curl -fsS http://127.0.0.1:8000/scan \
        -H "X-API-Key: $WEBSERVER_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"blocks": ["10.11.32.11-124"]}'

------------------------------------------------------------------------------
2. ENVIRONMENT
------------------------------------------------------------------------------
  WEBSERVER_API_KEY  (required) key clients must send in X-API-Key.
  SHODAN_API_KEY     (required) Shodan API key. The server refuses to start
                     if either of the above is unset.
  SCAN_DELAY         seconds slept between Shodan calls (default 1.0). Shodan
                     rate-limits host lookups to roughly 1/sec.
  OUTPUT_DIR         where dated response files are written (default
                     /app/output in the container).
  GUNICORN_TIMEOUT   gunicorn worker timeout in seconds (default 120). A
                     single /scan must finish within it; raise it for large
                     ranges. Settable at run time, no rebuild.
  PORT               build-time arg; the port gunicorn binds inside the
                     container (default 8000). EXPOSE, the HEALTHCHECK and the
                     gunicorn bind all read this one value so they cannot
                     drift.
  HOST_PORT          compose-only; host port mapped to the container PORT
                     (default 8000).

Put secrets in a .env file next to the compose file. It is excluded from the
image by .dockerignore.

------------------------------------------------------------------------------
3. BUILD AND RUN
------------------------------------------------------------------------------
    docker compose up --build -d
    docker compose logs -f
    docker compose down

ICMP echo (the ping follow-up) runs as the unprivileged scanner user. The
compose file sets net.ipv4.ping_group_range so gid 10001 may open ICMP
sockets without CAP_NET_RAW. If your host forbids that sysctl, remove it and
add `cap_add: [NET_RAW]` instead, or switch the check to a TCP-connect probe.
Without one of these every host falls through to the inactive bucket. The
image installs iputils-ping and curl for the ping and the healthcheck.

The gunicorn --timeout (120s in the Dockerfile) bounds a single /scan. A full
/24 at SCAN_DELAY=1.0 takes several minutes and will be killed. Raise
--timeout, send smaller blocks, or split a large range across requests.

------------------------------------------------------------------------------
4. ACLs SO THE CONTAINER (uid 10001) CAN WRITE RESULTS
------------------------------------------------------------------------------
The container runs as a pinned, unprivileged uid (10001). The application code
is baked into the image, so the only host path it touches is the bind-mounted
output directory. Grant that uid write access there and nothing more.

    # project directory on the host
    APP=/srv/iprange_webserver          # adjust to wherever you cloned this
    # results dir: read + write, with default ACLs so new files inherit
    mkdir -p "$APP/output"
    sudo setfacl -R  -m u:10001:rwX "$APP/output"
    sudo setfacl -R -d -m u:10001:rwX "$APP/output"
    # the container also needs to traverse into the project dir to reach output/
    sudo setfacl -m u:10001:rX "$APP"

If you later bind-mount any read-only input (for example a file of blocks),
grant it u:10001:r the same way.

------------------------------------------------------------------------------
5. FILES AND DEPENDENCIES
------------------------------------------------------------------------------
  webserver.py           Flask app: /scan and /health, plus response logging.
  shodan_block_scan.py   block expansion + per-IP Shodan lookup (imported by
                         the webserver; also runnable as a standalone CLI).
  requirements.txt       Python dependencies: flask, gunicorn, shodan.
                         Versions are unpinned; pin them before deploying.
  Dockerfile             image build.
  docker-compose.yml     service definition.
  .dockerignore          keeps secrets and local output out of the image.
