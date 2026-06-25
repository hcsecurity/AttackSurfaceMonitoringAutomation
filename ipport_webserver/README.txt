nmap_ip_port_webserver
=======================

Flask API that runs nmap against the supplied targets and ports, returns the
parsed result as JSON, and persists each result to OUTPUT_DIR. Wraps run_nmap
from nmap_ip_port_scan.py, which performs a TCP connect scan (-sT). nmap is
installed from the Debian package repositories inside the image.


Requirements
------------
Docker. nmap and curl are installed inside the image; nothing is needed on the
host. Python dependencies are pinned in requirements.txt.


Environment variables
---------------------
WEBSERVER_API_KEY  Required. The service refuses to start if unset. Compared
                   against the X-API-Key request header using hmac.compare_digest.
                   Generate one with:
                   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
OUTPUT_DIR         Output directory inside the container. Compose sets this to
                   /app/output. Defaults to ./output relative to /app otherwise.
GUNICORN_TIMEOUT   gunicorn worker timeout in seconds. Default 120. A single
                   /scan must finish within it or the worker is killed.
PORT               Internal port gunicorn binds. Build-time ARG, default 8000.
                   EXPOSE, the HEALTHCHECK and the gunicorn bind all read it.
HOST_PORT          Host-facing published port (compose). Default 8000.


Build
-----
    docker build -t nmap-ip-port-api .

To bind a different internal port, pass the build arg:

    docker build --build-arg PORT=9000 -t nmap-ip-port-api .

Or build through compose, which forwards PORT as a build arg:

    docker compose build


Output directory and ACL
------------------------
The container runs as the unprivileged UID 10001. A bind-mounted output
directory must grant that UID write access. Grant it on the specific output
directory only, never on a parent:

    mkdir -p ./output
    setfacl -m u:10001:rwx ./output

Files written by the container are already owned by 10001, so no default ACL is
required unless the container later creates subdirectories.


Run
---
Compose is the supported path. Put the key in a .env file or the shell:

    WEBSERVER_API_KEY=...
    HOST_PORT=8000          # optional, host-facing port
    GUNICORN_TIMEOUT=120    # optional, raise for large scans

    docker compose up -d --build

--build forces a rebuild on every up. Without it, compose reuses the cached
nmap-ip-port-api image and ignores edits to the Dockerfile or source.

Plain docker run, key from a file, single loopback binding:

    docker run -d --name nmap-ip-port-api \
      -e WEBSERVER_API_KEY="$(cat api.key)" \
      -e GUNICORN_TIMEOUT=120 \
      -p 127.0.0.1:8000:8000 \
      -v "$(pwd)/output:/app/output" \
      nmap-ip-port-api


Endpoints
---------
GET  /health
    No auth. Returns {"status": "ok"}. Used by the container HEALTHCHECK.

POST /scan
    Header: X-API-Key: <WEBSERVER_API_KEY>
    Body (JSON):
        targets       list of strings or a space-separated string. Required.
        ports         nmap port spec, digits/commas/hyphens only. Default "1-100".
        speed         nmap timing template, 1-5. Default 2.
        disable_ping  bool, sets -Pn. Default false.
    Returns:
        {"scanned_at": "<UTC timestamp>", "duration_s": <float>,
         "output": "scan_<UTC timestamp>.json", "results": [...]}
    The same result is written to OUTPUT_DIR/scan_<UTC timestamp>.json.

Example:

    curl -s http://127.0.0.1:8000/scan \
      -H "X-API-Key: $(cat api.key)" \
      -H "Content-Type: application/json" \
      -d '{"targets": ["10.0.0.5", "10.0.0.6"], "ports": "22,80,443", "speed": 2}'


Input validation
----------------
python-nmap passes both the arguments and host strings through shlex, so the
ports and targets fields are validated before the scan: ports must match
[0-9,\-]+, and no target may start with "-". This blocks injection of extra
nmap flags through the request body on the authenticated endpoint.


Operational notes
-----------------
- Unprivileged by design: no CAP_NET_RAW is granted and no ICMP sysctl is set,
  so nmap uses the TCP connect scan (-sT). Raw-packet scans (-sS, raw ICMP
  discovery) are not available in this container.
- --workers 1 is required: concurrent scans are serialized by an in-process
  threading.Lock, and the lock does not span worker processes. --threads 8
  lets the worker accept health checks and return HTTP 409 while a scan runs.
  Do not raise the worker count without moving serialization to a shared
  mechanism.
- GUNICORN_TIMEOUT bounds a single synchronous /scan. Raise it for large port
  ranges or many hosts, otherwise the worker is killed mid-scan. Constrain scan
  scope through the port range and timing template to stay within it.
