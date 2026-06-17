"""Flask API in front of two recon tools.

Endpoints (all under /api/, all require the X-API-Key header except /api/health):

    POST /api/subfinder?domain=<d>     start a subfinder job, returns a job_id
    GET  /api/subfinder/<job_id>       view a job: status, and results once done
    GET  /api/subfinder/summary?domain=<d>
                                       summarise the latest subfinder run
                                       for <domain> (diff against the prior run)
    GET  /api/puredns/summary?domain=<d>
                                       summarise the latest weekly puredns run
                                       for <domain> (diff against the prior run)
    GET  /api/health                   unauthenticated liveness probe

subfinder is run on demand: POST returns immediately with a job_id, the actual
discovery runs in a background thread, and the caller polls GET /api/subfinder/
<job_id> until status is "completed", at which point the parsed subdomains are
included in the response.

puredns is NOT triggered here. It runs as a weekly cron (see run_puredns.sh and
crontab) which writes JSON artifacts under output/puredns/<domain>/. The summary
endpoint just reads those artifacts and reports what changed week over week.

Run (production) via gunicorn; see entrypoint.sh / Dockerfile. The API key is
read from the WEBSERVER_API_KEY environment variable and is never baked into the
image.
"""

import hmac
import json
import os
import re
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, request
from werkzeug.routing import BaseConverter

# --- configuration -----------------------------------------------------------

# Required. Generate one with:
#   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
# and pass it in with -e WEBSERVER_API_KEY=... (or via docker-compose / .env).
API_KEY = os.environ.get("WEBSERVER_API_KEY")
if not API_KEY:
    raise RuntimeError(
        "WEBSERVER_API_KEY environment variable must be set "
        "(see README.txt). Refusing to start without an API key."
    )
API_KEY_HEADER = "X-API-Key"

APP_DIR = Path(__file__).resolve().parent          # /app in the container
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", APP_DIR / "output"))
SUBFINDER_OUT = OUTPUT_DIR / "subfinder"           # output/subfinder/<domain>/...
PROVIDER_CONFIG = APP_DIR / "provider-config.yaml"  # subfinder source API keys
SUMMARY_SCRIPT = APP_DIR / "generate_summary.py"

SUBFINDER_BIN = os.environ.get("SUBFINDER_BIN", "subfinder")
TIMESTAMP_FMT = "%Y-%m-%d_%H-%M-%S"

# Kill a wedged subfinder rather than leak a thread forever.
SUBFINDER_TIMEOUT = int(os.environ.get("SUBFINDER_TIMEOUT", "1800"))
SUMMARY_TIMEOUT = int(os.environ.get("SUMMARY_TIMEOUT", "300"))

app = Flask(__name__)


# A job_id is a uuid4().hex: exactly 32 lowercase hex characters. Constraining
# the route converter to that shape means /api/subfinder/<job_id> can never
# match /api/subfinder/summary (or any other non-id path), so the dynamic and
# static subfinder routes are structurally incapable of colliding -- we do not
# have to rely on Werkzeug's static-beats-dynamic rule ordering. A malformed id
# then gets a clean 404 straight from the router instead of reaching the view.
class JobIdConverter(BaseConverter):
    regex = r"[0-9a-f]{32}"


app.url_map.converters["jobid"] = JobIdConverter

# Validate untrusted input before it reaches a subprocess. We never invoke a
# shell (argv lists only), but a value like "-rf" or "--flag" could still be
# read as an option by the tool, so constrain the shape to a real domain.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

# In-memory job registry: job_id -> job dict. Single process only: jobs are
# lost on restart and are not shared across worker processes. That is why the
# Docker image runs gunicorn with exactly one worker (concurrency comes from
# threads). Swap for Redis or a DB if you ever need multiple workers.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


# --- helpers -----------------------------------------------------------------

def require_api_key(view):
    """Reject any request whose X-API-Key header does not match API_KEY."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get(API_KEY_HEADER, "")
        # Constant-time compare so the check does not leak the key via timing.
        if not hmac.compare_digest(supplied, API_KEY):
            return jsonify(error="invalid or missing API key"), 401
        return view(*args, **kwargs)

    return wrapper


def _param(name: str) -> str | None:
    """Read a parameter from the query string, form body, or JSON body."""
    body = request.get_json(silent=True) or {}
    return request.args.get(name) or request.form.get(name) or body.get(name)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _get_job(job_id: str | None) -> dict | None:
    """Return a snapshot copy of a job, or None if the id is unknown."""
    if not job_id:
        return None
    with _jobs_lock:
        job = _jobs.get(job_id)
        return dict(job) if job is not None else None


def _set_job(job_id: str, **fields) -> None:
    with _jobs_lock:
        _jobs[job_id].update(fields)


def _parse_subfinder_jsonl(path: Path) -> list[str]:
    """Extract sorted, de-duplicated hosts from a subfinder -oJ file.

    subfinder -oJ writes JSON Lines (one object per line, e.g.
    {"host": "sub.example.com", ...}), not a JSON array, so parse per line.
    """
    hosts: set[str] = set()
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") if isinstance(obj, dict) else None
        if host:
            hosts.add(host)
    return sorted(hosts)


def _run_subfinder(domain: str) -> Path:
    """Run subfinder for one domain and return the path to its output file.

    Command (provider-config is added only if the file is present):
        subfinder -d <domain> -oJ -o <outfile> -silent
                  [-provider-config provider-config.yaml]
    """
    ts = datetime.now(timezone.utc).strftime(TIMESTAMP_FMT)
    dest_dir = SUBFINDER_OUT / domain
    dest_dir.mkdir(parents=True, exist_ok=True)
    outfile = dest_dir / f"{domain}_subfinder_{ts}.json"

    argv = [SUBFINDER_BIN, "-d", domain, "-oJ", "-o", str(outfile), "-silent"]
    if PROVIDER_CONFIG.exists():
        argv += ["-provider-config", str(PROVIDER_CONFIG)]

    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=SUBFINDER_TIMEOUT
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        raise RuntimeError(
            f"subfinder exited {proc.returncode}: {detail[-1] if detail else 'no output'}"
        )
    if not outfile.exists():
        # subfinder writes nothing when it finds nothing; create an empty file
        # so the artifact path is always real.
        outfile.touch()
    return outfile


def _subfinder_worker(job_id: str, domain: str) -> None:
    _set_job(job_id, status="running", started_at=_now_iso())
    try:
        outfile = _run_subfinder(domain)
        subdomains = _parse_subfinder_jsonl(outfile)
        # NB: the completion update lives inside the try on purpose. It used to
        # sit after the except/return, so a failure here (see relative_to
        # below) escaped the thread and left the job pinned at "running"
        # forever. Anything that throws now lands in the except and the job is
        # honestly reported as "failed".
        _set_job(
            job_id,
            status="completed",
            # Report the artifact path relative to the output root. OUTPUT_DIR
            # is always a parent of outfile (it is built from SUBFINDER_OUT),
            # whereas APP_DIR is NOT when OUTPUT_DIR is set outside the app dir
            # (e.g. a mounted volume) -- relative_to(APP_DIR) raised ValueError
            # in that very common case, which is what wedged the job.
            output_file=str(outfile.relative_to(OUTPUT_DIR)),
            count=len(subdomains),
            subdomains=subdomains,
            finished_at=_now_iso(),
        )
    except Exception as exc:  # surface failure to the caller, do not crash
        _set_job(job_id, status="failed", error=str(exc), finished_at=_now_iso())


def _run_summary(domain: str, tool: str = "puredns") -> tuple[int, str, str]:
    """Run generate_summary.py for puredns and return (returncode, stdout, stderr)."""
    argv = [
        "python3", str(SUMMARY_SCRIPT),
        "--tool", tool,
        "--domain", domain,
        "--compare-previous",
        "--json",
        "--output-dir", str(OUTPUT_DIR),
    ]
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=SUMMARY_TIMEOUT
    )
    return proc.returncode, proc.stdout, proc.stderr


# --- endpoints ---------------------------------------------------------------

@app.post("/api/subfinder")
@require_api_key
def subfinder_start():
    domain = _param("domain")
    if not domain or not DOMAIN_RE.match(domain):
        return jsonify(error="missing or invalid 'domain'"), 400

    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {
            "tool": "subfinder",
            "domain": domain,
            "status": "pending",
            "error": None,
            "output_file": None,
            "count": None,
            "subdomains": None,
            "created_at": _now_iso(),
            "started_at": None,
            "finished_at": None,
        }
    threading.Thread(
        target=_subfinder_worker, args=(job_id, domain), daemon=True
    ).start()
    return jsonify(job_id=job_id, domain=domain, status="pending"), 202


# <jobid:job_id> uses the custom converter declared above, so this route only
# fires for a well-formed 32-hex job_id and never shadows /api/subfinder/summary.
@app.get("/api/subfinder/<jobid:job_id>")
@require_api_key
def subfinder_view(job_id: str):
    job = _get_job(job_id)
    if job is None:
        return jsonify(error="unknown job_id"), 404

    resp = {
        "job_id": job_id,
        "tool": job["tool"],
        "domain": job["domain"],
        "status": job["status"],
        "error": job["error"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
    }
    if job["status"] == "completed":
        resp["output_file"] = job["output_file"]
        resp["count"] = job["count"]
        resp["subdomains"] = job["subdomains"]
    return jsonify(resp)


@app.get("/api/puredns/summary")
@require_api_key
def puredns_summary():
    domain = _param("domain")
    if not domain or not DOMAIN_RE.match(domain):
        return jsonify(error="missing or invalid 'domain'"), 400

    rc, out, err = _run_summary(domain, "puredns")
    if rc == 0:
        return Response(out, mimetype="application/json")
    if rc == 3:
        return jsonify(error=f"no puredns results found for '{domain}'"), 404
    return jsonify(
        error="failed to build summary",
        detail=(err or out).strip(),
    ), 500

@app.get("/api/subfinder/summary")
@require_api_key
def subfinder_summary():
    domain = _param("domain")
    if not domain or not DOMAIN_RE.match(domain):
        return jsonify(error="missing or invalid 'domain'"), 400

    rc, out, err = _run_summary(domain, "subfinder")
    if rc == 0:
        return Response(out, mimetype="application/json")
    if rc == 3:
        return jsonify(error=f"no subfinder results found for '{domain}'"), 404
    return jsonify(
        error="failed to build summary",
        detail=(err or out).strip(),
    ), 500

@app.get("/api/health")
def health():
    return jsonify(status="ok", time=_now_iso())


if __name__ == "__main__":
    # Local development only. In the container, gunicorn binds the socket
    # (see entrypoint.sh); host port mapping decides what is reachable.
    app.run(host=os.environ.get("BIND_HOST", "0.0.0.0"), port=8001)
