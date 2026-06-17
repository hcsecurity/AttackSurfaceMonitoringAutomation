"""Minimal Flask API for triggering long-running domain generation jobs.

All endpoints live under /api/ and require the X-API-Key header.

    POST /api/generate?domain=<d>&keyword=<k>   start a job, returns job_id
    GET  /api/status?job_id=<id>                poll job state
    GET  /api/results?job_id=<id>               fetch text output of a done job

generate() returns immediately with a job_id; the actual work runs in a
background thread, and the caller polls /api/status until the job is done,
then pulls the text from /api/results.

Run with:
    sudo -u www-data env \
      PATH="/srv/n8n_webserver/.venv/bin:/usr/bin:/bin" \
      /srv/n8n_webserver/.venv/bin/python webserver.py
After setting up pip requirements with the venv.
"""

import hmac
import re
import subprocess
import threading
import time
import uuid
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request

# Generate a real key with:
#   python -c "import secrets; print(secrets.token_urlsafe(32))"
API_KEY = "change-me-to-a-long-random-secret"
API_KEY_HEADER = "X-API-Key"

app = Flask(__name__)

# Scanner pipeline lives in ./squatting_scanners/ next to this file.
SCANNER_DIR = Path(__file__).resolve().parent / "squatting_scanners"
SCANNER_SCRIPT = "./run_scanners.sh"          # run as: run_scanners.sh <domain>
SUMMARY_SCRIPT = "generate_summary.py"        # run_summary builds its argv
SCANNER_OUT = SCANNER_DIR / "run_scanners.out"

# Markers watched for in run_scanners.out (the script's final echo lines):
# success prints "... all complete - logs in ...", failure prints "... FAILED: ...",
# and a bad invocation prints "usage: ...".
SCANNER_OK = "all complete"
SCANNER_FAIL = "FAILED:"
SCANNER_USAGE = "usage:"

SCANNER_TIMEOUT = 1800   # seconds; kill a wedged run rather than block forever
POLL_INTERVAL = 2.0      # seconds between run_scanners.out reads

# run_scanners.out is a single shared file, so only one scan can use it safely
# at a time; serialize the scanner stage across worker threads with this lock.
_scanner_lock = threading.Lock()

# Validate untrusted input before it reaches a subprocess. We never invoke a
# shell (argv lists only), but a value like "-rf" or "--flag" could still be
# read as an option by the script or generate_summary.py, so constrain shape.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
KEYWORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

# In-memory job registry: job_id -> job dict.
# Single-process only: jobs are lost on restart and are not shared across
# multiple worker processes. Fine for a simple/internal tool; swap for Redis
# or a DB if you ever run this under gunicorn with more than one worker.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


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
    """Read a parameter from query string, form body, or JSON body."""
    body = request.get_json(silent=True) or {}
    return request.args.get(name) or request.form.get(name) or body.get(name)


def _get_job(job_id: str | None) -> dict | None:
    """Return a snapshot copy of a job, or None if the id is unknown."""
    if not job_id:
        return None
    with _jobs_lock:
        job = _jobs.get(job_id)
        return dict(job) if job is not None else None


def _last_line(text: str) -> str:
    """Return the last non-blank line of text (used for error reporting)."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def _run_scanners(domain: str) -> None:
    """Launch run_scanners.sh <domain> and block until run_scanners.out reports
    completion or failure. Raises RuntimeError on failure, crash, or timeout.
    """
    # Open in "w" to truncate the previous run's output. The child keeps its
    # own copy of the fd after we close ours, so it can keep writing.
    with SCANNER_OUT.open("w") as out:
        proc = subprocess.Popen(
            [SCANNER_SCRIPT, domain],
            cwd=SCANNER_DIR,
            stdout=out,
            stderr=subprocess.STDOUT,
        )

    deadline = time.monotonic() + SCANNER_TIMEOUT
    while True:
        text = SCANNER_OUT.read_text(errors="replace")
        if SCANNER_OK in text:
            return
        if SCANNER_FAIL in text or SCANNER_USAGE in text:
            raise RuntimeError(_last_line(text) or "run_scanners.sh reported failure")
        if proc.poll() is not None:
            # Process ended without printing a completion marker -> crashed.
            raise RuntimeError(
                f"run_scanners.sh exited ({proc.returncode}) without completing"
            )
        if time.monotonic() > deadline:
            proc.kill()
            raise RuntimeError("run_scanners.sh timed out")
        time.sleep(POLL_INTERVAL)


def _run_summary(domain: str, keyword: str | None) -> str:
    """Run generate_summary.py <domain> [keyword] --compare-previous and return
    its stdout. Raises RuntimeError on a non-zero exit.
    """
    argv = ["python3", SUMMARY_SCRIPT, domain]
    if keyword:
        argv.append(keyword)
    argv.append("--compare-previous")
    proc = subprocess.run(
        argv,
        cwd=SCANNER_DIR,
        capture_output=True,
        text=True,
        timeout=SCANNER_TIMEOUT,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"generate_summary.py failed ({proc.returncode}): {detail}")
    return proc.stdout


def run_generation(domain: str, keyword: str | None) -> str:
    """Run the scanner pipeline for one domain and return the summary text.

    1. run_scanners.sh <domain> in SCANNER_DIR, output to run_scanners.out
    2. poll run_scanners.out until it reports completion or failure
    3. generate_summary.py <domain> [keyword] --compare-previous; return stdout

    Serialized by _scanner_lock because run_scanners.out is a single shared
    file: two concurrent runs would clobber each other's output.
    """
    with _scanner_lock:
        _run_scanners(domain)
        return _run_summary(domain, keyword)


def _worker(job_id: str, domain: str, keyword: str | None) -> None:
    with _jobs_lock:
        _jobs[job_id]["status"] = "running"
    try:
        output = run_generation(domain, keyword)
    except Exception as exc:  # surface any failure to the caller, do not crash
        with _jobs_lock:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["error"] = str(exc)
        return
    with _jobs_lock:
        _jobs[job_id]["status"] = "completed"
        _jobs[job_id]["result"] = output


@app.post("/api/generate")
@require_api_key
def generate():
    domain = _param("domain")
    keyword = _param("keyword")
    if not domain or not DOMAIN_RE.match(domain):
        return jsonify(error="missing or invalid 'domain'"), 400
    if keyword is not None and not KEYWORD_RE.match(keyword):
        return jsonify(error="invalid 'keyword'"), 400

    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {
            "status": "pending",
            "result": None,
            "error": None,
            "domain": domain,
            "keyword": keyword,
        }
    threading.Thread(
        target=_worker, args=(job_id, domain, keyword), daemon=True
    ).start()
    return jsonify(job_id=job_id, status="pending"), 202


@app.get("/api/status")
@require_api_key
def status():
    job_id = _param("job_id")
    job = _get_job(job_id)
    if job is None:
        return jsonify(error="unknown job_id"), 404
    return jsonify(job_id=job_id, status=job["status"], error=job["error"])


@app.get("/api/results")
@require_api_key
def results():
    job_id = _param("job_id")
    job = _get_job(job_id)
    if job is None:
        return jsonify(error="unknown job_id"), 404
    if job["status"] != "completed":
        return jsonify(
            job_id=job_id, status=job["status"], error="results not ready"
        ), 409
    return job["result"], 200, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    # Bound to internal IP only
    app.run(host="172.30.0.13", port=8000)
