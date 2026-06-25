#!/usr/bin/env python3
"""Flask API: nmap scans the provided IPs and their ports as specified.
POST /scan  body: {"targets": list|str, "ports": str, "speed": 1-5, "disable_ping": bool}  header: X-API-Key
GET  /health
"""
import hmac
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request

from nmap_ip_port_scan import run_nmap

API_KEY = os.environ.get("WEBSERVER_API_KEY")
if not API_KEY:
    raise RuntimeError(
        "WEBSERVER_API_KEY environment variable must be set "
        "(see README.txt). Refusing to start without an API key."
    )
API_KEY_HEADER = "X-API-Key"
# Each scan response is also written here as scan_<UTC timestamp>.json.
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Accept only digits, commas, and hyphens so the ports field cannot inject nmap flags.
PORT_SPEC = re.compile(r"^[0-9,\-]+$")

# Serialize scans within the worker; assumes gunicorn --workers 1.
_scan_lock = threading.Lock()

app = Flask(__name__)


def require_api_key(view):
    """Reject any request whose X-API-Key header does not match API_KEY."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get(API_KEY_HEADER, "")
        if not hmac.compare_digest(supplied, API_KEY):
            return jsonify(error="invalid or missing API key"), 401
        return view(*args, **kwargs)
    return wrapper


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/scan")
@require_api_key
def scan():
    """Run an nmap scan, persist the result to OUTPUT_DIR, and return it."""
    body = request.get_json(silent=True) or {}

    targets = body.get("targets")
    if isinstance(targets, str):
        targets = targets.split()
    if not targets or not isinstance(targets, list):
        return jsonify(error="'targets' must be a non-empty list or string"), 400
    # A target starting with '-' would be parsed by nmap as an option.
    if any(not isinstance(t, str) or not t or t.startswith("-") for t in targets):
        return jsonify(error="invalid target"), 400

    ports = str(body.get("ports", "1-100"))
    if not PORT_SPEC.match(ports):
        return jsonify(error="invalid ports spec"), 400

    speed = body.get("speed", 2)
    disable_ping = bool(body.get("disable_ping", False))

    if not _scan_lock.acquire(blocking=False):
        return jsonify(error="a scan is already running"), 409
    try:
        started = time.perf_counter()
        try:
            results = run_nmap(" ".join(targets), ports, speed, disable_ping)
        except ValueError as e:
            return jsonify(error=str(e)), 400
        duration = round(time.perf_counter() - started, 3)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        outfile = os.path.join(OUTPUT_DIR, f"scan_{timestamp}.json")
        with open(outfile, "w") as f:
            json.dump(results, f, indent=2)
    finally:
        _scan_lock.release()

    return jsonify(
        scanned_at=timestamp,
        duration_s=duration,
        output=os.path.basename(outfile),
        results=results,
    )
