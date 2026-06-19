#!/usr/bin/env python3
"""Flask API: Shodan-scan IP blocks, ping the no-data hosts, summarise.

POST /scan  body: {"blocks": ["10.11.32.11-124", ...]}  header: X-API-Key
GET  /health
"""
import hmac
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from functools import wraps

import shodan
from flask import Flask, jsonify, request

from shodan_ip_range_scan import expand_block, scan_ip

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
if not SHODAN_API_KEY:
    raise RuntimeError("SHODAN_API_KEY environment variable must be set.")

API_KEY = os.environ.get("WEBSERVER_API_KEY")
if not API_KEY:
    raise RuntimeError(
        "WEBSERVER_API_KEY environment variable must be set "
        "(see README.txt). Refusing to start without an API key."
    )
API_KEY_HEADER = "X-API-Key"

SCAN_DELAY = float(os.environ.get("SCAN_DELAY", "1.0"))

# Each scan response is also written here as scan_<UTC timestamp>.json.
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

app = Flask(__name__)
api = shodan.Shodan(SHODAN_API_KEY)


def require_api_key(view):
    """Reject any request whose X-API-Key header does not match API_KEY."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get(API_KEY_HEADER, "")
        if not hmac.compare_digest(supplied, API_KEY):
            return jsonify(error="invalid or missing API key"), 401
        return view(*args, **kwargs)
    return wrapper


def is_alive(ip):
    """Return True if the host answers a single ICMP echo within 5s."""
    return subprocess.run(
        ["ping", "-c", "1", "-W", "5", ip],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/scan")
@require_api_key
def scan():
    body = request.get_json(silent=True) or {}
    blocks = body.get("blocks", []) if isinstance(body, dict) else body
    if isinstance(blocks, str):
        blocks = [b.strip() for b in blocks.split(",") if b.strip()]
    if not blocks:
        return jsonify(error="no blocks supplied"), 400

    try:
        ips = [ip for block in blocks for ip in expand_block(block)]
    except (ValueError, IndexError):
        return jsonify(error="malformed block (expected PREFIX.START-END)"), 400

    with_data, alive_no_data, inactive = [], [], []
    for ip in ips:
        entry = scan_ip(api, ip)
        time.sleep(SCAN_DELAY)
        if entry["has_data"]:
            with_data.append({"ip": ip, "ports": entry["ports"]})
        elif is_alive(ip):
            alive_no_data.append(ip)
        else:
            inactive.append(ip)

    now = datetime.now(timezone.utc)
    summary = {
        "timestamp": now.isoformat(),
        "scanned": len(ips),
        "with_data": with_data,
        "alive_no_data": alive_no_data,
        "inactive": inactive,
    }
    with open(os.path.join(OUTPUT_DIR, f"scan_{now:%Y%m%dT%H%M%S_%f}.json"), "w") as f:
        json.dump(summary, f, indent=2)
    return jsonify(summary)
