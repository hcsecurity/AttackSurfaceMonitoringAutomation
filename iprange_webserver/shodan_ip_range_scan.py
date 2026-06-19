#!/usr/bin/env python3
"""Scan IP blocks via the Shodan host API and write results to JSON.

Block format: PREFIX.START-END (e.g. 10.11.32.11-124) or a single IP
(e.g. 10.11.32.11). The last octet may be a single value or a range.
"""
import argparse
import json
import os
import sys
import time

import shodan


def expand_block(block):
    """Yield each IP in a block string like '10.11.32.11-124'."""
    parts = block.strip().split('.')
    prefix = '.'.join(parts[:3])
    last = parts[3].strip()
    if '-' in last:
        start, end = last.split('-')
    else:
        start = end = last
    # the same as: return [f"{prefix}.{octet}" for octet in range(int(start), int(end) + 1)]
    for octet in range(int(start), int(end) + 1):
        yield f"{prefix}.{octet}"


def scan_ip(api, ip):
    """Query Shodan for a single IP, returning a result entry dict."""
    entry = {"ip": ip, "has_data": False, "ports": []}
    try:
        host = api.host(ip)
        entry["has_data"] = True
        entry["ports"] = [
            {"port": item.get("port"), "banner": item.get("data")}
            for item in host.get("data", [])
        ]
    except shodan.exception.APIError as e:
        # "No information available" is an expected empty result, not an error.
        if "No information available for that IP." not in str(e):
            entry["error"] = str(e)
    return entry


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan IP blocks via the Shodan host API.")
    parser.add_argument(
        "blocks", nargs="*",
        help="IP blocks, e.g. 10.11.32.11-124 (last octet may be a range).")
    parser.add_argument(
        "-f", "--input-file",
        help="File of blocks, one per line (combined with positional blocks).")
    parser.add_argument(
        "-o", "--output", default="output.json",
        help="Output JSON path (default: output.json).")
    parser.add_argument(
        "--api-key", default=os.environ.get("SHODAN_API_KEY"),
        help="Shodan API key (defaults to the SHODAN_API_KEY env var).")
    parser.add_argument(
        "--delay", type=float, default=1.0,
        help="Seconds between requests to respect rate limits (default: 1.0).")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.api_key:
        sys.exit("error: no API key (set SHODAN_API_KEY or pass --api-key)")

    blocks = list(args.blocks)
    if args.input_file:
        with open(args.input_file) as f:
            blocks += [line.strip() for line in f if line.strip()]
    if not blocks:
        sys.exit("error: no blocks given (pass as args or via --input-file)")

    api = shodan.Shodan(args.api_key)
    results = []
    for block in blocks:
        for ip in expand_block(block):
            results.append(scan_ip(api, ip))
            if args.delay:
                time.sleep(args.delay)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"wrote {len(results)} entries to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
