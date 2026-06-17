#!/usr/bin/env python3
"""Summarise recon run artifacts and diff the latest run against the prior one.

Reads the JSON artifacts written under <output-dir>/<tool>/<domain>/, named
<domain>_<tool>_<YYYY-MM-DD_HH-MM-SS>.json, picks the most recent (and, with
--compare-previous, the one before it), and reports which subdomains appeared
or disappeared since the previous run.

Primarily used for the weekly puredns cron via the /api/puredns/summary
endpoint, but --tool subfinder works too (subfinder's -oJ JSON-Lines files are
parsed for their "host" field).

Usage:
    generate_summary.py --domain company.eu [--tool puredns]
                        [--compare-previous] [--json]
                        [--output-dir ./output]

Exit codes:
    0  success
    2  bad arguments
    3  no run artifacts found for that tool/domain
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

TIMESTAMP_FMT = "%Y-%m-%d_%H-%M-%S"


def _timestamp_of(path: Path, domain: str, tool: str) -> datetime:
    """Best-effort run time from the filename, falling back to mtime."""
    prefix = f"{domain}_{tool}_"
    stem = path.stem
    raw = stem[len(prefix):] if stem.startswith(prefix) else ""
    try:
        return datetime.strptime(raw, TIMESTAMP_FMT)
    except ValueError:
        return datetime.fromtimestamp(path.stat().st_mtime)


def find_runs(tool_dir: Path, domain: str, tool: str) -> list[Path]:
    """Return run artifact paths sorted oldest -> newest."""
    files = list(tool_dir.glob(f"{domain}_{tool}_*.json"))
    return sorted(files, key=lambda p: _timestamp_of(p, domain, tool))


def load_subdomains(path: Path) -> set[str]:
    """Load the set of subdomains from a run artifact.

    Handles three shapes:
      - JSON object with a "subdomains" list (puredns artifacts, see
        run_puredns.sh)
      - bare JSON array of strings
      - JSON Lines with a "host" field per line (subfinder -oJ)
    """
    text = path.read_text(errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        hosts: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("host"):
                hosts.add(obj["host"])
        return hosts

    if isinstance(data, dict):
        return {s for s in data.get("subdomains", []) if isinstance(s, str)}
    if isinstance(data, list):
        return {s for s in data if isinstance(s, str)}
    return set()


def build_summary(tool_dir: Path, domain: str, tool: str, compare: bool) -> dict:
    runs = find_runs(tool_dir, domain, tool)
    latest = runs[-1]
    current = load_subdomains(latest)

    summary: dict = {
        "tool": tool,
        "domain": domain,
        "latest_file": latest.name,
        "latest_timestamp": _timestamp_of(latest, domain, tool).strftime(TIMESTAMP_FMT),
        "current_count": len(current),
        "total_runs": len(runs),
    }

    if compare and len(runs) >= 2:
        previous = runs[-2]
        prev = load_subdomains(previous)
        new = sorted(current - prev)
        removed = sorted(prev - current)
        summary.update(
            compared=True,
            previous_file=previous.name,
            previous_timestamp=_timestamp_of(previous, domain, tool).strftime(TIMESTAMP_FMT),
            previous_count=len(prev),
            new_count=len(new),
            removed_count=len(removed),
            new_subdomains=new,
            removed_subdomains=removed,
        )
    else:
        # No prior run to diff against: hand back the full current list.
        summary.update(compared=False, subdomains=sorted(current))
    return summary


def print_text(summary: dict) -> None:
    tool = summary["tool"]
    domain = summary["domain"]
    print(f"{tool} summary for {domain}")
    print(f"  latest run:   {summary['latest_file']} ({summary['current_count']} subdomains)")

    if summary.get("compared"):
        print(f"  previous run: {summary['previous_file']} ({summary['previous_count']} subdomains)")
        print(f"  new since previous run:     {summary['new_count']}")
        for s in summary["new_subdomains"]:
            print(f"    + {s}")
        print(f"  removed since previous run: {summary['removed_count']}")
        for s in summary["removed_subdomains"]:
            print(f"    - {s}")
    else:
        print("  (no previous run to compare against; listing all current subdomains)")
        for s in summary["subdomains"]:
            print(f"    {s}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarise recon run artifacts.")
    parser.add_argument("--domain", required=True, help="root domain, e.g. company.eu")
    parser.add_argument("--tool", default="puredns", help="tool name (default: puredns)")
    parser.add_argument(
        "--compare-previous", action="store_true",
        help="diff the latest run against the one before it",
    )
    parser.add_argument(
        "--json", dest="as_json", action="store_true",
        help="emit the summary as JSON instead of text",
    )
    parser.add_argument(
        "--output-dir", default=str(Path(__file__).resolve().parent / "output"),
        help="base output directory (default: ./output)",
    )
    args = parser.parse_args(argv)

    tool_dir = Path(args.output_dir) / args.tool / args.domain
    if not tool_dir.is_dir():
        print(f"no {args.tool} output directory for '{args.domain}': {tool_dir}",
              file=sys.stderr)
        return 3

    runs = find_runs(tool_dir, args.domain, args.tool)
    if not runs:
        print(f"no {args.tool} run artifacts for '{args.domain}' in {tool_dir}",
              file=sys.stderr)
        return 3

    summary = build_summary(tool_dir, args.domain, args.tool, args.compare_previous)

    if args.as_json:
        print(json.dumps(summary, indent=2))
    else:
        print_text(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
