"""HIBS - Have I Been Squatted.

Scan a domain against the Have I Been Squatted API for typosquatting
permutations, store the raw findings, enumerate the unique squatting FQDNs,
and report what changed since the previous scan of the same domain.

Example directory listing after use:
    ├── <this_scanner>.py
    ├── .hibs_api_key
    └── output
        ├── hcsec.eu
        │   ├── hcsec.eu_domain_enum_2026-06-09_12-18-04.json
        │   ├── hcsec.eu_full_output_2026-06-09_12-18-04.json
        │   └── hcsec.eu_full_output_2026-06-09_12-40-58.json
        └── company.com
            ├── company.com_domain_enum_2026-06-09_12-33-57.json
            └── company.com_full_output_2026-06-09_12-45-25.json
"""

import argparse
import asyncio
import httpx
import itertools
import json
import sys
from datetime import datetime
from pathlib import Path

FULL_OUTPUT_MARKER = "_full_output_"
DOMAIN_ENUM_MARKER = "_domain_enum_"
SCRIPT_DIR = Path(__file__).resolve().parent # use the local directory of the file, not the caller.
OUTPUT_DIR = SCRIPT_DIR / "output"  # parent dir; each domain gets its own subfolder under here.
API_KEY_FILE = SCRIPT_DIR / ".hibs_api_key"


def load_api_key(key_file: Path) -> str:
    """Read the API key from a local file (whole file, stripped)."""
    try:
        key = key_file.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        sys.exit(f"[!] API key file not found: {key_file}")
    except OSError as exc:
        sys.exit(f"[!] Could not read API key file {key_file}: {exc}")
    if not key:
        sys.exit(f"[!] API key file is empty: {key_file}")
    return key


async def lookup_domain(domain: str, api_token: str, full_output_file: Path) -> None:
    """Stream a squat lookup for `domain`, writing each permutation message
    (one JSON object per line) to `full_output_file`."""
    found_ips = 0
    progress = 0
    total = 0
    url = f"https://api.haveibeensquatted.com/v1/lookup/squat/{domain}"
    headers = {"Authorization": f"Bearer {api_token}"}
    # set a timeout in case the server slows down or hangs, it is sending a lot of data
    timeout = httpx.Timeout(10.0, read=10.0)
    # create a loading spinner, so its possible to tell whether it froze or is waiting
    spinner = itertools.cycle("|/-\\") 

    with full_output_file.open("w", encoding="utf-8") as f:
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("GET", url, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    phase = "finalizing" if total and progress >= total else "scanning"
                    print(f"\rprogress: {progress}/{total}    found ips: {found_ips}    {phase} {next(spinner)}",
                        end="", flush=True)
                    if not line.strip():
                        continue
                    try:
                        result = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(result, dict):
                        continue

                    op = result.get("op")
                    data = result.get("data")

                    if op == "Meta" and isinstance(data, dict):
                        kind = data.get("kind")
                        if kind == "Progress":
                            values = data.get("data")
                            # expect [progress, total]; only unpack if it looks like that
                            if isinstance(values, (list, tuple)) and len(values) >= 2:
                                progress, total = values[0], values[1]
                        elif kind == "StoredResult":
                            # Second-to-last message carries the stored-result id; the
                            # final {"kind":"Done"} carries no data, so stop here.
                            print(f"\nThe results are stored at: {data.get('data')}")
                            break
                    elif op == "GeoIp":
                        found_ips += 1

                    # save permutation info - everything about potential squatting.
                    # FQDNs repeat across messages and carry many datapoints, so the
                    # unique domains are extracted later by parsing this full output.
                    if result.get("permutation"):
                        f.write(line + "\n")

    print("Scan complete!")
    print(f"Results stored at: {full_output_file}\n")


def extract_domains(full_output_file: Path) -> set[str]:
    """Parse a full-output JSONL file and return the unique permutation FQDNs."""
    domains: set[str] = set()
    try:
        lines = full_output_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return domains
    for line in lines:
        if not line.strip():
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue
        permutation = result.get("permutation") if isinstance(result, dict) else None
        if not isinstance(permutation, dict):
            continue
        domain = permutation.get("domain")
        fqdn = domain.get("fqdn") if isinstance(domain, dict) else None
        if fqdn:
            domains.add(fqdn)
    return domains


def previous_scan(domain_dir: Path) -> tuple[Path, set[str]] | None:
    """Return the most recent prior domain-enum file and its domains, if any.
    The file should contain: ["domain.1", "domain.2", ...]

    Enum filenames carry a ``YYYY-MM-DD_HH-MM-SS`` timestamp and therefore sort
    chronologically, so the lexicographically-greatest name is the most recent
    run. Unreadable/corrupt files are skipped in favour of the next newest.
    """
    candidates = sorted(domain_dir.glob(f"*{DOMAIN_ENUM_MARKER}*.json"), reverse=True)
    for path in candidates:
        try:
            domains = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue  # unreadable/corrupt - try the next most recent
        if isinstance(domains, list):
            return path, set(domains)
    return None


async def main() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=__doc__,
    )
    parser.add_argument(
        "domain",
        type=str,
        help="Fully qualified domain name to scan (e.g. google.com)",
    )
    args = parser.parse_args()
    domain = args.domain
    api_key = load_api_key(API_KEY_FILE)

    # manage file format and layout
    domain_dir = OUTPUT_DIR / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    full_output_file = domain_dir / f"{domain}{FULL_OUTPUT_MARKER}{current_datetime}.json"
    domain_enum_file = domain_dir / f"{domain}{DOMAIN_ENUM_MARKER}{current_datetime}.json"

    # perform the API query and save the full results
    try:
        await lookup_domain(domain, api_key, full_output_file)
    except httpx.TimeoutException as exc:
        sys.exit(f"[!] Server stopped responding: {exc}")
    except httpx.HTTPError as exc:
        sys.exit(f"[!] Request failed: {exc}")

    # enumerate the full output for unique squatting FQDNs
    domains = extract_domains(full_output_file)
    print(f"Found {len(domains)} unique squatting domain(s).")

    # compare against the previous scan
    # this is fine to do after saving the full results as it
    # only reads the FQDN enum file, which gets generated after.
    prior = previous_scan(domain_dir)
    if prior is None:
        print("No previous scan to compare against.")
    else:
        prev_path, prev_domains = prior
        added = sorted(domains - prev_domains)
        removed = sorted(prev_domains - domains)
        if not added and not removed:
            print(f"No change since {prev_path.name}; skipping enum save.")
            print("INFO: the full output stays saved, as it could contain new information on previosly found domains.\n")
            return
        print(f"Changes since {prev_path.name}:")
        for d in added:
            print(f"  + {d}")
        for d in removed:
            print(f"  - {d}")

    # save the enumerated domains
    domain_enum_file.write_text(json.dumps(sorted(domains)), encoding="utf-8")
    print(f"Saved {len(domains)} domain(s) to {domain_enum_file}\n")


if __name__ == "__main__":
    asyncio.run(main())
