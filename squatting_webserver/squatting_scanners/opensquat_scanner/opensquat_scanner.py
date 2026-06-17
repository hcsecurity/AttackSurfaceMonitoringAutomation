"""Query the openSquat NRD look-alike API for a target domain.
 
Designed to run daily (e.g. via cron). Results are saved to a timestamped
JSON file in an ``output/<keyword>`` directory, but a new file is only written when the
set of look-alike domains differs from the most recent previously saved run -
so an unchanged daily run won't litter the directory with identical files.

Example directory listing after use:
    ├── <this_scanner>.py
    ├── .opensquat_api_key
    └── output
        ├── hcsec
        │   ├── hcsec_domain_enum_2026-06-09_09-04-15.json
        │   └── hcsec_full_output_2026-06-09_09-04-15.json
        └── github
            ├── github_domain_enum_2026-06-09_09-03-52.json
            └── github_full_output_2026-06-09_09-03-52.json
"""

import argparse
import requests
import json
import sys
from datetime import datetime
from pathlib import Path

API_URL = "https://api.opensquat.com/v1/nrd/lookalike/"
REQUEST_TIMEOUT = 120
FULL_OUTPUT_MARKER = "_full_output_"
DOMAIN_ENUM_MARKER = "_domain_enum_"
SCRIPT_DIR = Path(__file__).resolve().parent # use the local directory of the file, not the caller.
OUTPUT_DIR = SCRIPT_DIR / ("output")  # parent dir; each domain gets its own subfolder under here.
API_KEY_FILE = SCRIPT_DIR / ".opensquat_api_key" 


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


def fetch_lookalikes(target_url: str, api_key: str) -> dict:
    """Query the openSquat look-alike API and return the parsed JSON payload."""
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    params = {
        "risk": "true",
        "similarity": "true",
        "fuzziness": "high",
        "format": "json",
    }
    try:
        resp = requests.post(
            target_url, headers=headers, params=params, timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        sys.exit(f"[!] Request to {target_url} failed: {exc}")
    try:
        return resp.json()
    except ValueError:
        sys.exit(f"[!] Response was not valid JSON:\n{resp.text[:500]}")


def extract_domains(data: dict) -> set[str]:
    return {
        entry["domain"]
        for entry in (data.get("results") or [])
        if isinstance(entry, dict) and entry.get("domain")
    }


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
 

def main() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=__doc__,
    )
    parser.add_argument(
        "keyword",
        type=str,
        help="Target domain keyword to scan (e.g. google, github) do not include TLD",
    )

    args = parser.parse_args()
    api_key = load_api_key(API_KEY_FILE)
    target_keyword = args.keyword
    target_url = API_URL + target_keyword
    
    # perform the request
    data = fetch_lookalikes(target_url, api_key)
    domains = extract_domains(data)

    # check for new domains
    domain_dir = OUTPUT_DIR / target_keyword
    prior = previous_scan(domain_dir)
    if prior is None:
        print("No previous scan to compare against.")
        prev_domains: set[str] = set()
    else:
        _prev_path, prev_domains = prior
    new_domains = domains - prev_domains

    if new_domains:
        # print the domains
        print("New domains since last scan:")
        for d in sorted(new_domains):
            print(f"  {d}")
        # manage file format and layout
        domain_dir.mkdir(parents=True, exist_ok=True)
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        full_output_file = domain_dir / f"{target_keyword}{FULL_OUTPUT_MARKER}{current_datetime}.json"
        domain_enum_file = domain_dir / f"{target_keyword}{DOMAIN_ENUM_MARKER}{current_datetime}.json"
        # save the files associated with new domains
        full_output_file.write_text(json.dumps(data), encoding="utf-8")
        domain_enum_file.write_text(json.dumps(sorted(domains)), encoding="utf-8")
        print(f"Saved {len(domains)} domain(s) to {domain_dir}/\n")
    else:
        print("No new domains since previous scan.\n")


if __name__ == "__main__":
    main()
