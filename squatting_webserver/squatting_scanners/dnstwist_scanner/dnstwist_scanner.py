"""dnstwist - detect registered look-alike domains for a target domain.

Scan a domain for registered typosquats, homoglyphs, bitsquats, and similar
permutations (with WHOIS and MX enrichment), enumerate the unique squatting
FQDNs, and report what changed since the previous scan of the same domain.

Example directory listing after use:
    ├── <this_scanner>.py
    └── output
        ├── hcsec.eu
        │   ├── hcsec.eu_domain_enum_2026-06-09_13-44-41.json
        │   └── hcsec.eu_full_output_2026-06-09_13-44-41.json
        └── company.com
            ├── company.com_domain_enum_2026-06-09_13-53-01.json
            └── company.com_full_output_2026-06-09_13-53-01.json
"""

import argparse
import json
import dnstwist
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent # use the local directory of the file, not the caller.
OUTPUT_DIR = SCRIPT_DIR / ("output")  # parent dir; each domain gets its own subfolder under here.
FULL_OUTPUT_MARKER = "_full_output_"
DOMAIN_ENUM_MARKER = "_domain_enum_"


def domain_set(records: list[dict]) -> set[str]:
    """Return the set of 'domain' values from a list of dnstwist result dicts."""
    return {item["domain"] for item in records if "domain" in item}


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
        "domain",
        type=str,
        help="Fully qualified domain name to scan (e.g. google.com)",
    )
    args = parser.parse_args()
    target_domain = args.domain

    # manage file format and layout
    domain_dir = OUTPUT_DIR / target_domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    full_output_file = domain_dir / f"{target_domain}{FULL_OUTPUT_MARKER}{current_datetime}.json"
    domain_enum_file = domain_dir / f"{target_domain}{DOMAIN_ENUM_MARKER}{current_datetime}.json"

    current_data: list[dict] = dnstwist.run(
        domain=target_domain,
        registered=True,
        whois=True,
        mxcheck=True,
        format="null",
    )
    
    # Diff against the previous run before writing anything new.
    prior = previous_scan(domain_dir)
    if prior is None:
        print("No previous scan found. All results will be reported as new.")
        previous_domains: set[str] = set()
    else:
        _, previous_domains = prior
    current_domains = domain_set(current_data)
    new_domains = current_domains - previous_domains

    if new_domains:
        print("New domains since last scan:")
        for d in sorted(new_domains):
            print(f"  {d}")
        # save the files associated with new domains
        full_output_file.write_text(json.dumps(current_data), encoding="utf-8")
        domain_enum_file.write_text(json.dumps(sorted(current_domains)), encoding="utf-8")
        print(f"Saved {len(current_domains)} domain(s) to {domain_dir}/\n")
    else:
        print("No new domains since previous scan.\n")


if __name__ == "__main__":
    main()
