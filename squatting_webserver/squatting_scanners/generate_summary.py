"""This tool summarizes the latest outputs from the different scanners.

This is the expected layout of the squatting scanner results,
where `company.eu` is on of the domains that were scanned, 
and `comapny` is one of the keywords which were scanned:
    .
    ├── dnstwist_scanner
    │   └── output
    │       └── company.eu
    │           ├── company.eu_domain_enum_2026-06-09_13-44-41.json
    │           └── company.eu_full_output_2026-06-09_13-44-41.json
    ├── hibs_scanner
    │   └── output
    │       └── company.eu
    │           ├── company.eu_domain_enum_2026-06-09_12-18-04.json
    │           ├── company.eu_full_output_2026-06-09_12-18-04.json
    │           └── company.eu_full_output_2026-06-09_13-02-45.json
    └── opensquat_scanner
        └── output
            └── company
                ├── company_domain_enum_2026-06-10_07-10-29.json
                └── company_full_output_2026-06-10_07-10-29.json
"""

import argparse
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
OPENSQUAT_DIR = SCRIPT_DIR / "opensquat_scanner"
DNSTWIST_DIR  = SCRIPT_DIR / "dnstwist_scanner"
HIBS_DIR      = SCRIPT_DIR / "hibs_scanner"
DOMAIN_ENUM_MARKER = "_domain_enum_"
COLUMN_PADDING = 25


def previous_scans(domain_dir: Path, start: int, count: int) -> list[str] | None:
    """Return the <count> most recent domain-enum file domains, if any.
    <start> indicates where it starts from in a sorted directory listing.
    The files should contain: ["domain.1", "domain.2", ...]

    Enum filenames carry a ``YYYY-MM-DD_HH-MM-SS`` timestamp and therefore sort
    chronologically, so the lexicographically-greatest name is the most recent
    run. Unreadable/corrupt files are skipped in favour of the next newest.

    Ensure that this tool hasn't been ran more than often than once a day,
    as it could include multiple files from the same day with the same domains.
    """
    total_domains: set[str] = set()
    candidates = sorted(domain_dir.glob(f"*{DOMAIN_ENUM_MARKER}*.json"), reverse=True)
    for path in candidates[start:count]:
        try:
            domains = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue  # unreadable/corrupt - try the next most recent
        if isinstance(domains, list):
            total_domains.update(domains)
    return list(total_domains)


def previous_scan(domain_dir: Path) -> list[str] | None:
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
            return domains
    return None


def extract_domains(
    found_domains: dict[str, set[str]],
    new_domains: list[str] | None,
    source_name: str,
) -> None:
    for domain in new_domains:
        if domain not in found_domains:
            found_domains[domain] = {source_name}
        else:
            found_domains[domain].add(source_name)


def print_domains(
    domains: dict[str, set[str]],
    show_sources: bool = False,
) -> None:
    print(f"\nFound {len(domains)} unique domains:\n")

    # for aligning domains and sources in 2 columns
    width = max(len(domain) for domain in domains) + 2

    for domain in sorted(domains):
        if show_sources:
            sources = ", ".join(sorted(domains[domain]))
            print(f"  - {domain:<{COLUMN_PADDING}} [{sources}]")
        else:
            print(f"  - {domain}")


def compare_and_print_changes(
    old_domains: dict[str, set[str]],
    new_domains: dict[str, set[str]],
) -> None:
    """Compare a previous scan against the current one and print the delta.

    Both dicts map a domain to the set of scanners that flagged it, so the
    scanner set is printed beside each domain to show cross-scanner overlap.

      `+`  domain seen now but not in the previous scan
      `-`  domain seen previously but not now
      `~`  domain seen in both, but by a different set of scanners
    """
    added = new_domains.keys() - old_domains.keys()
    removed = old_domains.keys() - new_domains.keys()
    common = old_domains.keys() & new_domains.keys()

    for domain in sorted(added):
        scanners = ", ".join(sorted(new_domains[domain]))
        print(f"  + {domain:<{COLUMN_PADDING}} [{scanners}]")

    for domain in sorted(removed):
        scanners = ", ".join(sorted(old_domains[domain]))
        print(f"  - {domain:<{COLUMN_PADDING}} [{scanners}]")

    for domain in sorted(common):
        old = old_domains[domain]
        new = new_domains[domain]
        if old == new:
            continue
        now = ", ".join(sorted(new))
        changes = []
        if new - old:
            changes.append("+" + ", ".join(sorted(new - old)))
        if old - new:
            changes.append("-" + ", ".join(sorted(old - new)))
        print(f"  ~ {domain:<{COLUMN_PADDING}} [{now}] ({'; '.join(changes)})")


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
    parser.add_argument(
        "keyword",
        type=str,
        nargs="?", # not required
        default=None,
        help=(
            "Target domain keyword to scan (e.g. google, github).\n"
            "If omitted, OpenSquat results will not be parsed.\n"
            "Do not include the TLD."
        )
    )
    parser.add_argument(
        "--compare-previous",
        action="store_true", # true on existing
        help="Compare current run with previous output."
    )

    args = parser.parse_args()
    keyword = args.keyword
    domain  = args.domain

    found_domains: dict[str: set(str)]= dict()

    # OpenSquat
    if keyword:
        target_dir = OPENSQUAT_DIR / "output" / keyword
        # special case for opensquat - compare previous week
        new_domains = previous_scans(target_dir, 0, 7)
        extract_domains(found_domains, new_domains, "OpenSquat")
    # DNStwist
    target_dir = DNSTWIST_DIR / "output" / domain
    new_domains = previous_scans(target_dir, 0 ,1)
    extract_domains(found_domains, new_domains, "DNStwist")
    # Have I Been Squatted 
    target_dir = HIBS_DIR / "output" / domain
    new_domains = previous_scans(target_dir, 0, 1)
    extract_domains(found_domains, new_domains, "HIBS")

    if (args.compare_previous):
        # search for old domains and their entries
        # then compare with the new `found_domains`
        # generate a + and a - section for each scanner
        old_domains: dict[str: set(str)]= dict()
        # OpenSquat
        if keyword:
            target_dir = OPENSQUAT_DIR / "output" / keyword
            # special case for opensquat - compare previous week
            new_domains = previous_scans(target_dir, 7, 14)
            extract_domains(old_domains, new_domains, "OpenSquat")
        # DNStwist
        target_dir = DNSTWIST_DIR / "output" / domain
        new_domains = previous_scans(target_dir, 1 ,2)
        extract_domains(old_domains, new_domains, "DNStwist")
        compare_and_print_changes(old_domains, found_domains)
        # Have I Been Squatted 
        target_dir = HIBS_DIR / "output" / domain
        new_domains = previous_scans(target_dir, 1, 2)
        extract_domains(old_domains, new_domains, "HIBS")

        compare_and_print_changes(old_domains, found_domains)

    else:
        # curently always show sources
        print_domains(found_domains, True)


if __name__ == "__main__":
    main()
