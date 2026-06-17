Domain Squatting Scanner Suite
==============================
 
This tool contains various scanners checking for domain squatting threats:
 
    opensquat_scanner.py    queries the openSquat NRD API for newly
                            registered domains matching a KEYWORD
                            (e.g. "company")
    hibs_scanner.py         queries the Have I Been Squatted API for a
                            DOMAIN (e.g. "company.eu")
    dnstwist_scanner.py     generates and resolves permutations of a
                            DOMAIN using dnstwist
 
It follows a strict directory layout and naming convention. Do not rename
or move output files: the timestamps embedded in the filenames drive both
deduplication and the --compare-previous diffing. If you need a file
elsewhere, copy it. Example layout with `company.eu` scanned:
 
    ├── README.txt
    ├── requirements.txt
    ├── run_scanners.sh
    ├── generate_summary.py
    ├── dnstwist_scanner
    │   ├── dnstwist_scanner.py
    │   └── output
    │       └── company.eu
    │           ├── company.eu_domain_enum_2026-06-09_13-44-41.json
    │           └── company.eu_full_output_2026-06-09_13-44-41.json
    ├── hibs_scanner
    │   ├── .hibs_api_key
    │   ├── hibs_scanner.py
    │   └── output
    │       └── company.eu
    │           ├── company.eu_domain_enum_2026-06-09_12-18-04.json
    │           ├── company.eu_full_output_2026-06-09_12-18-04.json
    │           └── company.eu_full_output_2026-06-09_13-02-45.json
    └── opensquat_scanner
        ├── .opensquat_api_key
        ├── opensquat_scanner.py
        └── output
            └── company
                ├── company_domain_enum_2026-06-10_07-10-29.json
                └── company_full_output_2026-06-10_07-10-29.json

Note: the openSquat output directory is named after the KEYWORD, not the
domain, because openSquat scans keywords. The dnstwist and HIBS output
directories are named after the full domain.

Each scan writes two files:

    *_full_output_*     the complete raw scan dump, kept as an archive
    *_domain_enum_*     the extracted domain list; this is what
                        generate_summary.py and --compare-previous read


API keys
--------
Place each API key as a single line of plain text in a hidden file next
to its scanner, with exactly these names:

    hibs_scanner/.hibs_api_key
    opensquat_scanner/.opensquat_api_key

Restrict permissions: `chmod 600` on both. dnstwist needs no key.


Retention
---------
Output files are never deleted automatically; it is recommended to keep
them for future reference. At minimum, keep 2 weeks of history: opensquat
runs daily and its summaries feed weekly reports, so the comparison needs
the previous period's domain_enum files to diff against.

The HIBS scanner sometimes saves duplicate full outputs without a new
enum file (it is by far the largest amount of data). The enum file is
deduplicated by filename date, but the full dump is kept so in case there 
are new details those can be examined. Review the duplicate and delete 
it if it adds nothing.


Install
-------
Requires Python 3.10+ and uv.

    uv venv
    source .venv/bin/activate
    uv pip install -r requirements.txt

Remember to activate the virtual environment when using the tools.


Daily scan (keyword-based)
--------------------------
    python3 opensquat_scanner.py company

To run it from cron, call the venv's interpreter directly so the
dependencies are available without activation:

    # m h dom mon dow (example: every day at 7:05)
    5 7 * * *  cd /path/to/scanners && .venv/bin/python3 squatting_scanners/opensquat_scanner/opensquat_scanner.py company

The current API plan is too limited to reliably run multiple keyword
scans per day. If needed, it can be attempted with several cron jobs
spaced apart, one per keyword.


Weekly scans (domain-based)
---------------------------
hibs_scanner.py and dnstwist_scanner.py are wrapped by run_scanners.sh.
Run it when you need a new report:

    setsid ./run_scanners.sh company.eu > run_scanners.out 2>&1 &

or install run_scanners.sh as a cron job running less often (e.g.
weekly), again using .venv/bin/python3 inside the script or activating
the venv first.

The run_scanners.sh script writes verbose errors and status updates inside:
    run_scanners.out
    run_logs/*
These are solely for debugging, feel free to delete them after a successful run.

Note: the script may cause "Job 1, 'setsid ./run_scanners.sh hcsec.…' has ended"
to be printed on stdout. That doesn't mean it has finished. To check progress do:

    cat run_scanners.out
    [18:26:59] starting scanners (parallel)...
    [+1m00s] still running...
    [+2m00s] still running...
    [+2m12s] all complete — logs in /path/to/squatting_scanners/run_logs


Summary
-------
    python3 generate_summary.py company.eu [keyword] [--compare-previous]

The domain (`company.eu`) is mandatory, as it is the one the summary will
be generated for.

The keyword is optional because one domain can map to several keywords.
For example, for the domain glass-security, keywords may be "glass" or
"security", so you may want to run the summary script once per keyword to
pick up the matching openSquat output directories.

The `--compare-previous` flag diffs the newest domain_enum files against
the previous ones and shows the changes:

    python3 generate_summary.py hcsec.eu hcsec --compare-previous
    + ccsec.uk                  [HIBS]
    + csec.eu                   [DNStwist, HIBS]
    + dtsec.ru                  [OpenSquat]
    ... <snip> ...
    - hcsea.com                 [HIBS]
    - hmsec.de                  [HIBS]
    ~ csec.eu                   [DNStwist, HIBS] (+DNStwist)
    ~ hsec.eu                   [DNStwist, HIBS] (+DNStwist)
 
    +   new domain since the previous scan
    -   domain no longer reported
    ~   domain gained or lost a source; the change is in parentheses
    []  sources that currently have data on the domain
