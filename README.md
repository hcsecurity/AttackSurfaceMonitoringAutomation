# Attack Surface Monitoring Automation

Two containerised services that monitor the external attack surface of domains you own, bundled with the recon tools each one drives. Both expose an HTTP API meant to be called by an orchestrator (n8n) on a schedule.

- `squatting_webserver` finds domains impersonating yours: lookalikes, permutations, and newly registered brand matches.
- `subdomain_webserver` discovers your own subdomains: passive enumeration and DNS bruteforce.

Each service is self-contained, runs as its own container, and ships its own `README.txt` with build, configuration, and endpoint detail.

## squatting_webserver

A Flask/gunicorn API over the scanner suite in `squatting_scanners/`. Three scanners, each writing two timestamped JSON files per run (the full raw dump and an extracted domain list; the domain list is what the summary and diffing read):

- `opensquat_scanner.py`: openSquat NRD API, newly registered domains matching a *keyword*. The daily scan.
- `hibs_scanner.py`: Have I Been Squatted API, for a full *domain*.
- `dnstwist_scanner.py`: generates and resolves permutations of a full *domain*. HIBS and dnstwist are the weekly scans, wrapped together by `run_scanners.sh`.
- `generate_summary.py`: aggregates the scanners for a domain. With `--compare-previous` it diffs the latest domain lists against the previous run (domain added, removed, or a change in which scanners report it).

The webserver runs scans as tracked background jobs behind authenticated endpoints; the suite can also be run directly from the shell (see `squatting_scanners/README.txt`).

## subdomain_webserver

A Flask/gunicorn API that ships its own compiled binaries (subfinder, puredns, massdns), so the host installs nothing.

- subfinder runs on demand for passive discovery: POST a domain, poll the job until it completes, read back the subdomain list.
- puredns runs weekly via an in-container cron (`crontab` + `run_puredns.sh`, started by `entrypoint.sh`). The API does not run puredns on demand; it only summarises each run with `generate_summary.py` and diffs it against the previous one (new and removed subdomains).

Deployed via `docker-compose.yml` (mounts, environment, ports).

## Common properties

- Endpoints are authenticated with an `X-API-Key` header; only the health probe is open.
- Domain inputs are validated before reaching a subprocess, and external tools are invoked as argument lists, never through a shell.
- Long-running work is a background job. Job state is in-process memory and is lost on restart.
- Durable results are timestamped JSON under a bind-mounted `output/` directory (not committed to the repo), so history persists across rebuilds and each run can be diffed against the previous one.
- API keys and provider config are bind-mounted or read from the environment, never baked into image layers. Containers run as a pinned, unprivileged uid.
