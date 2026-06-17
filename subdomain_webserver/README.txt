==============================================================================
subdomain-api  -  subfinder + puredns behind an HTTP API (for n8n)
==============================================================================

A small Flask/gunicorn webserver, containerised together with the recon tools
it drives. Built as a sibling to the squat-scan API, but this image actually
ships the Go/C binaries it needs (subfinder, puredns, massdns), so there is no
host tool install.

  - subfinder runs on demand via the API (passive subdomain discovery).
  - puredns runs weekly via cron (DNS bruteforce); the API only summarises its
    results.


------------------------------------------------------------------------------
ENDPOINTS  (all under /api/, all require the X-API-Key header except /health)
------------------------------------------------------------------------------

  POST /api/subfinder?domain=<d>      Start a subfinder job. Returns 202 with
                                      {"job_id": "...", "status": "pending"}.

  GET  /api/subfinder/<job_id>        View a job. Returns status; once
                                      "completed" the body also has
                                      "count" and "subdomains": [...].

  GET  /api/puredns/summary?domain=<d>
                                      Summarise the latest weekly puredns run
                                      for <domain> and diff it against the
                                      previous run (new / removed subdomains).
                                      JSON body. 404 if no runs exist yet.

  GET  /api/health                    Unauthenticated liveness probe.

domain is validated against a strict regex before it reaches any subprocess,
and tools are always invoked with argv lists (never a shell).


------------------------------------------------------------------------------
LAYOUT
------------------------------------------------------------------------------

  README.txt
  requirements.txt              Flask + gunicorn (the tools are Go/C binaries)
  webserver.py                  the API
  generate_summary.py           puredns/subfinder run diff (used by the summary endpoint)
  run_puredns.sh                weekly puredns wrapper (writes JSON artifacts)
  entrypoint.sh                 starts supercronic (cron) + gunicorn
  crontab                       weekly puredns schedule
  Dockerfile                    multi-stage build of all binaries + runtime
  .dockerignore                 keeps secrets/data out of image layers
  docker-compose.yml            one-command deploy (mounts + env + ports)

Timestamp format is %Y-%m-%d_%H-%M-%S, e.g.
  output/puredns/company.eu/company.eu_puredns_2026-06-12_13-44-41.json


------------------------------------------------------------------------------
RUNTIME DATA  (you provide these; they are bind-mounted, never baked in)
------------------------------------------------------------------------------

Five paths are mounted into the container at /app. They are excluded from the
image via .dockerignore so no secret or scan history ends up in a layer:

  provider-config.yaml   subfinder source API keys (SECRET). Optional: subfinder
                         runs without it, just with fewer sources.
  resolvers.txt          public DNS resolvers for puredns (one IP per line).
  wordlist.txt           subdomain wordlist for puredns bruteforce
                         (e.g. jhaddix all.txt).
  domains.txt            root domains the weekly puredns cron bruteforces.
  output/                results (read by the summary endpoint; written by both
                         the API and the weekly cron). Persists across rebuilds.


------------------------------------------------------------------------------
PREREQUISITES
------------------------------------------------------------------------------

Docker, plus `setfacl` (acl package) on the host. The build downloads Go
modules and clones massdns, so the build host needs outbound internet. Once
built, the container itself only needs network access to do DNS / talk to
subfinder's data sources.


------------------------------------------------------------------------------
1. PROVIDE THE DATA / CONFIG FILES
------------------------------------------------------------------------------

From the project directory:

    # for example, supply a wordlist:
    curl -L -o wordlist.txt https://raw.githubusercontent.com/<your-wordlist-source>

A good resolver list: https://github.com/trickest/resolvers  (raw resolvers.txt).


------------------------------------------------------------------------------
2. ACLs SO THE CONTAINER (uid 10001) CAN READ CONFIG AND WRITE RESULTS
------------------------------------------------------------------------------

The container runs as a pinned, unprivileged uid (10001). Bind mounts keep host
ownership, so grant that uid exactly what it needs and nothing more.

    # project directory on the host
    APP=/srv/subdomain_webserver        # adjust to wherever you cloned this

    # read-only config the container needs to read
    for f in provider-config.yaml resolvers.txt wordlist.txt domains.txt; do
      sudo setfacl -m u:10001:r "$APP/$f"
    done

    # results dir: read + write, with default ACLs so new files/dirs inherit
    # (run_puredns.sh creates output/puredns/<domain>/ on the fly)
    sudo mkdir -p "$APP/output/subfinder" "$APP/output/puredns"
    sudo setfacl -R  -m u:10001:rwX "$APP/output"
    sudo setfacl -R -d -m u:10001:rwX "$APP/output"

    # the container also needs to traverse into the project dir to reach output/
    sudo setfacl -m u:10001:rX "$APP"


------------------------------------------------------------------------------
3. SET THE API KEY
------------------------------------------------------------------------------

The webserver refuses to start without WEBSERVER_API_KEY (it is never baked into
the image). Generate one and put it in a .env file next to docker-compose.yml:

    echo "WEBSERVER_API_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" > .env

(.env is read automatically by docker compose. Keep it out of version control.)


------------------------------------------------------------------------------
4. BUILD AND RUN
------------------------------------------------------------------------------

Easiest (docker compose handles the five mounts, env, ports, --init):

    docker compose up -d --build
    docker compose logs -f

Or the plain docker form (mirrors the previous tool's run command):

    docker build -t subdomain-api .

    docker run -d \
      --name subdomain-api \
      --restart unless-stopped \
      --init \
      -e WEBSERVER_API_KEY="$(grep -m1 WEBSERVER_API_KEY .env | cut -d= -f2-)" \
      -p 127.0.0.1:8001:8001 \
      -p 172.30.0.13:8001:8001 \
      -v "$PWD/output":/app/output \
      -v "$PWD/provider-config.yaml":/app/provider-config.yaml:ro \
      -v "$PWD/resolvers.txt":/app/resolvers.txt:ro \
      -v "$PWD/wordlist.txt":/app/wordlist.txt:ro \
      -v "$PWD/domains.txt":/app/domains.txt:ro \
      subdomain-api

The 172.30.0.13 mapping is the internal interface for n8n; adjust or drop it to
match your host. Keep Docker itself running across reboots:

    sudo systemctl enable --now docker


------------------------------------------------------------------------------
5. USE THE API
------------------------------------------------------------------------------

    KEY=$(grep -m1 WEBSERVER_API_KEY .env | cut -d= -f2-)

    # health
    curl -s http://127.0.0.1:8001/api/health

    # start a subfinder job
    JOB=$(curl -s -H "X-API-Key: $KEY" \
      -X POST "http://127.0.0.1:8001/api/subfinder?domain=company.eu" \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['job_id'])")

    # view it (poll until status == completed)
    curl -s -H "X-API-Key: $KEY" "http://127.0.0.1:8001/api/subfinder/$JOB"

    # summarise the latest weekly puredns run for a domain
    curl -s -H "X-API-Key: $KEY" \
      "http://127.0.0.1:8001/api/puredns/summary?domain=company.eu"

In n8n: an HTTP Request node to POST /api/subfinder, then a polling loop (Wait +
HTTP Request to GET /api/subfinder/{{job_id}}) until status is "completed". The
puredns summary is a single GET. Add the X-API-Key header to every request.


------------------------------------------------------------------------------
6. THE WEEKLY puredns CRON
------------------------------------------------------------------------------

By default the cron runs INSIDE the container. supercronic (a container-friendly
cron that runs as the non-root user and logs to stdout) reads /app/crontab and
runs run_puredns.sh on the schedule there (Sunday 07:05 by default). run_puredns
iterates domains.txt and, per domain, runs:

  puredns bruteforce <wordlist> <domain> -r resolvers.txt \
      --wildcard-batch 500000 --wildcard-tests 5 \
      --rate-limit-trusted 100 --rate-limit 1000 --write <tmp> --quiet

then wraps puredns' plain domain list into
output/puredns/<domain>/<domain>_puredns_<ts>.json (puredns has no native JSON
output). Tunables (RATE_LIMIT, RATE_LIMIT_TRUSTED, WILDCARD_BATCH,
WILDCARD_TESTS) are environment variables, settable in docker-compose.yml.

Cron uses the container timezone (UTC by default). Set TZ in the environment to
change it. Edit the schedule in crontab; add domains by editing domains.txt
(no rebuild needed, both are in the bind mount / image as appropriate).

Trigger it once by hand to verify:

    docker compose exec subdomain-api /app/run_puredns.sh

Alternative: drive puredns from the HOST instead. Set ENABLE_CRON=false, then
either run the script via `docker compose exec` from a host cron line, e.g.

    5 7 * * 0  docker compose -f /srv/subdomain_webserver/docker-compose.yml exec -T subdomain-api /app/run_puredns.sh >> /srv/subdomain_webserver/cron.log 2>&1

Because output/ is a bind mount, results written either way are visible to the
summary endpoint.


------------------------------------------------------------------------------
NOTES / CAVEATS
------------------------------------------------------------------------------

- Jobs are in-process memory. gunicorn runs ONE worker on purpose (a second
  worker would not see the first's jobs). Concurrency comes from threads. Job
  state is lost on container restart; finished results are on disk under output/.
- subfinder jobs run concurrently (each writes its own timestamped file). A very
  large fan-out can hit source rate limits; that is a tuning concern, not a
  correctness one.
- puredns needs the massdns binary on PATH; the image installs it to
  /usr/local/bin, so this works out of the box.
- Resolver quality matters: bad public resolvers make puredns drop real
  subdomains. Curate resolvers.txt and refresh it periodically.
- Secrets: WEBSERVER_API_KEY comes from the environment; provider-config.yaml is
  bind-mounted. Neither is in any image layer (see .dockerignore).
- Only scan domains you are authorised to test.
