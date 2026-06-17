#!/bin/sh
#
# Container entrypoint. Starts the weekly puredns cron (via supercronic, which
# runs fine as a non-root user and forwards job output to stdout) and then the
# gunicorn webserver in the foreground.
#
# Disable the in-container cron with ENABLE_CRON=false if you would rather drive
# puredns from the host (host cron, or `docker exec ... run_puredns.sh`).

set -e

if [ "${ENABLE_CRON:-true}" = "true" ]; then
  echo "entrypoint: starting supercronic for /app/crontab"
  supercronic /app/crontab &
fi

echo "entrypoint: starting gunicorn on 0.0.0.0:8001"
# One worker: the job registry is in-process memory (see webserver.py). Threads
# provide concurrency for the I/O-light handlers and the background subfinder
# jobs.
exec gunicorn \
  --workers 1 \
  --threads "${GUNICORN_THREADS:-8}" \
  --timeout "${GUNICORN_TIMEOUT:-120}" \
  --bind 0.0.0.0:8001 \
  webserver:app
