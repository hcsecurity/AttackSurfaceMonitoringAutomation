#!/usr/bin/env bash

# usage: setsid ./run_scanners.sh company.com > run_scanners.out 2>&1 &

set -uo pipefail
# Safety flags:
#   -u  = error out if you use a variable that was never set (catches typos)
#   -o pipefail = if any command in a pipe (a | b) fails, the whole pipe fails

# Require exactly one argument: the domain to scan. Both scanners take it as
# their first (positional) argument, e.g. dnstwist_scanner.py company.com
if [ "$#" -ne 1 ]; then
    echo "usage: $0 <domain>" >&2 # >&2 = print the error to stderr, not stdout
    exit 2
fi
DOMAIN="$1"

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGDIR="$BASE/run_logs"
mkdir -p "$LOGDIR"
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
START=$(date +%s)

# A helper "function" that prints how long we've been running, like "3m07s".
elapsed() {
    local s=$(( $(date +%s) - START ))   # seconds elapsed
    printf '%dm%02ds' $(( s / 60 )) $(( s % 60 ))
}

# A helper that runs ONE scanner: cd into its folder, run its python script,
# capture all output to a log file, and save the exit code to a file.
run_scanner() {
    local dir="$1" script="$2"   # $1 and $2 are the two arguments passed in
    ( cd "$BASE/$dir" && python3 "$script" "$DOMAIN" ) \
        > "$LOGDIR/${dir}_${STAMP}.log" 2>&1
    #   ( ... )   = run in a subshell, so the "cd" doesn't affect the rest of the script
    #   2>&1      = also send error output (stderr) into that same log file
    echo "$?" > "$LOGDIR/${dir}_${STAMP}.exit"
}

echo "[$(date '+%H:%M:%S')] starting scanners (parallel)..."

# Heartbeat: a background loop that prints elapsed time once a minute, so if you
# 'tail' the log you can see the run is alive and how long it's been going.
( while true; do sleep 60; echo "[+$(elapsed)] still running..."; done ) &
HEARTBEAT=$! # $! = process ID of that background loop
trap 'kill "$HEARTBEAT" 2>/dev/null' EXIT
# trap '...' EXIT = run this command whenever the script exits. 
# Here it kills the heartbeat loop so it doesn't linger forever.

# background so they execute in parallel; $! captures each one's process ID.
# (opensquat is intentionally NOT run here - it runs separately on its own cron.)
run_scanner dnstwist_scanner  dnstwist_scanner.py  & p1=$!
run_scanner hibs_scanner      hibs_scanner.py      & p2=$!
wait "$p1" "$p2"
# wait <pids> = pause here until those three specific processes finish.
# dont wait on the infinite heartbeat loop (a bare 'wait' would hang forever).

# Now check whether any scanner failed.
failed=()
for d in dnstwist_scanner hibs_scanner; do
    code="$(cat "$LOGDIR/${d}_${STAMP}.exit" 2>/dev/null || echo 1)"
    #   read the saved exit code; if the file is missing, assume 1 (failure)
    [ "$code" != "0" ] && failed+=("$d (exit $code)")
    #   if the code isn't 0, append a description to the 'failed' array
done

# If anything failed, report it.
if [ "${#failed[@]}" -ne 0 ]; then
    #   ${#failed[@]} = number of items in the 'failed' array
    echo "[+$(elapsed)] FAILED: ${failed[*]} — see $LOGDIR"
    exit 1
fi

echo "[+$(elapsed)] all complete — logs in $LOGDIR"
