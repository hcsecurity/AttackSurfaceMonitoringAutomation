#!/usr/bin/env bash
#
# Weekly puredns bruteforce for every domain listed in domains.txt.
#
# For each domain it runs:
#   puredns bruteforce <wordlist> <domain> -r <resolvers> \
#       --wildcard-batch N --wildcard-tests N \
#       --rate-limit-trusted N --rate-limit N --write <tmp> --quiet
# then wraps puredns' plain domain list into a self-describing JSON artifact at
#   output/puredns/<domain>/<domain>_puredns_<YYYY-MM-DD_HH-MM-SS>.json
# (puredns has no native JSON output, hence the conversion).
#
# Invoked by supercronic inside the container (see crontab), or run manually /
# from a host cron. Tunables can be overridden via environment variables.

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RESOLVERS="${RESOLVERS:-$APP_DIR/resolvers.txt}"
WORDLIST="${WORDLIST:-$APP_DIR/wordlist.txt}"
DOMAINS_FILE="${DOMAINS_FILE:-$APP_DIR/domains.txt}"
OUTPUT_DIR="${OUTPUT_DIR:-$APP_DIR/output/puredns}"
PUREDNS_BIN="${PUREDNS_BIN:-puredns}"

# puredns tunables (match the reference command; override via env).
# --rate-limit-trusted takes a single integer (queries/sec against the trusted
# resolvers), so it is one value rather than a range.
RATE_LIMIT="${RATE_LIMIT:-1000}"
RATE_LIMIT_TRUSTED="${RATE_LIMIT_TRUSTED:-100}"
WILDCARD_BATCH="${WILDCARD_BATCH:-500000}"
WILDCARD_TESTS="${WILDCARD_TESTS:-5}"

for f in "$RESOLVERS" "$WORDLIST" "$DOMAINS_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "run_puredns: required file not found: $f" >&2
    exit 1
  fi
done

ts="$(date +%Y-%m-%d_%H-%M-%S)"

while IFS= read -r line || [[ -n "$line" ]]; do
  domain="$(echo "$line" | tr -d '[:space:]')"
  # skip blank lines and comments
  [[ -z "$domain" || "$domain" == \#* ]] && continue

  dest_dir="$OUTPUT_DIR/$domain"
  mkdir -p "$dest_dir"
  valid_txt="$(mktemp)"

  echo "run_puredns: bruteforcing $domain"
  # puredns bruteforce expects the wordlist and domain as positional args,
  # in that order.
  "$PUREDNS_BIN" bruteforce "$WORDLIST" "$domain" \
    -r "$RESOLVERS" \
    --wildcard-batch "$WILDCARD_BATCH" \
    --wildcard-tests "$WILDCARD_TESTS" \
    --rate-limit-trusted "$RATE_LIMIT_TRUSTED" \
    --rate-limit "$RATE_LIMIT" \
    --write "$valid_txt" \
    --quiet

  out_json="$dest_dir/${domain}_puredns_${ts}.json"
  python3 - "$domain" "$ts" "$valid_txt" "$out_json" <<'PY'
import json, sys
domain, ts, src, dst = sys.argv[1:5]
with open(src) as fh:
    subs = sorted({ln.strip() for ln in fh if ln.strip()})
with open(dst, "w") as fh:
    json.dump(
        {"domain": domain, "tool": "puredns", "timestamp": ts,
         "count": len(subs), "subdomains": subs},
        fh, indent=2,
    )
print(f"run_puredns: wrote {dst} ({len(subs)} subdomains)")
PY
  rm -f "$valid_txt"
done < "$DOMAINS_FILE"

echo "run_puredns: all domains complete"
