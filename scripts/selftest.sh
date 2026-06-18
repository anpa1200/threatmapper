#!/usr/bin/env sh
set -eu

BASE_URL="${ADVERSARYGRAPH_URL:-http://localhost:8000}"
MAX_WAIT_SECONDS="${SELFTEST_TIMEOUT:-120}"
SLEEP_SECONDS="${SELFTEST_INTERVAL:-3}"

echo "AdversaryGraph self-test: waiting for ${BASE_URL}/api/system/selftest"

elapsed=0
while [ "$elapsed" -le "$MAX_WAIT_SECONDS" ]; do
  if response="$(curl -fsS "${BASE_URL}/api/system/selftest" 2>/tmp/adversarygraph-selftest.err)"; then
    printf '%s\n' "$response"
    status="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","error"))')"
    if [ "$status" = "ok" ]; then
      echo "AdversaryGraph self-test passed."
      exit 0
    fi
    echo "AdversaryGraph self-test returned status=${status}."
    exit 1
  fi

  err="$(cat /tmp/adversarygraph-selftest.err 2>/dev/null || true)"
  echo "Self-test not ready after ${elapsed}s: ${err:-connection failed}"
  sleep "$SLEEP_SECONDS"
  elapsed=$((elapsed + SLEEP_SECONDS))
done

echo "AdversaryGraph self-test timed out after ${MAX_WAIT_SECONDS}s." >&2
exit 1
