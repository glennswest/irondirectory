#!/usr/bin/env bash
# Concurrent writers keep secondary indexes consistent (finding e925e45000f8, #80).
#
#   test/index-race-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION)
# and runs crates/store/tests/index_race.rs against it: 16 writers, each with
# its own etcd client (as separate daemons), storm one DN with puts of
# distinct indexed values, then puts racing deletes over 5 trials. Afterwards
# the index must name the DN under exactly the final entry's value, or under
# nothing when the entry is gone. Unguarded read-then-write left stale index
# entries behind.
# Needs curl.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/idxrace.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, metrics P+5
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; tail -20 "$W/fastetcd.log"; exit 1; }
command -v curl >/dev/null || fail "curl is not installed"

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done

IRON_STORE_TEST_ENDPOINT=http://127.0.0.1:$((P + 1)) cargo test --locked -p iron-store --test index_race -- --ignored --nocapture \
  > "$W/test.out" 2>&1 || { grep -vE "^\s+(Compiling|Downloaded|Downloading)" "$W/test.out" | tail -40; fail "index_race"; }
grep -E "puts by|^trial|test result" "$W/test.out"
echo "PASS: concurrent puts and deletes leave the secondary index matching the entry, fastetcd $FV (e925e45000f8)"
