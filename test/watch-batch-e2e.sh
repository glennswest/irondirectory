#!/usr/bin/env bash
# A subtree watch returns every event of a multi-event response (finding f7d57dd68673, #81).
#
#   test/watch-batch-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION)
# and runs crates/store/tests/watch_batch.rs against it: a watch on a
# subtree, then one etcd transaction writing 25 entries under it (one
# revision: its events come in one WatchResponse), one deleting them, and a
# lone put. Every put, every delete and the lone put must come out of
# next_entry_change, the helper iron-gc's live replica reads. It used to
# return the first event of each response and drop the rest.
# Needs curl.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/watchbatch.XXXX")
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

IRON_STORE_TEST_ENDPOINT=http://127.0.0.1:$((P + 1)) cargo test --locked -p iron-store --test watch_batch -- --ignored --nocapture \
  > "$W/test.out" 2>&1 || { grep -vE "^\s+(Compiling|Downloaded|Downloading)" "$W/test.out" | tail -40; fail "watch_batch"; }
grep -E "txn:|test result" "$W/test.out"
echo "PASS: every event of a multi-event watch response is returned, fastetcd $FV (f7d57dd68673)"
