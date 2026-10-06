#!/usr/bin/env bash
# Concurrent domain joins against a real three-member fastetcd (#24).
#
#   FASTETCD_VERSION=1.2.0 COUNT=25 test/rpc-concurrency-e2e.sh
#
# Starts a throwaway three-member fastetcd from its release tarball, runs
# iron-bootstrap, iron-kdcd and iron-rpcd against member 1, and runs
# `iron-simulate join $COUNT` with the harness's own store connection on
# member 2 -- the shape of the scale run that found #24, where every
# process reached `etcd.g8.lo` (three A records) on whichever member DNS
# gave it. Passes only if every join succeeds. Needs curl and a FIPS
# OPENSSL_CONF (the checked-in dev one by default). Ports are high, no root.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
COUNT=${COUNT:-25}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/rpce2e.XXXX")
P=$((20000 + RANDOM % 20000 / 10 * 10)) # port base; member i: client P+i, peer P+3+i, metrics P+6+i
PID_ID="rpc$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; grep -v "error_code=25 " "$f" | tail -20; done; exit 1; }

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
FE=$W/fastetcd-v$FV-x86_64-linux/fastetcd
cluster=""
for i in 1 2 3; do cluster+="${cluster:+,}n$i=http://127.0.0.1:$((P + 3 + i))"; done
for i in 1 2 3; do
  "$FE" --name "n$i" --data-dir "$W/data$i" \
    --listen-client-urls "http://127.0.0.1:$((P + i))" --advertise-client-urls "http://127.0.0.1:$((P + i))" \
    --listen-peer-urls "http://127.0.0.1:$((P + 3 + i))" --initial-advertise-peer-urls "http://127.0.0.1:$((P + 3 + i))" \
    --listen-metrics-url "127.0.0.1:$((P + 6 + i))" \
    --initial-cluster "$cluster" --initial-cluster-token "$PID_ID" > "$W/fastetcd$i.log" 2>&1 & pids+=($!)
done
for i in 1 2 3; do
  for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + i))/health" >/dev/null && break; sleep 0.2; done
  curl -sf "http://127.0.0.1:$((P + i))/health" >/dev/null || fail "fastetcd member $i not healthy"
done
echo "== fastetcd $("$FE" --version 2>&1 | head -1), 3 members on 127.0.0.1:$((P + 1))-$((P + 3))"

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd \
  -p iron-rpc --bin iron-rpcd -p iron-simulate --bin iron-simulate 2>&1 | tail -2
B=${CARGO_TARGET_DIR:-target}/release
E1=http://127.0.0.1:$((P + 1))
E2=http://127.0.0.1:$((P + 2))

printf 'TestPass123!\n' > "$W/password"
export IRON_BOOTSTRAP_FASTETCD_ENDPOINT=$E1 IRON_BOOTSTRAP_PARTITION_ID=$PID_ID IRON_BOOTSTRAP_BASE_DN=$BASE \
  IRON_BOOTSTRAP_REALM=$REALM IRON_BOOTSTRAP_NETBIOS_NAME=$(echo "$PID_ID" | tr a-z A-Z) \
  IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE=$W/password
# /health answers before the first leader takes writes, so a first write
# can be refused (UNAVAILABLE); a pod would be restarted, so retry the same.
for attempt in 1 2 3 4 5; do
  $B/iron-bootstrap > "$W/bootstrap.log" 2>&1 & BS=$!; pids+=($BS)
  for _ in $(seq 60); do grep -q "provisioned" "$W/bootstrap.log" && break; kill -0 $BS 2>/dev/null || break; sleep 1; done
  grep -q "provisioned" "$W/bootstrap.log" && break
  echo "== iron-bootstrap attempt $attempt: $(tail -1 "$W/bootstrap.log" | cut -c1-200)"
  [ "$attempt" = 5 ] && fail "iron-bootstrap did not provision"
  sleep 2
done
SID=$(sed 's/\x1b\[[0-9;]*m//g' "$W/bootstrap.log" | grep -o 'domain_sid=S-1-5-21-[0-9-]*' | head -1 | cut -d= -f2)
[ -n "$SID" ] || fail "no domain SID from iron-bootstrap"
echo "== provisioned $PID_ID ($SID)"

# The forest registry gives the KDC the domain SID; without it tickets carry no PAC.
IRON_KDC_FASTETCD_ENDPOINT=$E1 IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM \
  IRON_KDC_CONFIG_FASTETCD_ENDPOINT=$E1 IRON_KDC_CONFIG_PARTITION_ID=${PID_ID}-config IRON_KDC_CONFIG_BASE_DN=cn=configuration,$BASE \
  IRON_KDC_LISTEN=127.0.0.1:$((P + 10)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
IRON_RPC_FASTETCD_ENDPOINT=$E1 IRON_RPC_PARTITION_ID=$PID_ID IRON_RPC_BASE_DN=$BASE \
  IRON_RPC_DOMAIN_SID=$SID IRON_RPC_NETBIOS_NAME=$(echo "$PID_ID" | tr a-z A-Z) IRON_RPC_DNS_DOMAIN=${PID_ID}.example.lo \
  IRON_RPC_LISTEN=127.0.0.1:$((P + 11)) $B/iron-rpcd > "$W/rpcd.log" 2>&1 & pids+=($!)
sleep 2

set +e
IRON_SIM_RPC_ADDR=127.0.0.1:$((P + 11)) IRON_SIM_KDC_ADDR=127.0.0.1:$((P + 10)) IRON_SIM_PARTITION_ID=$PID_ID \
  IRON_SIM_BASE_DN=$BASE IRON_SIM_REALM=$REALM IRON_SIM_FASTETCD_ENDPOINT=$E2 \
  IRON_SIM_SERVICE_PRINCIPAL=host/sim.${PID_ID}.example.lo $B/iron-simulate join "$COUNT" SIMPC > "$W/simulate.out" 2>&1
rc=$?
set -e
grep -E '^FAIL' "$W/simulate.out" | sed 's/SIMPC[0-9]*\$/SIMPC*/' | sort | uniq -c || true
tail -1 "$W/simulate.out"
# What the daemons said about it (iron-kdcd logs every KRB-ERROR; 25,
# PREAUTH_REQUIRED, is the normal first round of every AS exchange).
for d in rpcd kdcd; do
  echo "-- iron-$d warnings and errors:"
  sed 's/\x1b\[[0-9;]*m//g' "$W/$d.log" | grep -E 'WARN|ERROR|KRB-ERROR' | grep -v 'error_code=25 ' |
    sed -E 's/^[^ ]+ +//; s/SIMPC[0-9]*\$/SIMPC*/g' | sort | uniq -c | head -20 || true
done
[ "$rc" -eq 0 ] || fail "iron-simulate join $COUNT on fastetcd $FV: not every join succeeded"
echo "PASS: $COUNT/$COUNT concurrent joins on fastetcd $FV"
