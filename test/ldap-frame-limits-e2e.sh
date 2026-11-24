#!/usr/bin/env bash
# iron-ldapd's frame limits (finding 6bbcf7596b07, #78), from raw sockets.
#
#   test/ldap-frame-limits-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION)
# and iron-ldapd, then test/ldap_frame_limits.py:
#  1. a 2 GiB declared length, then a stream of bytes: the server closes the
#     connection before 64 MiB have been sent;
#  2. 10 MiB + 1 declared: closed before the payload (the cap is 10 MiB);
#  3. a 9-octet BER length (2^64) is refused, not wrapped to a small length;
#  4. twenty concurrent oversize senders: iron-ldapd's RSS grows < 64 MiB;
#  5. a legal ~1 MiB search is still read and answered;
#  6. a frame started and left incomplete is dropped after ~120 s, while a
#     connection that sent nothing stays open and answers afterwards;
# and finally ldapsearch of the rootDSE still works.
# Needs curl, ldapsearch, python3.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/framee2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, LDAP P+3, health P+4, metrics P+5
PID_ID="fl$(date +%s)"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; tail -25 "$f"; done; exit 1; }
for t in curl ldapsearch python3; do command -v "$t" >/dev/null || fail "$t is not installed"; done

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done

cargo build --locked --release -p iron-ldap --bin iron-ldapd > "$W/cargo.log" 2>&1 || { tail -30 "$W/cargo.log"; fail "building iron-ldapd"; }
B=${CARGO_TARGET_DIR:-target}/release
IRON_LDAP_FASTETCD_ENDPOINT=http://127.0.0.1:$((P + 1)) IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN="dc=$PID_ID,dc=lo" \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 3)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 4)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & LDAPD=$!; pids+=($LDAPD)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 4))/health" >/dev/null && break; sleep 0.5; done

python3 -I "$PWD/test/ldap_frame_limits.py" 127.0.0.1 $((P + 3)) $LDAPD fast || fail "frame limits"
python3 -I "$PWD/test/ldap_frame_limits.py" 127.0.0.1 $((P + 3)) $LDAPD slow || fail "frame timeout"
kill -0 $LDAPD || fail "iron-ldapd died"
ldapsearch -x -LLL -H "ldap://127.0.0.1:$((P + 3))" -b "" -s base supportedLDAPVersion | grep -q "supportedLDAPVersion: 3" || fail "rootDSE after the checks"
echo "== iron-ldapd alive; rootDSE answers"
echo "PASS: LDAP frame limits: 10 MiB cap before buffering, 120 s per incomplete frame, idle connections kept (6bbcf7596b07)"
