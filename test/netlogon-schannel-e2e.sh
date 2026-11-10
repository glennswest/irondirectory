#!/usr/bin/env bash
# Netlogon secure channel + NetrServerPasswordSet2 (#20), against impacket.
#
#   test/netlogon-schannel-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball,
# FASTETCD_VERSION), provisions a domain with iron-bootstrap, runs
# iron-kdcd and iron-rpcd on high ports, then with impacket
# (test/netlogon_schannel_impacket.py):
#  1. the Zerologon handshake (all-zero challenge and credential) is refused;
#  2. for WS1 at PKT_INTEGRITY and WS2 at PKT_PRIVACY: SamrCreateUser2InDomain
#     creates the computer, iron-rpc-ctl gives it a first secret (the
#     stand-in for SAMR's own password set, see iron-rpc-ctl), a secure
#     channel is set up with it, NetrServerPasswordSet2 is refused on the
#     unauthenticated binding and accepted over the Schannel binding; the
#     server's response signature (and seal) and sequence are checked; a
#     replayed authenticator and an all-zero password buffer are refused;
#  3. the new password works and the old does not, for both NETLOGON
#     (NetrServerAuthenticate3) and Kerberos (kinit WS1$@REALM).
# Needs curl, kinit, python3 (impacket is pip-installed into a venv) and a
# FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/nlse2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5, RPC P+6
PID_ID="nls$(date +%s)"
NETBIOS=$(echo "$PID_ID" | tr a-z A-Z)
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="${NETBIOS}.EXAMPLE.LO"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -v "error_code=25 " | tail -30; done; exit 1; }
for t in curl kinit python3; do command -v "$t" >/dev/null || fail "$t is not installed"; done

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd \
  -p iron-rpc --bin iron-rpcd --bin iron-rpc-ctl 2>&1 | tail -1
B=${CARGO_TARGET_DIR:-target}/release

printf 'AdminPass123!\n' > "$W/password"
export IRON_BOOTSTRAP_FASTETCD_ENDPOINT=$E IRON_BOOTSTRAP_PARTITION_ID=$PID_ID IRON_BOOTSTRAP_BASE_DN=$BASE \
  IRON_BOOTSTRAP_REALM=$REALM IRON_BOOTSTRAP_NETBIOS_NAME=$NETBIOS IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE=$W/password
for attempt in 1 2 3 4 5; do
  $B/iron-bootstrap > "$W/bootstrap.log" 2>&1 & BS=$!; pids+=($BS)
  for _ in $(seq 60); do grep -q "provisioned" "$W/bootstrap.log" && break; kill -0 $BS 2>/dev/null || break; sleep 1; done
  grep -q "provisioned" "$W/bootstrap.log" && break
  [ "$attempt" = 5 ] && fail "iron-bootstrap did not provision"
  sleep 2
done
SID=$(sed 's/\x1b\[[0-9;]*m//g' "$W/bootstrap.log" | grep -o 'domain_sid=S-1-5-21-[0-9-]*' | head -1 | cut -d= -f2)
[ -n "$SID" ] || fail "no domain SID from iron-bootstrap"

IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM \
  IRON_KDC_CONFIG_FASTETCD_ENDPOINT=$E IRON_KDC_CONFIG_PARTITION_ID=${PID_ID}-config IRON_KDC_CONFIG_BASE_DN=cn=configuration,$BASE \
  IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
export IRON_RPC_FASTETCD_ENDPOINT=$E IRON_RPC_PARTITION_ID=$PID_ID IRON_RPC_BASE_DN=$BASE
IRON_RPC_DOMAIN_SID=$SID IRON_RPC_NETBIOS_NAME=$NETBIOS IRON_RPC_DNS_DOMAIN=${PID_ID}.example.lo IRON_RPC_REALM=$REALM \
  IRON_RPC_LISTEN=127.0.0.1:$((P + 6)) $B/iron-rpcd > "$W/rpcd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do grep -q "iron-rpcd listening" "$W/rpcd.log" && break; sleep 0.5; done
grep -q "iron-rpcd listening" "$W/rpcd.log" || fail "iron-rpcd did not start"
echo "== domain $NETBIOS ($SID), realm $REALM; iron-kdcd :$((P + 3)), iron-rpcd :$((P + 6))"

python3 -m venv "$W/venv" && "$W/venv/bin/pip" install -q impacket==0.13.1 > "$W/pip.out" 2>&1 || { tail -5 "$W/pip.out"; fail "pip install impacket"; }
# impacket runs without our FIPS OPENSSL_CONF (that is for the daemons).
imp() { env -u OPENSSL_CONF NETBIOS=$NETBIOS "$W/venv/bin/python" -I "$PWD/test/netlogon_schannel_impacket.py" $((P + 6)) "$@"; }

cat > "$W/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    udp_preference_limit = 1
[realms]
    $REALM = {
        kdc = 127.0.0.1:$((P + 3))
    }
EOF
export KRB5_CONFIG=$W/krb5.conf KRB5CCNAME=FILE:$W/cc
can_kinit() { : > "$W/trace.log"; echo "$2" | env -u OPENSSL_CONF KRB5_TRACE="$W/trace.log" kinit "$1@$REALM" > "$W/kinit.out" 2>&1; }
kinit_fail() { cat "$W/kinit.out"; tail -25 "$W/trace.log"; sed 's/\x1b\[[0-9;]*m//g' "$W/kdcd.log" | tail -10; fail "$@"; }

imp zerologon WS0 || fail "zerologon"

for pair in WS1:integrity WS2:privacy; do
  C=${pair%%:*} LEVEL=${pair#*:}
  OLD="Initial-${C}-Pass1!" NEW="Joined-${C}-$(date +%s)-xyz!"
  echo "== $C at PKT_${LEVEL^^}"
  imp create "$C" || fail "create $C"
  $B/iron-rpc-ctl set-computer-secret "$C\$" "$OLD" > /dev/null || fail "iron-rpc-ctl set-computer-secret $C\$"
  imp setpw "$C" "$OLD" "$NEW" "$LEVEL" || fail "setpw $C $LEVEL"
  imp auth "$C" "$NEW" || fail "NETLOGON with $C's new password"
  if imp auth "$C" "$OLD" > /dev/null 2>&1; then fail "NETLOGON still accepts $C's old password"; fi
  echo "ok: NetrServerAuthenticate3 refuses $C's old password"
  can_kinit "$C\$" "$NEW" || kinit_fail "kinit $C\$ with the password NetrServerPasswordSet2 set"
  echo "ok: kinit $C\$@$REALM with the new password"
done

sed 's/\x1b\[[0-9;]*m//g' "$W/rpcd.log" | grep -E "NetrServerPasswordSet2|denied|refused" | sed -E 's/^[^ ]+ +//' | head -20
echo "PASS: Netlogon secure channel (PKT_INTEGRITY and PKT_PRIVACY) + NetrServerPasswordSet2 against impacket"
