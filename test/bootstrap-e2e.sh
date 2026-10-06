#!/usr/bin/env bash
# End-to-end check of iron-bootstrap (#25) against real daemons: what a
# member pod does, without the pod. Needs a reachable fastetcd, a FIPS
# OPENSSL_CONF, ldapwhoami (openldap-clients) and kinit (krb5-workstation).
#
#   ENDPOINT=http://etcd.g8.lo:2379 test/bootstrap-e2e.sh
#
# Runs from a workspace checkout: builds iron-ldapd, iron-kdcd and
# iron-bootstrap, provisions a fresh partition, then checks
#  1. ldapwhoami -D cn=administrator,<base> -w <pw> and kinit administrator@REALM;
#  2. a second bootstrap run ("pod restart") with a different password file
#     creates nothing, and the original password still works (the new one
#     does not);
#  3. iron-bootstrap stays resident, and exits 0 on SIGTERM.
# Ports are high (no root): LDAP 13389, health 18080, KDC 13088.
set -euo pipefail

ENDPOINT=${ENDPOINT:-http://etcd.g8.lo:2379}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
W=$(mktemp -d "${TMPDIR:-$PWD/tmp}/bse2e.XXXX" 2>/dev/null || { mkdir -p "$PWD/tmp"; mktemp -d "$PWD/tmp/bse2e.XXXX"; })
PID_ID="e2e$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
PW='TestPass123!'
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; tail -20 "$f"; done; exit 1; }

for t in ldapwhoami kinit; do command -v "$t" >/dev/null || fail "$t is not installed"; done

cargo build --locked --release -p iron-ldap --bin iron-ldapd -p iron-kdc --bin iron-kdcd -p iron-bootstrap --bin iron-bootstrap 2>&1 | tail -2
B=${CARGO_TARGET_DIR:-target}/release

printf '%s\n' "$PW" > "$W/password"
export IRON_BOOTSTRAP_FASTETCD_ENDPOINT=$ENDPOINT IRON_BOOTSTRAP_PARTITION_ID=$PID_ID IRON_BOOTSTRAP_BASE_DN=$BASE \
  IRON_BOOTSTRAP_REALM=$REALM IRON_BOOTSTRAP_NETBIOS_NAME=$(echo "$PID_ID" | tr a-z A-Z) \
  IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE=$W/password

IRON_LDAP_FASTETCD_ENDPOINT=$ENDPOINT IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_LISTEN=127.0.0.1:13389 IRON_LDAP_HEALTH_LISTEN=127.0.0.1:18080 $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
IRON_KDC_FASTETCD_ENDPOINT=$ENDPOINT IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM \
  IRON_KDC_LISTEN=127.0.0.1:13088 IRON_KDC_KPASSWD_LISTEN=127.0.0.1:13464 $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
$B/iron-bootstrap > "$W/bootstrap1.log" 2>&1 & BS=$!; pids+=($BS)

for i in $(seq 60); do grep -q "provisioned" "$W/bootstrap1.log" && break; kill -0 $BS 2>/dev/null || fail "iron-bootstrap exited"; sleep 1; done
grep -q "provisioned" "$W/bootstrap1.log" || fail "iron-bootstrap did not provision in 60s"
echo "== first run:"; grep -o 'created=.*' "$W/bootstrap1.log"
sleep 2; kill -0 $BS 2>/dev/null || fail "iron-bootstrap did not stay resident"
echo "== still resident after provisioning"

cat > "$W/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    udp_preference_limit = 1
[realms]
    $REALM = {
        kdc = 127.0.0.1:13088
    }
EOF
export KRB5_CONFIG=$W/krb5.conf KRB5CCNAME=FILE:$W/cc

check() { # $1 = password that must work, $2 = one that must not
  ldapwhoami -x -H ldap://127.0.0.1:13389 -D "cn=administrator,$BASE" -w "$1" || fail "ldapwhoami with the right password"
  if ldapwhoami -x -H ldap://127.0.0.1:13389 -D "cn=administrator,$BASE" -w "$2" >/dev/null 2>&1; then fail "ldapwhoami accepted a wrong password"; fi
  echo "$1" | kinit "administrator@$REALM" >/dev/null || fail "kinit with the right password"
  klist | grep -q "krbtgt/$REALM@$REALM" || fail "no TGT in the cache"
  kdestroy -q
  if echo "$2" | kinit "administrator@$REALM" >/dev/null 2>&1; then fail "kinit accepted a wrong password"; fi
  echo "== ldapwhoami + kinit OK with the stored password, wrong password refused"
}
check "$PW" 'WrongPass999!'

kill -TERM $BS; wait $BS && echo "== SIGTERM: iron-bootstrap exited 0" || fail "iron-bootstrap exited non-zero on SIGTERM"

# "Restart the pod": same store, a changed Secret.
printf '%s\n' 'OtherPass456!' > "$W/password"
IRON_BOOTSTRAP_ONESHOT=1 $B/iron-bootstrap > "$W/bootstrap2.log" 2>&1 || fail "second run failed"
grep -q "already provisioned; nothing to do" "$W/bootstrap2.log" || fail "second run changed something"
echo "== second run: nothing to do"
check "$PW" 'OtherPass456!'

echo "PASS: iron-bootstrap e2e ($PID_ID, $REALM)"
