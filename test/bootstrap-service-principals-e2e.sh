#!/usr/bin/env bash
# iron-bootstrap's service principals (#43): a domain made by iron-bootstrap
# with IRON_BOOTSTRAP_SERVICE_HOSTS answers a GSSAPI LDAP bind with no hand
# provisioning. On a throwaway fastetcd, with real iron-ldapd/iron-kdcd and
# real MIT kinit/kvno and OpenLDAP ldapwhoami (Cyrus SASL GSSAPI):
#  1. iron-bootstrap with IRON_BOOTSTRAP_SERVICE_HOSTS="localhost, Dir.<pid>.SVC"
#     creates ldap/ and host/ for both names (lower-cased);
#  2. kinit administrator, then kvno gets a service ticket for each of the
#     four, and one for a name not listed (ldap/127.0.0.1) is refused;
#  3. ldapwhoami -Y GSSAPI -H ldap://localhost:<port> binds as
#     u:administrator@REALM -- iron-ldapd's acceptor finds the key bootstrap made;
#  4. a second run ("pod restart") creates nothing, and the bind still works;
#  5. a value that is not a host name stops iron-bootstrap with the reason.
# Needs curl, kinit, kvno, ldapwhoami (with the Cyrus SASL GSSAPI plugin) and
# a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/bsspne2e.XXXX")
# etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5, LDAP P+6, health P+7
P=$((20000 + RANDOM % 12000 / 10 * 10))
PID_ID="bssp$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
SVC="dir.${PID_ID}.svc"
PW='AdminPass123!'
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; [ -s "$W/out" ] && cat "$W/out"; for f in "$W"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | tail -20; done; exit 1; }
for t in curl kinit kvno ldapwhoami; do command -v "$t" >/dev/null || fail "$t is not installed"; done
curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd \
  -p iron-ldap --bin iron-ldapd 2>&1 | tail -1
B=${CARGO_TARGET_DIR:-target}/release

printf '%s\n' "$PW" > "$W/password"
export IRON_BOOTSTRAP_FASTETCD_ENDPOINT=$E IRON_BOOTSTRAP_PARTITION_ID=$PID_ID IRON_BOOTSTRAP_BASE_DN=$BASE \
  IRON_BOOTSTRAP_REALM=$REALM IRON_BOOTSTRAP_NETBIOS_NAME=$(echo "$PID_ID" | tr a-z A-Z) \
  IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE=$W/password IRON_BOOTSTRAP_ONESHOT=1 \
  IRON_BOOTSTRAP_SERVICE_HOSTS="localhost, $(echo "$SVC" | tr a-z A-Z)"
ok=
for attempt in 1 2 3 4 5; do
  timeout 60 $B/iron-bootstrap > "$W/bootstrap1.log" 2>&1 && grep -q "provisioned" "$W/bootstrap1.log" && { ok=1; break; }
  sleep 2
done
[ -n "$ok" ] || fail "iron-bootstrap did not provision"
for p in ldap/localhost host/localhost "ldap/$SVC" "host/$SVC"; do
  sed 's/\x1b\[[0-9;]*m//g' "$W/bootstrap1.log" | grep -qF "\"$p@$REALM\"" || fail "1. bootstrap did not report creating $p@$REALM"
done
echo "ok: 1. bootstrap created ldap/ and host/ for localhost and $SVC"

export IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM
IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 6)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 7)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null || fail "iron-ldapd did not come up"

cat > "$W/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 1
[realms]
    $REALM = {
        kdc = 127.0.0.1:$((P + 3))
    }
EOF
# The client tools run without the FIPS OPENSSL_CONF (it is for the daemons).
export KRB5_CONFIG=$W/krb5.conf KRB5CCNAME=FILE:$W/cc
client() { env -u OPENSSL_CONF "$@"; }
sleep 1
echo "$PW" | client kinit "administrator@$REALM" > "$W/out" 2>&1 || fail "kinit administrator@$REALM"
for p in ldap/localhost host/localhost "ldap/$SVC" "host/$SVC"; do
  client kvno "$p@$REALM" > "$W/out" 2>&1 || fail "2. kvno $p@$REALM"
done
if client kvno "ldap/127.0.0.1@$REALM" > "$W/out" 2>&1; then fail "2. kvno got a ticket for an unlisted name"; fi
echo "ok: 2. kvno: service tickets for all four; unlisted ldap/127.0.0.1 refused ($(tr -d '\n' < "$W/out"))"

WANT="u:administrator@$REALM"
whoami() { client ldapwhoami -Y GSSAPI -N -H "ldap://localhost:$((P + 6))" > "$W/out" 2>&1 && grep -qx "$WANT" "$W/out"; }
whoami || fail "3. ldapwhoami -Y GSSAPI to ldap://localhost"
echo "ok: 3. ldapwhoami -Y GSSAPI: $(grep -x "$WANT" "$W/out")"

$B/iron-bootstrap > "$W/bootstrap2.log" 2>&1 || fail "4. second bootstrap run failed"
grep -q "already provisioned; nothing to do" "$W/bootstrap2.log" || fail "4. second run created something"
client kdestroy -q; echo "$PW" | client kinit "administrator@$REALM" > "$W/out" 2>&1 || fail "4. kinit"
whoami || fail "4. ldapwhoami -Y GSSAPI after the second run"
echo "ok: 4. second run: nothing to do; GSSAPI bind still works"

rc=0; IRON_BOOTSTRAP_SERVICE_HOSTS="ldap/oops" $B/iron-bootstrap > "$W/out" 2>&1 || rc=$?
[ "$rc" != 0 ] && grep -q "not a host name" "$W/out" || fail "5. a bad IRON_BOOTSTRAP_SERVICE_HOSTS was not refused (rc $rc)"
echo "ok: 5. refused: $(grep -o 'IRON_BOOTSTRAP_SERVICE_HOSTS.*' "$W/out")"

echo "PASS: iron-bootstrap service principals ($PID_ID, $REALM)"
