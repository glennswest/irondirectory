#!/usr/bin/env bash
# A TGS-REQ must present a ticket-granting ticket, not a service ticket
# (finding 366e637ff815, #73), against a real iron-kdcd:
#
#   test/tgs-service-ticket-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd on a high port,
# gives alice, ldap/127.0.0.1 and host/victim Kerberos keys, and checks with
# impacket (test/tgs_service_ticket_impacket.py) that alice's TGT gets a
# host/victim ticket, and that her ldap/127.0.0.1 service ticket presented
# as a TGT is refused with KRB_AP_ERR_NOT_US; then with real MIT kinit/kvno
# that an ordinary TGS exchange still works.
# Needs curl, python3, kinit, kvno and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/tgse2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5
PID_ID="tgs$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
ALICE_PW='AliceKrb123!'
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; [ -s "$W/out" ] && cat "$W/out"; for f in "$W"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -v "error_code=25 " | tail -20; done; exit 1; }
for t in curl python3 kinit kvno; do command -v "$t" >/dev/null || fail "$t is not installed"; done
curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd --bin iron-kdc-ctl 2>&1 | tail -1
B=${CARGO_TARGET_DIR:-target}/release

printf 'AdminPass123!\n' > "$W/password"
export IRON_BOOTSTRAP_FASTETCD_ENDPOINT=$E IRON_BOOTSTRAP_PARTITION_ID=$PID_ID IRON_BOOTSTRAP_BASE_DN=$BASE \
  IRON_BOOTSTRAP_REALM=$REALM IRON_BOOTSTRAP_NETBIOS_NAME=$(echo "$PID_ID" | tr a-z A-Z) \
  IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE=$W/password
for attempt in 1 2 3 4 5; do
  $B/iron-bootstrap > "$W/bootstrap.log" 2>&1 & BS=$!; pids+=($BS)
  for _ in $(seq 60); do grep -q "provisioned" "$W/bootstrap.log" && break; kill -0 $BS 2>/dev/null || break; sleep 1; done
  grep -q "provisioned" "$W/bootstrap.log" && break
  [ "$attempt" = 5 ] && fail "iron-bootstrap did not provision"
  sleep 2
done

export IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM
IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
sleep 1
$B/iron-kdc-ctl set-password alice "$ALICE_PW" > /dev/null
$B/iron-kdc-ctl set-password ldap/127.0.0.1 'LdapService123!' > /dev/null
$B/iron-kdc-ctl set-password host/victim 'VictimService123!' > /dev/null
echo "== realm $REALM, iron-kdcd :$((P + 3))"

python3 -m venv "$W/venv" && "$W/venv/bin/pip" install -q impacket==0.13.1 > "$W/pip.out" 2>&1 || { tail -5 "$W/pip.out"; fail "pip install impacket"; }
"$W/venv/bin/python" -I "$PWD/test/tgs_service_ticket_impacket.py" $((P + 3)) "$REALM" alice "$ALICE_PW" ldap/127.0.0.1 host/victim \
  > "$W/out" 2>&1 || fail "a service ticket presented as a TGT"
cat "$W/out"

cat > "$W/krb5.conf" <<CONF
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
CONF
export KRB5_CONFIG=$W/krb5.conf KRB5CCNAME=FILE:$W/cc
echo "$ALICE_PW" | env -u OPENSSL_CONF kinit "alice@$REALM" > "$W/out" 2>&1 || fail "kinit alice"
env -u OPENSSL_CONF kvno "host/victim@$REALM" > "$W/out" 2>&1 || fail "kvno host/victim with a real TGT"
echo "ok: 3. MIT kinit + kvno: $(cat "$W/out")"

echo "PASS: the TGS accepts only a ticket-granting ticket"
