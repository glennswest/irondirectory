#!/usr/bin/env bash
# Tickets whose session key's enctype differs from the ticket's (finding
# bf4c13fcebad, #79).
#
#   test/session-enctype-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd (with kpasswd) and
# iron-ldapd, exports the krbtgt and ldap/127.0.0.1 keys to keytabs, and with
# impacket (test/session_enctype_impacket.py) builds tickets encrypted with
# the real key in aes256-cts-hmac-sha1-96 (18) that carry an
# aes128-cts-hmac-sha1-96 (17) session key -- what the AS issues when the
# krbtgt lacks the client's pre-auth enctype, and what a foreign KDC's
# cross-realm TGT often is. Every message under the session key is in 17:
#  1. TGS: impacket's TGS-REQ with such a TGT gets a service ticket, and the
#     TGS-REP decrypts under the session key;
#  2. kpasswd: such a kadmin/changepw ticket changes alice's password; the
#     AP-REP is in 17; kinit takes the new password, not the old;
#  3. iron-ldapd's GSSAPI acceptor takes such a ldap/127.0.0.1 ticket and its
#     AP-REP is in 17 and decrypts under the session key;
#  4. an ordinary kinit still works.
# On the unfixed code (the ticket's enctype used for the session key) 1-3
# fail: "failed to decrypt authenticator".
# Needs curl, kinit, python3 (impacket is pip-installed into a venv) and a
# FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/sesse2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5, LDAP P+6, health P+7
PID_ID="se$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; grep -v "error_code=25 " "$f" | tail -25; done; exit 1; }
for t in curl kinit python3; do command -v "$t" >/dev/null || fail "$t is not installed"; done

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd --bin iron-kdc-ctl -p iron-ldap --bin iron-ldapd > "$W/cargo.log" 2>&1 ||
  { tail -30 "$W/cargo.log"; fail "building irondirectory"; }
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

IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM \
  IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 6)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 7)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null && break; sleep 0.5; done
sleep 1

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
export IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM
can_kinit() { echo "$2" | env -u OPENSSL_CONF kinit "$1@$REALM" >/dev/null 2>&1; }
$B/iron-kdc-ctl set-password alice 'AlicePass123!' > /dev/null
can_kinit alice 'AlicePass123!' || fail "kinit alice before anything"
$B/iron-kdc-ctl set-password host/svc.example.lo "$(head -c 24 /dev/urandom | base64)" > /dev/null
$B/iron-kdc-ctl set-password ldap/127.0.0.1 'LdapService123!' > /dev/null
$B/iron-kdc-ctl export-keytab "krbtgt/$REALM" "$W/krbtgt.keytab" > /dev/null
$B/iron-kdc-ctl export-keytab ldap/127.0.0.1 "$W/ldap.keytab" > /dev/null

python3 -m venv "$W/venv" && "$W/venv/bin/pip" install -q impacket==0.13.1 > "$W/pip.out" 2>&1 || { tail -5 "$W/pip.out"; fail "pip install impacket"; }
imp() { "$W/venv/bin/python" -I "$PWD/test/session_enctype_impacket.py" "$@" > "$W/out" 2>&1 || { cat "$W/out"; fail "impacket $1"; }; sed 's/^ok  /ok: /' "$W/out"; }

imp tgs $((P + 3)) "$REALM" "$W/krbtgt.keytab" alice host/svc.example.lo
imp kpasswd $((P + 4)) "$REALM" "$W/krbtgt.keytab" alice 'AliceNew456!'
rm -f "$W/cc"; can_kinit alice 'AliceNew456!' || fail "2. kinit with the password set through the mismatched ticket"
can_kinit alice 'AlicePass123!' && fail "2. the old password still works"
echo "ok: 2. kinit takes the new password, not the old"
imp ldap $((P + 6)) "$REALM" "$W/ldap.keytab" alice ldap/127.0.0.1
rm -f "$W/cc"; can_kinit administrator 'AdminPass123!' || fail "4. an ordinary kinit"
echo "ok: 4. an ordinary kinit still works"

echo "PASS: session-key enctype, not the ticket's, for TGS, kpasswd and the GSSAPI acceptor (bf4c13fcebad)"
