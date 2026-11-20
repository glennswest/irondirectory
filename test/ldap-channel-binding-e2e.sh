#!/usr/bin/env bash
# GSSAPI channel binding, as Active Directory's LDAP channel binding (#65):
#
#   test/ldap-channel-binding-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd and iron-ldapd
# (StartTLS + LDAPS, a self-signed certificate) on high ports, kinit alice,
# and checks with real OpenLDAP clients (Cyrus SASL GSSAPI, MIT krb5):
#  1. ldapwhoami -Y GSSAPI with SASL_CBINDING=tls-endpoint over LDAPS and
#     over StartTLS: bound, and iron-ldapd logs the bindings as verified;
#  2. the same through a TLS-terminating relay with its own certificate
#     (test/tls_relay.py, the MITM channel binding defeats): refused, the
#     bindings name the relay's certificate; without bindings through the
#     relay: accepted (AD's "When supported" -- why "always" exists);
#  3. bindings on plain LDAP (test/ldap_cbind_impacket.py, impacket's
#     Kerberos client): refused; no bindings on plain LDAP: accepted;
#  4. IRON_LDAP_CHANNEL_BINDING=always: a bind over LDAPS without bindings
#     is refused, with bindings accepted, and a GSSAPI bind on plain LDAP is
#     unaffected; an unknown value stops iron-ldapd at startup.
# Needs curl, python3, openssl, kinit, ldapwhoami (with the Cyrus SASL GSSAPI
# plugin) and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/cbinde2e.XXXX")
# etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5, LDAP P+6, health P+7, LDAPS P+8, relay P+9
P=$((20000 + RANDOM % 12000 / 10 * 10))
PID_ID="cbind$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
ADMIN_PW='AdminPass123!' ALICE_PW='AliceKrb123!'
pids=() ldapd=
cleanup() { for p in "${pids[@]}" $ldapd; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; [ -s "$W/out" ] && cat "$W/out"; for f in "$W"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | tail -20; done; exit 1; }
for t in curl python3 openssl kinit ldapwhoami; do command -v "$t" >/dev/null || fail "$t is not installed"; done
curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd --bin iron-kdc-ctl \
  -p iron-ldap --bin iron-ldapd 2>&1 | tail -1
B=${CARGO_TARGET_DIR:-target}/release

printf '%s\n' "$ADMIN_PW" > "$W/password"
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

for c in server relay; do
  openssl req -x509 -newkey rsa:3072 -nodes -keyout "$W/$c.key" -out "$W/$c.crt" -days 1 -subj "/CN=127.0.0.1" \
    > "$W/out" 2>&1 || fail "self-signed $c certificate"
done

export IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM
IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
export IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_TLS_CERT=$W/server.crt IRON_LDAP_TLS_KEY=$W/server.key \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 6)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 7)) IRON_LDAP_LDAPS_LISTEN=127.0.0.1:$((P + 8))
start_ldapd() { # [policy]
  [ -n "$ldapd" ] && { kill "$ldapd" 2>/dev/null || true; wait "$ldapd" 2>/dev/null || true; }
  IRON_LDAP_CHANNEL_BINDING=${1:-} $B/iron-ldapd > "$W/ldapd.log" 2>&1 & ldapd=$!
  for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null && return; sleep 0.5; done
  fail "iron-ldapd did not come up (policy ${1:-default})"
}
start_ldapd
LDAP=ldap://127.0.0.1:$((P + 6)) LDAPS=ldaps://127.0.0.1:$((P + 8)) RELAY=ldaps://127.0.0.1:$((P + 9))
echo "== domain $BASE, realm $REALM; iron-ldapd :$((P + 6)) (StartTLS) :$((P + 8)) (LDAPS), iron-kdcd :$((P + 3))"
$B/iron-kdc-ctl set-password alice "$ALICE_PW" > /dev/null
$B/iron-kdc-ctl set-password ldap/127.0.0.1 'LdapService123!' > /dev/null

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
export KRB5_CONFIG=$W/krb5.conf KRB5CCNAME=FILE:$W/cc LDAPTLS_REQCERT=never
echo "$ALICE_PW" | env -u OPENSSL_CONF kinit "alice@$REALM" > "$W/out" 2>&1 || fail "kinit alice@$REALM"
WANT="u:alice@$REALM"

# whoami <uri> <cbinding: tls-endpoint|none> [-ZZ]: real ldapwhoami -Y GSSAPI;
# exit status of ldapwhoami, output in $W/out. The client tools run without
# the FIPS OPENSSL_CONF (it is for the daemons).
whoami() {
  local rc=0
  env -u OPENSSL_CONF LDAPSASL_CBINDING="$2" ldapwhoami -Y GSSAPI -N -H "$1" ${3:-} > "$W/out" 2>&1 || rc=$?
  return $rc
}
verified() { grep -c "channel bindings verified" "$W/ldapd.log" || true; }
refusals() { grep -c "GSSAPI bind refused: $1" "$W/ldapd.log" || true; }

# 1. Real bindings over LDAPS and StartTLS.
n=$(verified)
whoami "$LDAPS" tls-endpoint || fail "1. ldapwhoami -Y GSSAPI with tls-endpoint bindings over LDAPS"
grep -qx "$WANT" "$W/out" || fail "1. LDAPS: Who am I is not $WANT"
[ "$(verified)" -gt "$n" ] || fail "1. LDAPS: iron-ldapd did not verify any bindings (did the client send them?)"
echo "ok: 1. LDAPS, tls-endpoint bindings: $(grep -x "$WANT" "$W/out"), bindings verified"
n=$(verified)
whoami "$LDAP" tls-endpoint -ZZ || fail "1. ldapwhoami -ZZ -Y GSSAPI with tls-endpoint bindings (StartTLS)"
grep -qx "$WANT" "$W/out" || fail "1. StartTLS: Who am I is not $WANT"
[ "$(verified)" -gt "$n" ] || fail "1. StartTLS: iron-ldapd did not verify any bindings"
echo "ok: 1. StartTLS, tls-endpoint bindings: $(grep -x "$WANT" "$W/out"), bindings verified"

# 2. A TLS-terminating relay with its own certificate.
python3 -I "$PWD/test/tls_relay.py" $((P + 9)) $((P + 8)) "$W/relay.crt" "$W/relay.key" > "$W/relay.log" 2>&1 & pids+=($!)
for _ in $(seq 50); do grep -q listening "$W/relay.log" && break; sleep 0.1; done
n=$(refusals "channel bindings do not match")
if whoami "$RELAY" tls-endpoint; then fail "2. a bind relayed through another certificate was accepted"; fi
[ "$(refusals "channel bindings do not match")" -gt "$n" ] || fail "2. the relayed bind failed, but not on its bindings"
echo "ok: 2. relayed bind with bindings refused: $(grep -m1 -o 'channel bindings do not match[^"]*' "$W/ldapd.log")"
whoami "$RELAY" none || fail "2. a relayed bind without bindings (when-supported accepts it)"
grep -qx "$WANT" "$W/out" || fail "2. relayed bind without bindings: Who am I is not $WANT"
echo "ok: 2. relayed bind without bindings accepted under when-supported: $(grep -x "$WANT" "$W/out")"

# 3. Plain LDAP, tokens built with impacket.
python3 -m venv "$W/venv" && "$W/venv/bin/pip" install -q impacket==0.13.1 > "$W/pip.out" 2>&1 || { tail -5 "$W/pip.out"; fail "pip install impacket"; }
plain() { "$W/venv/bin/python" -I "$PWD/test/ldap_cbind_impacket.py" $((P + 6)) $((P + 3)) "$REALM" ldap/127.0.0.1 alice "$ALICE_PW" "$1" > "$W/out" 2>&1 || fail "3. impacket bind ($1)"; }
plain tls
grep -q '^result 49 .*channel bindings supplied on a connection without TLS' "$W/out" || fail "3. bindings on plain LDAP were not refused"
echo "ok: 3. bindings on plain LDAP refused: $(cat "$W/out")"
plain zero
grep -q '^result 14 ' "$W/out" || fail "3. a bind without bindings on plain LDAP did not proceed (want saslBindInProgress)"
echo "ok: 3. no bindings on plain LDAP accepted: $(cat "$W/out") (saslBindInProgress, AP-REP sent)"

# 4. IRON_LDAP_CHANNEL_BINDING=always.
start_ldapd always
n=$(refusals "channel bindings required")
if whoami "$LDAPS" none; then fail "4. always: a bind over LDAPS without bindings was accepted"; fi
[ "$(refusals "channel bindings required")" -gt "$n" ] || fail "4. always: the bind failed, but not for missing bindings"
echo "ok: 4. always: LDAPS bind without bindings refused"
whoami "$LDAPS" tls-endpoint || fail "4. always: LDAPS bind with bindings"
grep -qx "$WANT" "$W/out" || fail "4. always: Who am I is not $WANT"
echo "ok: 4. always: LDAPS bind with bindings: $(grep -x "$WANT" "$W/out")"
whoami "$LDAP" none || fail "4. always: GSSAPI bind on plain LDAP"
grep -qx "$WANT" "$W/out" || fail "4. always: plain LDAP Who am I is not $WANT"
echo "ok: 4. always: GSSAPI bind on plain LDAP unaffected: $(grep -x "$WANT" "$W/out")"
kill "$ldapd" 2>/dev/null || true; wait "$ldapd" 2>/dev/null || true; ldapd=
rc=0; IRON_LDAP_CHANNEL_BINDING=never timeout 20 $B/iron-ldapd > "$W/out" 2>&1 || rc=$?
[ "$rc" != 0 ] && [ "$rc" != 124 ] && grep -q 'IRON_LDAP_CHANNEL_BINDING: unknown channel binding policy "never"' "$W/out" \
  || fail "4. IRON_LDAP_CHANNEL_BINDING=never: exit $rc, want a startup error naming it"
echo "ok: 4. IRON_LDAP_CHANNEL_BINDING=never stops iron-ldapd: $(grep -o 'IRON_LDAP_CHANNEL_BINDING: .*' "$W/out")"

echo "PASS: GSSAPI channel bindings are checked against TLS as AD does (when-supported and always)"
