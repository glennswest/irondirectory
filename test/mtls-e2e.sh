#!/usr/bin/env bash
# fastetcd with --client-cert-auth enforces client certificates, and
# iron-store's mTLS path works against it (#32; fastetcd#6, fixed in v0.8.1).
#
#   test/mtls-e2e.sh
#
# Makes a throwaway CA, a server certificate (127.0.0.1) and a client
# certificate with openssl, starts a one-member fastetcd (release tarball,
# FASTETCD_VERSION) on https with --client-cert-auth, then runs
# crates/store/tests/mtls_spike.rs:
#  - mtls_connect_and_roundtrip: iron_store::connect with the client
#    certificate writes and reads back;
#  - mtls_refuses_a_client_without_a_certificate: a client that trusts the
#    CA but presents no certificate cannot write (what fastetcd#6 broke).
# Then the daemons over mTLS (#26), each with its <PREFIX>_FASTETCD_CA/_CERT/
# _KEY: iron-bootstrap provisions a domain (and persists its partitions with
# that TLS); iron-ldapd answers ldapwhoami as the administrator; iron-kdcd
# (store and forest registry) gives kinit a TGT; iron-gcd loads the registry
# and watches the domain partition with the TLS the registry holds, so an
# ldapsearch on the GC finds the administrator. A daemon given an https
# endpoint without the settings, or half of them, refuses to start.
# Needs curl, openssl, ldapwhoami, ldapsearch, kinit and a FIPS OPENSSL_CONF;
# no root.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/mtlse2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # client P+1, peer P+2, KDC P+3, kpasswd P+4, metrics P+5, LDAP P+6/P+7, GC P+8/P+9
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -v "error_code=25 " | tail -15; done; exit 1; }
for t in curl openssl ldapwhoami ldapsearch kinit; do command -v "$t" >/dev/null || fail "$t is not installed"; done

# Certificates (the system's default OpenSSL config: these are test fixtures,
# not the daemons' FIPS path).
ossl() { env -u OPENSSL_CONF openssl "$@" 2>>"$W/openssl.log"; }
C=$W/certs; mkdir -p "$C"
ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=iron-test-ca \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
  -keyout "$C/ca.key" -out "$C/ca.pem" || fail "CA"
leaf() { # <name> <extendedKeyUsage> [subjectAltName]
  ossl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$C/$1.key" -out "$C/$1.csr" || fail "$1 key"
  { echo "basicConstraints=critical,CA:FALSE"; echo "keyUsage=critical,digitalSignature"; echo "extendedKeyUsage=$2"
    [ -n "${3:-}" ] && echo "subjectAltName=$3"; } > "$C/$1.ext"
  ossl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -days 1 -extfile "$C/$1.ext" -out "$C/$1.pem" || fail "$1 cert"
}
leaf server serverAuth "IP:127.0.0.1,DNS:localhost"
leaf client clientAuth
echo "== certificates: CA, server (127.0.0.1), client"

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
FE=$W/fastetcd-v$FV-x86_64-linux/fastetcd
"$FE" --data-dir "$W/data" --listen-client-urls "https://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "https://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" \
  --cert-file "$C/server.pem" --key-file "$C/server.key" --trusted-ca-file "$C/ca.pem" --client-cert-auth \
  > "$W/fastetcd.log" 2>&1 & pids+=($!)
E=https://127.0.0.1:$((P + 1))
ok=
for _ in $(seq 100); do
  curl -sf --cacert "$C/ca.pem" --cert "$C/client.pem" --key "$C/client.key" "$E/health" >/dev/null && { ok=1; break; }
  kill -0 "${pids[0]}" 2>/dev/null || break
  sleep 0.2
done
[ -n "$ok" ] || { "$FE" --help 2>&1 | grep -iE "cert|tls" | head; fail "fastetcd $FV did not come up on https with --client-cert-auth"; }
echo "== fastetcd $FV on $E with --client-cert-auth; /health answers with the client certificate"

IRON_STORE_MTLS_ENDPOINT=$E IRON_STORE_MTLS_CA=$C/ca.pem IRON_STORE_MTLS_CERT=$C/client.pem IRON_STORE_MTLS_KEY=$C/client.key \
  cargo test --locked -p iron-store --test mtls_spike -- --ignored --test-threads=1 2>&1 | tee "$W/test.out" | grep -E "^test |test result" || true
grep -q "test result: ok. 2 passed" "$W/test.out" || { cat "$W/test.out" | tail -30; fail "mtls_spike"; }
echo "ok: fastetcd $FV enforces --client-cert-auth; iron-store's mTLS path round-trips"

# The daemons over mTLS (#26).
cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd \
  -p iron-ldap --bin iron-ldapd -p iron-gc --bin iron-gcd 2>&1 | tail -1
B=${CARGO_TARGET_DIR:-target}/release
tls() { echo "$1_CA=$C/ca.pem" "$1_CERT=$C/client.pem" "$1_KEY=$C/client.key"; } # <PREFIX>
PID_ID="tls$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
printf 'AdminPass123!\n' > "$W/password"
for attempt in 1 2 3 4 5; do
  env $(tls IRON_BOOTSTRAP_FASTETCD) IRON_BOOTSTRAP_FASTETCD_ENDPOINT=$E IRON_BOOTSTRAP_PARTITION_ID=$PID_ID \
    IRON_BOOTSTRAP_BASE_DN=$BASE IRON_BOOTSTRAP_REALM=$REALM IRON_BOOTSTRAP_NETBIOS_NAME=$(echo "$PID_ID" | tr a-z A-Z) \
    IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE=$W/password $B/iron-bootstrap > "$W/bootstrap.log" 2>&1 & BS=$!; pids+=($BS)
  for _ in $(seq 60); do grep -q "provisioned" "$W/bootstrap.log" && break; kill -0 $BS 2>/dev/null || break; sleep 1; done
  grep -q "provisioned" "$W/bootstrap.log" && break
  [ "$attempt" = 5 ] && fail "iron-bootstrap over mTLS did not provision"
  sleep 2
done
echo "ok: iron-bootstrap provisioned $BASE over mTLS"

env $(tls IRON_LDAP_FASTETCD) IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 6)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 7)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null && break; sleep 0.5; done
ldapwhoami -x -H "ldap://127.0.0.1:$((P + 6))" -D "cn=administrator,$BASE" -w 'AdminPass123!' > "$W/out" 2>&1 || { cat "$W/out"; fail "ldapwhoami via iron-ldapd over mTLS"; }
echo "ok: iron-ldapd over mTLS: $(cat "$W/out")"

env $(tls IRON_KDC_FASTETCD) $(tls IRON_KDC_CONFIG_FASTETCD) IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID \
  IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM IRON_KDC_CONFIG_FASTETCD_ENDPOINT=$E IRON_KDC_CONFIG_PARTITION_ID=${PID_ID}-config \
  IRON_KDC_CONFIG_BASE_DN=cn=configuration,$BASE IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) \
  $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do grep -q "iron-kdcd listening" "$W/kdcd.log" && break; sleep 0.5; done
grep -q "loaded forest topology" "$W/kdcd.log" || fail "iron-kdcd did not load the forest registry over mTLS"
printf '[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n rdns = false\n udp_preference_limit = 1\n[realms]\n %s = {\n  kdc = 127.0.0.1:%s\n }\n' \
  "$REALM" "$REALM" "$((P + 3))" > "$W/krb5.conf"
echo 'AdminPass123!' | env -u OPENSSL_CONF KRB5_CONFIG="$W/krb5.conf" KRB5CCNAME="FILE:$W/cc" kinit "administrator@$REALM" > "$W/out" 2>&1 ||
  { cat "$W/out"; fail "kinit via iron-kdcd over mTLS"; }
echo "ok: iron-kdcd over mTLS (store and forest registry): kinit administrator@$REALM"

env $(tls IRON_GC_CONFIG_FASTETCD) IRON_GC_CONFIG_FASTETCD_ENDPOINT=$E IRON_GC_CONFIG_PARTITION_ID=${PID_ID}-config \
  IRON_GC_CONFIG_BASE_DN=cn=configuration,$BASE IRON_GC_LISTEN=127.0.0.1:$((P + 8)) IRON_GC_HEALTH_LISTEN=127.0.0.1:$((P + 9)) \
  $B/iron-gcd > "$W/gcd.log" 2>&1 & pids+=($!)
found=
for _ in $(seq 40); do
  if ldapsearch -x -LLL -H "ldap://127.0.0.1:$((P + 8))" -b "$BASE" '(cn=administrator)' cn > "$W/out" 2>&1 && grep -q '^cn: administrator' "$W/out"; then found=1; break; fi
  sleep 0.5
done
[ -n "$found" ] || { cat "$W/out"; fail "iron-gcd over mTLS: the GC never saw the administrator"; }
echo "ok: iron-gcd loaded the registry over mTLS and watches the domain partition with the TLS the registry holds"

# Misconfigurations refuse to start rather than fall back to plaintext.
if env IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE IRON_LDAP_LISTEN=127.0.0.1:0 \
  IRON_LDAP_HEALTH_LISTEN=127.0.0.1:0 timeout 10 $B/iron-ldapd > "$W/neg1.out" 2>&1; then fail "iron-ldapd started on an https endpoint with no TLS settings"; fi
grep -q "IRON_LDAP_FASTETCD_CA" "$W/neg1.out" || { cat "$W/neg1.out"; fail "no TLS settings: the error does not name them"; }
if env IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_FASTETCD_CA=$C/ca.pem IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_LISTEN=127.0.0.1:0 IRON_LDAP_HEALTH_LISTEN=127.0.0.1:0 timeout 10 $B/iron-ldapd > "$W/neg2.out" 2>&1; then fail "iron-ldapd started with only a CA"; fi
grep -q "or none" "$W/neg2.out" || { cat "$W/neg2.out"; fail "half the settings: the error does not say so"; }
echo "ok: an https endpoint without TLS settings, or with only a CA, is refused: $(grep -o 'fastetcd TLS settings:.*' "$W/neg2.out" | head -1)"

echo "PASS: fastetcd $FV enforces --client-cert-auth; iron-store, iron-bootstrap, iron-ldapd, iron-kdcd and iron-gcd reach it over mTLS"
