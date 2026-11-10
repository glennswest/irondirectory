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
# Needs curl and openssl; no root.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/mtlse2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # client P+1, peer P+2, metrics P+5
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; [ -s "$W/fastetcd.log" ] && tail -20 "$W/fastetcd.log"; exit 1; }
for t in curl openssl; do command -v "$t" >/dev/null || fail "$t is not installed"; done

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
echo "PASS: fastetcd $FV enforces --client-cert-auth; iron-store's mTLS path round-trips"
