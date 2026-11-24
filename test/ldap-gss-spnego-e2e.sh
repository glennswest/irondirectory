#!/usr/bin/env bash
# GSS-SPNEGO SASL bind (#88): what Windows' LDAP client and the join bind with.
#
#   test/ldap-gss-spnego-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd and iron-ldapd
# (plain + LDAPS, a self-signed certificate) on high ports, kinit alice, then:
#  1. Cyrus SASL's GSS-SPNEGO over MIT krb5's SPNEGO (which verifies our
#     mechListMIC): ldapwhoami -Y GSS-SPNEGO is u:alice@REALM through the
#     sealed layer (default SSF, and maxssf=1: MIT asserts CONF), and with
#     no layer at maxssf=0;
#  2. a sealed ldapmodify -Y GSS-SPNEGO sets a computer's dNSHostName and
#     servicePrincipalName, as the Windows join does; they read back;
#  3. over LDAPS, as AD: a sign/seal bind is refused (unwillingToPerform), and
#     -O maxssf=0 (SSSD's advice for AD over LDAPS) binds with no layer;
#  4. impacket (its own SPNEGO encoder, test/ldap_spnego_impacket.py), the
#     Windows mech order [MS-KRB5, KRB5, NTLMSSP]: accept-completed,
#     supportedMech MS-KRB5, an AP-REP that decrypts to its ctime, a
#     mechListMIC equal to impacket's own GetMIC, then Who am I with no layer;
#     with GSS_C_INTEG_FLAG alone, an integrity layer (Who am I as Wrap
#     tokens checked with impacket's HMAC); NTLM-only and NTLM-first are
#     refused (authMethodNotSupported, 7);
#  5. rootDSE lists GSS-SPNEGO, and a GSSAPI bind is unaffected.
# Needs curl, python3, openssl, kinit, ldapwhoami, ldapmodify, ldapadd,
# ldapsearch (with the Cyrus SASL GSSAPI plugin, which serves GSS-SPNEGO) and
# a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/spnegoe2e.XXXX")
# etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5, LDAP P+6, health P+7, LDAPS P+8
P=$((20000 + RANDOM % 12000 / 10 * 10))
PID_ID="spnego$(date +%s)"
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

for c in server; do
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
  $B/iron-ldapd > "$W/ldapd.log" 2>&1 & ldapd=$!
  for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null && return; sleep 0.5; done
  fail "iron-ldapd did not come up (policy ${1:-default})"
}
start_ldapd
LDAP=ldap://127.0.0.1:$((P + 6)) LDAPS=ldaps://127.0.0.1:$((P + 8))
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
cli() { env -u OPENSSL_CONF "$@"; }
layer_logs() { sed 's/\x1b\[[0-9;]*m//g' "$W/ldapd.log" | grep -c "GSS-SPNEGO bind succeeded.*layer=$1\b" || true; }
spnego_whoami() { # <uri> <expected layer> [ldapwhoami options]
  local uri=$1 layer=$2; shift 2
  local n; n=$(layer_logs "$layer")
  cli ldapwhoami -Y GSS-SPNEGO -N -H "$uri" "$@" > "$W/out" 2>&1 || fail "ldapwhoami -Y GSS-SPNEGO $* on $uri"
  grep -qx "$WANT" "$W/out" || fail "Who am I is not $WANT on $uri $*"
  [ "$(layer_logs "$layer")" -gt "$n" ] || fail "iron-ldapd did not log a GSS-SPNEGO bind with layer=$layer ($uri $*)"
}

# 1. Cyrus SASL GSS-SPNEGO (MIT SPNEGO), three layers.
spnego_whoami "$LDAP" confidentiality
echo "ok: 1. ldapwhoami -Y GSS-SPNEGO (default SSF): $WANT, sealed layer"
# MIT asserts GSS_C_CONF_FLAG with integrity as soon as any SSF is allowed
# (maxssf=1 still reports SSF 256), and no flag at maxssf=0; an
# integrity-only layer is impacket's, step 4.
spnego_whoami "$LDAP" confidentiality -O maxssf=1
echo "ok: 1. maxssf=1: $WANT (MIT asserts CONF: sealed on both sides)"
spnego_whoami "$LDAP" none -O maxssf=0
grep -q "SASL SSF: 0" "$W/out" || fail "1. maxssf=0: the client did not report SSF 0"
echo "ok: 1. maxssf=0: $WANT, no layer on either side (client SSF 0)"

# 2. A sealed modify, as the join sets the computer's DNS name and SPNs.
cat > "$W/ws1.ldif" <<LDIF
dn: cn=WS1,$BASE
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
cn: WS1
sAMAccountName: WS1\$
LDIF
ldapadd -x -H "$LDAP" -D "cn=administrator,$BASE" -w "$ADMIN_PW" -f "$W/ws1.ldif" > "$W/out" 2>&1 || fail "ldapadd WS1"
cat > "$W/ws1-mod.ldif" <<LDIF
dn: cn=WS1,$BASE
changetype: modify
replace: dNSHostName
dNSHostName: ws1.example.lo
-
replace: servicePrincipalName
servicePrincipalName: HOST/ws1.example.lo
servicePrincipalName: HOST/WS1
LDIF
n=$(layer_logs confidentiality)
cli ldapmodify -Y GSS-SPNEGO -N -H "$LDAP" -f "$W/ws1-mod.ldif" > "$W/out" 2>&1 || fail "sealed ldapmodify -Y GSS-SPNEGO"
[ "$(layer_logs confidentiality)" -gt "$n" ] || fail "the modify was not over a sealed GSS-SPNEGO layer"
ldapsearch -x -LLL -H "$LDAP" -b "cn=WS1,$BASE" -s base dNSHostName servicePrincipalName > "$W/out" 2>&1
grep -qix "dNSHostName: ws1.example.lo" "$W/out" && grep -qix "servicePrincipalName: HOST/ws1.example.lo" "$W/out" &&
  grep -qix "servicePrincipalName: HOST/WS1" "$W/out" || fail "dNSHostName/servicePrincipalName did not read back"
echo "ok: 2. sealed ldapmodify -Y GSS-SPNEGO set WS1's dNSHostName and servicePrincipalName"

# 3. LDAPS: as AD (00002029), sign/seal on TLS is refused; SSSD's AD advice
# for LDAPS is maxssf=0, which binds with no layer.
if cli ldapwhoami -Y GSS-SPNEGO -N -H "$LDAPS" > "$W/out" 2>&1; then fail "3. a sealed GSS-SPNEGO bind over LDAPS was accepted"; fi
grep -q "(53)" "$W/out" && grep -q "cannot bind using sign/seal on a connection on which TLS is in effect" "$W/out" ||
  fail "3. the LDAPS sign/seal bind was not refused as unwillingToPerform naming why"
echo "ok: 3. LDAPS, sign/seal asked for: refused (53) as AD does"
spnego_whoami "$LDAPS" none -O maxssf=0
echo "ok: 3. LDAPS, maxssf=0: $WANT, no layer (TLS protects it)"

# 4. impacket, the Windows mech order; NTLM refused.
python3 -m venv "$W/venv" && "$W/venv/bin/pip" install -q impacket==0.13.1 > "$W/pip.out" 2>&1 || { tail -5 "$W/pip.out"; fail "pip install impacket"; }
for m in windows sign ntlm ntlmfirst; do
  "$W/venv/bin/python" -I "$PWD/test/ldap_spnego_impacket.py" $((P + 6)) $((P + 3)) "$REALM" ldap/127.0.0.1 alice "$ALICE_PW" $m > "$W/out" 2>&1 ||
    fail "4. impacket $m"
  sed 's/^ok  /ok: 4. /' "$W/out"
done
[ "$(layer_logs integrity)" -ge 1 ] && [ "$(layer_logs none)" -ge 1 ] || fail "4. iron-ldapd did not log the integrity and no-layer binds"
echo "ok: 4. iron-ldapd logged impacket's binds as layer=none and layer=integrity"

# 5. rootDSE and GSSAPI.
ldapsearch -x -LLL -H "$LDAP" -b "" -s base supportedSASLMechanisms > "$W/out" 2>&1
grep -qx "supportedSASLMechanisms: GSS-SPNEGO" "$W/out" || fail "rootDSE does not list GSS-SPNEGO"
cli ldapwhoami -Y GSSAPI -N -H "$LDAP" > "$W/out" 2>&1 && grep -qx "$WANT" "$W/out" || fail "a GSSAPI bind after the GSS-SPNEGO work"
echo "ok: 5. rootDSE lists GSS-SPNEGO; ldapwhoami -Y GSSAPI still $WANT"

echo "PASS: GSS-SPNEGO SASL bind (Cyrus/MIT and impacket), all three layers, NTLM refused (#88)"
