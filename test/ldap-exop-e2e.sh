#!/usr/bin/env bash
# LDAP extended operations on iron-ldapd (#63), with real OpenLDAP clients:
#
#   test/ldap-exop-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd and iron-ldapd (with
# a throwaway self-signed TLS cert, so StartTLS is on) on high ports, and checks:
#  1. rootDSE supportedExtension lists StartTLS, Who am I, Password Modify, Cancel;
#  2. Who am I (RFC 4532): ldapwhoami anonymous and as the administrator;
#  3. StartTLS (RFC 4511 §4.14): ldapwhoami -ZZ;
#  4. Password Modify (RFC 3062): ldappasswd as the administrator sets alice's
#     password and kinit alice works with it; anonymous ldappasswd is refused;
#  5. Cancel (RFC 3909), on one connection: noSuchOperation for an unknown id,
#     tooLate for a completed Who am I, cannotCancel for the bind;
#  6. an unknown extended operation: protocolError naming the OID.
# Needs curl, openssl, python3, kinit, ldapsearch, ldapwhoami, ldappasswd and a
# FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/exope2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5, LDAP P+6, health P+7
PID_ID="exop$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
ADMIN="cn=administrator,$BASE" ADMIN_PW='AdminPass123!'
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; [ -s "$W/out" ] && cat "$W/out"; for f in "$W"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | tail -20; done; exit 1; }
for t in curl openssl python3 kinit ldapsearch ldapwhoami ldappasswd; do command -v "$t" >/dev/null || fail "$t is not installed"; done

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

openssl req -x509 -newkey rsa:3072 -nodes -keyout "$W/tls.key" -out "$W/tls.crt" -days 1 -subj "/CN=127.0.0.1" \
  > "$W/out" 2>&1 || fail "self-signed TLS cert"

export IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM
IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_TLS_CERT=$W/tls.crt IRON_LDAP_TLS_KEY=$W/tls.key \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 6)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 7)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null && break; sleep 0.5; done
H=ldap://127.0.0.1:$((P + 6))
echo "== domain $BASE, realm $REALM; iron-ldapd :$((P + 6)) (StartTLS on), iron-kdcd :$((P + 3))"
$B/iron-kdc-ctl set-password alice 'AliceKrb123!' > /dev/null

# 1. rootDSE advertises exactly what is implemented.
ldapsearch -x -LLL -H "$H" -b '' -s base '(objectClass=*)' supportedExtension > "$W/out" 2>&1 || fail "rootDSE search"
for oid in 1.3.6.1.4.1.1466.20037 1.3.6.1.4.1.4203.1.11.3 1.3.6.1.4.1.4203.1.11.1 1.3.6.1.1.8; do
  grep -qx "supportedExtension: $oid" "$W/out" || fail "rootDSE supportedExtension lacks $oid"
done
echo "ok: rootDSE supportedExtension: $(grep -c '^supportedExtension' "$W/out") OIDs"

# 2. Who am I.
ldapwhoami -x -H "$H" > "$W/out" 2>&1 || fail "anonymous ldapwhoami"
grep -qx "anonymous" "$W/out" || fail "anonymous ldapwhoami did not answer anonymous"
ldapwhoami -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" > "$W/out" 2>&1 || fail "ldapwhoami as administrator"
grep -qx "dn:$ADMIN" "$W/out" || fail "ldapwhoami did not name the administrator"
echo "ok: Who am I: anonymous, then $(cat "$W/out")"

# 3. StartTLS.
LDAPTLS_REQCERT=never ldapwhoami -ZZ -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" > "$W/out" 2>&1 || fail "ldapwhoami -ZZ (StartTLS)"
grep -qx "dn:$ADMIN" "$W/out" || fail "ldapwhoami -ZZ did not name the administrator"
echo "ok: StartTLS, then Who am I over TLS: $(cat "$W/out")"

# 4. Password Modify.
if ldappasswd -x -H "$H" -s 'Anonymous123!' "cn=alice,$BASE" > "$W/out" 2>&1; then fail "anonymous ldappasswd was accepted"; fi
grep -qi "insufficient access" "$W/out" || fail "anonymous ldappasswd: not insufficientAccessRights"
echo "ok: anonymous ldappasswd refused ($(grep -i 'insufficient' "$W/out" | head -1))"
ldappasswd -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" -s 'AliceNew123!' "cn=alice,$BASE" > "$W/out" 2>&1 || fail "ldappasswd alice"
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
echo 'AliceNew123!' | env -u OPENSSL_CONF kinit "alice@$REALM" > "$W/out" 2>&1 || fail "kinit alice with the ldappasswd password"
if echo 'AliceKrb123!' | env -u OPENSSL_CONF kinit "alice@$REALM" > "$W/out" 2>&1; then fail "kinit alice still takes the old password"; fi
echo "ok: ldappasswd set alice's password: kinit with the new one works, the old one is refused"

# 5 + 6. Cancel and an unknown OID, with raw BER on one connection.
python3 -I - "127.0.0.1" "$((P + 6))" "$ADMIN" "$ADMIN_PW" > "$W/out" 2>&1 <<'PY' || fail "Cancel / unknown extended operation"
import socket, sys
host, port, dn, pw = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(), sys.argv[4].encode()

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(lb)]) + lb + body

def integer(v):
    return tlv(0x02, v.to_bytes((v.bit_length() + 8) // 8, "big"))

def msg(mid, op):
    return tlv(0x30, integer(mid) + op)

def ext(oid, value=None):
    body = tlv(0x80, oid)
    if value is not None:
        body += tlv(0x81, value)
    return tlv(0x77, body)

def read_tlv(buf, i):
    tag, n = buf[i], buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n

s = socket.create_connection((host, port), timeout=10)
f = s.makefile("rb")

def recv():
    head = f.read(2)
    n = head[1]
    extra = b""
    if n & 0x80:
        extra = f.read(n & 0x7F)
        n = int.from_bytes(extra, "big")
    body = f.read(n)
    _, mid, i = read_tlv(body, 0)
    tag, op, _ = read_tlv(body, i)
    _, code, j = read_tlv(op, 0)
    _, _matched, j = read_tlv(op, j)
    _, diag, j = read_tlv(op, j)
    rest = op[j:]
    return int.from_bytes(mid, "big"), tag, code[0], diag.decode(), rest

def expect(mid, want_code, what):
    rmid, tag, code, diag, rest = recv()
    assert rmid == mid, f"{what}: response to message {rmid}, wanted {mid}"
    assert code == want_code, f"{what}: result code {code} ({diag!r}), wanted {want_code}"
    print(f"ok: {what}: resultCode {code} {diag!r}")
    return tag, diag, rest

s.sendall(msg(1, tlv(0x60, integer(3) + tlv(0x04, dn) + tlv(0x80, pw))))
expect(1, 0, "simple bind")
s.sendall(msg(2, ext(b"1.3.6.1.4.1.4203.1.11.3")))
expect(2, 0, "Who am I")
cancel = lambda target: tlv(0x30, integer(target))
s.sendall(msg(3, ext(b"1.3.6.1.1.8", cancel(99))))
expect(3, 119, "Cancel of an unknown id is noSuchOperation")
s.sendall(msg(4, ext(b"1.3.6.1.1.8", cancel(2))))
_, _, rest = expect(4, 120, "Cancel of the completed Who am I is tooLate")
assert rest == b"", f"Cancel response carries a responseName/value: {rest!r}"
s.sendall(msg(5, ext(b"1.3.6.1.1.8", cancel(1))))
expect(5, 121, "Cancel of the bind is cannotCancel")
s.sendall(msg(6, ext(b"1.3.6.1.1.8")))
expect(6, 2, "Cancel with no value is protocolError")
s.sendall(msg(7, ext(b"1.2.3.4.5.6")))
tag, diag, rest = expect(7, 2, "unknown extended operation is protocolError")
assert tag == 0x78, f"unknown extended operation answered with tag {tag:#x}"
assert "1.2.3.4.5.6" in diag and "not implemented" not in diag, f"diagnostic does not name the OID: {diag!r}"
assert rest == b"", f"unknown extended operation response carries a responseName: {rest!r}"
s.sendall(msg(8, tlv(0x42, b"")))  # unbind
PY
cat "$W/out"

echo "PASS: LDAP extended operations: StartTLS, Who am I, Password Modify, Cancel; unknown OIDs refused by name"
