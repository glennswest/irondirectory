#!/usr/bin/env bash
# DC-locator DNS records (#87, MS-ADTS 6.3.2.3): what Windows' DsGetDcName
# looks up before its LDAP ping.
#
#   test/dc-locator-dns-e2e.sh
#
# Builds MicroDNS from its repository at MICRODNS_REF and irondirectory, then
# re-runs itself in an unprivileged user + network + mount namespace
# (`unshare -rnm`): root there, with a loopback and an /etc/resolv.conf of its
# own, so MicroDNS can answer on 127.0.0.1:53 and iron-ldapd's CLDAP on UDP
# 389. A throwaway fastetcd, iron-bootstrap (domain GUID), iron-ldapd with the
# forest registry, then:
#  0. Samba's DC locator (`net ads lookup`, no server named) does NOT find a
#     DC before the records exist, nor with only what `iron-dns-ctl ldap` and
#     `kerberos` publish (`_ldap._tcp`, `_kerberos._*`) plus the DC's A record;
#  1. `iron-dns-ctl dc` publishes the 13 records; DNS answers every one with
#     the DC host and the right port (389 LDAP, 88 Kerberos, 464 kpasswd);
#  2. re-running it leaves one answer per name (idempotent);
#  3. a child domain's DC: its records in the child zone, its domain-GUID
#     record in the forest zone; no GC record anywhere;
#  4. Samba's DC locator now finds the DC by DNS alone (realm, no -S) and its
#     CLDAP ping answers: dc1.<domain>, LOGON_SAM_LOGON_RESPONSE_EX, the GUID.
# DNS queries go through dnspython (an independent client; the build VM has
# no dig).
# Needs curl, git, net (samba-common-tools), unshare, ip, mount, protoc
# (MicroDNS's gRPC codegen), python3 with dnspython, and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
MDNS_REF=${MICRODNS_REF:-e10faa714dd8}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; tail -25 "$f"; done; exit 1; }
if [ -z "${DCLOC_E2E_NS:-}" ]; then
  mkdir -p "$PWD/tmp"
  W=$(mktemp -d "$PWD/tmp/dclocdns.XXXX")
  for t in curl git net unshare ip mount protoc python3; do command -v "$t" >/dev/null || fail "$t is not installed"; done
  python3 -I -c "import dns.resolver" 2>/dev/null || fail "python3 has no dnspython"
  curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
  git clone -q https://github.com/glennswest/microdns "$W/microdns"
  git -C "$W/microdns" checkout -q "$MDNS_REF"
  grep -q '^\[workspace\]' "$W/microdns/Cargo.toml" || printf '\n[workspace]\n' >> "$W/microdns/Cargo.toml"
  cargo build --release --manifest-path "$W/microdns/Cargo.toml" > "$W/microdns-build.txt" 2>&1 ||
    { tail -40 "$W/microdns-build.txt"; fail "MicroDNS did not build at $MDNS_REF"; }
  MDNS_BIN=
  for d in "${CARGO_TARGET_DIR:-}" "$W/microdns/target"; do
    [ -n "$d" ] && [ -x "$d/release/microdns" ] && { MDNS_BIN=$d/release/microdns; break; }
  done
  [ -x "$MDNS_BIN" ] || fail "no microdns binary after the build"
  echo "== MicroDNS $(git -C "$W/microdns" rev-parse --short=12 HEAD)"
  cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-ldap --bin iron-ldapd -p iron-dns --bin iron-dns-ctl > "$W/cargo.log" 2>&1 ||
    { tail -30 "$W/cargo.log"; fail "building irondirectory"; }
  exec unshare -rnm env DCLOC_E2E_NS=1 W="$W" MDNS_BIN="$MDNS_BIN" B="${CARGO_TARGET_DIR:-target}/release" bash "$0"
fi
ip link set lo up
printf 'nameserver 127.0.0.1\noptions timeout:2 attempts:1\n' > "$W/resolv.conf"
mount --bind "$W/resolv.conf" /etc/resolv.conf
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, LDAP TCP P+3, health P+4, metrics P+5, MicroDNS API P+6, dashboard P+7
PID_ID="dl$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
DOMAIN="${PID_ID}.example.lo"
REALM=$(echo "$DOMAIN" | tr a-z A-Z)
NETBIOS=$(echo "$PID_ID" | tr a-z A-Z)
DC="dc1.$DOMAIN"
# dq TYPE NAME: the answers, one per line, like dig +short (empty when none).
dq() {
  python3 -I - "$1" "$2" <<'PY'
import sys, dns.resolver
r = dns.resolver.Resolver(configure=False)
r.nameservers, r.port, r.lifetime = ["127.0.0.1"], 53, 4
try:
    for rr in r.resolve(sys.argv[2], sys.argv[1]):
        print(rr.to_text())
except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
    pass
PY
}
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cat > "$W/microdns.toml" <<EOF
[instance]
id = "dcloc-e2e"
mode = "standalone"

[dns.auth]
enabled = true
listen = "127.0.0.1:53"
zones = []

[api.rest]
enabled = true
listen = "127.0.0.1:$((P + 6))"
dashboard_listen = "127.0.0.1:$((P + 7))"

[database]
path = "$W/microdns.redb"

[logging]
level = "info"
format = "text"
EOF
"$MDNS_BIN" --config "$W/microdns.toml" > "$W/microdns.log" 2>&1 & pids+=($!)
API=http://127.0.0.1:$((P + 6))/api/v1
for _ in $(seq 50); do curl -sf "$API/zones" >/dev/null && break; sleep 0.2; done
curl -sf "$API/zones" >/dev/null || fail "MicroDNS API does not answer"

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
GUID=$(sed 's/\x1b\[[0-9;]*m//g' "$W/bootstrap.log" | grep -o 'domain_guid=[0-9a-f-]*' | head -1 | cut -d= -f2)
[ ${#GUID} = 36 ] || fail "no domain GUID from iron-bootstrap"

IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_CONFIG_FASTETCD_ENDPOINT=$E IRON_LDAP_CONFIG_PARTITION_ID=${PID_ID}-config IRON_LDAP_CONFIG_BASE_DN=cn=configuration,$BASE \
  IRON_LDAP_DC_HOSTNAME=dc1 IRON_LDAP_LISTEN=127.0.0.1:$((P + 3)) IRON_LDAP_CLDAP_LISTEN=127.0.0.1:389 \
  IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 4)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 4))/health" >/dev/null && break; sleep 0.5; done
grep -q "listening (CLDAP" "$W/ldapd.log" || fail "iron-ldapd opened no CLDAP listener"
echo "== domain $DOMAIN, GUID $GUID; MicroDNS on 127.0.0.1:53, CLDAP on UDP 389"

mkdir -p "$W/samba"
cat > "$W/smb.conf" <<EOF
[global]
    workgroup = $NETBIOS
    realm = $REALM
    security = ads
    disable netbios = yes
    lock directory = $W/samba
    state directory = $W/samba
    cache directory = $W/samba
    private dir = $W/samba
    ncalrpc dir = $W/samba
EOF
lookup() { net -s "$W/smb.conf" -d 3 ads lookup > "$W/net-ads-lookup.out" 2>&1; }

# 0. No records yet: Samba's locator finds nothing.
lookup && { cat "$W/net-ads-lookup.out"; fail "net ads lookup found a DC before any DC-locator record existed"; }
echo "== 0. before publishing: net ads lookup finds no DC"
# 0b. What iron-dns-ctl published before #87 (_ldap._tcp, _kerberos._udp/_tcp)
# plus the DC's A record is not enough for the locator.
"$B/iron-dns-ctl" ldap "$API" "$DOMAIN" "$DC:389" > "$W/publish0.out" 2>&1 || { cat "$W/publish0.out"; fail "iron-dns-ctl ldap"; }
"$B/iron-dns-ctl" kerberos "$API" "$REALM" "$DC:88" >> "$W/publish0.out" 2>&1 || { cat "$W/publish0.out"; fail "iron-dns-ctl kerberos"; }
ZID=$(curl -sf "$API/zones" | python3 -I -c "import json,sys; print([z['id'] for z in json.load(sys.stdin) if z['name'].rstrip('.')=='$DOMAIN'][0])")
curl -sf -X POST -H 'Content-Type: application/json' "$API/zones/$ZID/records" \
  -d '{"name":"dc1","ttl":300,"data":{"type":"A","data":"127.0.0.1"},"enabled":true}' > /dev/null || fail "creating dc1's A record"
[ "$(dq A "$DC")" = 127.0.0.1 ] || fail "dc1's A record does not resolve"
[ "$(dq SRV "_ldap._tcp.$DOMAIN")" = "10 20 389 $DC." ] || fail "the plain _ldap._tcp record does not resolve"
rm -rf "$W/samba" && mkdir -p "$W/samba"
lookup && { cat "$W/net-ads-lookup.out"; fail "net ads lookup found a DC from the plain _ldap._tcp/_kerberos records alone"; }
echo "== 0b. with only _ldap._tcp/_kerberos (the old iron-dns-ctl ldap/kerberos) + the A record: still no DC"

"$B/iron-dns-ctl" dc "$API" "$DOMAIN" "$DOMAIN" "$GUID" "$DC" > "$W/publish.out" 2>&1 || { cat "$W/publish.out"; fail "iron-dns-ctl dc"; }
tail -1 "$W/publish.out"

# 1. Every name, its port and its target.
srv() { dq SRV "$1" | sort; }
S=Default-First-Site-Name
check() { # name port target -- asked as given (Windows' case) and lower-cased
  local got lower; got=$(srv "$1"); lower=$(srv "$(echo "$1" | tr A-Z a-z)")
  [ "$lower" = "10 20 $2 $3." ] || fail "SRV $(echo "$1" | tr A-Z a-z): got '$lower', want '10 20 $2 $3.'"
  [ "$got" = "10 20 $2 $3." ] || fail "SRV $1 (mixed case; the lower-case name answers): got '$got' -- MicroDNS matches names case-sensitively (RFC 4343)"
}
for n in "_ldap._tcp" "_ldap._tcp.$S._sites" "_ldap._tcp.dc._msdcs" "_ldap._tcp.$S._sites.dc._msdcs" "_ldap._tcp.pdc._msdcs" "_ldap._tcp.$GUID.domains._msdcs"; do
  check "$n.$DOMAIN" 389 "$DC"
done
for n in "_kerberos._tcp" "_kerberos._udp" "_kerberos._tcp.$S._sites" "_kerberos._tcp.dc._msdcs" "_kerberos._tcp.$S._sites.dc._msdcs"; do
  check "$n.$DOMAIN" 88 "$DC"
done
for n in "_kpasswd._tcp" "_kpasswd._udp"; do check "$n.$DOMAIN" 464 "$DC"; done
[ -z "$(srv "_ldap._tcp.gc._msdcs.$DOMAIN")$(srv "_gc._tcp.$DOMAIN")" ] || fail "a GC record was published"
echo "== 1. all 13 DC-locator SRV names answer $DC (389/88/464); no GC record"

# 2. Idempotent.
"$B/iron-dns-ctl" dc "$API" "$DOMAIN" "$DOMAIN" "$GUID" "$DC" > "$W/publish2.out" 2>&1 || { cat "$W/publish2.out"; fail "iron-dns-ctl dc, second run"; }
check "_ldap._tcp.dc._msdcs.$DOMAIN" 389 "$DC"
check "_kerberos._tcp.dc._msdcs.$DOMAIN" 88 "$DC"
echo "== 2. a second run leaves one answer per name"

# 3. A child domain's DC, on other ports.
CHILD="eu.$DOMAIN"; CGUID=00112233-4455-4677-8899-aabbccddeeff; DC2="dc2.$CHILD"
"$B/iron-dns-ctl" dc "$API" "$CHILD" "$DOMAIN" "$CGUID" "$DC2" 1389 1088 1464 > "$W/publish3.out" 2>&1 || { cat "$W/publish3.out"; fail "iron-dns-ctl dc for the child"; }
check "_ldap._tcp.dc._msdcs.$CHILD" 1389 "$DC2"
check "_kerberos._tcp.dc._msdcs.$CHILD" 1088 "$DC2"
check "_kpasswd._udp.$CHILD" 1464 "$DC2"
check "_ldap._tcp.$CGUID.domains._msdcs.$DOMAIN" 1389 "$DC2"
[ -z "$(srv "_ldap._tcp.$CGUID.domains._msdcs.$CHILD")" ] || fail "the child's GUID record is in the child zone"
check "_ldap._tcp.dc._msdcs.$DOMAIN" 389 "$DC"
echo "== 3. child domain: its records in $CHILD, its GUID record in the forest zone $DOMAIN"

# 4. Samba's DC locator, by DNS alone (its cache cleared of step 0's miss).
rm -rf "$W/samba" && mkdir -p "$W/samba"
lookup || { cat "$W/net-ads-lookup.out"; fail "net ads lookup (no -S) after publishing"; }
grep -E "^(Information for Domain Controller|Response Type|GUID|Domain Controller):" "$W/net-ads-lookup.out"
grep -qE "^Information for Domain Controller:[[:space:]]+127\.0\.0\.1" "$W/net-ads-lookup.out" || fail "not the DC at 127.0.0.1"
grep -qE "^Response Type:[[:space:]]+LOGON_SAM_LOGON_RESPONSE_EX" "$W/net-ads-lookup.out" || fail "no EX response"
grep -qE "^GUID:[[:space:]]+$GUID" "$W/net-ads-lookup.out" || fail "wrong GUID"
grep -qE "^Domain Controller:[[:space:]]+$DC\$" "$W/net-ads-lookup.out" || fail "wrong DC name"
q=$(grep -oiE "_ldap\._tcp\.[A-Za-z0-9._-]*_msdcs\.$DOMAIN" "$W/net-ads-lookup.out" | sort -u | tr '\n' ' ' || true)
echo "== 4. Samba's locator found $DC by DNS (queried: ${q:-<not logged>}) and its CLDAP ping answered"

echo "PASS: DC-locator SRV records published and used by Samba's DC locator (#87)"
