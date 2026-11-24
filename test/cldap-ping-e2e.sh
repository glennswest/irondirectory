#!/usr/bin/env bash
# The LDAP ping (#52, MS-ADTS 6.3.3): how Windows finds a DC before it joins.
#
#   test/cldap-ping-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap (which now stores a domain GUID),
# and runs iron-ldapd with the forest registry, so it answers the ping on UDP
# (CLDAP) and TCP at the same address. Then:
#  1. Samba's own client, `net ads lookup` (CLDAP, decoded by Samba's NDR
#     code), reports this DC: the response type, the domain GUID iron-bootstrap
#     logged, the forest/domain/DC names, the NetBIOS names, the site, the
#     flags (PDC, LDAP, DS, KDC, writable; not GC, not a time server);
#  2. test/cldap_ping.py (written from the spec, no shared code) checks the
#     raw answer: entry + done in ONE datagram with the request's message id,
#     every NETLOGON_SAM_LOGON_RESPONSE_EX field, the names compressed, the
#     DcSockAddr for _WITH_IP, NextClosestSiteName for WITH_CLOSEST_SITE;
#  3. User/AAC: administrator is known (opcode 23); an unknown name, a
#     workstation account asked for as a normal account, and a disabled
#     workstation are unknown (25); the workstation asked for as one is 23;
#  4. a ping naming another DnsDomain, another DomainGuid or another
#     DomainSid gets a done with no entry; the right GUID and SID get one;
#  5. the same ping over TCP gets the same bytes; a CLDAP search that is not
#     a ping is refused (unwillingToPerform, 53);
#  6. rootDSE's dnsHostName is the DC name the ping gives.
# Samba's client only speaks to UDP 389 (4.24 has no `cldap port`), so after
# the download and the build the script re-runs itself in an unprivileged
# user + network namespace (`unshare -rn`): root there, on a loopback of its
# own, where iron-ldapd may bind 389.
# Needs curl, unshare, ip, ldapadd, ldapsearch, net (samba-common-tools),
# python3 and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; tail -25 "$f"; done; exit 1; }
if [ -z "${CLDAP_E2E_NS:-}" ]; then
  mkdir -p "$PWD/tmp"
  W=$(mktemp -d "$PWD/tmp/cldape2e.XXXX")
  for t in curl unshare ip ldapadd ldapsearch net python3; do command -v "$t" >/dev/null || fail "$t is not installed"; done
  curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
  cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-ldap --bin iron-ldapd > "$W/cargo.log" 2>&1 ||
    { tail -30 "$W/cargo.log"; fail "building irondirectory"; }
  exec unshare -rn env CLDAP_E2E_NS=1 W="$W" B="${CARGO_TARGET_DIR:-target}/release" bash "$0"
fi
ip link set lo up
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, LDAP TCP P+3, health P+4, metrics P+5; CLDAP UDP 389
PID_ID="cl$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
DOMAIN="${PID_ID}.example.lo"
REALM=$(echo "$DOMAIN" | tr a-z A-Z)
NETBIOS=$(echo "$PID_ID" | tr a-z A-Z)
DC="dc1.$DOMAIN"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

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
plain_log=$(sed 's/\x1b\[[0-9;]*m//g' "$W/bootstrap.log")
SID=$(echo "$plain_log" | grep -o 'domain_sid=S-1-5-21-[0-9-]*' | head -1 | cut -d= -f2)
GUID=$(echo "$plain_log" | grep -o 'domain_guid=[0-9a-f-]*' | head -1 | cut -d= -f2)
[ -n "$SID" ] || fail "no domain SID from iron-bootstrap"
[ ${#GUID} = 36 ] || fail "no domain GUID from iron-bootstrap (got '$GUID')"
echo "== domain $DOMAIN, SID $SID, GUID $GUID"

IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_CONFIG_FASTETCD_ENDPOINT=$E IRON_LDAP_CONFIG_PARTITION_ID=${PID_ID}-config IRON_LDAP_CONFIG_BASE_DN=cn=configuration,$BASE \
  IRON_LDAP_DC_HOSTNAME=dc1 IRON_LDAP_LISTEN=127.0.0.1:$((P + 3)) IRON_LDAP_CLDAP_LISTEN=127.0.0.1:389 IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 4)) \
  $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 4))/health" >/dev/null && break; sleep 0.5; done
grep -q "listening (CLDAP" "$W/ldapd.log" || fail "iron-ldapd opened no CLDAP listener"

# Two computer accounts: WS1$ (workstation, 4096) and WS2$ (disabled, 4098).
for n in 1 2; do
  uac=$([ $n = 1 ] && echo 4096 || echo 4098)
  cat > "$W/ws$n.ldif" <<LDIF
dn: cn=WS$n,$BASE
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
cn: WS$n
sAMAccountName: WS$n\$
userAccountControl: $uac
LDIF
  ldapadd -x -H "ldap://127.0.0.1:$((P + 3))" -D "cn=administrator,$BASE" -w 'AdminPass123!' -f "$W/ws$n.ldif" > "$W/ldapadd.out" 2>&1 ||
    { cat "$W/ldapadd.out"; fail "ldapadd of WS$n\$"; }
done

ping_() {
  local port=389
  [ "$1" = tcp ] && port=$((P + 3))
  python3 -I "$PWD/test/cldap_ping.py" "$1" 127.0.0.1 $port "${@:2}"
}
# jq-free field access: q JSON python-expression
q() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print(($2))" <<< "$1"; }

# 1. Samba's client.
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
mkdir -p "$W/samba"
net -s "$W/smb.conf" ads lookup -S 127.0.0.1 > "$W/net-ads-lookup.out" 2>&1 || { cat "$W/net-ads-lookup.out"; fail "net ads lookup"; }
cat "$W/net-ads-lookup.out"
expect_net() { grep -qiE "$1" "$W/net-ads-lookup.out" || fail "net ads lookup: no line matching '$1'"; }
expect_net "Response Type:[[:space:]]+LOGON_SAM_LOGON_RESPONSE_EX"
expect_net "GUID:[[:space:]]+$GUID"
expect_net "Forest:[[:space:]]+$DOMAIN\$"
expect_net "^Domain:[[:space:]]+$DOMAIN\$"
expect_net "Domain Controller:[[:space:]]+$DC\$"
expect_net "Pre-Win2k Domain:[[:space:]]+$NETBIOS\$"
expect_net "Pre-Win2k Hostname:[[:space:]]+DC1\$"
expect_net "Server Site Name ?:[[:space:]]+Default-First-Site-Name"
expect_net "Client Site Name ?:[[:space:]]+Default-First-Site-Name"
for f in "Is a PDC" "Is an LDAP server" "Supports DS" "Is running a KDC" "Is writable" "Is the closest DC"; do
  expect_net "$f\??:[[:space:]]+yes"
done
for f in "Is a GC of the forest" "Is running time services" "Is an RODC"; do
  grep -qiE "$f\??:[[:space:]]+yes" "$W/net-ads-lookup.out" && fail "net ads lookup says '$f: yes'"
done
echo "== 1. net ads lookup (Samba's CLDAP client) decodes this DC"

# 2. The raw answer, decoded from the spec.
r=$(ping_ udp DnsDomain=$DOMAIN Host=WS9 NtVer=0x1e)
echo "$r" > "$W/ping-full.json"
[ "$(q "$r" 'd["datagrams"], d["messages"], d["msgids"], d["result_code"], d["entry_dn"], d["netlogon_values"]')" = "(1, ['0x64', '0x65'], [7], 0, '', 1)" ] ||
  fail "UDP answer shape: $r"
want="23 0 $GUID $DOMAIN $DOMAIN $DC $NETBIOS DC1  Default-First-Site-Name Default-First-Site-Name"
got=$(q "$r" '" ".join(str(d["response"][k]) for k in ["opcode","sbz","domain_guid","forest","domain","host","netbios_domain","netbios_computer","user","dc_site","client_site"])')
[ "$got" = "$want" ] || fail "fields: got '$got', want '$want'"
[ "$(q "$r" 'd["response"]["sockaddr"]')" = "{'family': 2, 'ip': '127.0.0.1', 'port': 0, 'size': 16}" ] || fail "DcSockAddr: $r"
[ "$(q "$r" 'd["response"]["next_closest_site"], hex(d["response"]["nt_version"]), d["response"]["lmnt_token"], d["response"]["lm20_token"], d["response"]["trailing_bytes"]')" = "('', '0xd', 65535, 65535, 0)" ] ||
  fail "tail fields: $r"
[ "$(q "$r" 'd["response"]["compression_pointers"] >= 3')" = True ] || fail "names are not compressed: $r"
flags=$(q "$r" 'd["response"]["flags"]')
for bit in 0x1 0x8 0x10 0x20 0x80 0x100 0x20000000 0x40000000 0x80000000; do
  [ $((flags & bit)) != 0 ] || fail "flag $bit missing from $(printf %#x "$flags")"
done
for bit in 0x4 0x40 0x200; do
  [ $((flags & bit)) = 0 ] || fail "flag $bit claimed in $(printf %#x "$flags")"
done
r=$(ping_ udp DnsDomain=$DOMAIN NtVer=0x4)
[ "$(q "$r" '"sockaddr" in d["response"], hex(d["response"]["nt_version"]), d["response"]["trailing_bytes"]')" = "(False, '0x5', 0)" ] ||
  fail "plain 5EX answer: $r"
echo "== 2. raw NETLOGON_SAM_LOGON_RESPONSE_EX: every field, one datagram, flags $(printf %#x "$flags")"

# 3. User / AAC.
opcode() { q "$(ping_ udp DnsDomain=$DOMAIN NtVer=6 "$@")" 'd["response"]["opcode"], d["response"]["user"]'; }
[ "$(opcode User=administrator AAC=0x10)" = "(23, 'administrator')" ] || fail "administrator as a normal account: $(opcode User=administrator AAC=0x10)"
[ "$(opcode 'User=NOBODY$')" = "(25, 'NOBODY\$')" ] || fail "unknown user: $(opcode 'User=NOBODY$')"
[ "$(opcode 'User=WS1$' AAC=0x80)" = "(23, 'WS1\$')" ] || fail "WS1\$ as a workstation"
[ "$(opcode 'User=WS1$' AAC=0x10)" = "(25, 'WS1\$')" ] || fail "WS1\$ as a normal account must be unknown"
[ "$(opcode 'User=WS2$' AAC=0x80)" = "(25, 'WS2\$')" ] || fail "disabled WS2\$ must be unknown"
echo "== 3. User/AAC: known 23, unknown/wrong type/disabled 25"

# 4. Another domain gets no entry.
none() { q "$(ping_ udp NtVer=6 "$@")" '"entry_dn" in d, d["result_code"]'; }
[ "$(none DnsDomain=other.example.lo)" = "(False, 0)" ] || fail "another DnsDomain was answered"
[ "$(none DomainGuid=11111111-2222-4333-8444-555555555555)" = "(False, 0)" ] || fail "another DomainGuid was answered"
[ "$(none DomainSid=S-1-5-21-1-2-3)" = "(False, 0)" ] || fail "another DomainSid was answered"
[ "$(none DomainGuid=$GUID DomainSid=$SID "DnsDomain=$DOMAIN.")" = "(True, 0)" ] || fail "the right GUID/SID/DNS name (trailing dot) got no entry"
echo "== 4. pings for another domain get a done with no entry"

# 5. TCP gives the same bytes; a non-ping CLDAP search is refused.
u=$(q "$(ping_ udp DnsDomain=$DOMAIN NtVer=6 'User=WS1$')" 'd["netlogon_hex"]')
t=$(q "$(ping_ tcp DnsDomain=$DOMAIN NtVer=6 'User=WS1$')" 'd["netlogon_hex"]')
[ -n "$u" ] && [ "$u" = "$t" ] || fail "TCP answer differs from UDP: $t vs $u"
[ "$(q "$(ping_ udp DnsDomain=$DOMAIN Attr=namingContexts)" '"entry_dn" in d, d["result_code"]')" = "(False, 53)" ] ||
  fail "a non-ping CLDAP search was not refused"
echo "== 5. TCP ping == UDP ping; non-ping CLDAP search: unwillingToPerform"

# 6. rootDSE names the same DC.
ldapsearch -x -LLL -H "ldap://127.0.0.1:$((P + 3))" -b "" -s base dnsHostName ldapServiceName > "$W/rootdse.out"
grep -qx "dnsHostName: $DC" "$W/rootdse.out" || { cat "$W/rootdse.out"; fail "rootDSE dnsHostName"; }
grep -qx "ldapServiceName: $DOMAIN:dc1\\\$@$REALM" "$W/rootdse.out" || { cat "$W/rootdse.out"; fail "rootDSE ldapServiceName"; }
echo "== 6. rootDSE dnsHostName $DC"

echo "PASS: LDAP ping (CLDAP + TCP) answered from the forest registry"
