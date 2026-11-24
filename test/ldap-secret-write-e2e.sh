#!/usr/bin/env bash
# LDAP never writes the KDC's credential attributes (#75).
#
#   test/ldap-secret-write-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd and iron-ldapd, and,
# bound as the domain's administrator (the strongest LDAP identity there is):
#  1. ldapadd of an entry carrying krbPrincipalName: krbtgt/<REALM>@EVIL.LO and
#     a krbKey (a planted inter-realm trust) is refused, unwillingToPerform
#     (53), and nothing is stored: no entry, no principal-name index hit;
#     so is an ldapadd whose RDN is krbPrincipalName=...;
#  2. ldapmodify of krbtgt's krbKey (replace), of administrator's krbKey
#     (delete), krbSalt, krbPwdHistory, netlogonNTOWF, pwdLastSet and
#     krbPrincipalName (add), in any case and with an attribute option, is
#     refused (53); a modify that also changes `description` changes nothing
#     (all or nothing); krbtgt and administrator read back byte for byte as
#     before (uSNChanged included), and kinit administrator still works;
#  3. modrdn to a krbPrincipalName= RDN is refused (53);
#  4. what stays allowed: ldapadd of a user without those attributes, an
#     ordinary modify, and RFC 3062 Password Modify (ldappasswd), after which
#     kinit takes the new password.
# Needs curl, kinit, ldapadd, ldapmodify, ldapmodrdn, ldappasswd, ldapsearch
# and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/secwe2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5, LDAP P+6, health P+7
PID_ID="sw$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
ADMIN="cn=administrator,$BASE"
KRBTGT="cn=krbtgt,$BASE"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; grep -v "error_code=25 " "$f" | tail -25; done; exit 1; }
for t in curl kinit ldapadd ldapmodify ldapmodrdn ldappasswd ldapsearch; do command -v "$t" >/dev/null || fail "$t is not installed"; done

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd -p iron-ldap --bin iron-ldapd > "$W/cargo.log" 2>&1 ||
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
can_kinit() { echo "$2" | env -u OPENSSL_CONF kinit "$1@$REALM" >/dev/null 2>&1; }
can_kinit administrator 'AdminPass123!' || fail "kinit administrator before anything"

H="ldap://127.0.0.1:$((P + 6))"
AUTH=(-x -H "$H" -D "$ADMIN" -w 'AdminPass123!')
snap() { ldapsearch "${AUTH[@]}" -LLL -o ldif-wrap=no -b "$1" -s base '*' '+' 2>&1; }
# expect_53 <what> <command...>: the command fails with LDAP result 53 and a
# diagnostic naming the attribute ("not writable over LDAP").
expect_53() {
  local what=$1; shift
  set +e; "$@" > "$W/out" 2>&1; local rc=$?; set -e
  [ "$rc" = 53 ] || { cat "$W/out"; fail "$what: exit $rc, want 53 (unwillingToPerform)"; }
  grep -q "not writable over LDAP" "$W/out" || { cat "$W/out"; fail "$what: the refusal does not say why"; }
}
krbtgt0=$(snap "$KRBTGT"); admin0=$(snap "$ADMIN")
grep -qi "^krbkey:" <<< "$krbtgt0" || fail "krbtgt has no krbkey to protect (read: $krbtgt0)"

# 1. A planted trust.
cat > "$W/trust.ldif" <<LDIF
dn: cn=evil-trust,$BASE
objectClass: top
objectClass: person
cn: evil-trust
sn: x
krbPrincipalName: krbtgt/$REALM@EVIL.LO
krbKey: 20:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
LDIF
expect_53 "ldapadd of a planted cross-realm key" ldapadd "${AUTH[@]}" -f "$W/trust.ldif"
set +e; ldapsearch "${AUTH[@]}" -LLL -b "cn=evil-trust,$BASE" -s base dn > "$W/out" 2>&1; rc=$?; set -e
[ "$rc" = 32 ] || { cat "$W/out"; fail "the refused entry exists (search exit $rc, want 32 noSuchObject)"; }
[ -z "$(ldapsearch "${AUTH[@]}" -LLL -b "$BASE" "(krbPrincipalName=krbtgt/$REALM@EVIL.LO)" dn)" ] || fail "a principal krbtgt/$REALM@EVIL.LO is findable"
cat > "$W/rdn.ldif" <<LDIF
dn: krbPrincipalName=evil@$REALM,$BASE
objectClass: top
objectClass: person
cn: evil
sn: x
LDIF
expect_53 "ldapadd with a krbPrincipalName RDN" ldapadd "${AUTH[@]}" -f "$W/rdn.ldif"
echo "== 1. ldapadd of krbPrincipalName krbtgt/$REALM@EVIL.LO + krbKey (and a krbPrincipalName RDN): 53, nothing stored"

# 2. Modifies of key material, whoever is bound.
mod() { printf 'dn: %s\nchangetype: modify\n%s\n' "$1" "$2" > "$W/mod.ldif"; ldapmodify "${AUTH[@]}" -f "$W/mod.ldif"; }
expect_53 "replace krbtgt's krbKey" mod "$KRBTGT" $'replace: krbKey\nkrbKey: 20:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
expect_53 "delete administrator's krbKey" mod "$ADMIN" $'delete: krbKey'
expect_53 "replace KRBSALT" mod "$ADMIN" $'replace: KRBSALT\nKRBSALT: 00'
expect_53 "replace krbPwdHistory" mod "$ADMIN" $'replace: krbPwdHistory\nkrbPwdHistory: x'
expect_53 "add netlogonNTOWF" mod "$ADMIN" $'add: netlogonNTOWF\nnetlogonNTOWF: 00'
expect_53 "replace pwdLastSet" mod "$ADMIN" $'replace: pwdLastSet\npwdLastSet: 0'
expect_53 "add krbPrincipalName" mod "$ADMIN" $'add: krbPrincipalName\nkrbPrincipalName: krbtgt/'"$REALM"'@EVIL.LO'
expect_53 "krbKey with an option" mod "$ADMIN" $'replace: krbKey;binary\nkrbKey;binary: 00'
expect_53 "description + krbSalt in one modify" mod "$ADMIN" $'replace: description\ndescription: changed\n-\nreplace: krbSalt\nkrbSalt: 00'
[ "$(snap "$KRBTGT")" = "$krbtgt0" ] || { diff <(echo "$krbtgt0") <(snap "$KRBTGT"); fail "krbtgt changed"; }
[ "$(snap "$ADMIN")" = "$admin0" ] || { diff <(echo "$admin0") <(snap "$ADMIN"); fail "administrator changed"; }
rm -f "$W/cc"; can_kinit administrator 'AdminPass123!' || fail "kinit administrator after the refused modifies"
echo "== 2. modifies of krbKey/krbSalt/krbPwdHistory/netlogonNTOWF/pwdLastSet/krbPrincipalName: 53; krbtgt and administrator unchanged; kinit works"

# 3. modrdn into a krbPrincipalName RDN.
cat > "$W/bob.ldif" <<LDIF
dn: cn=bob,$BASE
objectClass: top
objectClass: person
objectClass: user
cn: bob
sn: b
sAMAccountName: bob
LDIF
ldapadd "${AUTH[@]}" -f "$W/bob.ldif" > "$W/out" 2>&1 || { cat "$W/out"; fail "ldapadd of a plain user"; }
expect_53 "modrdn to krbPrincipalName=" ldapmodrdn "${AUTH[@]}" "cn=bob,$BASE" "krbPrincipalName=bob@$REALM"
echo "== 3. modrdn to a krbPrincipalName RDN: 53"

# 4. What stays allowed.
mod "cn=bob,$BASE" $'replace: description\ndescription: an ordinary change' > "$W/out" 2>&1 || { cat "$W/out"; fail "an ordinary modify"; }
ldappasswd "${AUTH[@]}" -s 'BobPass123!' "cn=bob,$BASE" > "$W/out" 2>&1 || { cat "$W/out"; fail "ldappasswd (RFC 3062)"; }
rm -f "$W/cc"; can_kinit bob 'BobPass123!' || fail "kinit bob with the Password Modify password"
echo "== 4. plain ldapadd, ordinary modify and Password Modify still work; kinit bob takes the new password"

echo "PASS: LDAP Add/Modify/ModDN refuse the KDC's credential attributes (#75)"
