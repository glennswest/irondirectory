#!/usr/bin/env bash
# The server half of the macOS light path (#22): what the macOS LDAPv3
# plugin, with Directory Utility's "RFC2307 (Unix)" mappings, asks iron-ldapd,
# and the Kerberos TGT a Mac gets from iron-kdcd. The Mac half is
# docs/MACOS-LDAP-KERBEROS.md, run on a real Mac.
#
#   test/macos-ldap-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd and iron-ldapd on
# high ports, provisions alice as the runbook does (iron-kdc-ctl set-password,
# then ldapmodify for the posix attributes and userPassword) and a posixGroup,
# then checks, with real ldapsearch/ldapwhoami/kinit:
#  1. the plugin's lookups, anonymous as it binds by default: a user by
#     RecordName (uid), by UniqueID (uidNumber), all users, a name search
#     (dscl -search / Directory Utility: substring on uid or cn), a group by
#     PrimaryGroupID (gidNumber), groups by GroupMembership (memberUid) --
#     each with the attributes the mapping reads, and no userPassword;
#  2. the plugin's password check (an LDAP simple bind as the user's DN, what
#     `dscl ... -authonly` and login do without Kerberos): right password
#     accepted, wrong refused;
#  3. kinit alice@REALM with her Kerberos password.
# Needs curl, kinit, ldapsearch, ldapmodify, ldapadd, ldapwhoami and a FIPS
# OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/mace2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5, LDAP P+6, health P+7
PID_ID="mac$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
ADMIN="cn=administrator,$BASE" ADMIN_PW='AdminPass123!'
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; [ -s "$W/out" ] && cat "$W/out"; for f in "$W"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -v "error_code=25 " | tail -20; done; exit 1; }
for t in curl kinit ldapsearch ldapmodify ldapadd ldapwhoami; do command -v "$t" >/dev/null || fail "$t is not installed"; done

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

export IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM
IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 6)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 7)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null && break; sleep 0.5; done
H=ldap://127.0.0.1:$((P + 6))
echo "== domain $BASE, realm $REALM; iron-ldapd :$((P + 6)), iron-kdcd :$((P + 3))"

# Provision as docs/MACOS-LDAP-KERBEROS.md does: the Kerberos principal
# first (it creates cn=alice), then the posix attributes and the LDAP
# password on the same entry.
$B/iron-kdc-ctl set-password alice 'AliceKrb123!' > /dev/null
ldapmodify -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" > "$W/out" 2>&1 <<LDIF || fail "ldapmodify alice"
dn: cn=alice,$BASE
changetype: modify
add: objectClass
objectClass: inetOrgPerson
objectClass: posixAccount
-
add: uid
uid: alice
-
add: sn
sn: Liddell
-
add: uidNumber
uidNumber: 5001
-
add: gidNumber
gidNumber: 5000
-
add: homeDirectory
homeDirectory: /Users/alice
-
add: loginShell
loginShell: /bin/zsh
-
add: userPassword
userPassword: AliceLdap123!
LDIF
ldapadd -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" > "$W/out" 2>&1 <<LDIF || fail "ldapadd group"
dn: cn=ironstaff,$BASE
objectClass: top
objectClass: posixGroup
cn: ironstaff
gidNumber: 5000
memberUid: alice
LDIF
echo "== provisioned alice (posixAccount + Kerberos keys) and group ironstaff (posixGroup)"

# 1. The plugin's lookups (anonymous).
q() { # <what> <filter> <expected regex>... ; the attributes the RFC2307 mapping reads
  local what=$1 filter=$2; shift 2
  ldapsearch -x -LLL -H "$H" -b "$BASE" "$filter" uid cn uidNumber gidNumber homeDirectory loginShell memberUid userPassword > "$W/out" 2>&1 ||
    fail "$what: ldapsearch $filter"
  for re in "$@"; do grep -qiE "$re" "$W/out" || fail "$what: no line matching '$re' for $filter"; done
  grep -qi '^userPassword' "$W/out" && fail "$what: userPassword returned to an anonymous search"
  echo "ok: $what  $filter"
}
q "user by RecordName" '(&(objectClass=posixAccount)(uid=alice))' '^uidNumber: 5001$' '^gidNumber: 5000$' '^homeDirectory: /Users/alice$' '^loginShell: /bin/zsh$' '^cn: alice$'
q "user by UniqueID" '(&(objectClass=posixAccount)(uidNumber=5001))' '^uid: alice$'
q "every user" '(objectClass=posixAccount)' '^uid: alice$'
q "user name search" '(&(objectClass=posixAccount)(|(uid=ali*)(cn=ali*)))' '^uid: alice$'
q "user with inetOrgPerson" '(&(objectClass=inetOrgPerson)(objectClass=posixAccount)(uid=alice))' '^uid: alice$'
q "group by PrimaryGroupID" '(&(objectClass=posixGroup)(gidNumber=5000))' '^cn: ironstaff$' '^memberUid: alice$'
q "groups by GroupMembership" '(&(objectClass=posixGroup)(memberUid=alice))' '^cn: ironstaff$'
ldapsearch -x -LLL -H "$H" -b "$BASE" '(&(objectClass=posixAccount)(uid=nobody))' uid > "$W/out" 2>&1 || fail "lookup of a missing user errored"
[ -s "$W/out" ] && fail "a missing user returned entries"
echo "ok: a missing user returns nothing"

# 2. The plugin's password check: a simple bind as the user's DN.
ldapwhoami -x -H "$H" -D "cn=alice,$BASE" -w 'AliceLdap123!' > "$W/out" 2>&1 || fail "LDAP bind as alice with her password"
grep -q "dn:cn=alice,$BASE" "$W/out" || fail "ldapwhoami did not name alice"
echo "ok: LDAP bind as alice ($(cat "$W/out"))"
if ldapwhoami -x -H "$H" -D "cn=alice,$BASE" -w 'WrongPass123!' > "$W/out" 2>&1; then fail "a wrong password was accepted"; fi
echo "ok: a wrong password is refused ($(head -1 "$W/out"))"

# 3. Kerberos: a TGT for alice.
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
echo 'AliceKrb123!' | env -u OPENSSL_CONF kinit "alice@$REALM" > "$W/out" 2>&1 || fail "kinit alice@$REALM"
env -u OPENSSL_CONF klist > "$W/out" 2>&1 || fail "klist"
grep -q "krbtgt/$REALM@$REALM" "$W/out" || fail "no TGT in the cache"
echo "ok: kinit alice@$REALM: $(grep -o "krbtgt/$REALM@$REALM" "$W/out")"

echo "PASS: macOS light path, server half: RFC2307 lookups, LDAP bind auth, Kerberos TGT"
