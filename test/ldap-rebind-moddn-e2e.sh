#!/usr/bin/env bash
# Re-binds through a SASL security layer and subtree rename (#67), on
# iron-ldapd with real clients:
#
#   test/ldap-rebind-moddn-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd and iron-ldapd on
# high ports, gives alice and ldap/127.0.0.1 Kerberos keys, and checks:
#  1. re-binds on one connection (test/ldap_rebind_impacket.py, impacket's
#     Kerberos client + RFC 4752/4121 written out): GSSAPI with
#     confidentiality, then a simple and a failed simple bind through that
#     layer (it stays, RFC 4513 §5.2.1.4), then a GSSAPI re-bind selecting
#     integrity (it replaces the layer, RFC 4422 §3.8), then one selecting no
#     layer (the integrity layer stays);
#  2. modDN of a non-leaf entry with ldapmodify (rename + newSuperior): every
#     descendant moves, the old DNs are gone, deleteoldrdn applies;
#  3. modDN refusals: entryAlreadyExists (nothing half-moved after it),
#     newSuperior under the entry itself (unwillingToPerform), a missing
#     newSuperior (noSuchObject), the naming context head
#     (affectsMultipleDSAs);
#  4. Add (#71): an existing entry and the naming context head are
#     entryAlreadyExists (68) and stay unchanged; an entry whose parent does
#     not exist is noSuchObject (32) with matchedDN the nearest existing
#     ancestor; an add under an existing parent works.
# Needs curl, python3, ldapsearch, ldapadd, ldapmodify and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/rebinde2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, KDC P+3, kpasswd P+4, metrics P+5, LDAP P+6, health P+7
PID_ID="rebind$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
ADMIN="cn=administrator,$BASE" ADMIN_PW='AdminPass123!' ALICE_PW='AliceKrb123!'
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; [ -s "$W/out" ] && cat "$W/out"; for f in "$W"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | tail -20; done; exit 1; }
for t in curl python3 ldapsearch ldapadd ldapmodify; do command -v "$t" >/dev/null || fail "$t is not installed"; done
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
$B/iron-kdc-ctl set-password alice "$ALICE_PW" > /dev/null
$B/iron-kdc-ctl set-password ldap/127.0.0.1 'LdapService123!' > /dev/null

# 1. Re-binds through a security layer, one connection.
python3 -m venv "$W/venv" && "$W/venv/bin/pip" install -q impacket==0.13.1 > "$W/pip.out" 2>&1 || { tail -5 "$W/pip.out"; fail "pip install impacket"; }
"$W/venv/bin/python" -I "$PWD/test/ldap_rebind_impacket.py" $((P + 6)) $((P + 3)) "$REALM" ldap/127.0.0.1 "$BASE" \
  "$ALICE_PW" "$ADMIN_PW" > "$W/out" 2>&1 || fail "re-binds through a security layer"
cat "$W/out"

# 2. Subtree rename.
mod() { ldapmodify -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" > "$W/out" 2>&1; }
ldapadd -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" > "$W/out" 2>&1 <<LDIF || fail "ldapadd the tree"
dn: ou=eng,$BASE
objectClass: organizationalUnit
ou: eng

dn: cn=bob,ou=eng,$BASE
objectClass: person
cn: bob
sn: Builder

dn: ou=team,ou=eng,$BASE
objectClass: organizationalUnit
ou: team

dn: cn=carol,ou=team,ou=eng,$BASE
objectClass: person
cn: carol
sn: Coder

dn: ou=sales,$BASE
objectClass: organizationalUnit
ou: sales

dn: ou=taken,$BASE
objectClass: organizationalUnit
ou: taken
LDIF
mod <<LDIF || fail "modDN of ou=eng (a non-leaf) to ou=engineering under ou=sales"
dn: ou=eng,$BASE
changetype: modrdn
newrdn: ou=engineering
deleteoldrdn: 1
newsuperior: ou=sales,$BASE
LDIF
NEW="ou=engineering,ou=sales,$BASE"
ldapsearch -x -LLL -o ldif-wrap=no -H "$H" -b "$NEW" -s sub '(objectClass=*)' dn > "$W/out" 2>&1 || fail "search the moved subtree"
got=$(grep '^dn:' "$W/out" | tr 'A-Z' 'a-z' | sort | tr '\n' ' ')
want=$(printf 'dn: %s\n' "$NEW" "cn=bob,$NEW" "ou=team,$NEW" "cn=carol,ou=team,$NEW" | tr 'A-Z' 'a-z' | sort | tr '\n' ' ')
[ "$got" = "$want" ] || fail "moved subtree: got [$got], want [$want]"
ldapsearch -x -LLL -o ldif-wrap=no -H "$H" -b "$NEW" -s base '(objectClass=*)' ou > "$W/out" 2>&1 || fail "read the renamed entry"
grep -qx 'ou: engineering' "$W/out" && ! grep -qx 'ou: eng' "$W/out" || fail "deleteoldrdn: the renamed entry's ou is not just engineering"
ldapsearch -x -LLL -o ldif-wrap=no -H "$H" -b "cn=carol,ou=team,$NEW" -s base '(objectClass=*)' sn > "$W/out" 2>&1 || fail "read carol at her new DN"
grep -qx 'sn: Coder' "$W/out" || fail "carol's attributes did not move with her"
for old in "ou=eng,$BASE" "cn=bob,ou=eng,$BASE" "cn=carol,ou=team,ou=eng,$BASE"; do
  rc=0; ldapsearch -x -LLL -o ldif-wrap=no -H "$H" -b "$old" -s base '(objectClass=*)' dn > "$W/out" 2>&1 || rc=$?
  [ "$rc" = 32 ] || fail "old DN $old: search exit $rc, want 32 (noSuchObject)"
done
echo "ok: 2. modDN of a non-leaf (rename + newSuperior): 4 entries now under $NEW, old DNs noSuchObject, deleteoldrdn applied"

# 3. Refusals.
refused() { # <want rc> <what> ; LDIF on stdin
  local rc=0; mod || rc=$?
  [ "$rc" = "$1" ] || fail "$2: ldapmodify exit $rc, want $1"
  echo "ok: 3. $2 refused: $(grep -m1 -i 'ldap_rename\|result' "$W/out" || true)"
}
refused 68 "a move onto an existing DN (entryAlreadyExists)" <<LDIF
dn: $NEW
changetype: modrdn
newrdn: ou=taken
deleteoldrdn: 0
newsuperior: $BASE
LDIF
ldapsearch -x -LLL -o ldif-wrap=no -H "$H" -b "$NEW" -s sub '(objectClass=*)' dn > "$W/out" 2>&1 || fail "search after the refused move"
[ "$(grep -c '^dn:' "$W/out")" = 4 ] || fail "the refused move left the subtree changed"
ldapsearch -x -LLL -o ldif-wrap=no -H "$H" -b "ou=taken,$BASE" -s sub '(objectClass=*)' dn > "$W/out" 2>&1 || fail "search ou=taken"
[ "$(grep -c '^dn:' "$W/out")" = 1 ] || fail "the refused move left entries under ou=taken"
refused 53 "newSuperior below the entry itself (unwillingToPerform)" <<LDIF
dn: ou=sales,$BASE
changetype: modrdn
newrdn: ou=sales
deleteoldrdn: 0
newsuperior: ou=team,$NEW
LDIF
refused 32 "a newSuperior that does not exist (noSuchObject)" <<LDIF
dn: $NEW
changetype: modrdn
newrdn: ou=engineering
deleteoldrdn: 0
newsuperior: ou=nowhere,$BASE
LDIF
refused 71 "the naming context head (affectsMultipleDSAs)" <<LDIF
dn: $BASE
changetype: modrdn
newrdn: dc=renamed
deleteoldrdn: 0
LDIF

# 4. Add (#71): an existing DN is entryAlreadyExists and changes nothing; an
# entry needs its parent (noSuchObject, matchedDN the nearest ancestor).
add() { ldapadd -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" > "$W/out" 2>&1; }
add_refused() { # <want rc> <what> ; LDIF on stdin
  local rc=0; add || rc=$?
  [ "$rc" = "$1" ] || { cat "$W/out"; fail "$2: ldapadd exit $rc, want $1"; }
  echo "ok: 4. $2 refused: $(grep -i 'ldap_add\|matched\|additional' "$W/out" | tr '\n\t' '  ')"
}
add_refused 68 "an add of an existing entry (entryAlreadyExists)" <<LDIF
dn: cn=bob,$NEW
objectClass: person
cn: bob
sn: Overwriter
LDIF
ldapsearch -x -LLL -o ldif-wrap=no -H "$H" -b "cn=bob,$NEW" -s base '(objectClass=*)' sn > "$W/out" 2>&1 || fail "search cn=bob after the refused add"
grep -qx 'sn: Builder' "$W/out" || fail "the refused add changed cn=bob: $(cat "$W/out")"
add_refused 68 "an add of the naming context head (entryAlreadyExists)" <<LDIF
dn: $BASE
objectClass: top
objectClass: domain
dc: $PID_ID
LDIF
add_refused 32 "an add under a parent that does not exist (noSuchObject)" <<LDIF
dn: cn=orphan,ou=deeper,ou=nowhere,$BASE
objectClass: person
cn: orphan
LDIF
grep -qi "matched DN: $BASE\$" "$W/out" || fail "noSuchObject's matchedDN is not the nearest existing ancestor ($BASE): $(cat "$W/out")"
ldapsearch -x -LLL -H "$H" -b "$BASE" -s sub '(cn=orphan)' dn > "$W/out" 2>&1 || fail "search for the orphan"
grep -q '^dn:' "$W/out" && fail "the refused orphan was created"
add <<LDIF || fail "an add under an existing parent: $(cat "$W/out")"
dn: cn=dave,$NEW
objectClass: person
cn: dave
LDIF
echo "ok: 4. an add under an existing parent works"

# 5. Key escaping (#77, finding 0c66d8e55849): a '/' in a value is one key
# segment, so a subtree search under it returns its child at the right DN;
# cn=x\+sn=y (one AVA) and cn=x+sn=y (two AVAs) are two entries, not one key.
add <<LDIF || fail "add entries whose values hold '/' and '+': $(cat "$W/out")"
dn: ou=a/b,$NEW
objectClass: organizationalUnit
ou: a/b

dn: cn=c,ou=a/b,$NEW
objectClass: person
cn: c
sn: Slash

dn: cn=x\+sn=y,$NEW
objectClass: person
cn: x+sn=y
sn: OneAva

dn: cn=x+sn=y,$NEW
objectClass: person
cn: x
sn: y
LDIF
ldapsearch -x -LLL -o ldif-wrap=no -H "$H" -b "ou=a/b,$NEW" -s sub '(objectClass=*)' dn > "$W/out" 2>&1 || fail "subtree search under ou=a/b"
[ "$(grep -c '^dn:' "$W/out")" = 2 ] || fail "subtree under ou=a/b should hold 2 entries: $(cat "$W/out")"
grep -qix "dn: cn=c,ou=a/b,$NEW" "$W/out" || fail "cn=c came back at the wrong DN: $(cat "$W/out")"
ldapsearch -x -LLL -o ldif-wrap=no -H "$H" -b "$NEW" -s one '(sn=*)' dn sn > "$W/out" 2>&1 || fail "one-level search under $NEW"
grep -qx 'sn: OneAva' "$W/out" || fail "cn=x\\+sn=y is missing: $(cat "$W/out")"
grep -qx 'sn: y' "$W/out" || fail "cn=x+sn=y is missing: $(cat "$W/out")"
grep -qi 'dn: cn=x\\+sn' "$W/out" || fail "cn=x\\+sn=y came back at the wrong DN: $(cat "$W/out")"
echo "ok: 5. '/' and an escaped '+' in RDN values keep their own keys and DNs"

echo "PASS: re-binds keep or replace the SASL layer as RFC 4513/4422 say; subtree modDN moves every descendant; Add refuses existing DNs and orphans; RDN delimiters are escaped in keys"
