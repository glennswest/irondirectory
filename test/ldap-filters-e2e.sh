#!/usr/bin/env bash
# LDAP search filters through real ldapsearch (#27).
#
#   test/ldap-filters-e2e.sh
#
# Throwaway one-member fastetcd (FASTETCD_VERSION), a domain from
# iron-bootstrap, iron-ldapd and iron-gcd on high ports. Seeds people and
# computers with ldapadd, then checks each filter kind -- substrings,
# >=/<= (numeric, so 900 is not >= 1000), approx, the AD bitwise rules
# SSSD uses, caseExactMatch, an unknown rule under NOT (matches nothing,
# RFC 4511 Undefined) and the size limit -- against the exact set of
# entries it must return, on iron-ldapd and, for the shared filter code,
# iron-gcd. Needs curl, ldapadd, ldapsearch and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/filte2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, LDAP P+3, health P+4, GC P+5, GC health P+6, metrics P+7
PID_ID="flt$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; tail -15 "$f"; done; exit 1; }
for t in curl ldapadd ldapsearch; do command -v "$t" >/dev/null || fail "$t is not installed"; done

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 7))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-ldap --bin iron-ldapd -p iron-gc --bin iron-gcd 2>&1 | tail -1
B=${CARGO_TARGET_DIR:-target}/release

printf 'AdminPass123!\n' > "$W/password"
export IRON_BOOTSTRAP_FASTETCD_ENDPOINT=$E IRON_BOOTSTRAP_PARTITION_ID=$PID_ID IRON_BOOTSTRAP_BASE_DN=$BASE \
  IRON_BOOTSTRAP_REALM=$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO IRON_BOOTSTRAP_NETBIOS_NAME=$(echo "$PID_ID" | tr a-z A-Z) \
  IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE=$W/password
for attempt in 1 2 3 4 5; do
  $B/iron-bootstrap > "$W/bootstrap.log" 2>&1 & BS=$!; pids+=($BS)
  for _ in $(seq 60); do grep -q "provisioned" "$W/bootstrap.log" && break; kill -0 $BS 2>/dev/null || break; sleep 1; done
  grep -q "provisioned" "$W/bootstrap.log" && break
  [ "$attempt" = 5 ] && fail "iron-bootstrap did not provision"
  sleep 2
done

IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 3)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 4)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 4))/health" >/dev/null && break; sleep 0.5; done

person() { printf 'dn: cn=%s,%s\nobjectClass: top\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: %s\nuidNumber: %s\n\n' "$1" "$BASE" "$1" "$2"; }
computer() { printf 'dn: cn=%s,%s\nobjectClass: top\nobjectClass: computer\ncn: %s\nuserAccountControl: %s\n\n' "$1" "$BASE" "$1" "$2"; }
{ person "Alice Smith" 1500; person "Bob Jones" 900; person "Alan Turing" 2000
  computer TESTPC1 4098; computer TESTPC2 4096; } > "$W/seed.ldif"
ldapadd -x -H "ldap://127.0.0.1:$((P + 3))" -D "cn=administrator,$BASE" -w 'AdminPass123!' -f "$W/seed.ldif" > "$W/ldapadd.out" 2>&1 ||
  { cat "$W/ldapadd.out"; fail "seeding entries"; }

IRON_GC_CONFIG_FASTETCD_ENDPOINT=$E IRON_GC_CONFIG_PARTITION_ID=${PID_ID}-config IRON_GC_CONFIG_BASE_DN=cn=configuration,$BASE \
  IRON_GC_ATTRIBUTES=objectclass,cn,uidnumber,useraccountcontrol \
  IRON_GC_LISTEN=127.0.0.1:$((P + 5)) IRON_GC_HEALTH_LISTEN=127.0.0.1:$((P + 6)) $B/iron-gcd > "$W/gcd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 6))/health" | grep -q '"entries":[1-9]' && break; sleep 0.5; done

# cns of the entries `filter` returns on port $1, sorted, ';'-joined.
cns() { ldapsearch -LLL -x -H "ldap://127.0.0.1:$1" -b "$BASE" -s sub "$2" cn 2>/dev/null | sed -n 's/^cn: //p' | sort | paste -sd';' -; }
check() { # port, filter, expected
  local got; got=$(cns "$1" "$2")
  [ "$got" = "$3" ] || fail "$2 on :$1 returned [$got], expected [$3]"
  echo "ok  $2 -> [$3]"
}
L=$((P + 3)); G=$((P + 5))
check $L '(cn=al*)'                     'Alan Turing;Alice Smith'
check $L '(cn=*SMITH)'                  'Alice Smith'
check $L '(cn=a*i*g)'                   'Alan Turing'
check $L '(cn=b*o*s)'                   'Bob Jones'
check $L '(uidNumber>=1000)'            'Alan Turing;Alice Smith'
check $L '(uidNumber<=1500)'            'Alice Smith;Bob Jones'
check $L '(cn~=alice   SMITH)'          'Alice Smith'
check $L '(userAccountControl:1.2.840.113556.1.4.803:=2)' 'TESTPC1'
check $L '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' 'TESTPC2'
check $L '(userAccountControl:1.2.840.113556.1.4.804:=6)' 'TESTPC1'
check $L '(cn:caseExactMatch:=Alice Smith)' 'Alice Smith'
check $L '(cn:2.5.13.5:=alice smith)'   ''
check $L '(!(memberOf:1.2.840.113556.1.4.1941:=cn=x))' ''
check $G '(cn=al*)'                     'Alan Turing;Alice Smith'
check $G '(uidNumber>=1000)'            'Alan Turing;Alice Smith'
check $G '(userAccountControl:1.2.840.113556.1.4.803:=2)' 'TESTPC1'

# Size limit: one entry, then sizeLimitExceeded (4); not a silent cut.
set +e
out=$(ldapsearch -LLL -x -z 1 -H "ldap://127.0.0.1:$L" -b "$BASE" -s sub '(cn=al*)' cn 2>&1); rc=$?
set -e
[ "$rc" = 4 ] || fail "-z 1 exited $rc, expected 4 (sizeLimitExceeded): $out"
[ "$(echo "$out" | grep -c '^cn: ')" = 1 ] || fail "-z 1 returned other than one entry: $out"
echo "ok  -z 1 '(cn=al*)' -> one entry, then sizeLimitExceeded"
echo "PASS: LDAP filters on iron-ldapd and iron-gcd"
