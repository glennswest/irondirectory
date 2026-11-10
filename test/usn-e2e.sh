#!/usr/bin/env bash
# D2's USN from etcd revisions (#28), against real iron-ldapd + ldapsearch.
#
#   test/usn-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-ldapd, then checks:
#  1. rootDSE's highestCommittedUSN is the store's revision: an integer that
#     grows with every write (it used to be a fixed "1");
#  2. an added entry has uSNCreated = uSNChanged, above the earlier
#     highestCommittedUSN, and highestCommittedUSN is then at least that;
#  3. a modify raises uSNChanged and keeps uSNCreated;
#  4. (uSNChanged>=N), the filter an AD client polls with, returns the
#     entries changed since N and not the ones before; past the highest
#     USN it returns nothing; uSNChanged comes back with `*`, as in AD.
# Needs curl, ldapsearch, ldapadd, ldapmodify and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/usne2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, metrics P+5, LDAP P+6, health P+7
PID_ID="usn$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
ADMIN="cn=administrator,$BASE" ADMIN_PW='AdminPass123!'
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; [ -s "$W/out" ] && cat "$W/out"; for f in "$W"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | tail -20; done; exit 1; }
for t in curl ldapsearch ldapadd ldapmodify; do command -v "$t" >/dev/null || fail "$t is not installed"; done

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-ldap --bin iron-ldapd 2>&1 | tail -1
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
IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 6)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 7)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null && break; sleep 0.5; done
H=ldap://127.0.0.1:$((P + 6))

# One attribute's single value from an LDIF search result (attribute names
# come back case-folded).
val() { ldapsearch -x -LLL -o ldif-wrap=no -H "$H" "$@" 2>"$W/out" | awk -v a="$ATTR" 'tolower($1)==tolower(a)":" {print $2; exit}'; }
hcu() { ATTR=highestCommittedUSN val -b "" -s base highestCommittedUSN; }
usn() { ATTR=$2 val -b "$1" -s base "$2"; } # <dn> <attr>
int() { [[ $1 =~ ^[0-9]+$ ]] || fail "$2: '$1' is not an integer"; }

# 1.
H0=$(hcu); int "$H0" "highestCommittedUSN"
[ "$H0" -gt 1 ] || fail "highestCommittedUSN is $H0 after bootstrap's writes"
echo "ok: highestCommittedUSN $H0 after bootstrap"

# 2.
ldapadd -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" > "$W/out" 2>&1 <<LDIF || fail "ldapadd"
dn: cn=usnprobe,$BASE
objectClass: top
objectClass: person
cn: usnprobe
sn: Probe
LDIF
C=$(usn "cn=usnprobe,$BASE" uSNCreated); int "$C" "uSNCreated"
M=$(usn "cn=usnprobe,$BASE" uSNChanged); int "$M" "uSNChanged"
[ "$C" = "$M" ] || fail "a new entry: uSNCreated $C, uSNChanged $M"
[ "$C" -gt "$H0" ] || fail "a new entry's uSNCreated $C is not above the earlier highestCommittedUSN $H0"
H1=$(hcu); [ "$H1" -ge "$C" ] || fail "highestCommittedUSN $H1 is below the new entry's USN $C"
echo "ok: added entry: uSNCreated = uSNChanged = $C > $H0; highestCommittedUSN now $H1"

# 3.
ldapmodify -x -H "$H" -D "$ADMIN" -w "$ADMIN_PW" > "$W/out" 2>&1 <<LDIF || fail "ldapmodify"
dn: cn=usnprobe,$BASE
changetype: modify
replace: sn
sn: Probed
LDIF
C2=$(usn "cn=usnprobe,$BASE" uSNCreated); M2=$(usn "cn=usnprobe,$BASE" uSNChanged); int "$M2" "uSNChanged after modify"
[ "$C2" = "$C" ] || fail "modify changed uSNCreated $C -> $C2"
[ "$M2" -gt "$M" ] || fail "modify did not raise uSNChanged ($M -> $M2)"
echo "ok: modify: uSNChanged $M -> $M2, uSNCreated stays $C"

# 4.
ldapsearch -x -LLL -H "$H" -b "$BASE" "(uSNChanged>=$M2)" dn > "$W/out" 2>&1 || fail "search (uSNChanged>=$M2)"
grep -q "cn=usnprobe" "$W/out" || fail "(uSNChanged>=$M2) misses the modified entry"
grep -qi "cn=administrator" "$W/out" && fail "(uSNChanged>=$M2) returned the administrator, unchanged since bootstrap"
echo "ok: (uSNChanged>=$M2) returns the changed entry only: $(grep -c '^dn:' "$W/out") entry"
NEXT=$(( $(hcu) + 1 ))
ldapsearch -x -LLL -H "$H" -b "$BASE" "(uSNChanged>=$NEXT)" dn > "$W/out" 2>&1 || fail "search (uSNChanged>=$NEXT)"
grep -q '^dn:' "$W/out" && fail "(uSNChanged>=$NEXT), past highestCommittedUSN, returned entries"
echo "ok: (uSNChanged>=$NEXT), past highestCommittedUSN, returns nothing"
ldapsearch -x -LLL -H "$H" -b "cn=usnprobe,$BASE" -s base '*' > "$W/out" 2>&1 || fail "search *"
grep -qi '^usnchanged:' "$W/out" || fail "uSNChanged not returned with *"
echo "ok: uSNCreated/uSNChanged come back with *"

echo "PASS: USN from etcd revisions (highestCommittedUSN, uSNCreated, uSNChanged, (uSNChanged>=N))"
