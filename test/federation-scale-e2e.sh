#!/usr/bin/env bash
# Federation at scale, the parts of #21 that are built (D10).
#
#   test/federation-scale-e2e.sh
#
# Two throwaway one-member fastetcd clusters (FASTETCD_VERSION), all
# daemons on high ports, everything torn down on exit.
#
# Suite A -- many partitions, many clusters, one forest:
#   iron-config-ctl init-forest, then CHILDREN (default 25) child domains,
#   every second one on the second cluster (IRON_CHILD_FASTETCD_ENDPOINT).
#   An iron-ldapd per child (each on its own partition and cluster) plus
#   the root's, which loads the forest registry. Checks:
#   - every child entry, added with ldapadd on its own child server, shows
#     in one iron-gcd search from the forest root (GC over N+1 partitions
#     on two clusters), and a child-scoped search returns only its own;
#   - for every child, a search on the root server returns a Referral to
#     that child's URL, and `ldapsearch -C` chases it to the child's entry;
#   - an add and a delete on a child of each cluster reach the GC while it
#     runs, each within STALE_MS.
#
# Suite B -- many forests, one federated GAL:
#   FORESTS (default 100) independent forests (separate init-forest), one
#   principal each (iron-kdc-ctl set-password), one iron-gcd over all of
#   them (IRON_GC_FORESTS) with a strict whitelist (objectclass,cn).
#   Checks: it converges (all FORESTS partitions ready, every entry
#   present) within CONVERGE_S; no Kerberos attribute (krbkey, krbsalt,
#   krbprincipalname) crosses into it; a new principal in every forest
#   appears within STALE_MS, measured from before the write command starts
#   (an upper bound); a delete in DELETE_SAMPLE forests (via a short-lived
#   iron-ldapd on that forest) disappears within STALE_MS.
#
# Prints the convergence time and the max/median staleness. Needs curl,
# ldapadd, ldapdelete, ldapsearch and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
CHILDREN=${CHILDREN:-25}
FORESTS=${FORESTS:-100}
DELETE_SAMPLE=${DELETE_SAMPLE:-5}
STALE_MS=${STALE_MS:-5000}
CONVERGE_S=${CONVERGE_S:-120}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/fede2e.XXXX")
# Ports: P+1..P+19 infrastructure, P+100+2i / P+101+2i child i's LDAP/health.
P=$((20000 + RANDOM % 8000 / 10 * 10))
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; tail -8 "$f"; done; exit 1; }
for t in curl ldapadd ldapdelete ldapsearch; do command -v "$t" >/dev/null || fail "$t is not installed"; done
[ $((P + 101 + 2 * CHILDREN)) -lt 32768 ] || fail "CHILDREN=$CHILDREN needs too many ports"
now_ms() { echo $(($(date +%s%N) / 1000000)); }
wait_health() { # url, what
  for _ in $(seq 60); do curl -sf "$1" >/dev/null && return 0; sleep 0.5; done
  fail "$2 never became healthy ($1)"
}

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
for c in 1 2; do # cluster c: client P+10c+1, peer P+10c+2, metrics P+10c+3
  o=$((P + 10 * c))
  "$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data$c" --listen-client-urls "http://127.0.0.1:$((o + 1))" \
    --advertise-client-urls "http://127.0.0.1:$((o + 1))" --listen-peer-urls "http://127.0.0.1:$((o + 2))" \
    --listen-metrics-url "127.0.0.1:$((o + 3))" > "$W/fastetcd$c.log" 2>&1 & pids+=($!)
  wait_health "http://127.0.0.1:$((o + 1))/health" "fastetcd $c"
done
E1=http://127.0.0.1:$((P + 11)); E2=http://127.0.0.1:$((P + 21))

cargo build --locked --release -p iron-config --bin iron-config-ctl -p iron-kdc --bin iron-kdc-ctl \
  -p iron-ldap --bin iron-ldapd -p iron-gc --bin iron-gcd 2>&1 | tail -1
B=${CARGO_TARGET_DIR:-target}/release

# Polls an LDAP search until it returns `want` entries; prints the ms it took.
# port, base, filter, want, timeout-ms
await_count() {
  local start got; start=$(now_ms)
  while :; do
    got=$(ldapsearch -LLL -x -H "ldap://127.0.0.1:$1" -b "$2" -s sub "$3" dn 2>/dev/null | grep -c '^dn: ' || true)
    [ "$got" = "$4" ] && { echo $(($(now_ms) - start)); return 0; }
    [ $(($(now_ms) - start)) -gt "$5" ] && { echo "TIMEOUT($got)"; return 1; }
    sleep 0.05
  done
}
stats() { sort -n | awk '{a[NR]=$1} END {printf "max %d ms, median %d ms over %d", a[NR], a[int((NR+1)/2)], NR}'; }

# ---------------- Suite A: many partitions on two clusters ----------------
echo "== Suite A: one forest, $CHILDREN child domains on two clusters"
ROOT=dc=fed,dc=lo
CFG=cn=configuration,$ROOT
child_port() { echo $((P + 100 + 2 * $1)); }
child_ep() { if [ $(($1 % 2)) = 0 ]; then echo "$E2"; else echo "$E1"; fi; }
IRON_CONFIG_FASTETCD_ENDPOINT=$E1 IRON_CONFIG_ROOT_LDAP_URL=ldap://127.0.0.1:$((P + 3)) \
  $B/iron-config-ctl init-forest fed fed-config "$CFG" fed "$ROOT" > "$W/config.log" 2>&1 || fail "init-forest fed"
for i in $(seq "$CHILDREN"); do
  IRON_CONFIG_FASTETCD_ENDPOINT=$E1 IRON_CONFIG_PARTITION_ID=fed-config IRON_CONFIG_BASE_DN=$CFG \
    IRON_CHILD_FASTETCD_ENDPOINT=$(child_ep "$i") IRON_CONFIG_LDAP_URL=ldap://127.0.0.1:$(child_port "$i") \
    $B/iron-config-ctl create-child fed "fed-c$i" "dc=c$i,$ROOT" >> "$W/config.log" 2>&1 || fail "create-child fed-c$i"
done
IRON_CONFIG_FASTETCD_ENDPOINT=$E1 IRON_CONFIG_PARTITION_ID=fed-config IRON_CONFIG_BASE_DN=$CFG \
  $B/iron-config-ctl show > "$W/show.out" 2>&1 || fail "iron-config-ctl show"
for i in $(seq "$CHILDREN"); do
  grep -q "fed-c$i\b" "$W/show.out" || fail "fed-c$i missing from the registry: $(cat "$W/show.out")"
done
echo "ok  registry holds the root and $CHILDREN children"

IRON_LDAP_FASTETCD_ENDPOINT=$E1 IRON_LDAP_PARTITION_ID=fed IRON_LDAP_BASE_DN=$ROOT \
  IRON_LDAP_CONFIG_FASTETCD_ENDPOINT=$E1 IRON_LDAP_CONFIG_PARTITION_ID=fed-config IRON_LDAP_CONFIG_BASE_DN=$CFG \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 3)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 4)) \
  $B/iron-ldapd > "$W/ldapd-root.log" 2>&1 & pids+=($!)
for i in $(seq "$CHILDREN"); do
  lp=$(child_port "$i")
  IRON_LDAP_FASTETCD_ENDPOINT=$(child_ep "$i") IRON_LDAP_PARTITION_ID=fed-c$i IRON_LDAP_BASE_DN=dc=c$i,$ROOT \
    IRON_LDAP_LISTEN=127.0.0.1:$lp IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((lp + 1)) \
    $B/iron-ldapd > "$W/ldapd-c$i.log" 2>&1 & pids+=($!)
done
wait_health "http://127.0.0.1:$((P + 4))/health" "root iron-ldapd"
for i in $(seq "$CHILDREN"); do wait_health "http://127.0.0.1:$(($(child_port "$i") + 1))/health" "iron-ldapd fed-c$i"; done

person() { printf 'dn: cn=%s,%s\nobjectClass: top\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: %s\n\n' "$1" "$2" "$1"; }
add() { # port, cn, base
  person "$2" "$3" | ldapadd -x -H "ldap://127.0.0.1:$1" > "$W/ldapadd.out" 2>&1 || { cat "$W/ldapadd.out"; fail "adding cn=$2,$3"; }
}
add $((P + 3)) rootuser "$ROOT"
for i in $(seq "$CHILDREN"); do add "$(child_port "$i")" "user$i" "dc=c$i,$ROOT"; done

IRON_GC_CONFIG_FASTETCD_ENDPOINT=$E1 IRON_GC_CONFIG_PARTITION_ID=fed-config IRON_GC_CONFIG_BASE_DN=$CFG \
  IRON_GC_LISTEN=127.0.0.1:$((P + 5)) IRON_GC_HEALTH_LISTEN=127.0.0.1:$((P + 6)) $B/iron-gcd > "$W/gcd-forest.log" 2>&1 & pids+=($!)
wait_health "http://127.0.0.1:$((P + 6))/health" "forest iron-gcd"
h=$(curl -s "http://127.0.0.1:$((P + 6))/health")
echo "$h" | grep -q "\"ready_partitions\":$((CHILDREN + 1))," || fail "GC health $h, expected $((CHILDREN + 1)) ready partitions"
GC=$((P + 5)); N1=$((CHILDREN + 1))
t=$(await_count $GC "$ROOT" '(cn=*)' $N1 10000) || fail "GC search from the root: $t, expected $N1 entries"
echo "ok  GC over $N1 partitions on 2 clusters: one search returns all $N1 entries"
for i in $(seq "$CHILDREN"); do
  got=$(ldapsearch -LLL -x -H "ldap://127.0.0.1:$GC" -b "dc=c$i,$ROOT" -s sub '(cn=*)' cn | sed -n 's/^cn: //p' | paste -sd';' -)
  [ "$got" = "user$i" ] || fail "GC search scoped to dc=c$i returned [$got], expected [user$i]"
done
echo "ok  GC search scoped to each child returns only that child's entry"

for i in $(seq "$CHILDREN"); do
  lp=$(child_port "$i")
  out=$(ldapsearch -LLL -x -H "ldap://127.0.0.1:$((P + 3))" -b "dc=c$i,$ROOT" -s sub "(cn=user$i)" cn 2>&1 || true)
  echo "$out" | grep -qi "ref: ldap://127.0.0.1:$lp/" || fail "root server, base dc=c$i: no referral to :$lp: $out"
  out=$(ldapsearch -LLL -C -x -H "ldap://127.0.0.1:$((P + 3))" -b "dc=c$i,$ROOT" -s sub "(cn=user$i)" cn 2>&1 || true)
  echo "$out" | grep -q "^cn: user$i$" || fail "ldapsearch -C did not chase to fed-c$i's entry: $out"
done
echo "ok  root server refers to each of $CHILDREN children, and -C chases every referral to the child's entry"

: > "$W/stale-a"
for i in 1 2; do # child 1 is on cluster 1, child 2 on cluster 2
  start=$(now_ms); add "$(child_port "$i")" "late$i" "dc=c$i,$ROOT"
  t=$(await_count $GC "dc=c$i,$ROOT" "(cn=late$i)" 1 "$STALE_MS") || fail "late$i never reached the GC: $t"
  echo $(($(now_ms) - start)) >> "$W/stale-a"
  start=$(now_ms)
  ldapdelete -x -H "ldap://127.0.0.1:$(child_port "$i")" "cn=user$i,dc=c$i,$ROOT" > "$W/ldapdelete.out" 2>&1 ||
    { cat "$W/ldapdelete.out"; fail "deleting user$i"; }
  # (cn=*), not (cn=user$i) -> 0: late$i must still be there, so an erroring search can't pass.
  t=$(await_count $GC "dc=c$i,$ROOT" '(cn=*)' 1 "$STALE_MS") || fail "the delete of user$i never reached the GC: $t"
  echo $(($(now_ms) - start)) >> "$W/stale-a"
done
echo "ok  add + delete on a child of each cluster reach the running GC: $(stats < "$W/stale-a")"

# ---------------- Suite B: many forests, one federated GAL ----------------
echo "== Suite B: $FORESTS independent forests, one federated GAL"
fbase() { echo "dc=f$1,dc=gal,dc=lo"; }
kdcctl() { # forest, principal
  IRON_KDC_FASTETCD_ENDPOINT=$E1 IRON_KDC_PARTITION_ID=f$1 IRON_KDC_BASE_DN=$(fbase "$1") IRON_KDC_REALM=F$1.GAL.LO \
    $B/iron-kdc-ctl set-password "$2" 'ForestPass123!' >> "$W/kdcctl.log" 2>&1 || fail "set-password $2 in forest f$1"
}
forests=""
for j in $(seq "$FORESTS"); do
  IRON_CONFIG_FASTETCD_ENDPOINT=$E1 $B/iron-config-ctl init-forest "f$j" "f$j-config" "cn=configuration,$(fbase "$j")" \
    "f$j" "$(fbase "$j")" >> "$W/config.log" 2>&1 || fail "init-forest f$j"
  kdcctl "$j" "member$j"
  forests+="$E1|f$j-config|cn=configuration,$(fbase "$j");"
done
start=$(now_ms)
IRON_GC_FORESTS=$forests IRON_GC_ATTRIBUTES=objectclass,cn \
  IRON_GC_LISTEN=127.0.0.1:$((P + 7)) IRON_GC_HEALTH_LISTEN=127.0.0.1:$((P + 8)) $B/iron-gcd > "$W/gcd-gal.log" 2>&1 & pids+=($!)
GAL=$((P + 7))
until h=$(curl -sf "http://127.0.0.1:$((P + 8))/health"); do
  [ $(($(now_ms) - start)) -gt $((CONVERGE_S * 1000)) ] && fail "GAL not ready in ${CONVERGE_S}s: $(curl -s "http://127.0.0.1:$((P + 8))/health")"
  sleep 0.2
done
echo "$h" | grep -q "\"ready_partitions\":$FORESTS," || fail "GAL health $h, expected $FORESTS ready partitions"
echo "$h" | grep -q "\"entries\":$FORESTS}" || fail "GAL health $h, expected $FORESTS entries"
echo "ok  GAL over $FORESTS forests converged in $(($(now_ms) - start)) ms ($h)"
t=$(await_count $GAL dc=gal,dc=lo '(cn=member*)' "$FORESTS" 10000) || fail "GAL search: $t, expected $FORESTS entries"
echo "ok  one GAL search returns the entry of every forest"
leak=$(ldapsearch -LLL -x -H "ldap://127.0.0.1:$GAL" -b dc=gal,dc=lo -s sub '(cn=*)' '*' | grep -ci '^krb' || true)
[ "$leak" = 0 ] || fail "$leak Kerberos attribute values crossed into the GAL"
echo "ok  no krbkey/krbsalt/krbprincipalname crosses the forest boundary (whitelist objectclass,cn)"

: > "$W/stale-b"
for j in $(seq "$FORESTS"); do
  start=$(now_ms); kdcctl "$j" "new$j"
  t=$(await_count $GAL "$(fbase "$j")" "(cn=new$j)" 1 "$STALE_MS") || fail "new$j (forest f$j) never reached the GAL: $t"
  echo $(($(now_ms) - start)) >> "$W/stale-b"
done
echo "ok  a new entry in each of $FORESTS forests reaches the GAL: $(stats < "$W/stale-b") (from before the write)"

: > "$W/stale-d"
step=$((FORESTS / DELETE_SAMPLE)); [ "$step" -ge 1 ] || step=1
for j in $(seq 1 "$step" "$FORESTS" | head -n "$DELETE_SAMPLE"); do
  IRON_LDAP_FASTETCD_ENDPOINT=$E1 IRON_LDAP_PARTITION_ID=f$j IRON_LDAP_BASE_DN=$(fbase "$j") \
    IRON_LDAP_LISTEN=127.0.0.1:$((P + 9)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 10)) \
    $B/iron-ldapd > "$W/ldapd-f$j.log" 2>&1 & lpid=$!; pids+=($lpid)
  wait_health "http://127.0.0.1:$((P + 10))/health" "iron-ldapd f$j"
  start=$(now_ms)
  ldapdelete -x -H "ldap://127.0.0.1:$((P + 9))" "cn=member$j,$(fbase "$j")" > "$W/ldapdelete.out" 2>&1 ||
    { cat "$W/ldapdelete.out"; fail "deleting member$j"; }
  t=$(await_count $GAL "$(fbase "$j")" '(cn=*)' 1 "$STALE_MS") || fail "the delete in f$j never reached the GAL: $t" # new$j stays
  echo $(($(now_ms) - start)) >> "$W/stale-d"
  kill "$lpid"; wait "$lpid" 2>/dev/null || true
done
echo "ok  a delete in $DELETE_SAMPLE sampled forests leaves the GAL: $(stats < "$W/stale-d")"
echo "PASS: federation at scale ($CHILDREN partitions on 2 clusters; $FORESTS-forest GAL)"
