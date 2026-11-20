#!/usr/bin/env bash
# Domain password policy (#70) against real MIT krb5 clients, impacket and
# OpenLDAP's ldappasswd.
#
#   test/password-policy-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd (kpasswd on a high
# port) and iron-ldapd, gives alice (sAMAccountName alice, displayName
# "Alice Liddell") a password, then:
#  1. with no policy on the domain head, a lowercase-only password is taken
#     (only the 8-character FIPS floor applies);
#  2. sets the policy over LDAP on the domain head, as on AD (minPwdLength
#     10, pwdHistoryLength 3, pwdProperties 1 = complex);
#  3. MIT kpasswd: too short, not complex, containing the account name and
#     a reuse of one of the last 3 are each refused; kpasswd prints AD's
#     policy record as MIT decodes it, the KDC's log names the reason; the
#     password is unchanged; a fourth-oldest password is taken again;
#  4. impacket decodes the same record (minimum length 10, history 3,
#     Complex);
#  5. a reset by administrator (impacket set password) is held to
#     complexity but not to history; a machine account (TESTMAC1$) is held
#     to neither;
#  6. LDAP Password Modify (ldappasswd as administrator) is held to the
#     same policy: constraintViolation, and a complying one works in kinit;
#  7. minPwdAge one hour: alice may not change her own again (MIT: "once a
#     day"), administrator may still reset it;
#  8. maxPwdAge 6 seconds: once it has passed, kinit is refused "Password
#     has expired" (KDC_ERR_KEY_EXPIRED) -- and MIT kinit's own change
#     prompt, on a kadmin/changepw ticket the expired password still gets,
#     sets a new one and logs in with it.
# Needs curl, kinit, kpasswd, ldapadd, ldapmodify, ldappasswd, python3
# (impacket is pip-installed into a venv) and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/ppe2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, KDC P+3, kpasswd P+4, LDAP P+6, health P+7
PID_ID="pp$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
ADMIN="cn=administrator,$BASE"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; [ -s "$W/kpasswd.out" ] && cat "$W/kpasswd.out"; for f in "$W"/*.log; do echo "--- $f"; grep -v "error_code=25 " "$f" | tail -30; done; exit 1; }
for t in curl kinit kpasswd ldapadd ldapmodify ldappasswd python3; do command -v "$t" >/dev/null || fail "$t is not installed"; done

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd --bin iron-kdc-ctl -p iron-ldap --bin iron-ldapd 2>&1 | tail -1
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

export IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM
IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
IRON_LDAP_FASTETCD_ENDPOINT=$E IRON_LDAP_PARTITION_ID=$PID_ID IRON_LDAP_BASE_DN=$BASE \
  IRON_LDAP_LISTEN=127.0.0.1:$((P + 6)) IRON_LDAP_HEALTH_LISTEN=127.0.0.1:$((P + 7)) $B/iron-ldapd > "$W/ldapd.log" 2>&1 & pids+=($!)
for _ in $(seq 30); do curl -sf "http://127.0.0.1:$((P + 7))/health" >/dev/null && break; sleep 0.5; done
grep -q "kpasswd listening" "$W/kdcd.log" || fail "iron-kdcd did not start kpasswd"
H="ldap://127.0.0.1:$((P + 6))"
ldapmod() { ldapmodify -x -H "$H" -D "$ADMIN" -w 'AdminPass123!' > "$W/ldapmodify.out" 2>&1 || { cat "$W/ldapmodify.out"; fail "ldapmodify: $1"; }; }

$B/iron-kdc-ctl set-password alice 'OldPass123!' > /dev/null
ldapmod "alice's account attributes" <<LDIF
dn: cn=alice,$BASE
changetype: modify
replace: objectClass
objectClass: top
objectClass: person
objectClass: user
-
replace: sAMAccountName
sAMAccountName: alice
-
replace: displayName
displayName: Alice Liddell
LDIF

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
        kpasswd_server = 127.0.0.1:$((P + 4))
        admin_server = 127.0.0.1:$((P + 4))
    }
EOF
export KRB5_CONFIG=$W/krb5.conf KRB5CCNAME=FILE:$W/cc
client() { env -u OPENSSL_CONF KRB5_TRACE="$W/trace.log" "$@"; }
can_kinit() { echo "$2" | client kinit "$1@$REALM" >/dev/null 2>&1; }
change() { : > "$W/trace.log"; printf '%s\n%s\n%s\n' "$2" "$3" "$3" | client kpasswd "$1@$REALM" > "$W/kpasswd.out" 2>&1; }
refused() { # $1 = current, $2 = candidate, $3 = what the KDC log must name
  local before; before=$(grep -c "kpasswd: refused" "$W/kdcd.log" || true)
  if change alice "$1" "$2"; then cat "$W/kpasswd.out"; fail "alice's change to '$2' was accepted"; fi
  grep -q "Password change rejected" "$W/kpasswd.out" || fail "'$2': kpasswd did not report a rejection"
  can_kinit alice "$1" || fail "a refused change ('$2') altered the password"
  sed 's/\x1b\[[0-9;]*m//g' "$W/kdcd.log" | grep "kpasswd: refused" | tail -n +$((before + 1)) | grep -q "$3" || fail "'$2': the KDC log does not name '$3'"
  echo "   refused '$2': $3"
}
CUR='OldPass123!'
can_kinit alice "$CUR" || fail "kinit alice before any change"

# 1. No policy: the FIPS floor only.
change alice "$CUR" 'lowercaseonly' || { cat "$W/kpasswd.out"; fail "no policy: a lowercase-only password was refused"; }
CUR='lowercaseonly'
can_kinit alice "$CUR" || fail "kinit after the no-policy change"
echo "== no policy: a lowercase-only password is taken"

# 2. The policy, on the domain head.
ldapmod "the domain policy" <<LDIF
dn: $BASE
changetype: modify
replace: minPwdLength
minPwdLength: 10
-
replace: pwdHistoryLength
pwdHistoryLength: 3
-
replace: pwdProperties
pwdProperties: 1
LDIF
echo "== policy set on $BASE: minPwdLength 10, pwdHistoryLength 3, pwdProperties 1"

# 3. MIT kpasswd against it.
refused "$CUR" 'Ab1!short' "at least 10 characters"
grep -q "at least 10 characters" "$W/kpasswd.out" || fail "MIT kpasswd did not decode the policy record: $(cat "$W/kpasswd.out")"
grep -q "different from the previous 3 passwords" "$W/kpasswd.out" || fail "MIT kpasswd's message has no history: $(cat "$W/kpasswd.out")"
echo "   MIT kpasswd says: $(grep -o 'The password must include.*' "$W/kpasswd.out" | head -1)"
refused "$CUR" 'nouppercase2026' "complexity requirements: it uses 2 of the 5"
refused "$CUR" 'xAlice2026!x' "contains the account name"
refused "$CUR" 'Liddell2026!' "contains part of the display name"
for pw in 'Policy#One1' 'Policy#Two2'; do
  change alice "$CUR" "$pw" || { cat "$W/kpasswd.out"; fail "a complying change to '$pw' was refused"; }
  CUR=$pw
done
can_kinit alice "$CUR" || fail "kinit after complying changes"
ldapmod "pwdProperties 0, to show history alone" <<LDIF
dn: $BASE
changetype: modify
replace: pwdProperties
pwdProperties: 0
LDIF
refused "$CUR" "$CUR" "used within the last 3 passwords"
refused "$CUR" 'lowercaseonly' "used within the last 3 passwords"
change alice "$CUR" 'Policy#Three3' || fail "change to Policy#Three3"
CUR='Policy#Three3'
change alice "$CUR" 'lowercaseonly' || { cat "$W/kpasswd.out"; fail "the fourth-newest password was refused with a history of 3"; }
CUR='lowercaseonly'
change alice "$CUR" 'Policy#Four4' || fail "change to Policy#Four4"
CUR='Policy#Four4'
ldapmod "pwdProperties 1 again" <<LDIF
dn: $BASE
changetype: modify
replace: pwdProperties
pwdProperties: 1
LDIF
echo "== MIT kpasswd: length, complexity, account/display name and history refused; the 4th-newest taken again"

# 4. impacket decodes the record.
python3 -m venv "$W/venv" && "$W/venv/bin/pip" install -q impacket==0.13.1 > "$W/pip.out" 2>&1 || { tail -5 "$W/pip.out"; fail "pip install impacket"; }
imp() { "$W/venv/bin/python" -I "$PWD/test/kpasswd_impacket.py" $((P + 3)) $((P + 4)) "$REALM" "$@"; }
if out=$(imp alice "$CUR" 'short' 2>&1); then fail "impacket: a 5-character password was accepted"; fi
for want in "Minimum length: 10" "Password history: 3" "Complex"; do echo "$out" | grep -q "$want" || fail "impacket's decoded policy lacks '$want': $out"; done
echo "== impacket decodes the policy record: $(echo "$out" | tr '\n\t' '  ' | sed 's/  */ /g')"

# 5. Reset by administrator: complexity yes, history no; machines exempt.
if out=$(imp administrator 'AdminPass123!' 'nouppercase2026' alice 2>&1); then fail "administrator reset alice to a non-complex password"; fi
can_kinit alice "$CUR" || fail "a refused reset changed alice's password"
out=$(imp administrator 'AdminPass123!' "$CUR" alice 2>&1) || fail "administrator could not reset alice to her current password (history must not apply): $out"
can_kinit alice "$CUR" || fail "kinit after the administrator's reset"
ldapadd -x -H "$H" -D "$ADMIN" -w 'AdminPass123!' > "$W/ldapadd.out" 2>&1 <<LDIF || { cat "$W/ldapadd.out"; fail "ldapadd of the computer account"; }
dn: cn=TESTMAC1,$BASE
objectClass: top
objectClass: person
objectClass: user
objectClass: computer
cn: TESTMAC1
sAMAccountName: TESTMAC1\$
LDIF
out=$(imp administrator 'AdminPass123!' 'machinelowercase' 'TESTMAC1$' 2>&1) || fail "a machine account was held to complexity: $out"
can_kinit 'TESTMAC1$' 'machinelowercase' || fail "kinit TESTMAC1\$"
if out=$(imp administrator 'AdminPass123!' 'mach1' 'TESTMAC1$' 2>&1); then fail "a machine account took a 5-character password"; fi
echo "== administrator reset: held to complexity, not history; TESTMAC1\$ held only to the length"

# 6. LDAP Password Modify.
if ldappasswd -x -H "$H" -D "$ADMIN" -w 'AdminPass123!' -s 'nouppercase2026' "cn=alice,$BASE" > "$W/out" 2>&1; then fail "ldappasswd set a non-complex password"; fi
grep -qi "constraint violation" "$W/out" || fail "ldappasswd: not constraintViolation: $(cat "$W/out")"
echo "   ldappasswd refused: $(grep -i 'additional info' "$W/out" | head -1)"
ldappasswd -x -H "$H" -D "$ADMIN" -w 'AdminPass123!' -s 'Ldap#Reset5' "cn=alice,$BASE" > "$W/out" 2>&1 || fail "ldappasswd with a complying password: $(cat "$W/out")"
CUR='Ldap#Reset5'
can_kinit alice "$CUR" || fail "kinit after ldappasswd"
echo "== LDAP Password Modify is held to the policy (constraintViolation), a complying one works in kinit"

# 7. Minimum age: an hour.
ldapmod "minPwdAge" <<LDIF
dn: $BASE
changetype: modify
replace: minPwdAge
minPwdAge: -36000000000
LDIF
refused "$CUR" 'Policy#Five5' "less than the minimum password age"
grep -q "can only be changed once a day" "$W/kpasswd.out" || fail "MIT kpasswd's message has no minimum age: $(cat "$W/kpasswd.out")"
out=$(imp administrator 'AdminPass123!' 'Admin#Reset6' alice 2>&1) || fail "the minimum age stopped an administrator's reset: $out"
CUR='Admin#Reset6'
can_kinit alice "$CUR" || fail "kinit after the reset under a minimum age"
echo "== minPwdAge: alice may not change hers again yet; administrator may reset it"

# 8. Maximum age: six seconds; MIT kinit changes the expired password.
# The reset comes first: administrator's own password is older than six
# seconds, so administrator gets no ticket once maxPwdAge is set.
out=$(imp administrator 'AdminPass123!' 'Fresh#Pass7' alice 2>&1) || fail "reset before the expiry check: $out"
CUR='Fresh#Pass7'
ldapmod "maxPwdAge" <<LDIF
dn: $BASE
changetype: modify
replace: minPwdAge
minPwdAge: 0
-
replace: maxPwdAge
maxPwdAge: -60000000
LDIF
can_kinit alice "$CUR" || fail "kinit within maxPwdAge"
sleep 7
: > "$W/trace.log"
echo "$CUR" | client kinit "alice@$REALM" > "$W/kinit.out" 2>&1 && fail "kinit with an expired password got a TGT"
grep -qi "expired" "$W/kinit.out" || fail "kinit was not told the password expired: $(cat "$W/kinit.out")"
grep -q "error from KDC: 23\|Password has expired" "$W/trace.log" || fail "the KDC did not answer KDC_ERR_KEY_EXPIRED"
echo "   kinit: $(grep -i expired "$W/kinit.out" | head -1)"
printf '%s\n%s\n%s\n' "$CUR" 'Renewed#Pass8' 'Renewed#Pass8' | client kinit "alice@$REALM" > "$W/kinit.out" 2>&1 ||
  fail "MIT kinit could not change the expired password: $(cat "$W/kinit.out")"
can_kinit alice 'Renewed#Pass8' || fail "kinit with the password kinit set"
can_kinit alice "$CUR" && fail "the expired password still works after the change"
echo "== maxPwdAge: an expired password gets KDC_ERR_KEY_EXPIRED; kinit's change prompt sets a new one and logs in"

echo "-- iron-kdcd kpasswd refusals:"; sed 's/\x1b\[[0-9;]*m//g' "$W/kdcd.log" | grep -E "kpasswd: refused|password expired" | sed -E 's/^[^ ]+ +//' | head -14
echo "PASS: password policy (fastetcd $FV)"
