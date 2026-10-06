#!/usr/bin/env bash
# kpasswd (RFC 3244, #20) against real MIT krb5 clients.
#
#   test/kpasswd-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball,
# FASTETCD_VERSION), provisions a domain with iron-bootstrap, runs
# iron-kdcd with kpasswd on a high port, then:
#  1. MIT `kpasswd` (protocol version 1, an INITIAL kadmin/changepw ticket
#     from the AS) changes alice's password, over UDP and then over TCP;
#     kinit works with the new password and not the old one;
#  2. a too-short new password is refused (soft error) and changes nothing;
#  3. a wrong current password never gets a kadmin/changepw ticket.
# Needs curl, kinit and kpasswd (krb5-workstation) and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/kpwe2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # below the ephemeral range: etcd P+1/P+2, KDC P+3, kpasswd P+4
PID_ID="kpw$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; grep -v "error_code=25 " "$f" | tail -20; done; exit 1; }
for t in curl kinit kpasswd; do command -v "$t" >/dev/null || fail "$t is not installed"; done

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd --bin iron-kdc-ctl 2>&1 | tail -1
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
IRON_KDC_CONFIG_FASTETCD_ENDPOINT=$E IRON_KDC_CONFIG_PARTITION_ID=${PID_ID}-config IRON_KDC_CONFIG_BASE_DN=cn=configuration,$BASE \
  IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 4)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
sleep 1
grep -q "kpasswd listening" "$W/kdcd.log" || fail "iron-kdcd did not start kpasswd"
$B/iron-kdc-ctl set-password alice 'OldPass123!' > /dev/null

krb5conf() { # $1 = udp_preference_limit (1 forces TCP)
  cat > "$W/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    udp_preference_limit = $1
[realms]
    $REALM = {
        kdc = 127.0.0.1:$((P + 3))
        kpasswd_server = 127.0.0.1:$((P + 4))
        admin_server = 127.0.0.1:$((P + 4))
    }
EOF
}
export KRB5_CONFIG=$W/krb5.conf KRB5CCNAME=FILE:$W/cc
can_kinit() { echo "$2" | kinit "$1@$REALM" >/dev/null 2>&1; }
change() { printf '%s\n%s\n%s\n' "$2" "$3" "$3" | kpasswd "$1@$REALM" > "$W/kpasswd.out" 2>&1; }

# 1. A real change, over UDP then over TCP.
krb5conf 1465
change alice 'OldPass123!' 'NewPass456!' || { cat "$W/kpasswd.out"; fail "kpasswd over UDP"; }
grep -q "Password changed" "$W/kpasswd.out" || { cat "$W/kpasswd.out"; fail "kpasswd over UDP did not say 'Password changed'"; }
can_kinit alice 'NewPass456!' || fail "kinit with the new password (after UDP change)"
can_kinit alice 'OldPass123!' && fail "the old password still works"
echo "== MIT kpasswd over UDP changed alice's password; kinit takes the new one, not the old"

krb5conf 1
change alice 'NewPass456!' 'Third789!xyz' || { cat "$W/kpasswd.out"; fail "kpasswd over TCP"; }
can_kinit alice 'Third789!xyz' || fail "kinit with the new password (after TCP change)"
can_kinit alice 'NewPass456!' && fail "the previous password still works"
echo "== MIT kpasswd over TCP changed it again"

# 2. Too short: refused, nothing changes.
if change alice 'Third789!xyz' 'short1'; then cat "$W/kpasswd.out"; fail "a 6-character password was accepted"; fi
grep -qi "at least 8" "$W/kpasswd.out" || { cat "$W/kpasswd.out"; fail "the refusal did not carry the server's reason"; }
can_kinit alice 'Third789!xyz' || fail "a refused change altered the password"
echo "== a too-short password is refused with the server's reason: $(grep -i 'at least 8' "$W/kpasswd.out" | head -1)"

# 3. Wrong current password: no ticket, no change.
if change alice 'NotThePassword1' 'Whatever123!'; then fail "a wrong current password changed it"; fi
can_kinit alice 'Third789!xyz' || fail "a failed change altered the password"
echo "== a wrong current password is refused"

echo "-- iron-kdcd kpasswd log:"; sed 's/\x1b\[[0-9;]*m//g' "$W/kdcd.log" | grep -i kpasswd | sed -E 's/^[^ ]+ +//' | head -10
echo "PASS: kpasswd (fastetcd $FV)"
