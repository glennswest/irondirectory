#!/usr/bin/env bash
# The irondirectory golden's acceptance (#25), without a pod: every daemon
# runs chrooted into the golden root with an empty environment, so nothing
# comes from the host — not a library, not a setting. That is what a pod with
# no image config is.
#
#   test/golden-e2e.sh <root>        # the irondirectory golden's tree
#
# stormcos's stage build runs this against the golden it seals (stormcos
# deploy/build-goldens.sh, `ONLY="fastetcd fips-base irondirectory"`).
#
# Checks, as the issue states them:
#  1. fastetcd + iron-ldapd + iron-kdcd + iron-bootstrap come up; iron-ldapd's
#     :8080-style /health answers;
#  2. ldapwhoami -D cn=administrator,<base> -w <pw> and kinit administrator@REALM
#     succeed (and a wrong password is refused);
#  3. stopping everything and starting it again on the same data keeps the
#     data and the password, even with a changed password file.
# Needs ldapwhoami, kinit and curl on the host; user namespaces; no root.
# Ports are high: fastetcd 12379/12380, LDAP 13389, health 18080, KDC 13088.
set -euo pipefail

ROOT=$(cd "${1:?usage: golden-e2e.sh <root>}" && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/golden-e2e.XXXX")
PID_ID=corp BASE=dc=corp,dc=example,dc=lo REALM=CORP.EXAMPLE.LO PW='TestPass123!'
EP=http://127.0.0.1:12379
pids=()
stop_all() { for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; pids=(); }
trap stop_all EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; tail -20 "$f"; done; exit 1; }
for t in ldapwhoami kinit curl; do command -v "$t" >/dev/null || fail "$t is not installed"; done

# One daemon, chrooted into the golden, with only the settings named here.
in_golden() { # <log> <command> [VAR=value...]
  local log=$1 cmd=$2; shift 2
  env -i OPENSSL_CONF=/etc/irondirectory/fips.cnf "$@" unshare -r --root="$ROOT" "$cmd" >> "$W/$log" 2>&1 &
  pids+=($!)
}

install -D -m 600 /dev/stdin "$ROOT/run/secrets/admin/password" <<< "$PW"

start_all() { # <round>
  in_golden "fastetcd$1.log" /usr/bin/fastetcd FASTETCD_DATA_DIR=/var/lib/irondirectory/fastetcd \
    FASTETCD_LISTEN_CLIENT_URLS=$EP FASTETCD_LISTEN_PEER_URLS=http://127.0.0.1:12380
  in_golden "bootstrap$1.log" /usr/bin/iron-bootstrap IRON_BOOTSTRAP_FASTETCD_ENDPOINT=$EP \
    IRON_BOOTSTRAP_PARTITION_ID=$PID_ID IRON_BOOTSTRAP_BASE_DN=$BASE IRON_BOOTSTRAP_REALM=$REALM \
    IRON_BOOTSTRAP_NETBIOS_NAME=CORP IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE=/run/secrets/admin/password
  in_golden "ldapd$1.log" /usr/bin/iron-ldapd IRON_LDAP_FASTETCD_ENDPOINT=$EP IRON_LDAP_PARTITION_ID=$PID_ID \
    IRON_LDAP_BASE_DN=$BASE IRON_LDAP_LISTEN=127.0.0.1:13389 IRON_LDAP_HEALTH_LISTEN=127.0.0.1:18080
  in_golden "kdcd$1.log" /usr/bin/iron-kdcd IRON_KDC_FASTETCD_ENDPOINT=$EP IRON_KDC_PARTITION_ID=$PID_ID \
    IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM IRON_KDC_LISTEN=127.0.0.1:13088 IRON_KDC_KPASSWD_LISTEN=127.0.0.1:13464
  for i in $(seq 60); do
    grep -qE 'provisioned' "$W/bootstrap$1.log" && curl -sf http://127.0.0.1:18080/health >/dev/null && return 0
    for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null || fail "a daemon exited (round $1)"; done
    sleep 1
  done
  fail "not up in 60s (round $1)"
}

cat > "$W/krb5.conf" <<K
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    udp_preference_limit = 1
[realms]
    $REALM = {
        kdc = 127.0.0.1:13088
    }
K
export KRB5_CONFIG=$W/krb5.conf KRB5CCNAME=FILE:$W/cc

check() { # <password that must work> <one that must not>
  ldapwhoami -x -H ldap://127.0.0.1:13389 -D "cn=administrator,$BASE" -w "$1" || fail "ldapwhoami with the right password"
  if ldapwhoami -x -H ldap://127.0.0.1:13389 -D "cn=administrator,$BASE" -w "$2" >/dev/null 2>&1; then fail "ldapwhoami accepted a wrong password"; fi
  echo "$1" | kinit "administrator@$REALM" >/dev/null || fail "kinit with the right password"
  klist | grep -q "krbtgt/$REALM@$REALM" || fail "no TGT in the cache"
  kdestroy -q
  if echo "$2" | kinit "administrator@$REALM" >/dev/null 2>&1; then fail "kinit accepted a wrong password"; fi
  echo "== ldapwhoami + kinit OK, wrong password refused"
}

echo "== golden: $(grep -E '^(fedora|rpm|irondirectory|fastetcd) ' "$ROOT/etc/irondirectory/golden.txt" | tr '\n' ';')"
start_all 1
# tracing colours its field names; strip that before reading the log.
sed 's/\x1b\[[0-9;]*m//g' "$W/bootstrap1.log" | grep -o 'created=.*' | head -1 || true
check "$PW" 'WrongPass999!'
kill -0 "${pids[1]}" || fail "iron-bootstrap did not stay resident"
echo "== iron-bootstrap resident after provisioning"

stop_all
echo "== restart on the same data, with a changed password file"
install -m 600 /dev/stdin "$ROOT/run/secrets/admin/password" <<< 'OtherPass456!'
start_all 2
grep -q 'already provisioned; nothing to do' "$W/bootstrap2.log" || fail "the restart provisioned something"
check "$PW" 'OtherPass456!'
echo "PASS: irondirectory golden e2e"
