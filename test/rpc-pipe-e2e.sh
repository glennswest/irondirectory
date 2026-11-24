#!/usr/bin/env bash
# SAMR over SMB named pipes (#53): Samba's rpcclient -> rocketsmbd (Kerberos
# SMB session, IPC$ \PIPE\samr) -> iron-rpcd's pipe socket.
#
#   test/rpc-pipe-e2e.sh
#
# Starts a throwaway one-member fastetcd (release tarball, FASTETCD_VERSION),
# provisions a domain with iron-bootstrap, runs iron-kdcd (with the forest
# registry, so tickets carry a PAC) and iron-rpcd with IRON_RPC_PIPE_SOCKET,
# builds rocketsmbd from its repository at ROCKETSMBD_REF with the kerberos
# feature and runs it on a high port with an iron-kdc keytab for
# cifs/localhost and [ipc] backend = iron-rpcd's socket. Then, with Samba's
# rpcclient over a Kerberos SMB session (signing required):
#  1. administrator (RID 500 in the PAC) creates the users carol and bob
#     over \PIPE\samr (createdomuser: USER_NORMAL_ACCOUNT);
#  2. administrator sets carol's password with setuserinfo2 level 31
#     (SAMPR_ENCRYPTED_PASSWORD_AES keyed from the SMB session key); kinit
#     carol works with it, and not with a wrong one;
#  3. bob's password with PasswordExpired set: kinit bob is told it expired;
#  4. refusals: an RC4 level (25) is STATUS_INVALID_INFO_CLASS, a password the
#     domain policy refuses (#70) is STATUS_PASSWORD_RESTRICTION and changes
#     nothing, and alice (Kerberos, no PAC SIDs: not a Domain Admin) may
#     neither set a password nor create an account.
# Needs curl, git, kinit, rpcclient (samba-client), krb5 GSS development files
# (to build rocketsmbd's kerberos feature) and a FIPS OPENSSL_CONF.
set -euo pipefail

FV=${FASTETCD_VERSION:-1.2.0}
RSMB_REF=${ROCKETSMBD_REF:-036a59e642a4}
export OPENSSL_CONF=${OPENSSL_CONF:-$PWD/crates/crypto/testdata/fips-dev.cnf}
mkdir -p "$PWD/tmp"
W=$(mktemp -d "$PWD/tmp/npe2e.XXXX")
P=$((20000 + RANDOM % 12000 / 10 * 10)) # etcd P+1/P+2, KDC P+3, rpcd P+4, metrics P+5, SMB P+6, kpasswd P+7
PID_ID="np$(date +%s)"
BASE="dc=${PID_ID},dc=example,dc=lo"
REALM="$(echo "$PID_ID" | tr a-z A-Z).EXAMPLE.LO"
NETBIOS=$(echo "$PID_ID" | tr a-z A-Z)
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; grep -v "error_code=25 " "$f" | tail -25; done; exit 1; }
for t in curl git kinit rpcclient; do command -v "$t" >/dev/null || fail "$t is not installed"; done

curl -fsSL "https://github.com/glennswest/fastetcd/releases/download/v$FV/fastetcd-v$FV-x86_64-linux-musl.tar.gz" | tar -xz -C "$W"
"$W/fastetcd-v$FV-x86_64-linux/fastetcd" --data-dir "$W/data" --listen-client-urls "http://127.0.0.1:$((P + 1))" \
  --advertise-client-urls "http://127.0.0.1:$((P + 1))" --listen-peer-urls "http://127.0.0.1:$((P + 2))" \
  --listen-metrics-url "127.0.0.1:$((P + 5))" > "$W/fastetcd.log" 2>&1 & pids+=($!)
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$((P + 1))/health" >/dev/null && break; sleep 0.2; done
E=http://127.0.0.1:$((P + 1))

cargo build --locked --release -p iron-bootstrap --bin iron-bootstrap -p iron-kdc --bin iron-kdcd --bin iron-kdc-ctl \
  -p iron-rpc --bin iron-rpcd > "$W/cargo.log" 2>&1 || { tail -30 "$W/cargo.log"; fail "building irondirectory"; }
B=${CARGO_TARGET_DIR:-target}/release

git clone -q https://github.com/glennswest/rocketsmbd "$W/rocketsmbd"
git -C "$W/rocketsmbd" checkout -q "$RSMB_REF"
# The clone sits under this checkout, so cargo would take it for a member of
# our workspace; an empty [workspace] table makes it its own.
grep -q '^\[workspace\]' "$W/rocketsmbd/Cargo.toml" || printf '\n[workspace]\n' >> "$W/rocketsmbd/Cargo.toml"
cargo build --locked --release --features kerberos --manifest-path "$W/rocketsmbd/Cargo.toml" > "$W/rsmb-build.txt" 2>&1 ||
  { tail -40 "$W/rsmb-build.txt"; fail "rocketsmbd did not build at $RSMB_REF"; }
RSMB=$B/rocketsmbd
[ -x "$RSMB" ] || fail "rocketsmbd did not build at $RSMB_REF"
echo "== rocketsmbd $(git -C "$W/rocketsmbd" rev-parse --short=12 HEAD), kerberos feature"

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
SID=$(sed 's/\x1b\[[0-9;]*m//g' "$W/bootstrap.log" | grep -o 'domain_sid=S-1-5-21-[0-9-]*' | head -1 | cut -d= -f2)
[ -n "$SID" ] || fail "no domain SID from iron-bootstrap"

export IRON_KDC_FASTETCD_ENDPOINT=$E IRON_KDC_PARTITION_ID=$PID_ID IRON_KDC_BASE_DN=$BASE IRON_KDC_REALM=$REALM
IRON_KDC_CONFIG_FASTETCD_ENDPOINT=$E IRON_KDC_CONFIG_PARTITION_ID=${PID_ID}-config IRON_KDC_CONFIG_BASE_DN=cn=configuration,$BASE \
  IRON_KDC_LISTEN=127.0.0.1:$((P + 3)) IRON_KDC_KPASSWD_LISTEN=127.0.0.1:$((P + 7)) $B/iron-kdcd > "$W/kdcd.log" 2>&1 & pids+=($!)
SOCK=$W/np.sock
IRON_RPC_FASTETCD_ENDPOINT=$E IRON_RPC_PARTITION_ID=$PID_ID IRON_RPC_BASE_DN=$BASE IRON_RPC_DOMAIN_SID=$SID \
  IRON_RPC_NETBIOS_NAME=$NETBIOS IRON_RPC_DNS_DOMAIN=${PID_ID}.example.lo IRON_RPC_REALM=$REALM \
  IRON_RPC_LISTEN=127.0.0.1:$((P + 4)) IRON_RPC_PIPE_SOCKET=$SOCK $B/iron-rpcd > "$W/rpcd.log" 2>&1 & pids+=($!)
for _ in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.2; done
[ -S "$SOCK" ] || fail "iron-rpcd made no pipe socket"
[ "$(stat -c %a "$SOCK")" = 660 ] || fail "the pipe socket is mode $(stat -c %a "$SOCK"), not 660"

$B/iron-kdc-ctl set-password cifs/localhost "$(head -c 24 /dev/urandom | base64)" > /dev/null
$B/iron-kdc-ctl export-keytab cifs/localhost "$W/smb.keytab" > /dev/null
$B/iron-kdc-ctl set-password alice 'AlicePass123!' > /dev/null
mkdir -p "$W/share"
cat > "$W/rocketsmbd.toml" <<EOF
listen = "127.0.0.1:$((P + 6))"
workers = 1
server_name = "localhost"
log_level = 1
core_pinning = false
require_signing = true
allow_guest = false
auth = "kerberos"

[kerberos]
keytab = "$W/smb.keytab"
spn = "cifs/localhost"
realm = "$REALM"

[ipc]
backend = "$SOCK"
pipes = ["samr", "lsarpc", "netlogon"]

[[share]]
name = "data"
path = "$W/share"
EOF
cat > "$W/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 1
[realms]
    $REALM = {
        kdc = 127.0.0.1:$((P + 3))
        kpasswd_server = 127.0.0.1:$((P + 7))
    }
[domain_realm]
    localhost = $REALM
EOF
export KRB5_CONFIG=$W/krb5.conf
"$RSMB" --config "$W/rocketsmbd.toml" --check > "$W/rsmbcheck.log" 2>&1 || fail "rocketsmbd --check refused the config"
env -u OPENSSL_CONF "$RSMB" --config "$W/rocketsmbd.toml" > "$W/rocketsmbd.log" 2>&1 & pids+=($!)
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$((P + 6))) 2>/dev/null && break; sleep 0.2; done

mkdir -p "$W/samba/lock" "$W/samba/state" "$W/samba/cache" "$W/samba/private"
cat > "$W/smb.conf" <<EOF
[global]
    workgroup = $NETBIOS
    realm = $REALM
    client signing = required
    client min protocol = SMB2_10
    lock directory = $W/samba/lock
    state directory = $W/samba/state
    cache directory = $W/samba/cache
    private dir = $W/samba/private
    ncalrpc dir = $W/samba/ncalrpc
EOF
# The MIT and Samba clients run without our FIPS OPENSSL_CONF (that is for the daemons).
client() { env -u OPENSSL_CONF KRB5_TRACE="$W/trace.log" "$@"; }
login() { echo "$2" | client kinit -c "$W/cc.$1" "$1@$REALM" > /dev/null 2>&1; }
can_kinit() { echo "$2" | client kinit -c "$W/cc.probe" "$1@$REALM" > "$W/kinit.out" 2>&1; }
rpc() { # <user> <command>: rpcclient over \PIPE\samr as <user>'s ticket
  client rpcclient -s "$W/smb.conf" --port=$((P + 6)) --use-kerberos=required --use-krb5-ccache="$W/cc.$1" \
    -c "$2" localhost > "$W/rpc.out" 2>&1
}
saw() { grep -q -- "$1" "$W/rpc.out" || fail "rpcclient output lacks '$1': $(cat "$W/rpc.out")"; }
# Judged by the output, not rpcclient's exit status: a failed command prints
# its NTSTATUS ("result was NT_STATUS_...").
rpc_ok() { rpc "$1" "$2" || true; grep -q "NT_STATUS_\|result was\|Cannot connect\|failed" "$W/rpc.out" && fail "$1: rpcclient '$2': $(cat "$W/rpc.out")"; return 0; }
rpc_refused() { rpc "$1" "$2" || true; saw "$3"; }

login administrator 'AdminPass123!' || fail "kinit administrator"
login alice 'AlicePass123!' || fail "kinit alice"

# 1. Create accounts over the pipe.
rpc_ok administrator 'createdomuser bob'
rpc_ok administrator 'createdomuser carol'
sed 's/\x1b\[[0-9;]*m//g' "$W/rpcd.log" | grep -q 'accepted pipe.*pipe=samr.*user=administrator@' || fail "iron-rpcd did not log the pipe's user"
echo "== 1. administrator created bob and carol over \\PIPE\\samr (rocketsmbd -> iron-rpcd)"

# 2. setuserinfo2 level 31 (AES).
rpc_ok administrator 'setuserinfo2 carol 31 Carol#Pass2026'
can_kinit 'carol' 'Carol#Pass2026' || fail "kinit carol with the password set over SAMR: $(cat "$W/kinit.out")"
can_kinit 'carol' 'Carol#Pass2025' && fail "kinit carol took a wrong password"
sed 's/\x1b\[[0-9;]*m//g' "$W/rpcd.log" | grep -q 'SamrSetInformationUser2: password set (AES)' || fail "iron-rpcd did not log the AES password set"
echo "== 2. setuserinfo2 carol 31 (AES, SMB session key): kinit carol works with the new password"

# 3. PasswordExpired.
rpc_ok administrator 'setuserinfo2 bob 31 Bob#Pass2026 1'
if can_kinit bob 'Bob#Pass2026'; then fail "kinit bob got a TGT although the password was set expired"; fi
grep -qi "expired" "$W/kinit.out" || fail "kinit bob was not told the password expired: $(cat "$W/kinit.out")"
echo "== 3. setuserinfo2 bob 31 ... 1 (PasswordExpired): kinit bob: $(grep -i expired "$W/kinit.out" | head -1)"

# 4. Refusals.
rpc_refused administrator 'setuserinfo2 carol 25 Rc4#Pass2026' NT_STATUS_INVALID_INFO_CLASS
rpc_refused administrator 'setuserinfo2 carol 31 short' NT_STATUS_PASSWORD_RESTRICTION
can_kinit 'carol' 'Carol#Pass2026' || fail "a refused set changed carol's password"
rpc_refused alice 'setuserinfo2 carol 31 Alice#Took2026' NT_STATUS_ACCESS_DENIED
can_kinit 'carol' 'Carol#Pass2026' || fail "alice's refused set changed carol's password"
rpc_refused alice 'createdomuser mallory' NT_STATUS_ACCESS_DENIED
echo "== 4. refused: RC4 level 25 (INVALID_INFO_CLASS), a too-short password (PASSWORD_RESTRICTION), alice's set and create (ACCESS_DENIED)"

echo "-- iron-rpcd:"; sed 's/\x1b\[[0-9;]*m//g' "$W/rpcd.log" | grep -E "Samr|pipe" | sed -E 's/^[^ ]+ +//' | head -16
echo "PASS: SAMR over SMB named pipes (rpcclient -> rocketsmbd $RSMB_REF -> iron-rpcd), AES password set"
