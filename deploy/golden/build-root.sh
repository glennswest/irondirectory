#!/usr/bin/env bash
# Assemble the irondirectory golden's root tree (#25) in <dir>.
#
#   deploy/golden/build-root.sh <dir>
#
# The golden is a Fedora root, like stormcos's fedora-base: Fedora's own
# glibc and openssl-libs, installed by dnf into <dir> (`--installroot`), so the
# FIPS provider is the OS's validated fips.so, never one we build (D4). It is
# rebuilt whenever FEDORA_RELEASE changes (owner, 2026-09-28: "use fips from
# fedora ... update it when fedora version changes").
#
# What lands in <dir> (the operator's contract, irondirectory-operator
# deploy/config.example.yaml):
#   /usr/bin/fastetcd                       static musl, pinned FASTETCD_REF
#   /usr/bin/iron-ldapd iron-kdcd iron-kdc-ctl iron-bootstrap
#                                           glibc, linked against the root's libcrypto
#   /etc/irondirectory/fips.cnf             OPENSSL_CONF for every daemon
#   /etc/irondirectory/golden.txt           what went in, by version and sha256
# No ENTRYPOINT/ENV: the operator names every command and setting.
#
# Run from a checkout on a Fedora $FEDORA_RELEASE host (the binaries link
# against that release's glibc/OpenSSL ABI) with rustup, protoc, musl-gcc and
# dnf5; no root: dnf runs as root inside a user namespace (`unshare -r`).
#
#   FEDORA_RELEASE   Fedora release of the root (default 43, stormcos's)
#   FASTETCD_BIN     use this fastetcd binary instead of building FASTETCD_REF
#   FASTETCD_REF     fastetcd tag to build (default: deploy/golden/fastetcd.ref)
set -euo pipefail

OUT=${1:?usage: build-root.sh <dir>}
HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
FEDORA_RELEASE=${FEDORA_RELEASE:-43}
FASTETCD_REF=${FASTETCD_REF:-$(tr -d ' \n' < "$HERE/fastetcd.ref")}
PACKAGES="glibc openssl-libs"
BINS="iron-ldapd iron-kdcd iron-kdc-ctl iron-bootstrap"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/golden.XXXX")
trap 'rm -rf "$WORK"' EXIT
die() { echo "build-root: $*" >&2; exit 1; }

. /etc/os-release
[ "${ID:-}" = fedora ] && [ "${VERSION_ID:-}" = "$FEDORA_RELEASE" ] ||
  die "host is ${ID:-?} ${VERSION_ID:-?}; the binaries must be built on Fedora $FEDORA_RELEASE to match the root's glibc and OpenSSL"
[ ! -e "$OUT" ] || [ -z "$(ls -A "$OUT")" ] || die "$OUT is not empty"
# rpm scriptlets write their temp files to the root's /var/tmp.
mkdir -p "$OUT/var/tmp" "$OUT/tmp"
chmod 1777 "$OUT/var/tmp" "$OUT/tmp"

echo "== Fedora $FEDORA_RELEASE: $PACKAGES"
# As fedora-base does it: the host's dnf and repo definitions, its state kept
# on this build's drive.
# shellcheck disable=SC2086
unshare -r dnf5 -y -q --installroot="$OUT" --releasever="$FEDORA_RELEASE" --use-host-config \
  --setopt=install_weak_deps=False --setopt=tsflags=nodocs --setopt=countme=0 \
  --setopt=cachedir="$WORK/dnf-cache" --setopt=persistdir="$WORK/dnf-persist" \
  install $PACKAGES > "$WORK/dnf.log" 2>&1 || { tail -20 "$WORK/dnf.log" >&2; die "dnf could not install $PACKAGES"; }
rm -rf "$OUT/var/cache/dnf" "$OUT/var/cache/libdnf5" "$OUT"/var/log/dnf5.log* "$OUT/var/lib/dnf"
[ -f "$OUT/usr/lib64/ossl-modules/fips.so" ] || die "Fedora $FEDORA_RELEASE's $PACKAGES has no /usr/lib64/ossl-modules/fips.so"

echo "== irondirectory $(git -C "$TOP" rev-parse --short HEAD): $BINS"
(cd "$TOP" && cargo build --release --locked \
  -p iron-ldap --bin iron-ldapd -p iron-kdc --bin iron-kdcd --bin iron-kdc-ctl \
  -p iron-bootstrap --bin iron-bootstrap)
R=${CARGO_TARGET_DIR:-$TOP/target}/release
for b in $BINS; do install -m 755 "$R/$b" "$OUT/usr/bin/$b"; done

if [ -n "${FASTETCD_BIN:-}" ]; then
  echo "== fastetcd: $FASTETCD_BIN"; fe_src="given: $(sha256sum < "$FASTETCD_BIN" | cut -c1-16)"
else
  echo "== fastetcd $FASTETCD_REF"
  git clone -q --depth 1 --branch "$FASTETCD_REF" https://github.com/glennswest/fastetcd "$WORK/fastetcd"
  (cd "$WORK/fastetcd" && CARGO_TARGET_DIR="$WORK/fe-target" \
    cargo build --release --locked --target x86_64-unknown-linux-musl -p fastetcd-server --bin fastetcd)
  FASTETCD_BIN=$WORK/fe-target/x86_64-unknown-linux-musl/release/fastetcd
  fe_src="$FASTETCD_REF $(git -C "$WORK/fastetcd" rev-parse HEAD)"
fi
install -m 755 "$FASTETCD_BIN" "$OUT/usr/bin/fastetcd"

install -D -m 644 "$HERE/fips.cnf" "$OUT/etc/irondirectory/fips.cnf"
mkdir -p "$OUT/var/lib/irondirectory" "$OUT/run"

# Every shared library the daemons (and fips.so) need must be in the root.
for f in $BINS; do
  for lib in $(readelf -d "$OUT/usr/bin/$f" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'); do
    [ -e "$OUT/usr/lib64/$lib" ] || die "$f needs $lib, which the root does not have"
  done
done

{
  echo "fedora $FEDORA_RELEASE"
  rpm --root "$OUT" -q $PACKAGES 2>/dev/null | sed 's/^/rpm /'
  echo "irondirectory $(git -C "$TOP" rev-parse HEAD)"
  echo "fastetcd $fe_src"
  (cd "$OUT/usr/bin" && sha256sum fastetcd $BINS) | sed 's/^/sha256 /'
} > "$OUT/etc/irondirectory/golden.txt"
cat "$OUT/etc/irondirectory/golden.txt"
echo "== root: $(du -sh "$OUT" | cut -f1) in $OUT"
