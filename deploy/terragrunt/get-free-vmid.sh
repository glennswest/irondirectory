#!/bin/bash
# Finds the lowest currently-unused Proxmox VMID within a range, by
# querying LIVE state on the node -- never guess/increment from memory
# or from what a terragrunt.hcl file says, since that can silently drift
# from reality (a hand-created or another automation's VM can occupy an
# ID this repo never allocated). This is the root-cause fix for a real
# incident: a VMID was picked by pattern-guessing "next free after the
# ones I know about" instead of checking live state, collided with an
# existing VM outside this repo's management, and `terraform apply`
# followed by `terraform destroy` destroyed it.
#
# Structural guardrail: the shared terraform-modules//modules/proxmox-fedora-vm
# module (v0.3.0+) validates every vm_id against vm_id_min/vm_id_max
# (default 2000-2100), a range disjoint from every hand-created VM, and
# its API token is ACL-scoped to only the terraform-managed pool. This
# script is the second, process-level layer: never even propose an ID
# without checking it's actually free right now.
#
# Two race windows this guards against, not just one:
#  1. Two concurrent invocations of this script both scanning at once --
#     guarded by a portable mkdir-based lock (mkdir is atomic on every
#     POSIX filesystem, unlike GNU flock which isn't on macOS by default).
#  2. An ID handed out by this script but not yet turned into a real VM
#     (so it doesn't show up in `qm list` yet) being handed out AGAIN by
#     a later, non-overlapping invocation -- guarded by a local "reserved"
#     file recording IDs this script already returned. Entries are
#     dropped automatically once `qm list` shows them as real, so the
#     file doesn't grow stale forever; `--release <id>` also removes one
#     by hand (e.g. if a reservation was never used).
#
# Usage: ./get-free-vmid.sh [min] [max]
#        ./get-free-vmid.sh --release <id>
# Defaults to the module's current range (2000-2100). Prints one free
# VMID to stdout, or exits non-zero with a message on stderr if the
# whole range is exhausted or the lock can't be acquired.

set -euo pipefail

PVE_HOST="${PVE_HOST:-pve.g8.lo}"
JUMP_HOST="${JUMP_HOST:-root@dev.g8.lo}"
LOCK_DIR="${TMPDIR:-/tmp}/irondirectory-get-free-vmid.lock"
RESERVED_FILE="${TMPDIR:-/tmp}/irondirectory-get-free-vmid.reserved"
LOCK_TIMEOUT_SECS=30

acquire_lock() {
    local waited=0
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        if [ "$waited" -ge "$LOCK_TIMEOUT_SECS" ]; then
            # A crashed prior run can leave the lock dir behind forever;
            # a lock held longer than the timeout is treated as stale.
            echo "warning: stale lock at $LOCK_DIR (older than ${LOCK_TIMEOUT_SECS}s) -- removing" >&2
            rmdir "$LOCK_DIR" 2>/dev/null || true
            continue
        fi
        sleep 1
        waited=$((waited + 1))
    done
    trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT
}

if [ "${1:-}" = "--release" ]; then
    id="${2:?usage: get-free-vmid.sh --release <id>}"
    acquire_lock
    touch "$RESERVED_FILE"
    grep -vx "$id" "$RESERVED_FILE" > "$RESERVED_FILE.tmp" 2>/dev/null || true
    mv "$RESERVED_FILE.tmp" "$RESERVED_FILE"
    echo "released $id"
    exit 0
fi

MIN="${1:-2000}"
MAX="${2:-2100}"

acquire_lock
touch "$RESERVED_FILE"

used_ids="$(ssh -o BatchMode=yes "$JUMP_HOST" "ssh -o BatchMode=yes root@$PVE_HOST 'qm list' 2>/dev/null" | awk 'NR>1 {print $1}')"

# Prune reservations that are now real VMs (qm list shows them) -- keeps
# the reserved file from growing forever with entries that no longer
# need protecting.
still_reserved="$(comm -23 <(sort -u "$RESERVED_FILE") <(sort -u <<<"$used_ids") 2>/dev/null || true)"
printf '%s\n' "$still_reserved" | grep -v '^$' > "$RESERVED_FILE.tmp" || true
mv "$RESERVED_FILE.tmp" "$RESERVED_FILE"

for id in $(seq "$MIN" "$MAX"); do
    if grep -qx "$id" <<<"$used_ids"; then
        continue
    fi
    if grep -qx "$id" "$RESERVED_FILE" 2>/dev/null; then
        continue
    fi
    echo "$id" >> "$RESERVED_FILE"
    echo "$id"
    exit 0
done

echo "no free vmid in range [$MIN, $MAX] on $PVE_HOST (accounting for in-flight reservations)" >&2
exit 1
