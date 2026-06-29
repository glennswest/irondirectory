# irondirectory backing etcd cluster (Proxmox VMs)

Provisions irondirectory's **dedicated** etcd cluster (decision D1 — never the
Kubernetes etcd) as three minimal Fedora 43 cloud VMs on Proxmox, forming a
3-node Raft cluster.

Topology (see `cluster.env` for the source of truth):

| Node | VMID | IP | Role |
|------|------|----|------|
| dm1.g8.lo | 131 | 192.168.8.41 | etcd member |
| dm2.g8.lo | 132 | 192.168.8.42 | etcd member |
| dm3.g8.lo | 133 | 192.168.8.43 | etcd member |

- Host: `pve.g8.lo`, bridge `vmbr0` (192.168.8.0/24), storage `local-lvm`.
- Static IPs `.41-.43` sit **outside** the g8 DHCP pool (`.100-.200`).
- Each VM has a dedicated data disk mounted at `/var/lib/etcd`.
- etcd is upstream `v3.6.12` for now; **fastetcd is a drop-in swap** — it reads
  the same flags/env, so only `ETCD_FLAVOR`/binary source change.

## Usage

```sh
./ironetcd.sh up      # create VMs -> install etcd -> DNS -> verify
./ironetcd.sh status  # qm status + cluster health
./ironetcd.sh verify  # member list + endpoint health/status
./ironetcd.sh down    # stop VMs (data preserved)
./ironetcd.sh wipe    # destroy VMs + disks, remove DNS records (back to default)
./ironetcd.sh ssh dm1 # shell into a node
```

`up` is idempotent on create (skips existing VMIDs). Phases can also be run
individually: `create`, `installetcd`, `dns`, `verify`.

## Prerequisites (workstation)

- On the same subnet as the VMs (drives `qm` via SSH to the PVE host and SSHes
  the nodes directly).
- SSH access to `pve.g8.lo` as root; an SSH public key at `SSH_PUBKEY`.
- `curl`, `python3`, `tar` (etcdctl is downloaded automatically and cached).

## Not yet (hardening follow-ups)

- **mTLS** between clients/peers (D1 wants it; currently HTTP on the isolated
  g8 net). Swap to `https://` URLs + `--cert/--key/--trusted-ca` once a CA is in
  place.
- Swap upstream etcd for **fastetcd** (`ETCD_FLAVOR=fastetcd`).
