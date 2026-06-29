# irondirectory etcd backend — Terraform (bpg/proxmox)

Infrastructure-as-code for irondirectory's **dedicated** etcd cluster (decision
D1), modeled on the house `terraform8` pattern. This is the going-forward fleet
tool; the bash `../proxmox/ironetcd.sh` was the bootstrap that proved the steps.

Provisions three Fedora 43 VMs on Proxmox forming a 3-node etcd Raft cluster:

| Node | VMID | IP | Notes |
|------|------|----|-------|
| dm1.g8.lo | 131 | 192.168.8.41 | etcd member, data disk at /var/lib/etcd |
| dm2.g8.lo | 132 | 192.168.8.42 | etcd member |
| dm3.g8.lo | 133 | 192.168.8.43 | etcd member |

How it works (same primitives as terraform8):
- A **MicroDNS DHCP reservation** pins each node's MAC → IP and auto-registers
  DNS; the VM boots DHCP and gets the reserved IP (outside the .100-.200 pool).
- A per-node **cloud-init snippet** installs etcd `v3.6.12`, formats the
  dedicated data disk to `/var/lib/etcd`, and enables the service. All three
  boot together so the `Type=notify` units reach quorum and signal ready.
- **fastetcd is a drop-in swap** — same flags/env; change the install source in
  the cloud-init template and bump nothing else.

## Usage

```sh
cp terraform.tfvars.example terraform.tfvars   # fill in token + ssh key
terraform init
terraform plan
terraform apply
terraform output etcd_endpoints                # feed to ETCDCTL_ENDPOINTS

# verify from the workstation (native etcdctl: brew install etcd)
export ETCDCTL_ENDPOINTS=$(terraform output -raw etcd_endpoints)
etcdctl member list -w table
```

`terraform destroy` removes the VMs, disks, and DHCP/DNS reservations.

## Notes / follow-ups

- **mTLS** (D1 wants it): switch the cloud-init etcd URLs to `https://` and add
  cert/key/ca once a CA is in place.
- Fleet growth: add client/test-machine roles as more maps/modules (RHEL+SSSD,
  Windows-join, macOS), reusing the reservation + cloud-init pattern.
- The token and SSH key live in `terraform.tfvars` (gitignored) — never commit.
