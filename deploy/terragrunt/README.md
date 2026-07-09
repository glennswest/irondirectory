# irondirectory infrastructure — Terragrunt

Provisions irondirectory's infrastructure using the **shared, versioned**
module at [`github.com/glennswest/terraform-modules`](https://github.com/glennswest/terraform-modules)
(`modules/proxmox-fedora-vm`). We never copy `.tf` files — units reference the
module by a pinned `?ref=` tag.

```
deploy/terragrunt/
  root.hcl            # provider + token wiring (PROXMOX_API_TOKEN from env), once
  get-free-vmid.sh    # queries live state for a genuinely-unused vm_id -- run before every new unit
  etcd/               # unit: dm1/dm2/dm3.g8.lo — the dedicated etcd backend (D1), pinned to an older
                       # module version (vm_id 131-133, outside the current 2000-2100 range)
  ldap/               # unit: il1/il2/il3.g8.lo — redundant iron-ldap (vm_id 134-136, same as above)
    terragrunt.hcl
    templates/etcd-user-data.yaml.tftpl
```

Throwaway validation units (e.g. for a specific GitHub issue) come and
go -- built with `terragrunt apply`, `destroy`ed once done, and their
directories removed from the repo afterward rather than left around
with stale `vm_id`s from a since-changed allowed range.

## One-time setup

```sh
brew install hashicorp/tap/terraform terragrunt
# Proxmox node must trust your ~/.ssh/id_rsa.pub (root@pve.g8.lo).
```

**Never use a `root@pam` token with `--privsep 0`.** That grants the
token full root privileges over every VM on the node, with nothing
stopping a misconfigured `vm_id` from touching infrastructure this repo
doesn't own -- this is exactly how a real incident happened (a picked
`vm_id` collided with an unrelated, important VM, and `terraform
destroy` deleted it). Use the dedicated, pool-scoped service account
instead:

```sh
# One-time, as root on pve.g8.lo: a service user + token scoped to
# EXACTLY the terraform-managed pool and the storages this repo uses --
# never root@pam, never unscoped.
pveum user add terraform-svc@pve
pveum role add TerraformOperator -privs "VM.Allocate,VM.Config.Disk,VM.Config.CPU,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.Config.Cloudinit,VM.Monitor,VM.PowerMgmt,VM.Console,Datastore.AllocateSpace,Datastore.Audit,Pool.Audit,Sys.Audit"
pveum acl modify /pool/terraform-managed --users terraform-svc@pve --roles TerraformOperator
pveum user token add terraform-svc@pve irondirectory --privsep 1
pveum acl modify /pool/terraform-managed --tokens 'terraform-svc@pve!irondirectory' --roles TerraformOperator
pveum acl modify /storage/<vm_datastore> --tokens 'terraform-svc@pve!irondirectory' --roles TerraformOperator
pveum acl modify /storage/<snippet_datastore> --tokens 'terraform-svc@pve!irondirectory' --roles TerraformOperator

export PROXMOX_API_TOKEN='terraform-svc@pve!irondirectory=<the-value>'
```

**Always check for VMID conflicts against live state before writing a
`vm_id` into any `terragrunt.hcl`** -- never pattern-guess "next free
after the ones I know about". Use `./get-free-vmid.sh [min] [max]`
(defaults to the module's current allowed range, 2000-2100): it queries
`qm list` on the real node and prints the lowest genuinely unused ID.
The module (`proxmox-fedora-vm` v0.3.0+) also validates every `vm_id`
falls within `vm_id_min`/`vm_id_max` and places every VM in the
`terraform-managed` pool the token is ACL-scoped to -- two independent
layers, but neither substitutes for actually checking.

## etcd cluster

```sh
cd etcd
terragrunt init
terragrunt apply
export ETCDCTL_ENDPOINTS=http://192.168.8.41:2379,http://192.168.8.42:2379,http://192.168.8.43:2379
etcdctl member list -w table     # brew install etcd for a native macOS etcdctl
```

`terragrunt destroy` removes the VMs, their DHCP reservations, and DNS records.

- **dm1/dm2/dm3.g8.lo** → VMID 131/132/133 → 192.168.8.41/.42/.43 (reserved,
  outside the .100-.200 DHCP pool). etcd `v3.6.12`; **fastetcd is a drop-in swap**.
- Per-node etcd install rides the module's `user_data` hook (rendered
  cloud-config). `/var/lib/etcd` is on the root disk today — a dedicated data
  disk is filed as an enhancement on `terraform-modules`.

> The bash `../proxmox/ironetcd.sh` was the bootstrap that proved these steps;
> Terragrunt is the going-forward tool.
