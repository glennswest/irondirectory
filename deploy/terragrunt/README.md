# irondirectory infrastructure — Terragrunt

Provisions irondirectory's infrastructure using the **shared, versioned**
module at [`github.com/glennswest/terraform-modules`](https://github.com/glennswest/terraform-modules)
(`modules/proxmox-fedora-vm`). We never copy `.tf` files — units reference the
module by a pinned `?ref=` tag.

```
deploy/terragrunt/
  root.hcl            # provider + token wiring (PROXMOX_API_TOKEN from env), once
  etcd/               # unit: dm1/dm2/dm3.g8.lo — the dedicated etcd backend (D1), pinned to an older
                       # module version (vm_id 131-133, outside the current 2000-2100 range)
  ldap/               # unit: il1/il2/il3.g8.lo — redundant iron-ldap (vm_id 134-136, same as above)
    terragrunt.hcl
    templates/etcd-user-data.yaml.tftpl
```

No local copy of `get-free-vmid.sh` lives in this repo -- the canonical
copy is `terraform-modules`' own, at
`examples/terragrunt/get-free-vmid.sh` (sibling checkout: `../../../terraform-modules/examples/terragrunt/get-free-vmid.sh`
from this directory, or `git clone` it if missing). One copy, not two
drifting in parallel -- its lock/reservation files are keyed by the
target Proxmox host, so this repo and any other project pointed at the
same node share the same protection automatically.

Throwaway validation units (e.g. for a specific GitHub issue) come and
go -- built with `terragrunt apply`, `destroy`ed once done, and their
directories removed from the repo afterward rather than left around
with stale `vm_id`s from a since-changed allowed range.

## One-time setup

```sh
brew install hashicorp/tap/terraform terragrunt
# Proxmox node must trust your ~/.ssh/id_rsa.pub (root@pve.g8.lo).

# Day to day: the token lives in .env at the repo root (gitignored,
# chmod 600) — source it, don't mint a fresh one:
source .env   # from the repo root; adjust the path from a unit subdir
```

**Never use a `root@pam` token, with or without `--privsep 0`.** A
`root@pam` token has no ACL boundary at all -- nothing stops a
misconfigured `vm_id` from touching infrastructure this repo doesn't
own. This is exactly how a real incident happened: a picked `vm_id`
collided with an unrelated, important VM, and `terraform destroy`
deleted it -- made worse because the token secret was never persisted
anywhere retrievable, so every operator minted a *fresh* unrestricted
root token rather than reusing one (five of them, over time: terraform,
irondir, terraform-cli, -cli-2, -cli-3). Full writeup: terraform-modules
CLAUDE.md, "Incident: 2026-07-08".

If `.env`'s token is genuinely lost, Proxmox never re-displays a token
secret after creation, so you'll need a new one -- always the
dedicated, pool-scoped service account, never `root@pam`:

```sh
# One-time, as root on pve.g8.lo: a service user + token scoped to
# EXACTLY the terraform-managed pool and the storages this repo uses.
pveum user add terraform-svc@pve
pveum role add TerraformOperator -privs "VM.Allocate,VM.Config.Disk,VM.Config.CPU,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.Config.Cloudinit,VM.Monitor,VM.PowerMgmt,VM.Console,Datastore.AllocateSpace,Datastore.Audit,Pool.Audit,Sys.Audit"
pveum acl modify /pool/terraform-managed --users terraform-svc@pve --roles TerraformOperator
pveum user token add terraform-svc@pve <name> --privsep 1
pveum acl modify /pool/terraform-managed --tokens 'terraform-svc@pve!<name>' --roles TerraformOperator
pveum acl modify /storage/<vm_datastore> --tokens 'terraform-svc@pve!<name>' --roles TerraformOperator

# Snippets get their OWN dedicated storage, not "local" -- Proxmox's
# Datastore.AllocateSpace permission isn't scoped by content type, so a
# token granted "local" for snippets could also touch its ISOs/vztmpl/
# import content (there is no such thing as "snippets-only" access to a
# storage that also hosts other content). An isolated storage with
# nothing else on it closes that gap instead of accepting it as residual
# risk -- one-time setup:
pvesm add dir terraform-snippets --path /var/lib/terraform-snippets --content snippets
pveum acl modify /storage/terraform-snippets --tokens 'terraform-svc@pve!<name>' --roles TerraformOperator

export PROXMOX_API_TOKEN='terraform-svc@pve!<name>=<the-value>'
# ...then save it into .env (chmod 600, gitignored) so it isn't lost again.
```

`vm_datastore` and `snippet_datastore` in every unit's `inputs` should be
`test-lvm-thin` and `terraform-snippets` respectively -- never
`local-lvm`/`local`, which also host hand-created/production VMs and
other content this token has no reason to touch.

**Always check for VMID conflicts against live state before writing a
`vm_id` into any `terragrunt.hcl`** -- never pattern-guess "next free
after the ones I know about". Use terraform-modules'
`examples/terragrunt/get-free-vmid.sh [min] [max]` (defaults to the
module's current allowed range, 2000-2100): it queries `qm list` on the
real node and prints the lowest genuinely unused ID. The module
(`proxmox-fedora-vm` v0.3.0+) also validates every `vm_id` falls within
`vm_id_min`/`vm_id_max` and places every VM in the `terraform-managed`
pool the token is ACL-scoped to -- two independent layers, but neither
substitutes for actually checking.

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
