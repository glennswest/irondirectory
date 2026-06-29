# ─── Proxmox connection (mirrors terraform8) ─────────────────────────────────

variable "proxmox_endpoint" {
  description = "Proxmox API endpoint URL"
  type        = string
  default     = "https://pve.g8.lo:8006/"
}

variable "proxmox_api_token" {
  description = "Proxmox API token, format: user@realm!tokenid=uuid"
  type        = string
  sensitive   = true
}

variable "proxmox_insecure" {
  description = "Skip TLS verification (self-signed certs)"
  type        = bool
  default     = true
}

variable "proxmox_ssh_username" {
  description = "SSH username for node-side operations"
  type        = string
  default     = "root"
}

variable "proxmox_ssh_private_key" {
  description = "Path to the SSH private key authorized on the Proxmox node"
  type        = string
  default     = "~/.ssh/id_rsa"
}

variable "node_name" {
  description = "Proxmox node to create resources on"
  type        = string
  default     = "pve"
}

# ─── Image / storage / network ───────────────────────────────────────────────

variable "fedora_image" {
  description = "Datastore volume ID of the Fedora cloud qcow2 to import from"
  type        = string
  default     = "local:import/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2"
}

variable "vm_datastore" {
  description = "Datastore for VM disks and cloud-init drive"
  type        = string
  default     = "local-lvm"
}

variable "snippet_datastore" {
  description = "Datastore (with snippets content) for cloud-init user-data"
  type        = string
  default     = "local"
}

variable "network_bridge" {
  description = "Proxmox bridge to attach VM NICs to"
  type        = string
  default     = "vmbr0"
}

variable "search_domain" {
  description = "DNS search domain"
  type        = string
  default     = "g8.lo"
}

variable "microdns_base_url" {
  description = "MicroDNS REST API on dns.g8.lo (DHCP reservation + auto DNS)"
  type        = string
  default     = "http://192.168.8.252:8080/api/v1"
}

variable "ci_user" {
  description = "cloud-init default user"
  type        = string
  default     = "fedora"
}

variable "ci_ssh_public_keys" {
  description = "SSH public keys to inject via cloud-init"
  type        = list(string)
}

# ─── etcd backend (D1: irondirectory's dedicated cluster) ────────────────────

variable "etcd_version" {
  description = "Upstream etcd release to install (fastetcd is a drop-in swap)"
  type        = string
  default     = "v3.6.12"
}

variable "etcd_cluster_token" {
  description = "etcd initial-cluster-token (guards against cross-cluster mixups)"
  type        = string
  default     = "irondir-etcd"
}

variable "etcd_data_dir" {
  description = "etcd data directory (its own disk)"
  type        = string
  default     = "/var/lib/etcd"
}

# ─── etcd node fleet ─────────────────────────────────────────────────────────
# Each node gets a fixed MAC; a MicroDNS DHCP reservation pins MAC -> IP and
# auto-registers DNS. IPs sit outside the g8 DHCP pool (.100-.200). The second
# disk (data_disk_size) is dedicated to etcd at var.etcd_data_dir.

variable "nodes" {
  description = "etcd cluster nodes (key = short hostname)"
  type = map(object({
    vm_id          = number
    mac            = string
    ip             = string
    cores          = number
    memory         = number
    root_disk_size = number
    data_disk_size = number
  }))
  default = {
    dm1 = { vm_id = 131, mac = "BC:24:11:08:00:11", ip = "192.168.8.41", cores = 2, memory = 2048, root_disk_size = 20, data_disk_size = 10 }
    dm2 = { vm_id = 132, mac = "BC:24:11:08:00:12", ip = "192.168.8.42", cores = 2, memory = 2048, root_disk_size = 20, data_disk_size = 10 }
    dm3 = { vm_id = 133, mac = "BC:24:11:08:00:13", ip = "192.168.8.43", cores = 2, memory = 2048, root_disk_size = 20, data_disk_size = 10 }
  }
}
