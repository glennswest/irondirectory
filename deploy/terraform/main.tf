# irondirectory backing etcd cluster (D1) — provisioned on Proxmox with the
# bpg/proxmox provider, modeled on the house terraform8 pattern: a MicroDNS DHCP
# reservation pins MAC -> IP (and auto-registers DNS), and a per-node cloud-init
# snippet installs etcd and forms the Raft cluster.

locals {
  # etcd static-bootstrap peer list: name=http://ip:2380,...
  initial_cluster = join(",", [for k, v in var.nodes : "${k}=http://${v.ip}:2380"])
}

# ─── MicroDNS DHCP reservation (MAC -> IP, auto DNS) ──────────────────────────
resource "terraform_data" "dns_reservation" {
  for_each = var.nodes

  triggers_replace = {
    mac      = lower(each.value.mac)
    ip       = each.value.ip
    hostname = each.key
    base_url = var.microdns_base_url
  }

  provisioner "local-exec" {
    command = <<-EOT
      curl -fsS -X POST '${self.triggers_replace.base_url}/dhcp/reservations' \
        -H 'Content-Type: application/json' \
        -d '{"mac":"${self.triggers_replace.mac}","ip":"${self.triggers_replace.ip}","hostname":"${self.triggers_replace.hostname}"}' \
        || curl -fsS -X PATCH '${self.triggers_replace.base_url}/dhcp/reservations/${self.triggers_replace.mac}' \
             -H 'Content-Type: application/json' \
             -d '{"ip":"${self.triggers_replace.ip}","hostname":"${self.triggers_replace.hostname}"}'
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "curl -fsS -X DELETE '${self.triggers_replace.base_url}/dhcp/reservations/${self.triggers_replace.mac}' || true"
  }
}

# ─── cloud-init user-data (one etcd snippet per node) ─────────────────────────
resource "proxmox_virtual_environment_file" "user_data" {
  for_each = var.nodes

  content_type = "snippets"
  datastore_id = var.snippet_datastore
  node_name    = var.node_name

  source_raw {
    file_name = "${each.key}-etcd-user-data.yaml"
    data = templatefile("${path.module}/templates/etcd-user-data.yaml.tftpl", {
      hostname        = each.key
      fqdn            = "${each.key}.${var.search_domain}"
      ci_user         = var.ci_user
      ssh_keys        = [for k in var.ci_ssh_public_keys : trimspace(k)]
      node_ip         = each.value.ip
      initial_cluster = local.initial_cluster
      cluster_token   = var.etcd_cluster_token
      etcd_version    = var.etcd_version
      data_dir        = var.etcd_data_dir
    })
  }
}

# ─── etcd VMs ─────────────────────────────────────────────────────────────────
resource "proxmox_virtual_environment_vm" "etcd" {
  for_each = var.nodes

  name      = "${each.key}.${var.search_domain}"
  node_name = var.node_name
  vm_id     = each.value.vm_id
  tags      = ["terraform", "fedora", "irondirectory", "etcd"]

  depends_on = [terraform_data.dns_reservation]

  agent { enabled = true }

  cpu {
    cores = each.value.cores
    type  = "host"
  }

  memory {
    dedicated = each.value.memory
  }

  scsi_hardware = "virtio-scsi-single"

  # scsi0: root (imported from the Fedora cloud image)
  disk {
    datastore_id = var.vm_datastore
    import_from  = var.fedora_image
    interface    = "scsi0"
    size         = each.value.root_disk_size
    discard      = "on"
    ssd          = true
  }

  # scsi1: dedicated etcd data disk -> mounted at var.etcd_data_dir
  disk {
    datastore_id = var.vm_datastore
    interface    = "scsi1"
    size         = each.value.data_disk_size
    discard      = "on"
    ssd          = true
  }

  network_device {
    bridge      = var.network_bridge
    mac_address = each.value.mac
  }

  operating_system {
    type = "l26"
  }

  initialization {
    datastore_id = var.vm_datastore
    interface    = "ide2"

    # DHCP: the MicroDNS reservation supplies IP, gateway, DNS and domain.
    ip_config {
      ipv4 { address = "dhcp" }
    }

    user_data_file_id = proxmox_virtual_environment_file.user_data[each.key].id
  }

  lifecycle {
    ignore_changes = [
      disk[0].import_from, # avoid re-import churn after first create
    ]
  }
}
