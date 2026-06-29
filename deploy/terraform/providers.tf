provider "proxmox" {
  endpoint  = var.proxmox_endpoint
  api_token = var.proxmox_api_token
  insecure  = var.proxmox_insecure

  # Disk import / snippet upload need SSH to the node. Explicit key file so it
  # doesn't depend on ssh-agent (the provider ignores ~/.ssh/config otherwise).
  ssh {
    agent       = false
    username    = var.proxmox_ssh_username
    private_key = file(pathexpand(var.proxmox_ssh_private_key))
  }
}
