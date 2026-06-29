#!/usr/bin/env bash
#
# ironetcd.sh — provision / destroy irondirectory's dedicated etcd cluster as
# minimal Fedora cloud VMs on Proxmox (D1: a separate, isolated backend, never
# the Kubernetes etcd).
#
# Orchestrated from a workstation on the same subnet as the VMs:
#   - VM lifecycle (create/start/stop/destroy)  -> ssh to the PVE host, run `qm`
#   - etcd install / config                      -> ssh the nodes directly
#   - DNS A/PTR records                          -> MicroDNS REST API
#
# Usage:
#   ./ironetcd.sh up           # create -> installetcd -> dns -> verify
#   ./ironetcd.sh create       # create + start the VMs, wait for SSH
#   ./ironetcd.sh installetcd  # format data disk, install etcd, form cluster
#   ./ironetcd.sh dns          # create A + PTR records
#   ./ironetcd.sh verify       # cluster health + member list
#   ./ironetcd.sh status       # qm status + cluster health
#   ./ironetcd.sh down         # stop the VMs (data preserved)
#   ./ironetcd.sh wipe         # stop+destroy VMs and disks, remove DNS records
#   ./ironetcd.sh ssh dm1      # ssh into a node
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster.env
source "${HERE}/cluster.env"

SSH_OPTS=(-o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o BatchMode=yes)
CACHE="${TMPDIR:-/tmp}/irondir-etcd-cache"
ARCH="amd64"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

pve()      { ssh "${SSH_OPTS[@]}" "$PVE_HOST" "$@"; }
node_ssh() { local ip="$1"; shift; ssh "${SSH_OPTS[@]}" "${CLOUD_USER}@${ip}" "$@"; }

# Field accessors for a "name vmid ip" node line.
n_name() { echo "$1" | awk '{print $1}'; }
n_vmid() { echo "$1" | awk '{print $2}'; }
n_ip()   { echo "$1" | awk '{print $3}'; }

# Comma-separated initial-cluster string: name=http://ip:2380,...
initial_cluster() {
  local out=""
  for node in "${NODES[@]}"; do
    out+="$(n_name "$node")=http://$(n_ip "$node"):2380,"
  done
  echo "${out%,}"
}

# ---------------------------------------------------------------- create ----
cmd_create() {
  [[ -f "$SSH_PUBKEY" ]] || die "SSH pubkey not found: $SSH_PUBKEY"
  log "Copying SSH pubkey to PVE host"
  scp "${SSH_OPTS[@]}" "$SSH_PUBKEY" "${PVE_HOST#*@}":/tmp/irondir_id.pub >/dev/null 2>&1 \
    || pve "cat > /tmp/irondir_id.pub" < "$SSH_PUBKEY"

  for node in "${NODES[@]}"; do
    local name vmid ip
    name="$(n_name "$node")"; vmid="$(n_vmid "$node")"; ip="$(n_ip "$node")"
    if pve "qm status $vmid" >/dev/null 2>&1; then
      warn "VM $vmid ($name) already exists — skipping create"
      continue
    fi
    log "Creating VM $vmid: ${name}.${SEARCH_DOMAIN} @ ${ip}"
    pve "qm create $vmid \
          --name ${name} \
          --memory ${MEMORY_MB} --cores ${CORES} \
          --net0 virtio,bridge=${BRIDGE} \
          --scsihw virtio-scsi-single --agent enabled=1 --ostype l26"
    pve "qm set $vmid --scsi0 ${STORAGE}:0,import-from=${IMAGE_PATH}"
    pve "qm disk resize $vmid scsi0 ${ROOT_DISK_GB}G"
    pve "qm set $vmid --scsi1 ${STORAGE}:${DATA_DISK_GB}"
    pve "qm set $vmid --ide2 ${STORAGE}:cloudinit"
    pve "qm set $vmid --boot order=scsi0 --serial0 socket --vga serial0"
    pve "qm set $vmid \
          --ciuser ${CLOUD_USER} --sshkeys /tmp/irondir_id.pub \
          --ipconfig0 ip=${ip}/${NETMASK},gw=${GATEWAY} \
          --nameserver ${DNS_SERVER} --searchdomain ${SEARCH_DOMAIN}"
    pve "qm start $vmid"
  done

  log "Waiting for SSH on all nodes..."
  for node in "${NODES[@]}"; do
    local ip name; ip="$(n_ip "$node")"; name="$(n_name "$node")"
    for i in $(seq 1 60); do
      if node_ssh "$ip" true 2>/dev/null; then log "  ${name} (${ip}) up"; break; fi
      [[ $i -eq 60 ]] && die "timeout waiting for SSH on ${name} (${ip})"
      sleep 5
    done
  done
}

# ------------------------------------------------------------ etcd binary ----
download_etcd() {
  local tgz="${CACHE}/etcd-${ETCD_VERSION}-linux-${ARCH}.tar.gz"
  mkdir -p "$CACHE"
  if [[ ! -f "${CACHE}/etcd" || ! -f "${CACHE}/etcdctl" ]]; then
    log "Downloading etcd ${ETCD_VERSION} (${ARCH})"
    local url="https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-${ARCH}.tar.gz"
    curl -fsSL "$url" -o "$tgz"
    tar -xzf "$tgz" -C "$CACHE" --strip-components=1 \
      "etcd-${ETCD_VERSION}-linux-${ARCH}/etcd" \
      "etcd-${ETCD_VERSION}-linux-${ARCH}/etcdctl"
  fi
}

# -------------------------------------------------------------- installetcd ----
cmd_installetcd() {
  download_etcd
  local ic; ic="$(initial_cluster)"
  for node in "${NODES[@]}"; do
    local name ip; name="$(n_name "$node")"; ip="$(n_ip "$node")"
    log "Installing etcd on ${name} (${ip})"

    # 1) dedicated data disk -> xfs -> mounted at $ETCD_DATA_DIR
    node_ssh "$ip" "sudo bash -s" <<EOF
set -e
ROOTPART=\$(findmnt -nro SOURCE / | sed 's/\[.*\]//')      # strip btrfs subvol suffix
ROOTDISK=\$(lsblk -no PKNAME "\${ROOTPART}" | head -1)
[ -n "\${ROOTDISK}" ] || { echo "could not determine root disk"; exit 1; }
DISKNAME=\$(lsblk -dnro NAME,TYPE | awk '\$2=="disk"{print \$1}' | grep -vx "\${ROOTDISK}" | grep -v '^zram' | head -1)
[ -n "\${DISKNAME}" ] || { echo "no data disk found"; exit 1; }
DISK="/dev/\${DISKNAME}"
echo "data disk: \${DISK} (root on \${ROOTDISK})"
# self-heal any earlier malformed fstab entry for the data dir
sudo sed -i "\\#[[:space:]]${ETCD_DATA_DIR}[[:space:]]#{/^UUID=/!d}" /etc/fstab
if ! blkid "\${DISK}" >/dev/null 2>&1; then
  sudo mkfs.xfs -q "\${DISK}"
fi
UUID=\$(blkid -s UUID -o value "\${DISK}")
[ -n "\${UUID}" ] || { echo "no UUID on \${DISK}"; exit 1; }
sudo mkdir -p ${ETCD_DATA_DIR}
grep -q "\${UUID}" /etc/fstab || echo "UUID=\${UUID} ${ETCD_DATA_DIR} xfs defaults 0 0" | sudo tee -a /etc/fstab >/dev/null
mountpoint -q ${ETCD_DATA_DIR} || sudo mount "\${DISK}" ${ETCD_DATA_DIR}
sudo getent group etcd >/dev/null || sudo groupadd -r etcd
sudo getent passwd etcd >/dev/null || sudo useradd -r -g etcd -d ${ETCD_DATA_DIR} -s /sbin/nologin etcd
sudo chown -R etcd:etcd ${ETCD_DATA_DIR}
EOF

    # 2) binaries
    scp "${SSH_OPTS[@]}" "${CACHE}/etcd" "${CACHE}/etcdctl" "${CLOUD_USER}@${ip}:/tmp/" >/dev/null
    node_ssh "$ip" "sudo install -m0755 /tmp/etcd /tmp/etcdctl /usr/local/bin/ && rm -f /tmp/etcd /tmp/etcdctl"

    # 3) config + unit
    node_ssh "$ip" "sudo bash -s" <<EOF
set -e
sudo mkdir -p /etc/etcd
sudo tee /etc/etcd/etcd.conf >/dev/null <<CONF
ETCD_NAME=${name}
ETCD_DATA_DIR=${ETCD_DATA_DIR}
ETCD_LISTEN_PEER_URLS=http://0.0.0.0:2380
ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:2379
ETCD_INITIAL_ADVERTISE_PEER_URLS=http://${ip}:2380
ETCD_ADVERTISE_CLIENT_URLS=http://${ip}:2379
ETCD_INITIAL_CLUSTER=${ic}
ETCD_INITIAL_CLUSTER_TOKEN=${ETCD_CLUSTER_TOKEN}
ETCD_INITIAL_CLUSTER_STATE=new
CONF
sudo tee /etc/systemd/system/etcd.service >/dev/null <<UNIT
[Unit]
Description=irondirectory etcd (${name})
Documentation=https://github.com/glennswest/irondirectory
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=etcd
EnvironmentFile=/etc/etcd/etcd.conf
ExecStart=/usr/local/bin/etcd
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable etcd
EOF
  done

  # Start all nodes together (non-blocking): Type=notify etcd only signals ready
  # once quorum forms, so they must come up simultaneously, not one-by-one.
  log "Starting etcd on all nodes simultaneously"
  for node in "${NODES[@]}"; do
    local ip; ip="$(n_ip "$node")"
    node_ssh "$ip" "sudo systemctl restart etcd --no-block"
  done
  log "etcd starting (static bootstrap forms the Raft cluster); verify shortly"
}

# --------------------------------------------------------------------- dns ----
dns_a()   { # name ip
  curl -fsS -X POST "${DNS_API}/zones/${DNS_ZONE_ID}/records" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$1\",\"ttl\":300,\"data\":{\"type\":\"A\",\"data\":\"$2\"},\"enabled\":true}" >/dev/null || true
}
dns_ptr() { # last-octet fqdn
  curl -fsS -X POST "${DNS_API}/zones/${DNS_PTR_ZONE_ID}/records" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$1\",\"ttl\":300,\"data\":{\"type\":\"PTR\",\"data\":\"$2\"},\"enabled\":true}" >/dev/null || true
}
cmd_dns() {
  for node in "${NODES[@]}"; do
    local name ip oct; name="$(n_name "$node")"; ip="$(n_ip "$node")"; oct="${ip##*.}"
    log "DNS: ${name}.${SEARCH_DOMAIN} -> ${ip} (+PTR)"
    dns_a   "$name" "$ip"
    dns_ptr "$oct"  "${name}.${SEARCH_DOMAIN}"
  done
}
dns_del() { # zone_id record_name
  local zid="$1" rname="$2"
  local rid
  rid=$(curl -fsS "${DNS_API}/zones/${zid}/records?limit=500" 2>/dev/null \
        | python3 -c "import sys,json;d=json.load(sys.stdin);r=d if isinstance(d,list) else d.get('records',d.get('data',[]));print(next((x['id'] for x in r if x.get('name')=='${rname}'),''))" 2>/dev/null)
  [[ -n "$rid" ]] && curl -fsS -X DELETE "${DNS_API}/zones/${zid}/records/${rid}" >/dev/null || true
}

# ------------------------------------------------------------------ verify ----
endpoints_csv() {
  local eps=""; for node in "${NODES[@]}"; do eps+="http://$(n_ip "$node"):2379,"; done; echo "${eps%,}"
}

cmd_endpoints() {
  echo "export ETCDCTL_ENDPOINTS=$(endpoints_csv)"
}

cmd_verify() {
  local eps; eps="$(endpoints_csv)"
  log "Endpoints: ${eps}"
  if command -v etcdctl >/dev/null 2>&1; then
    # Native (e.g. macOS) etcdctl on the workstation.
    etcdctl --endpoints="$eps" member list -w table || warn "member list failed (forming?)"
    etcdctl --endpoints="$eps" endpoint health || true
    etcdctl --endpoints="$eps" endpoint status -w table || true
  else
    # Fall back to a node's installed etcdctl.
    local first_ip; first_ip="$(n_ip "${NODES[0]}")"
    node_ssh "$first_ip" "
      etcdctl --endpoints=$eps member list -w table || echo '(forming)'
      etcdctl --endpoints=$eps endpoint health || true
      etcdctl --endpoints=$eps endpoint status -w table || true
    "
  fi
}

# ------------------------------------------------------------------ status ----
cmd_status() {
  for node in "${NODES[@]}"; do
    local name vmid; name="$(n_name "$node")"; vmid="$(n_vmid "$node")"
    printf '%-6s vmid=%s  ' "$name" "$vmid"; pve "qm status $vmid" 2>/dev/null || echo "absent"
  done
  cmd_verify
}

# -------------------------------------------------------------------- down ----
cmd_down() {
  for node in "${NODES[@]}"; do
    local vmid; vmid="$(n_vmid "$node")"
    log "Stopping VM $vmid"; pve "qm stop $vmid" 2>/dev/null || true
  done
}

# -------------------------------------------------------------------- wipe ----
cmd_wipe() {
  warn "WIPING cluster: VMs ${NODES[*]} will be destroyed (disks purged)."
  for node in "${NODES[@]}"; do
    local vmid name; vmid="$(n_vmid "$node")"; name="$(n_name "$node")"
    log "Destroying VM $vmid ($name)"
    pve "qm stop $vmid" 2>/dev/null || true
    pve "qm destroy $vmid --destroy-unreferenced-disks 1 --purge 1" 2>/dev/null || true
  done
  log "Removing DNS records"
  for node in "${NODES[@]}"; do
    local name ip oct; name="$(n_name "$node")"; ip="$(n_ip "$node")"; oct="${ip##*.}"
    dns_del "$DNS_ZONE_ID" "$name"
    dns_del "$DNS_PTR_ZONE_ID" "$oct"
  done
  log "Wiped — back to default."
}

# --------------------------------------------------------------------- ssh ----
cmd_ssh() {
  local want="${1:?usage: ssh <node-name>}"
  for node in "${NODES[@]}"; do
    [[ "$(n_name "$node")" == "$want" ]] && exec ssh "${SSH_OPTS[@]}" "${CLOUD_USER}@$(n_ip "$node")"
  done
  die "unknown node: $want"
}

# -------------------------------------------------------------------- main ----
case "${1:-}" in
  up)          cmd_create; cmd_installetcd; cmd_dns; sleep 5; cmd_verify ;;
  create)      cmd_create ;;
  installetcd) cmd_installetcd ;;
  dns)         cmd_dns ;;
  verify)      cmd_verify ;;
  endpoints)   cmd_endpoints ;;
  status)      cmd_status ;;
  down)        cmd_down ;;
  wipe)        cmd_wipe ;;
  ssh)         shift; cmd_ssh "$@" ;;
  *) die "usage: $0 {up|create|installetcd|dns|verify|endpoints|status|down|wipe|ssh <node>}" ;;
esac
