#!/usr/bin/env bash
#
# etcd-lb.sh — (re)create the health-checked DNS load-balancer record for the
# etcd backend: etcd.g8.lo -> the 3 etcd node IPs, each with an etcd /health
# probe. MicroDNS is record-based: "add 3 IPs to one name" + a per-record
# health_check; the LB monitor then returns only healthy members (last-alive
# failsafe). Idempotent.
#
# Note: the g8 MicroDNS LB *monitor* is enabled via mkube (the launcher of the
# g8 microdns container) — there is no REST toggle. Until it's on, the name
# round-robins across all three (etcd clients are cluster-aware, so that's fine).
#
# Usage: ./etcd-lb.sh up | down
set -euo pipefail

DNS_API="http://192.168.8.252:8080/api/v1"
ZONE_ID="9bed60c8-1664-4183-88f9-a1a21b927edc"   # g8.lo
NAME="etcd"
IPS=(192.168.8.41 192.168.8.42 192.168.8.43)
PORT=2379
# HTTP GET :2379/health — fastetcd#5 landed in v0.7.0, cluster running v0.8.0.
PROBE_TYPE="http"
PROBE_ENDPOINT=":2379/health"

records_json() { curl -fsS --max-time 6 "${DNS_API}/zones/${ZONE_ID}/records?limit=500"; }

cmd_up() {
  for ip in "${IPS[@]}"; do
    echo "-> ${NAME}.g8.lo A ${ip} (health: ${PROBE_TYPE} ${PROBE_ENDPOINT})"
    curl -fsS --max-time 6 -X POST "${DNS_API}/zones/${ZONE_ID}/records" \
      -H 'Content-Type: application/json' \
      -d "{\"name\":\"${NAME}\",\"ttl\":60,\"enabled\":true,
           \"data\":{\"type\":\"A\",\"data\":\"${ip}\"},
           \"health_check\":{\"probe_type\":\"${PROBE_TYPE}\",\"interval_secs\":10,\"timeout_secs\":5,\"unhealthy_threshold\":3,\"healthy_threshold\":2,\"endpoint\":\"${PROBE_ENDPOINT}\"}}" \
      -o /dev/null -w '   [HTTP %{http_code}]\n' || true   # 201 created, or already exists
  done
}

cmd_down() {
  local ids
  ids=$(records_json | python3 -c "
import sys,json
d=json.load(sys.stdin); r=d if isinstance(d,list) else d.get('records',d.get('data',[]))
print('\n'.join(x['id'] for x in r if x.get('name')=='${NAME}' and x.get('type')=='A'))")
  for id in $ids; do
    echo "-> delete record ${id}"
    curl -fsS --max-time 6 -X DELETE "${DNS_API}/zones/${ZONE_ID}/records/${id}" -o /dev/null -w '   [HTTP %{http_code}]\n' || true
  done
}

case "${1:-up}" in
  up)   cmd_up ;;
  down) cmd_down ;;
  *) echo "usage: $0 {up|down}" >&2; exit 1 ;;
esac
