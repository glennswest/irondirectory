#!/usr/bin/env bash
#
# ldap-lb.sh — (re)create the health-checked DNS load-balancer record for the
# iron-ldap backend: ldap.g8.lo -> the 3 il1/il2/il3 IPs, each with an HTTP
# health probe against iron-ldapd's real /health (does a fastetcd Status RPC,
# not just TCP liveness -- see crates/ldap/src/health.rs). Idempotent. Mirrors
# ../etcd/../dns/etcd-lb.sh's pattern exactly.
#
# Note: the g8 MicroDNS LB *monitor* is enabled via mkube -- there is no REST
# toggle. Until it's on, the name round-robins across all three (LDAP clients
# aren't cluster-aware the way etcd clients are, but since every replica is
# stateless and independently backed by the same fastetcd cluster, any of the
# three answers identically).
#
# Usage: ./ldap-lb.sh up | down
set -euo pipefail

DNS_API="http://192.168.8.252:8080/api/v1"
ZONE_ID="9bed60c8-1664-4183-88f9-a1a21b927edc"   # g8.lo
NAME="ldap"
IPS=(192.168.8.44 192.168.8.45 192.168.8.46)
PROBE_TYPE="http"
PROBE_ENDPOINT=":8080/"

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
