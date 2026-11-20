"""Presents a SERVICE ticket in a TGS-REQ (finding 366e637ff815, #73), for
test/tgs-service-ticket-e2e.sh, with impacket's Kerberos client (an
implementation independent of this project).

  python tgs_service_ticket_impacket.py <kdc-port> <realm> <user> <password> <service> <victim>

1. alice's real TGT gets a ticket for <victim> (the control);
2. alice gets a service ticket for <service>, then sends it to the TGS as if
   it were her TGT, asking for <victim>. A KDC that accepts it lets anyone
   holding a service ticket, or a service's key, mint tickets for every
   other service. Expected: KRB_AP_ERR_NOT_US (35).

Prints "ok: ..." lines; exits 1 with "FAIL: ..." otherwise.
"""

import sys

import impacket.krb5.kerberosv5 as kerberosv5
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.types import Principal

kdc_port, realm, user, password, service, victim = sys.argv[1:7]

_send = kerberosv5.sendReceive
kerberosv5.sendReceive = lambda data, host, kdcHost, port=88: _send(data, host, kdcHost, int(kdc_port))


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def srv(name):
    return Principal(name, type=constants.PrincipalNameType.NT_SRV_INST.value)


client = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
tgt, cipher, _, tgt_key = kerberosv5.getKerberosTGT(client, password, realm, b"", b"", kdcHost="127.0.0.1")

# 1. The control: a real TGT is accepted.
kerberosv5.getKerberosTGS(srv(victim), realm, "127.0.0.1", tgt, cipher, tgt_key)
print(f"ok: 1. {user}'s TGT gets a ticket for {victim}")

# 2. A service ticket presented as a TGT. getKerberosTGS reads its `tgt`
# argument as an AS-REP (ticket, crealm, cname); a TGS-REP has the same
# fields under [APPLICATION 13], so retagging it [APPLICATION 11] (0x6b)
# hands impacket the service ticket and its session key as if a TGT.
tgs, svc_cipher, _, svc_key = kerberosv5.getKerberosTGS(srv(service), realm, "127.0.0.1", tgt, cipher, tgt_key)
if tgs[0] != 0x6D:
    fail(f"TGS-REP starts with {tgs[0]:#x}, expected 0x6d")
as_shaped = b"\x6b" + tgs[1:]
try:
    kerberosv5.getKerberosTGS(srv(victim), realm, "127.0.0.1", as_shaped, svc_cipher, svc_key)
except KerberosError as e:
    code = e.getErrorCode()
    if code != 35:
        fail(f"2. the service ticket was refused, but with error {code} ({e}), expected 35 KRB_AP_ERR_NOT_US")
    print(f"ok: 2. a {service} service ticket presented as a TGT is refused: KRB_AP_ERR_NOT_US ({e})")
    sys.exit(0)
fail(f"2. the KDC issued a {victim} ticket for a {service} service ticket presented as a TGT")
