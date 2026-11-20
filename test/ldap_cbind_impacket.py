"""A GSSAPI bind carrying channel bindings over PLAIN LDAP (#65), for
test/ldap-channel-binding-e2e.sh.

OpenLDAP's client sends channel bindings only over TLS, so this builds the
AP-REQ itself with impacket's Kerberos client (an implementation independent
of this project), putting the RFC 4121 §4.1.1.2 Bnd of a tls-server-end-point
binding in the GSS checksum, and sends it on a plain connection.

  python ldap_cbind_impacket.py <ldap-port> <kdc-port> <realm> <spn> <user> <password> <bnd>

<bnd> is "zero" (no bindings) or "tls" (the MD5 of a tls-server-end-point
struct). Prints the bind's resultCode and diagnosticMessage:
"result <code> <message>".
"""

import datetime
import hashlib
import socket
import struct
import sys

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

import impacket.krb5.kerberosv5 as kerberosv5
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
from impacket.krb5.gssapi import GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG, KRB_OID, CheckSumField
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.ldap.ldapasn1 import BindRequest, LDAPMessage

ldap_port, kdc_port, realm, spn, user, password, bnd_kind = sys.argv[1:8]

_send = kerberosv5.sendReceive
kerberosv5.sendReceive = lambda data, host, kdcHost, port=88: _send(data, host, kdcHost, int(kdc_port))

if bnd_kind == "zero":
    bnd = bytes(16)
else:
    app = b"tls-server-end-point:" + hashlib.sha256(b"some certificate").digest()
    bnd = hashlib.md5(bytes(16) + struct.pack("<I", len(app)) + app).digest()

name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
tgt, cipher, _, tgt_key = kerberosv5.getKerberosTGT(name, password, realm, b"", b"", kdcHost="127.0.0.1")
server = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
tgs, cipher, _, key = kerberosv5.getKerberosTGS(server, realm, "127.0.0.1", tgt, cipher, tgt_key)
ticket = Ticket()
ticket.from_asn1(decoder.decode(tgs, asn1Spec=TGS_REP())[0]["ticket"])

ap = AP_REQ()
ap["pvno"] = 5
ap["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
ap["ap-options"] = constants.encodeFlags([])
seq_set(ap, "ticket", ticket.to_asn1)
auth = Authenticator()
auth["authenticator-vno"] = 5
auth["crealm"] = realm
seq_set(auth, "cname", name.components_to_asn1)
now = datetime.datetime.now(datetime.timezone.utc)
auth["cusec"] = now.microsecond
auth["ctime"] = KerberosTime.to_asn1(now)
auth["cksum"] = noValue
auth["cksum"]["cksumtype"] = 0x8003
chk = CheckSumField()
chk["Lgth"] = 16
chk["Bnd"] = bnd
chk["Flags"] = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG
auth["cksum"]["checksum"] = chk.getData()
ap["authenticator"] = noValue
ap["authenticator"]["etype"] = cipher.enctype
ap["authenticator"]["cipher"] = cipher.encrypt(key, 11, encoder.encode(auth), None)
inner = KRB_OID + b"\x01\x00" + encoder.encode(ap)
n = len(inner)
length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
token = b"\x60" + length + inner

req = BindRequest()
req["version"] = 3
req["name"] = ""
req["authentication"]["sasl"]["mechanism"] = "GSSAPI"
req["authentication"]["sasl"]["credentials"] = token
msg = LDAPMessage()
msg["messageID"] = 1
msg["protocolOp"].setComponentByType(req.getTagSet(), req)

s = socket.create_connection(("127.0.0.1", int(ldap_port)), timeout=15)
s.sendall(encoder.encode(msg))
buf = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
    try:
        reply, _ = ber_decoder.decode(buf, asn1Spec=LDAPMessage())
        break
    except Exception:  # incomplete PDU: read more
        continue
r = reply["protocolOp"]["bindResponse"]
print(f"result {int(r['resultCode'])} {r['diagnosticMessage']}")
