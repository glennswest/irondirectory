"""GSS-SPNEGO binds built with impacket (#88), for test/ldap-gss-spnego-e2e.sh.

impacket's SPNEGO encoder and Kerberos client are independent of this
project. Modes:

  python ldap_spnego_impacket.py <ldap-port> <kdc-port> <realm> <spn> <user> <password> windows
      negTokenInit [MS-KRB5, KRB5, NTLMSSP] + AP-REQ (mutual, no subkey, no
      sign/seal). Checks the bind response itself: success; a negTokenResp
      with negState accept-completed, supportedMech MS-KRB5 (the client's
      first), a responseToken whose AP-REP decrypts (usage 12) to our ctime,
      and a mechListMIC equal byte for byte to the RFC 4121 GetMIC impacket's
      own HMAC computes over the mechTypes DER (acceptor, usage 23, seq 0).
      Then an unwrapped Who am I on the same connection.
  ... sign        the same with GSS_C_INTEG_FLAG (no CONF): an integrity layer.
      Who am I is sent as an RFC 4121 §4.2.4 Wrap token (4-octet length,
      checksum usage 24) built with impacket's HMAC, and the reply's Wrap
      token (SentByAcceptor, checksum usage 22) is verified the same way.
  ... ntlm        negTokenInit [NTLMSSP] only: refused (result 7)
  ... ntlmfirst   negTokenInit [NTLMSSP, MS-KRB5]: refused (result 7)

Prints "ok ..." lines and exits non-zero on the first mismatch.
"""

import datetime
import socket
import struct
import sys

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

import impacket.krb5.kerberosv5 as kerberosv5
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REP, AP_REQ, TGS_REP, Authenticator, EncAPRepPart, seq_set
from impacket.krb5.crypto import _checksum_table
from impacket.krb5.gssapi import GSS_C_MUTUAL_FLAG, KRB_OID, CheckSumField
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.ldap.ldapasn1 import BindRequest, ExtendedRequest, LDAPMessage
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

ldap_port, kdc_port, realm, spn, user, password, mode = sys.argv[1:8]
MS_KRB5 = TypesMech["MS KRB5 - Microsoft Kerberos 5"]
KRB5 = TypesMech["KRB5 - Kerberos 5"]
NTLM = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def oid_tlv(m):
    # TypesMech values are DER OIDs (tag 06 included) in impacket.
    return m if m[:1] == b"\x06" else b"\x06" + bytes([len(m)]) + m


def der_len(n):
    return bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")


def ap_req(flags):
    _send = kerberosv5.sendReceive
    kerberosv5.sendReceive = lambda data, host, kdcHost, port=88: _send(data, host, kdcHost, int(kdc_port))
    name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, cipher, _, tgt_key = kerberosv5.getKerberosTGT(name, password, realm, b"", b"", kdcHost="127.0.0.1")
    server = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    tgs, cipher, _, key = kerberosv5.getKerberosTGS(server, realm, "127.0.0.1", tgt, cipher, tgt_key)
    ticket = Ticket()
    ticket.from_asn1(decoder.decode(tgs, asn1Spec=TGS_REP())[0]["ticket"])
    ap = AP_REQ()
    ap["pvno"] = 5
    ap["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap["ap-options"] = constants.encodeFlags([constants.APOptions.mutual_required.value])
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
    chk["Bnd"] = bytes(16)
    chk["Flags"] = flags
    auth["cksum"]["checksum"] = chk.getData()
    ap["authenticator"] = noValue
    ap["authenticator"]["etype"] = cipher.enctype
    ap["authenticator"]["cipher"] = cipher.encrypt(key, 11, encoder.encode(auth), None)
    inner = KRB_OID + b"\x01\x00" + encoder.encode(ap)
    return b"\x60" + der_len(len(inner)) + inner, cipher, key, now


def tlv(b, pos):
    tag, n = b[pos], b[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[pos : pos + k], "big")
        pos += k
    return tag, b[pos : pos + n], pos + n


def whoami_value(ldap_message_der):
    """The responseValue of an LDAPMessage carrying an extendedResponse (by hand:
    RFC 4511 [APPLICATION 24], responseValue [11])."""
    tag, msg, _ = tlv(ldap_message_der, 0)
    _, _, pos = tlv(msg, 0)  # messageID
    tag, op, _ = tlv(msg, pos)
    if tag != 0x78:
        fail(f"not an extendedResponse: tag {tag:#x}")
    _, code, pos = tlv(op, 0)
    if int.from_bytes(code, "big") != 0:
        fail(f"Who am I result {int.from_bytes(code, 'big')}")
    value = b""
    while pos < len(op):
        t, content, pos = tlv(op, pos)
        if t == 0x8B:
            value = content
    return value.decode()


def read_pdu(sock):
    buf = b""
    while True:
        if len(buf) >= 2:
            n = buf[1]
            total = 2 + n if n < 0x80 else 2 + (n & 0x7F) + int.from_bytes(buf[2 : 2 + (n & 0x7F)], "big")
            if len(buf) >= total:
                return buf[:total]
        chunk = sock.recv(65536)
        if not chunk:
            fail(f"connection closed after {len(buf)} bytes")
        buf += chunk


def mech_list_mic(resp_der):
    """negTokenResp [1] SEQUENCE { ... [3] OCTET STRING }: impacket's parser drops it."""
    tag, seq, _ = tlv(resp_der, 0)
    tag2, body, _ = tlv(seq, 0)
    if (tag, tag2) != (0xA1, 0x30):
        fail(f"not a negTokenResp: {resp_der[:8].hex()}")
    pos = 0
    while pos < len(body):
        t, content, pos = tlv(body, pos)
        if t == 0xA3:
            return tlv(content, 0)[1]
    fail("the negTokenResp has no mechListMIC")


def exchange(sock, msg, want_op):
    sock.sendall(encoder.encode(msg))
    buf = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            fail("connection closed")
        buf += chunk
        try:
            reply, _ = ber_decoder.decode(buf, asn1Spec=LDAPMessage())
            return reply["protocolOp"][want_op]
        except Exception:  # incomplete PDU: read more
            continue


def bind(sock, token):
    req = BindRequest()
    req["version"] = 3
    req["name"] = ""
    req["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
    req["authentication"]["sasl"]["credentials"] = token
    msg = LDAPMessage()
    msg["messageID"] = 1
    msg["protocolOp"].setComponentByType(req.getTagSet(), req)
    return exchange(sock, msg, "bindResponse")


def init_token(mechs, mech_token):
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = mechs
    blob["MechToken"] = mech_token
    return blob.getData()


sock = socket.create_connection(("127.0.0.1", int(ldap_port)), timeout=15)
if mode in ("ntlm", "ntlmfirst"):
    mechs = [NTLM] if mode == "ntlm" else [NTLM, MS_KRB5]
    r = bind(sock, init_token(mechs, b"NTLMSSP\x00\x01\x00\x00\x00" + bytes(24)))
    code, diag = int(r["resultCode"]), str(r["diagnosticMessage"])
    if code != 7:
        fail(f"{mode}: result {code} {diag!r}, want 7 (authMethodNotSupported)")
    print(f"ok  {mode}: result {code} {diag}")
    sys.exit(0)

GSS_C_INTEG_FLAG = 0x20
token, cipher, key, ctime = ap_req(GSS_C_MUTUAL_FLAG | (GSS_C_INTEG_FLAG if mode == "sign" else 0))
mechs = [MS_KRB5, KRB5, NTLM]
r = bind(sock, init_token(mechs, token))
code, diag = int(r["resultCode"]), str(r["diagnosticMessage"])
if code != 0:
    fail(f"windows-order bind: result {code} {diag!r}")
creds = bytes(r["serverSaslCreds"])
resp = SPNEGO_NegTokenResp(creds)
neg_state = resp["NegState"]
neg_state = neg_state[0] if isinstance(neg_state, (bytes, bytearray)) else int(neg_state)
if neg_state != 0:
    fail(f"negState {neg_state}, want 0 (accept-completed)")
if oid_tlv(resp["SupportedMech"]) != oid_tlv(MS_KRB5):
    fail(f"supportedMech {resp['SupportedMech'].hex()}, want MS-KRB5")
print("ok  negTokenResp: accept-completed, supportedMech MS-KRB5 (the client's first)")

rt = resp["ResponseToken"]
pos = 2 if rt[1] < 0x80 else 2 + (rt[1] & 0x7F)
body = rt[pos:]
if body[: len(KRB_OID)] != KRB_OID or body[len(KRB_OID) : len(KRB_OID) + 2] != b"\x02\x00":
    fail(f"responseToken is not a krb5 AP-REP token: {rt[:24].hex()}")
ap_rep = decoder.decode(body[len(KRB_OID) + 2 :], asn1Spec=AP_REP())[0]
plain = cipher.decrypt(key, 12, bytes(ap_rep["enc-part"]["cipher"]))
part = decoder.decode(plain, asn1Spec=EncAPRepPart())[0]
if KerberosTime.from_asn1(part["ctime"]).replace(microsecond=0) != ctime.replace(microsecond=0, tzinfo=None) or int(part["cusec"]) != ctime.microsecond:
    fail("the AP-REP's ctime/cusec are not ours")
print("ok  responseToken: an AP-REP that decrypts (usage 12) to our ctime/cusec")

mech_types_der = b"\x30" + der_len(sum(len(oid_tlv(m)) for m in mechs)) + b"".join(oid_tlv(m) for m in mechs)
header = b"\x04\x04\x01" + b"\xff" * 5 + struct.pack(">Q", 0)
cks = _checksum_table[{17: 15, 18: 16}[cipher.enctype]]
want_mic = header + cks.checksum(key, 23, mech_types_der + header)
got_mic = mech_list_mic(creds)
if bytes(got_mic) != want_mic:
    fail(f"mechListMIC {bytes(got_mic).hex()} != impacket's GetMIC {want_mic.hex()}")
print(f"ok  mechListMIC equals impacket's RFC 4121 GetMIC over mechTypes (acceptor, usage 23, {len(want_mic)} bytes)")

ext = ExtendedRequest()
ext["requestName"] = "1.3.6.1.4.1.4203.1.11.3"
msg = LDAPMessage()
msg["messageID"] = 2
msg["protocolOp"].setComponentByType(ext.getTagSet(), ext)
if mode == "windows":
    sock.sendall(encoder.encode(msg))
    got = whoami_value(read_pdu(sock))
    layer = "no layer asked for"
else:
    ec = cks.macsize
    plain_req = encoder.encode(msg)
    hdr = b"\x05\x04\x00\xff" + struct.pack(">HH", ec, 0) + struct.pack(">Q", 1)
    zeroed = hdr[:4] + b"\x00\x00\x00\x00" + hdr[8:]
    wrapped = hdr + plain_req + cks.checksum(key, 24, plain_req + zeroed)
    sock.sendall(struct.pack(">I", len(wrapped)) + wrapped)
    buf = b""
    while len(buf) < 4 or len(buf) < 4 + struct.unpack(">I", buf[:4])[0]:
        chunk = sock.recv(65536)
        if not chunk:
            fail("connection closed before the wrapped reply")
        buf += chunk
    tok = buf[4 : 4 + struct.unpack(">I", buf[:4])[0]]
    if tok[:2] != b"\x05\x04" or tok[2] & 0x01 == 0 or tok[2] & 0x02:
        fail(f"reply is not an unsealed acceptor Wrap token: {tok[:16].hex()}")
    rrc = struct.unpack(">H", tok[6:8])[0]
    rest = tok[16:]
    rest = rest[rrc % len(rest) :] + rest[: rrc % len(rest)] if rest else rest
    data, mac = rest[:-ec], rest[-ec:]
    zeroed = tok[:4] + b"\x00\x00\x00\x00" + tok[8:16]
    if cks.checksum(key, 22, data + zeroed) != mac:
        fail("the reply's Wrap checksum does not verify (usage 22)")
    got = whoami_value(data)
    layer = "integrity layer: request and reply Wrap tokens checked with impacket's HMAC"
if got != f"u:{user}@{realm}":
    fail(f"Who am I after the bind: {got!r}")
print(f"ok  {mode}: Who am I on the same connection ({layer}): {got}")
