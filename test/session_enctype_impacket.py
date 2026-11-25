"""Tickets whose session key's enctype is not the ticket's (finding
bf4c13fcebad, #79), for test/session-enctype-e2e.sh.

A KDC may issue one: the AS keeps the client's pre-auth enctype for the
session key while the krbtgt encrypts the TGT with another, and a foreign
KDC's cross-realm TGT often does the same. impacket (independent of this
project) builds such tickets from the real service key, exported to a
keytab: the ticket under aes256-cts-hmac-sha1-96 (18), its session key
aes128-cts-hmac-sha1-96 (17), every message under the session key in 17.

  python session_enctype_impacket.py tgs     <kdc-port> <realm> <krbtgt.keytab> <client> <service>
      A forged TGT -> impacket's own TGS-REQ (Authenticator usage 7) -> the
      TGS-REP must decrypt under the session key (usage 8) and carry a
      service ticket for <service>.
  python session_enctype_impacket.py kpasswd <kpasswd-port> <realm> <krbtgt.keytab> <client> <new-password>
      A forged kadmin/changepw ticket (read with the krbtgt key, as in AD) ->
      impacket's own kpasswd request -> the reply's AP-REP/KRB-PRIV decode
      and say success.
  python session_enctype_impacket.py ldap    <ldap-port> <realm> <service.keytab> <client> <spn>
      A forged service ticket for <spn> -> a SASL GSSAPI bind to iron-ldapd
      -> SaslBindInProgress with an AP-REP that decrypts under the session
      key (usage 12).

Prints "ok ..." or "FAIL ..." and exits 0 or 1.
"""

import datetime
import os
import socket
import struct
import sys

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

import impacket.krb5.kerberosv5 as kerberosv5
from impacket.krb5 import constants, kpasswd
from impacket.krb5.asn1 import AP_REP, AP_REQ, AS_REP, TGS_REP, Authenticator, EncAPRepPart, EncTicketPart, seq_set
from impacket.krb5.asn1 import Ticket as TicketAsn1
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import GSS_C_MUTUAL_FLAG, KRB_OID, CheckSumField
from impacket.krb5.keytab import Keytab
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.ldap.ldapasn1 import BindRequest, LDAPMessage

TICKET_ETYPE, SESSION_ETYPE = 18, 17
mode, port, realm, keytab_path, client, arg = sys.argv[1:7]
port = int(port)


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def forge(service_principal, key_principal=None):
    """A ticket for service_principal, encrypted with key_principal's key
    (default: its own; enctype 18) from the keytab, carrying a fresh
    enctype-17 session key."""
    key_principal = key_principal or service_principal
    kt = Keytab.loadFile(keytab_path)
    kb = kt.getKey(key_principal, specificEncType=TICKET_ETYPE)
    if kb is None:
        fail(f"no enctype {TICKET_ETYPE} key for {key_principal} in {keytab_path}")
    service_key = Key(TICKET_ETYPE, kb["keyvalue"]["data"])
    session_key = Key(SESSION_ETYPE, os.urandom(16))
    now = datetime.datetime.now(datetime.timezone.utc)
    etp = EncTicketPart()
    etp["flags"] = constants.encodeFlags([constants.TicketFlags.initial.value, constants.TicketFlags.pre_authent.value])
    etp["key"] = noValue
    etp["key"]["keytype"] = SESSION_ETYPE
    etp["key"]["keyvalue"] = session_key.contents
    etp["crealm"] = realm
    seq_set(etp, "cname", Principal(client, type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
    etp["transited"] = noValue
    etp["transited"]["tr-type"] = 0
    etp["transited"]["contents"] = b""
    etp["authtime"] = KerberosTime.to_asn1(now)
    etp["starttime"] = KerberosTime.to_asn1(now)
    etp["endtime"] = KerberosTime.to_asn1(now + datetime.timedelta(hours=1))
    cipher_text = _enctype_table[TICKET_ETYPE].encrypt(service_key, 2, encoder.encode(etp), None)
    t = TicketAsn1()
    t["tkt-vno"] = 5
    t["realm"] = realm
    seq_set(t, "sname", Principal(service_principal, type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
    t["enc-part"] = noValue
    t["enc-part"]["etype"] = TICKET_ETYPE
    t["enc-part"]["kvno"] = next(
        int(e.kvno) for e in kt.entries if e.main_part["keyblock"]["keytype"] == TICKET_ETYPE
    )
    t["enc-part"]["cipher"] = cipher_text
    tk = Ticket()
    tk.from_asn1(t)
    return tk, session_key, _enctype_table[SESSION_ETYPE]


if mode == "tgs":
    _send = kerberosv5.sendReceive
    kerberosv5.sendReceive = lambda data, host, kdcHost, p=88: _send(data, host, kdcHost, port)
    t, session_key, cipher = forge(f"krbtgt/{realm}")
    # getKerberosTGS takes an AS-REP: wrap the forged TGT in one.
    rep = AS_REP()
    rep["pvno"] = 5
    rep["msg-type"] = int(constants.ApplicationTagNumbers.AS_REP.value)
    rep["crealm"] = realm
    seq_set(rep, "cname", Principal(client, type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
    seq_set(rep, "ticket", t.to_asn1)
    rep["enc-part"] = noValue
    rep["enc-part"]["etype"] = SESSION_ETYPE
    rep["enc-part"]["cipher"] = b""
    # impacket asks for (rc4, des3, des, <the session key's>); ask for the two
    # SHA-1 AES types instead, so the service ticket's key is one impacket
    # can read (it has no aes-sha2).
    _seq_set_iter = kerberosv5.seq_set_iter
    kerberosv5.seq_set_iter = lambda obj, name, values: _seq_set_iter(obj, name, (18, 17) if name == "etype" else values)
    server = Principal(arg, type=constants.PrincipalNameType.NT_SRV_INST.value)
    try:
        tgs, _, _, new_key = kerberosv5.getKerberosTGS(server, realm, "127.0.0.1", encoder.encode(rep), cipher, session_key)
    except Exception as e:
        fail(f"TGS-REQ with a 17 session key in an 18 TGT: {e}")
    st = decoder.decode(tgs, asn1Spec=TGS_REP())[0]["ticket"]
    print(f"ok  TGS: a TGT encrypted with enctype {TICKET_ETYPE} and an enctype-{SESSION_ETYPE} session key was accepted;"
          f" the TGS-REP decrypted under that session key; service ticket for {arg} (etype {int(st['enc-part']['etype'])})")

elif mode == "kpasswd":
    ticket, session_key, cipher = forge("kadmin/changepw", f"krbtgt/{realm}")
    sub_key = Key(SESSION_ETYPE, os.urandom(16))
    principal = Principal(client, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    req = kpasswd.createKPasswdRequest(principal, realm, arg.encode(), ticket, cipher, session_key, sub_key)
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(struct.pack("!I", len(req)) + req)
        buf = b""
        while len(buf) < 4 or len(buf) < 4 + struct.unpack("!I", buf[:4])[0]:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    rep = buf[4:]
    ap_rep_len = struct.unpack("!H", rep[4:6])[0]
    if ap_rep_len == 0:
        fail(f"kpasswd answered a KRB-ERROR: {rep[6:]!r}")
    ap_rep = decoder.decode(rep[6 : 6 + ap_rep_len], asn1Spec=AP_REP())[0]
    if int(ap_rep["enc-part"]["etype"]) != SESSION_ETYPE:
        fail(f"the kpasswd AP-REP is etype {int(ap_rep['enc-part']['etype'])}, not the session key's {SESSION_ETYPE}")
    cipher.decrypt(session_key, 12, bytes(ap_rep["enc-part"]["cipher"]))
    try:
        success, code, code_message, message = kpasswd.decodeKPasswdReply(rep, cipher, sub_key)
    except Exception as e:
        fail(f"kpasswd with a 17 session key in an 18 ticket: {e}")
    if not success:
        fail(f"kpasswd result {code} {code_message}: {message}")
    print(f"ok  kpasswd: an enctype-{TICKET_ETYPE} kadmin/changepw ticket with an enctype-{SESSION_ETYPE} session key changed {client}'s password;"
          f" the AP-REP is etype {SESSION_ETYPE} and decrypts under the session key")

elif mode == "ldap":
    t, session_key, cipher = forge(arg)
    ap = AP_REQ()
    ap["pvno"] = 5
    ap["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap["ap-options"] = constants.encodeFlags([constants.APOptions.mutual_required.value])
    seq_set(ap, "ticket", t.to_asn1)
    auth = Authenticator()
    auth["authenticator-vno"] = 5
    auth["crealm"] = realm
    seq_set(auth, "cname", Principal(client, type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)
    auth["cusec"] = now.microsecond
    auth["ctime"] = KerberosTime.to_asn1(now)
    auth["cksum"] = noValue
    auth["cksum"]["cksumtype"] = 0x8003
    chk = CheckSumField()
    chk["Lgth"] = 16
    chk["Bnd"] = bytes(16)
    chk["Flags"] = GSS_C_MUTUAL_FLAG
    auth["cksum"]["checksum"] = chk.getData()
    ap["authenticator"] = noValue
    ap["authenticator"]["etype"] = SESSION_ETYPE
    ap["authenticator"]["cipher"] = cipher.encrypt(session_key, 11, encoder.encode(auth), None)
    inner = KRB_OID + b"\x01\x00" + encoder.encode(ap)
    n = len(inner)
    token = b"\x60" + (bytes([n]) if n < 128 else bytes([0x82]) + n.to_bytes(2, "big")) + inner
    req = BindRequest()
    req["version"] = 3
    req["name"] = ""
    req["authentication"]["sasl"]["mechanism"] = "GSSAPI"
    req["authentication"]["sasl"]["credentials"] = token
    msg = LDAPMessage()
    msg["messageID"] = 1
    msg["protocolOp"].setComponentByType(req.getTagSet(), req)
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(encoder.encode(msg))
    buf = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            fail("connection closed")
        buf += chunk
        try:
            reply, _ = ber_decoder.decode(buf, asn1Spec=LDAPMessage())
            break
        except Exception:  # incomplete PDU
            continue
    r = reply["protocolOp"]["bindResponse"]
    code = int(r["resultCode"])
    if code != 14:
        fail(f"GSSAPI bind with a 17 session key in an 18 ticket: result {code} {r['diagnosticMessage']}")
    out = bytes(r["serverSaslCreds"])
    pos = 2 if out[1] < 0x80 else 2 + (out[1] & 0x7F)
    body = out[pos + len(KRB_OID) + 2 :]
    ap_rep = decoder.decode(body, asn1Spec=AP_REP())[0]
    if int(ap_rep["enc-part"]["etype"]) != SESSION_ETYPE:
        fail(f"the AP-REP is in etype {int(ap_rep['enc-part']['etype'])}, not the session key's {SESSION_ETYPE}")
    part = decoder.decode(cipher.decrypt(session_key, 12, bytes(ap_rep["enc-part"]["cipher"])), asn1Spec=EncAPRepPart())[0]
    if int(part["cusec"]) != now.microsecond:
        fail("the AP-REP's cusec is not ours")
    print(f"ok  iron-ldapd GSSAPI: an enctype-{TICKET_ETYPE} ticket for {arg} with an enctype-{SESSION_ETYPE} session key was accepted;"
          f" the AP-REP is etype {SESSION_ETYPE} and decrypts under the session key")
else:
    fail(f"unknown mode {mode}")
