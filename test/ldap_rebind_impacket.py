"""SASL/GSSAPI re-binds through an installed security layer (#67), for
test/ldap-rebind-e2e.sh.

A GSSAPI LDAP client built from impacket's Kerberos client (getKerberosTGT,
getKerberosTGS, its ASN.1 types and RFC 3961 crypto) -- an implementation
independent of this project -- with the RFC 4752 handshake and RFC 4121 Wrap
tokens written out here, so the client chooses the security layer itself
(impacket's LDAP client only does GSS-SPNEGO, with its own layer choice).

  python ldap_rebind_impacket.py <ldap-port> <kdc-port> <realm> <spn> <base-dn> \
      <alice-password> <administrator-password>

On ONE connection, checking every answer with Who am I (RFC 4532):
  1. GSSAPI bind as alice selecting confidentiality: the reply to Who am I
     is a sealed token, "u:alice@REALM";
  2. simple bind as the administrator, sent through that layer: success, the
     answer still sealed by alice's context (RFC 4513 §5.2.1.4: a non-SASL
     bind leaves the layer), "dn:cn=administrator,...";
  3. simple bind with a wrong password: invalidCredentials, the layer stays,
     the connection is anonymous ("");
  4. GSSAPI re-bind as the administrator through the layer, selecting
     integrity: the handshake runs inside alice's sealed layer; afterwards
     the administrator's context replaces it (RFC 4422 §3.8): an unsealed
     integrity token, "u:administrator@REALM";
  5. GSSAPI re-bind as alice selecting no layer: the administrator's
     integrity layer remains in effect (RFC 4422 §3.8), "u:alice@REALM".

Prints one "ok: ..." line per step; exits 1 with "FAIL: ..." otherwise.
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
from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
from impacket.krb5.gssapi import (GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG,
                                  KRB_OID, CheckSumField)
from impacket.krb5.crypto import _get_checksum_profile
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.ldap.ldapasn1 import BindRequest, ExtendedRequest, LDAPMessage

ldap_port, kdc_port, realm, spn, base_dn, alice_pw, admin_pw = sys.argv[1:8]
admin_dn = f"cn=administrator,{base_dn}"
WHOAMI = "1.3.6.1.4.1.4203.1.11.3"

_send = kerberosv5.sendReceive
kerberosv5.sendReceive = lambda data, host, kdcHost, port=88: _send(data, host, kdcHost, int(kdc_port))

# Checksum types of the RFC 3961 simplified profile, by enctype (RFC 3962).
CKSUM = {17: 15, 18: 16}
SEALED, ACCEPTOR = 0x02, 0x01


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


class Context:
    """One GSS context: the initiator's base key and send sequence."""

    def __init__(self, cipher, key):
        self.cipher, self.key, self.seq = cipher, key, 0
        self.sealed = False  # the layer this context installs: confidentiality?

    def wrap(self, data, sealed):
        """RFC 4121 §4.2.6.2 Wrap token from the initiator (usage 24), RRC 0."""
        hdr = bytearray(b"\x05\x04" + bytes([SEALED if sealed else 0]) + b"\xff" + bytes(4) + struct.pack(">Q", self.seq))
        self.seq += 1
        if sealed:
            return bytes(hdr) + self.cipher.encrypt(self.key, 24, data + bytes(hdr), None)
        ck = _get_checksum_profile(CKSUM[self.cipher.enctype])
        mic = ck.checksum(self.key, 24, data + bytes(hdr))
        hdr[4:6] = struct.pack(">H", len(mic))
        return bytes(hdr) + data + mic

    def unwrap(self, token):
        """Returns (plaintext, sealed) of the acceptor's Wrap token (usage 22)."""
        if token[:2] != b"\x05\x04":
            fail(f"not a Wrap token: {token[:16].hex()}")
        flags = token[2]
        if not flags & ACCEPTOR:
            fail("the server's Wrap token lacks SentByAcceptor")
        rrc = struct.unpack(">H", token[6:8])[0]
        body = token[16:]
        if body:
            rrc %= len(body)
            body = body[rrc:] + body[:rrc]
        if flags & SEALED:
            plain = self.cipher.decrypt(self.key, 22, body)
            hdr = bytearray(token[:16])
            hdr[6:8] = b"\0\0"
            if plain[-16:] != bytes(hdr):
                fail("sealed token's header copy does not match")
            return plain[:-16], True
        ck = _get_checksum_profile(CKSUM[self.cipher.enctype])
        n = ck.macsize
        data, mic = body[:-n], body[-n:]
        hdr = bytearray(token[:16])
        hdr[4:8] = b"\0\0\0\0"
        if ck.checksum(self.key, 22, data + bytes(hdr)) != mic:
            fail("integrity token's checksum does not verify")
        return data, False


class Conn:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", int(ldap_port)), timeout=15)
        self.layer = None  # the Context whose layer is in effect
        self.msgid = 0
        self.buf = b""

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                fail("the server closed the connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read_ber(self):
        head = self._read(2)
        if head[1] < 0x80:
            return head + self._read(head[1])
        lb = self._read(head[1] & 0x7F)
        return head + lb + self._read(int.from_bytes(lb, "big"))

    def request(self, op):
        """Sends one request; returns (protocolOp, sealed?) of its one reply.
        `sealed?` is None when no layer is in effect."""
        self.msgid += 1
        msg = LDAPMessage()
        msg["messageID"] = self.msgid
        msg["protocolOp"].setComponentByType(op.getTagSet(), op)
        data = encoder.encode(msg)
        if self.layer:
            tok = self.layer.wrap(data, self.layer.sealed)
            self.s.sendall(struct.pack(">I", len(tok)) + tok)
            tok = self._read(struct.unpack(">I", self._read(4))[0])
            data, sealed = self.layer.unwrap(tok)
        else:
            self.s.sendall(data)
            data, sealed = self._read_ber(), None
        reply, _ = ber_decoder.decode(data, asn1Spec=LDAPMessage())
        if int(reply["messageID"]) != self.msgid:
            fail(f"reply to message {reply['messageID']}, expected {self.msgid}")
        return reply["protocolOp"], sealed

    def whoami(self):
        req = ExtendedRequest()
        req["requestName"] = WHOAMI
        op, sealed = self.request(req)
        r = op["extendedResp"]
        if int(r["resultCode"]) != 0:
            fail(f"Who am I: {r['resultCode']} {r['diagnosticMessage']}")
        return bytes(r["responseValue"]).decode() if r["responseValue"].hasValue() else "", sealed

    def simple_bind(self, dn, pw):
        req = BindRequest()
        req["version"] = 3
        req["name"] = dn
        req["authentication"]["simple"] = pw
        op, sealed = self.request(req)
        return int(op["bindResponse"]["resultCode"]), sealed

    def sasl_step(self, creds):
        req = BindRequest()
        req["version"] = 3
        req["name"] = ""
        req["authentication"]["sasl"]["mechanism"] = "GSSAPI"
        if creds is not None:
            req["authentication"]["sasl"]["credentials"] = creds
        op, _ = self.request(req)
        r = op["bindResponse"]
        code = int(r["resultCode"])
        if code not in (0, 14):
            fail(f"GSSAPI bind step: {r['resultCode']} {r['diagnosticMessage']}")
        creds = bytes(r["serverSaslCreds"]) if r["serverSaslCreds"].hasValue() else b""
        return code, creds

    def gssapi_bind(self, user, pw, layer):
        """RFC 4752 bind as `user`, selecting `layer` (1 none, 2 integrity,
        4 confidentiality). Returns the new Context; installs its layer only
        when one was selected (RFC 4422 §3.8)."""
        name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, _, tgt_key = kerberosv5.getKerberosTGT(name, pw, realm, b"", b"", kdcHost="127.0.0.1")
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
        # No GSS_C_MUTUAL_FLAG: the server answers the AP-REQ with the
        # security-layer challenge directly.
        chk["Flags"] = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG
        auth["cksum"]["checksum"] = chk.getData()
        ap["authenticator"] = noValue
        ap["authenticator"]["etype"] = cipher.enctype
        ap["authenticator"]["cipher"] = cipher.encrypt(key, 11, encoder.encode(auth), None)
        inner = KRB_OID + b"\x01\x00" + encoder.encode(ap)
        n = len(inner)
        length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
        token = b"\x60" + length + inner

        ctx = Context(cipher, key)
        ctx.sealed = layer == 4
        code, challenge = self.sasl_step(token)
        if code != 14 or not challenge:
            fail("GSSAPI bind: no security-layer challenge")
        offer, sealed = ctx.unwrap(challenge)
        if sealed or len(offer) != 4 or not offer[0] & layer:
            fail(f"challenge offers {offer.hex()}, wanted layer {layer}")
        code, _ = self.sasl_step(ctx.wrap(bytes([layer]) + offer[1:4], False))
        if code != 0:
            fail("GSSAPI bind did not complete")
        if layer != 1:
            self.layer = ctx
        return ctx


c = Conn()
user_alice, user_admin = f"u:alice@{realm}", f"u:administrator@{realm}"

alice = c.gssapi_bind("alice", alice_pw, 4)
who, sealed = c.whoami()
if (who, sealed) != (user_alice, True):
    fail(f"1. after alice's GSSAPI bind (confidentiality): {who!r} sealed={sealed}")
print(f"ok: 1. GSSAPI bind as alice, confidentiality layer: Who am I = {who}, sealed")

code, sealed = c.simple_bind(admin_dn, admin_pw)
if code != 0 or sealed is not True:
    fail(f"2. simple re-bind through the layer: resultCode {code}, sealed={sealed}")
who, sealed = c.whoami()
if (who, sealed) != (f"dn:{admin_dn}", True):
    fail(f"2. after the simple re-bind: {who!r} sealed={sealed}")
print(f"ok: 2. simple re-bind as the administrator: the layer stays (sealed), Who am I = {who}")

code, sealed = c.simple_bind(admin_dn, "not-the-password")
if code != 49 or sealed is not True:
    fail(f"3. wrong-password re-bind: resultCode {code} (want 49), sealed={sealed}")
who, sealed = c.whoami()
if (who, sealed) != ("", True):
    fail(f"3. after the failed re-bind: {who!r} sealed={sealed}")
print("ok: 3. failed re-bind: invalidCredentials, the layer stays (sealed), anonymous")

admin = c.gssapi_bind("administrator", admin_pw, 2)
if c.layer is not admin or alice.key.contents == admin.key.contents:
    fail("4. the administrator's context did not get its own key")
who, sealed = c.whoami()
if (who, sealed) != (user_admin, False):
    fail(f"4. after the GSSAPI re-bind (integrity): {who!r} sealed={sealed}")
print(f"ok: 4. GSSAPI re-bind as the administrator through alice's layer, integrity: "
      f"the new layer replaced it, Who am I = {who}, integrity token")

c.gssapi_bind("alice", alice_pw, 1)
if c.layer is not admin:
    fail("5. client bookkeeping")
who, sealed = c.whoami()
if (who, sealed) != (user_alice, False):
    fail(f"5. after the no-layer GSSAPI re-bind: {who!r} sealed={sealed}")
print(f"ok: 5. GSSAPI re-bind as alice selecting no layer: the administrator's integrity layer remains, Who am I = {who}")
