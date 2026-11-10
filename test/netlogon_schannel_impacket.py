"""Netlogon secure channel + NetrServerPasswordSet2 through impacket (#20),
for test/netlogon-schannel-e2e.sh.

impacket is an independent implementation (the one #19 was checked
against); it drives the same calls a joining Windows computer makes after
it has an account: NetrServerReqChallenge + NetrServerAuthenticate3 on an
unauthenticated binding, then a new binding authenticated with the
Netlogon secure channel (auth type 68) at PKT_INTEGRITY or PKT_PRIVACY,
and NetrServerPasswordSet2 over it.

impacket's client unseals responses but never checks their signatures, so
this script captures every response PDU and checks the server's
NL_AUTH_SHA2_SIGNATURE itself (MS-NRPC 3.3.4.2.2, written here from the
spec with Cryptodome, not with iron-rpc's code): checksum, the server
direction of the sequence number, and the expected sequence value.

  python netlogon_schannel_impacket.py <port> create <computer>
  python netlogon_schannel_impacket.py <port> setpw <computer> <old> <new> integrity|privacy
  python netlogon_schannel_impacket.py <port> auth <computer> <password>
  python netlogon_schannel_impacket.py <port> zerologon <computer>

Prints what it checked; exits 1 on the first failed check.
"""

import hashlib
import hmac
import os
import struct
import sys
import time

from Cryptodome.Cipher import AES
from impacket.dcerpc.v5 import nrpc, rpcrt, samr, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException

STATUS_ACCESS_DENIED = 0xC0000022
FLAGS = 0x612FFFFF  # what impacket's own examples negotiate; includes AES


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def connect(port, uuid, level=None, account=None, session_key=None):
    t = transport.DCERPCTransportFactory(f"ncacn_ip_tcp:127.0.0.1[{port}]")
    dce = t.get_dce_rpc()
    if level is not None:
        # A domain makes impacket send a well-formed NL_AUTH_MESSAGE (flags
        # NetBIOS domain | NetBIOS host | UTF-8 host); without one it writes
        # "WORKGROUP\0<host>\0" under flag 0x10 alone, which MS-NRPC 2.2.1.3.1
        # does not allow and Windows never sends.
        dce.set_credentials(account, "", os.environ["NETBIOS"])
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_NETLOGON)
        dce.set_auth_level(level)
        dce.set_session_key(session_key)
        dce.set_aes(True)
    dce.connect()
    received = []
    real_recv = dce._transport.recv

    def recv(*a, **kw):
        data = real_recv(*a, **kw)
        received.append(bytes(data))
        return data

    dce._transport.recv = recv
    dce.bind(uuid)
    return dce, received


def pdus(received):
    """The PDUs in the captured byte stream (impacket reads each in two
    recv calls: the header, then the rest)."""
    buf, out = b"".join(received), []
    while len(buf) >= 16:
        frag_len = struct.unpack("<H", buf[8:10])[0]
        out.append(buf[:frag_len])
        buf = buf[frag_len:]
    return out


def status_of(e):
    return getattr(e, "error_code", None) or getattr(e, "get_error_code", lambda: None)()


def cfb8(key, iv, data, encrypt):
    c = AES.new(key, AES.MODE_CFB, iv, segment_size=8)
    return c.encrypt(data) if encrypt else c.decrypt(data)


def check_server_signature(pdu, session_key, seq, sealed):
    """MS-NRPC 3.3.4.2.2 on a response PDU the server sent as sequence `seq`."""
    auth_len = struct.unpack("<H", pdu[10:12])[0]
    if auth_len < 32:
        fail(f"response carries no NL_AUTH_SHA2_SIGNATURE (auth_len {auth_len})")
    sig = pdu[-auth_len:]
    trailer = pdu[-auth_len - 8 : -auth_len]
    if trailer[0] != 0x44:
        fail(f"response auth_type {trailer[0]}")
    stub = pdu[24 : -auth_len - 8]
    if struct.unpack("<HH", sig[:4]) != (0x13, 0x1A if sealed else 0xFFFF):
        fail(f"response signature header {sig[:8].hex()}")
    checksum = sig[16:24]
    seqb = cfb8(session_key, checksum * 2, sig[8:16], False)
    want = struct.pack(">LL", seq & 0xFFFFFFFF, seq >> 32)  # no 0x80: the server sent it
    if seqb != want:
        fail(f"response sequence {seqb.hex()}, expected {want.hex()} (server direction, number {seq})")
    if sealed:
        xor_key = bytes(b ^ 0xF0 for b in session_key)
        plain = cfb8(xor_key, seqb * 2, sig[24:32] + stub, False)
        confounder, data = plain[:8], plain[8:]
    else:
        confounder, data = b"", stub
    mac = hmac.new(session_key, sig[:8] + confounder + data, hashlib.sha256).digest()[:8]
    if mac != checksum:
        fail("response checksum does not verify")


def challenge(dce, computer, password):
    """ReqChallenge + Authenticate3; returns (session key, client credential)."""
    cc = os.urandom(8)
    resp = nrpc.hNetrServerReqChallenge(dce, nrpc.NULL, computer + "\x00", cc)
    sc = resp["ServerChallenge"]
    sk = nrpc.ComputeSessionKeyAES(password, cc, sc)
    ccred = nrpc.ComputeNetlogonCredentialAES(cc, sk)
    resp = nrpc.hNetrServerAuthenticate3(
        dce, nrpc.NULL, computer + "$\x00", nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
        computer + "\x00", ccred, FLAGS,
    )
    if resp["ServerCredential"] != nrpc.ComputeNetlogonCredentialAES(sc, sk):
        fail("server credential does not prove the session key")
    return sk, ccred


def plus(credential, n):
    low = (struct.unpack("<L", credential[:4])[0] + n) & 0xFFFFFFFF
    return struct.pack("<L", low) + credential[4:]


def authenticator(stored, sk):
    ts = int(time.time())
    a = nrpc.NETLOGON_AUTHENTICATOR()
    a["Credential"] = nrpc.ComputeNetlogonCredentialAES(plus(stored, ts), sk)
    a["Timestamp"] = ts
    return a, ts


def trust_password(password, sk):
    pw = password.encode("utf-16-le")
    blob = os.urandom(512 - len(pw)) + pw + struct.pack("<L", len(pw))
    return nrpc.ComputeNetlogonCredentialAES(blob, sk)


def password_set2(dce, computer, auth, blob):
    return nrpc.hNetrServerPasswordSet2(
        dce, nrpc.NULL, computer + "$\x00", nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
        computer + "\x00", auth, blob,
    )


def expect_denied(what, call):
    try:
        call()
    except DCERPCException as e:
        if status_of(e) == STATUS_ACCESS_DENIED:
            print(f"ok: {what}: STATUS_ACCESS_DENIED")
            return
        fail(f"{what}: {e}")
    fail(f"{what}: accepted")


def cmd_create(port, computer):
    dce, _ = connect(port, samr.MSRPC_UUID_SAMR)
    server = samr.hSamrConnect5(dce)["ServerHandle"]
    sid = samr.hSamrLookupDomainInSamServer(dce, server, os.environ["NETBIOS"])["DomainId"]
    domain = samr.hSamrOpenDomain(dce, server, domainId=sid)["DomainHandle"]
    resp = samr.hSamrCreateUser2InDomain(dce, domain, computer + "$", samr.USER_WORKSTATION_TRUST_ACCOUNT)
    print(f"ok: SamrCreateUser2InDomain {computer}$ (RID {resp['RelativeId']})")


def cmd_setpw(port, computer, old, new, level_name):
    level = {"integrity": rpcrt.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, "privacy": rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY}[level_name]
    sealed = level_name == "privacy"
    plain, _ = connect(port, nrpc.MSRPC_UUID_NRPC)
    sk, stored = challenge(plain, computer, old)
    print(f"ok: secure channel for {computer} with the current password")

    # Refused on the unauthenticated binding (Zerologon's path), even with a
    # good authenticator. Refused before the chain steps, so `stored` holds.
    auth, ts = authenticator(stored, sk)
    expect_denied("NetrServerPasswordSet2 on an unauthenticated binding", lambda: password_set2(plain, computer, auth, trust_password(new, sk)))

    dce, received = connect(port, nrpc.MSRPC_UUID_NRPC, level, computer + "$", sk)
    auth, ts = authenticator(stored, sk)
    resp = password_set2(dce, computer, auth, trust_password(new, sk))
    if resp["ErrorCode"] != 0:
        fail(f"NetrServerPasswordSet2 status 0x{resp['ErrorCode']:08x}")
    stored = plus(plus(stored, ts), 1)
    if resp["ReturnAuthenticator"]["Credential"] != nrpc.ComputeNetlogonCredentialAES(stored, sk):
        fail("return authenticator does not chain")
    # PDU 0 is the bind_ack; 1 answers request 0 (sequence 0), as sequence 1.
    check_server_signature(pdus(received)[1], sk, 1, sealed)
    print(f"ok: NetrServerPasswordSet2 over a {level_name} Schannel binding; return authenticator chains; "
          f"response signature{' and seal' if sealed else ''} verified (server sequence 1)")

    # The same authenticator again: a replay.
    expect_denied("replayed authenticator", lambda: password_set2(dce, computer, auth, trust_password(new, sk)))
    # Request 2 was refused, response 3; the binding's counter moved on.
    check_server_signature(pdus(received)[2], sk, 3, sealed)
    # Zerologon's all-zero password buffer, with a good authenticator.
    auth, ts = authenticator(stored, sk)
    expect_denied("all-zero NL_TRUST_PASSWORD", lambda: password_set2(dce, computer, auth, b"\x00" * 516))


def cmd_auth(port, computer, password):
    dce, _ = connect(port, nrpc.MSRPC_UUID_NRPC)
    try:
        challenge(dce, computer, password)
    except DCERPCException as e:
        fail(f"NetrServerAuthenticate3 with {computer}'s password: {e}")
    print(f"ok: NetrServerAuthenticate3 accepts {computer}'s password")


def cmd_zerologon(port, computer):
    dce, _ = connect(port, nrpc.MSRPC_UUID_NRPC)
    zero = b"\x00" * 8
    nrpc.hNetrServerReqChallenge(dce, nrpc.NULL, computer + "\x00", zero)
    expect_denied(
        "NetrServerAuthenticate3 with an all-zero client challenge and credential (CVE-2020-1472)",
        lambda: nrpc.hNetrServerAuthenticate3(
            dce, nrpc.NULL, computer + "$\x00", nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
            computer + "\x00", zero, FLAGS,
        ),
    )


def main():
    port, cmd, *args = sys.argv[1:]
    {"create": cmd_create, "setpw": cmd_setpw, "auth": cmd_auth, "zerologon": cmd_zerologon}[cmd](int(port), *args)


if __name__ == "__main__":
    main()
