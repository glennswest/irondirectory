"""RFC 3244 set/change password through impacket (#20), for test/kpasswd-e2e.sh.

impacket is an implementation independent of this project (the one #19 was
checked against). It always speaks protocol version 0xff80 (set password,
ChgPwdData) and gets its kadmin/changepw ticket from the AS -- the shape of
macOS dsconfigad's request -- where MIT kpasswd speaks version 1.

  python kpasswd_impacket.py <kdc-port> <kpasswd-port> <realm> <client> <client-password> <new-password> [<target>]

Prints "OK" or "REFUSED <reason>" and exits 0 or 1. With KPW_CAPTURE=<file>
the request's bytes are also written to <file> (for the replay check, #64).

  python kpasswd_impacket.py replay <kpasswd-port> <file>

sends a captured request again, as is, over TCP and prints the server's
answer: "REFUSED <the KRB-ERROR, as bytes>" (exit 1) or "ACCEPTED ..." (exit 0).
"""

import os
import socket
import struct
import sys

import impacket.krb5.kerberosv5 as kerberosv5
from impacket.krb5 import kpasswd

if sys.argv[1] == "replay":
    port, path = int(sys.argv[2]), sys.argv[3]
    req = open(path, "rb").read()
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
        # A KRB-ERROR whose e-data is the result code and text (RFC 3244).
        text = rep[6:]
        print(f"REFUSED {text!r}")
        sys.exit(1)
    print(f"ACCEPTED (AP-REP of {ap_rep_len} bytes)")
    sys.exit(0)

kdc_port, kpasswd_port, realm, client, client_pw, new_pw = sys.argv[1:7]
target = sys.argv[7] if len(sys.argv) > 7 else None

# getKerberosTGT always talks to port 88; the test KDC runs unprivileged.
_send = kerberosv5.sendReceive
kerberosv5.sendReceive = lambda data, host, kdcHost, port=88: _send(data, host, kdcHost, int(kdc_port))

capture = os.environ.get("KPW_CAPTURE")
if capture:
    _kpw_send = kpasswd.sendReceive

    def _capturing(data, *args, **kwargs):
        with open(capture, "wb") as f:
            f.write(data)
        return _kpw_send(data, *args, **kwargs)

    kpasswd.sendReceive = _capturing

try:
    kpasswd.setPassword(
        client, realm, target, realm if target else None, new_pw,
        oldPasswd=client_pw, kdcHost="127.0.0.1", kpasswdHost="127.0.0.1", kpasswdPort=int(kpasswd_port),
    )
except kpasswd.KPasswdError as e:
    print(f"REFUSED {e}")
    sys.exit(1)
print("OK")
