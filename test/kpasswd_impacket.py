"""RFC 3244 set/change password through impacket (#20), for test/kpasswd-e2e.sh.

impacket is an implementation independent of this project (the one #19 was
checked against). It always speaks protocol version 0xff80 (set password,
ChgPwdData) and gets its kadmin/changepw ticket from the AS -- the shape of
macOS dsconfigad's request -- where MIT kpasswd speaks version 1.

  python kpasswd_impacket.py <kdc-port> <kpasswd-port> <realm> <client> <client-password> <new-password> [<target>]

Prints "OK" or "REFUSED <reason>" and exits 0 or 1.
"""

import sys

import impacket.krb5.kerberosv5 as kerberosv5
from impacket.krb5 import kpasswd

kdc_port, kpasswd_port, realm, client, client_pw, new_pw = sys.argv[1:7]
target = sys.argv[7] if len(sys.argv) > 7 else None

# getKerberosTGT always talks to port 88; the test KDC runs unprivileged.
_send = kerberosv5.sendReceive
kerberosv5.sendReceive = lambda data, host, kdcHost, port=88: _send(data, host, kdcHost, int(kdc_port))

try:
    kpasswd.setPassword(
        client, realm, target, realm if target else None, new_pw,
        oldPasswd=client_pw, kdcHost="127.0.0.1", kpasswdHost="127.0.0.1", kpasswdPort=int(kpasswd_port),
    )
except kpasswd.KPasswdError as e:
    print(f"REFUSED {e}")
    sys.exit(1)
print("OK")
