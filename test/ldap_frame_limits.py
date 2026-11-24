#!/usr/bin/env python3
"""Raw-socket checks of iron-ldapd's frame limits (finding 6bbcf7596b07).

    ldap_frame_limits.py HOST PORT LDAPD_PID

Standard library only. Prints one line per check and exits non-zero on the
first failure.
"""
import socket
import sys
import time

HOST, PORT, PID = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
SEARCH_ROOTDSE = bytes.fromhex(
    # msgid 2, searchRequest base "" scope base, (objectClass=*), no attrs
    "3025020102632004000a01000a0100020100020100010100870b6f626a656374436c6173733000"
)


def rss_kb():
    with open(f"/proc/{PID}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise SystemExit("no VmRSS")


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def closed_by_server(s, timeout):
    """Whether the server closes s within timeout (EOF or reset)."""
    s.settimeout(timeout)
    try:
        return s.recv(65536) == b""
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


def answers(s):
    s.settimeout(10)
    s.sendall(SEARCH_ROOTDSE)
    data = s.recv(65536)
    return len(data) > 0 and data[0] == 0x30


def stream_until_closed(header, limit_bytes, seconds):
    """Sends header then junk until the server closes; returns bytes sent."""
    s = socket.create_connection((HOST, PORT))
    s.sendall(header)
    sent, chunk, t0 = 0, b"\0" * 65536, time.time()
    s.settimeout(0.5)
    try:
        while sent < limit_bytes and time.time() - t0 < seconds:
            sent += s.send(chunk)
    except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
        pass
    gone = closed_by_server(s, 5)
    s.close()
    return sent, gone


mode = sys.argv[4] if len(sys.argv) > 4 else "fast"
if mode == "fast":
    base = rss_kb()
    # 1. 2 GiB declared, streamed: closed long before 64 MiB arrive.
    sent, gone = stream_until_closed(bytes.fromhex("30847fffffff"), 64 << 20, 20)
    if not gone or sent >= 64 << 20:
        fail(f"a 2 GiB declared frame: closed={gone} after {sent} bytes")
    print(f"ok  2 GiB declared length: connection closed after {sent} bytes")
    # 2. One byte over the 10 MiB cap.
    n = 10 * 1024 * 1024 - 6 + 1  # 30 84 + 4 length octets
    sent, gone = stream_until_closed(bytes([0x30, 0x84]) + n.to_bytes(4, "big"), 64 << 20, 20)
    if not gone or sent >= 10 << 20:
        fail(f"10 MiB + 1: closed={gone} after {sent} bytes")
    print(f"ok  10 MiB + 1 byte declared: closed after {sent} bytes (before the payload)")
    # 3. Nine length octets (2^64): refused, not wrapped to a tiny length.
    s = socket.create_connection((HOST, PORT))
    s.sendall(bytes([0x30, 0x89, 0x01]) + bytes(8) + SEARCH_ROOTDSE)
    if not closed_by_server(s, 5):
        fail("a 9-octet length was not refused")
    print("ok  a 9-octet BER length (2^64) closes the connection")
    # 4. Twenty concurrent oversize senders leave the server's memory alone.
    socks = []
    for _ in range(20):
        c = socket.create_connection((HOST, PORT))
        c.sendall(bytes.fromhex("30847fffffff") + b"\0" * 60000)
        socks.append(c)
    time.sleep(2)
    grown = rss_kb() - base
    for c in socks:
        c.close()
    if grown > 64 * 1024:
        fail(f"RSS grew {grown} kB")
    print(f"ok  20 concurrent oversize senders: RSS grew {grown} kB")
    # 5. A legal 1 MiB message is still read and answered.
    value = b"a" * (1 << 20)
    eq = bytes([0xA3]) + b"\x83" + (len(value) + 9).to_bytes(3, "big") + bytes([0x04, 0x02]) + b"cn" + bytes([0x04, 0x83]) + len(value).to_bytes(3, "big") + value
    body = bytes.fromhex("04000a01000a0100020100020100010100") + eq + bytes.fromhex("3000")
    op = bytes([0x63, 0x83]) + len(body).to_bytes(3, "big") + body
    inner = bytes.fromhex("020103") + op
    msg = bytes([0x30, 0x83]) + len(inner).to_bytes(3, "big") + inner
    s = socket.create_connection((HOST, PORT))
    s.settimeout(20)
    s.sendall(msg)
    if not s.recv(65536).startswith(b"\x30"):
        fail("a legal 1 MiB search got no answer")
    s.close()
    print(f"ok  a legal {len(msg)}-byte search is answered")
else:
    # 6. A started frame left incomplete is dropped after ~120 s; an idle
    #    connection that sent nothing is kept and still answers afterwards.
    idle = socket.create_connection((HOST, PORT))
    slow = socket.create_connection((HOST, PORT))
    slow.sendall(SEARCH_ROOTDSE[:5])
    t0 = time.time()
    if not closed_by_server(slow, 180):
        fail("an incomplete frame was kept for 180 s")
    took = time.time() - t0
    if not 110 <= took <= 140:
        fail(f"the incomplete frame was dropped after {took:.0f} s, want ~120")
    print(f"ok  an incomplete frame is dropped after {took:.0f} s")
    if not answers(idle):
        fail("an idle connection was dropped or does not answer")
    print(f"ok  a connection idle for {time.time() - t0:.0f} s still answers")
