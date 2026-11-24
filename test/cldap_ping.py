#!/usr/bin/env python3
"""LDAP ping client and NETLOGON_SAM_LOGON_RESPONSE_EX decoder (#52).

Written from MS-ADTS 6.3.3 (the ping), 6.3.1.9 (the response), RFC 4511
(the BER of the request and replies) and RFC 1035 4.1.4 (name
compression), sharing no code with iron-ldap. Standard library only.

    cldap_ping.py udp|tcp HOST PORT [term=value ...]

Terms: DnsDomain=, Host=, User= (text), AAC=, NtVer= (integers, sent as
4-byte little-endian), DomainGuid= (text GUID, sent in wire order),
DomainSid= (S-1-5-..., sent binary), Attr= (the attribute asked for,
default Netlogon). Prints one JSON object: the result code, whether an
entry came back, and the decoded response.
"""
import json
import socket
import struct
import sys
import uuid


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def ber_int(tag, v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(tag, b)


def sid_bytes(text):
    parts = text.split("-")
    assert parts[0] == "S"
    rev, auth, subs = int(parts[1]), int(parts[2]), [int(x) for x in parts[3:]]
    return bytes([rev, len(subs)]) + auth.to_bytes(6, "big") + b"".join(struct.pack("<I", s) for s in subs)


def search_request(msgid, terms, attr):
    eqs = b""
    for name, value in terms:
        eqs += tlv(0xA3, tlv(0x04, name.encode()) + tlv(0x04, value))
    filt = tlv(0xA0, eqs)  # and
    body = (
        tlv(0x04, b"")  # baseObject
        + ber_int(0x0A, 0)  # scope baseObject
        + ber_int(0x0A, 0)  # derefAliases never
        + ber_int(0x02, 0)
        + ber_int(0x02, 0)
        + tlv(0x01, b"\x00")
        + filt
        + tlv(0x30, tlv(0x04, attr.encode()))
    )
    return tlv(0x30, ber_int(0x02, msgid) + tlv(0x63, body))


def read_tlv(b, off):
    tag = b[off]
    n = b[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[off : off + k], "big")
        off += k
    return tag, b[off : off + n], off + n


def parse_messages(b):
    """Every LDAPMessage in b: (msgid, op tag, op content)."""
    out, off = [], 0
    while off < len(b):
        tag, msg, off = read_tlv(b, off)
        assert tag == 0x30, hex(tag)
        _, mid, o = read_tlv(msg, 0)
        optag, op, _ = read_tlv(msg, o)
        out.append((int.from_bytes(mid, "big"), optag, op))
    return out


def entry_attrs(op):
    _, dn, o = read_tlv(op, 0)
    _, attrs, _ = read_tlv(op, o)
    out, o = {}, 0
    while o < len(attrs):
        _, pa, o = read_tlv(attrs, o)
        _, name, p = read_tlv(pa, 0)
        _, vals, _ = read_tlv(pa, p)
        vs, q = [], 0
        while q < len(vals):
            _, v, q = read_tlv(vals, q)
            vs.append(v)
        out[name.decode()] = vs
    return dn, out


def read_name(b, off):
    labels, end, hops = [], None, 0
    while True:
        n = b[off]
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | b[off + 1]
            hops += 1
            assert hops < 32, "pointer loop"
            continue
        if n == 0:
            if end is None:
                end = off + 1
            return ".".join(labels), end, hops
        labels.append(b[off + 1 : off + 1 + n].decode())
        off += 1 + n


def decode_ex(b, req_ntver):
    r = {}
    r["opcode"], r["sbz"], r["flags"] = struct.unpack_from("<HHI", b, 0)
    r["domain_guid"] = str(uuid.UUID(bytes_le=bytes(b[8:24])))
    off, pointers = 24, 0
    for field in ["forest", "domain", "host", "netbios_domain", "netbios_computer", "user", "dc_site", "client_site"]:
        r[field], off, hops = read_name(b, off)
        pointers += hops
    if req_ntver & 0x8:
        size = b[off]
        fam, port = struct.unpack_from("<H", b, off + 1)[0], struct.unpack_from(">H", b, off + 3)[0]
        r["sockaddr"] = {"size": size, "family": fam, "port": port, "ip": socket.inet_ntoa(b[off + 5 : off + 9])}
        off += 1 + size
    if req_ntver & 0x10:
        r["next_closest_site"], off, _ = read_name(b, off)
    r["nt_version"], r["lmnt_token"], r["lm20_token"] = struct.unpack_from("<IHH", b, off)
    off += 8
    r["trailing_bytes"] = len(b) - off
    r["compression_pointers"] = pointers
    r["length"] = len(b)
    return r


def main():
    proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    terms, attr, ntver = [], "Netlogon", 0
    for arg in sys.argv[4:]:
        k, v = arg.split("=", 1)
        if k == "Attr":
            attr = v
        elif k in ("AAC", "NtVer"):
            terms.append((k, struct.pack("<I", int(v, 0))))
            if k == "NtVer":
                ntver = int(v, 0)
        elif k == "DomainGuid":
            terms.append((k, uuid.UUID(v).bytes_le))
        elif k == "DomainSid":
            terms.append((k, sid_bytes(v)))
        else:
            terms.append((k, v.encode()))
    req = search_request(7, terms, attr)
    if proto == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(req, (host, port))
        data, _ = s.recvfrom(65535)
        datagrams = 1
    else:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(req)
        data = b""
        while True:
            chunk = s.recv(65535)
            if not chunk:
                break
            data += chunk
            try:
                if any(t == 0x65 for _, t, _ in parse_messages(data)):
                    break
            except (IndexError, AssertionError):
                continue
        datagrams = None
    msgs = parse_messages(data)
    out = {"datagrams": datagrams, "messages": [hex(t) for _, t, _ in msgs], "msgids": sorted({m for m, _, _ in msgs})}
    for _, t, op in msgs:
        if t == 0x64:
            dn, attrs = entry_attrs(op)
            out["entry_dn"] = dn.decode()
            vals = attrs.get("Netlogon") or attrs.get("netlogon") or []
            out["netlogon_values"] = len(vals)
            if vals:
                out["netlogon_hex"] = vals[0].hex()
                out["response"] = decode_ex(vals[0], ntver)
        elif t == 0x65:
            _, code, _ = read_tlv(op, 0)
            out["result_code"] = int.from_bytes(code, "big")
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
