#!/usr/bin/env python3
"""
Non-destructive ZMTP (ZeroMQ) handshake prober.

Confirms whether a TCP endpoint speaks ZMTP, negotiates the ZMTP 3.x greeting
with the NULL security mechanism, completes the READY/READY exchange, and parses
the peer's advertised metadata (Socket-Type, Identity, Resource...). An exposed
ROUTER/PUB/etc. socket with mechanism=NULL is an unauthenticated message-plane
exposure (CWE-306) — a common find on a full-range network scan.

Reads only. Sends a standard ZMTP 3.1 greeting + an empty NULL READY command.
Does NOT send any application message frames -> no message is injected into the
peer's message plane. Captures raw greeting bytes as evidence.

Usage:
  python3 zmtp_probe.py <host> <port[,port,...]>
Example:
  python3 zmtp_probe.py 203.0.113.10 5558,6000
"""
import socket, sys, json, binascii

def build_greeting():
    # ZMTP 3.1 greeting (64 bytes)
    sig = b'\xff' + b'\x00' * 8 + b'\x7f'      # signature (10)
    ver = b'\x03\x01'                           # version 3.1 (2)
    mech = b'NULL' + b'\x00' * 16               # mechanism, 20 bytes
    asserver = b'\x00'                          # as-server = false (1)
    filler = b'\x00' * 31                       # filler (31)
    return sig + ver + mech + asserver + filler # 64

def build_ready_command():
    # NULL mechanism: send a READY command with our own (minimal) metadata.
    # Command body: 0x05 'READY' + properties. We advertise Socket-Type=DEALER
    # so a ROUTER peer will accept and reply. Properties: name(1-byte-len)+name,
    # value(4-byte-len BE)+value.
    def prop(name, value):
        return bytes([len(name)]) + name + len(value).to_bytes(4, 'big') + value
    body = b'\x05READY'
    body += prop(b'Socket-Type', b'DEALER')
    body += prop(b'Identity', b'')
    # short command frame: flag 0x04 (command), 1-byte length
    return bytes([0x04, len(body)]) + body

def parse_metadata(body):
    """body starts after 'READY' name; parse name/value property list."""
    props = {}
    i = 0
    while i < len(body):
        nlen = body[i]; i += 1
        name = body[i:i+nlen].decode('latin1'); i += nlen
        vlen = int.from_bytes(body[i:i+4], 'big'); i += 4
        val = body[i:i+vlen]; i += vlen
        try:
            props[name] = val.decode('utf-8')
        except Exception:
            props[name] = binascii.hexlify(val).decode()
    return props

def recv_exact(s, n, timeout=8):
    s.settimeout(timeout)
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

def probe(host, port):
    out = {"host": host, "port": port}
    try:
        s = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        out["error"] = f"connect: {e}"
        return out
    try:
        s.sendall(build_greeting())
        # Peer greeting is 64 bytes (or 10-byte partial for v2 downgrade)
        peer = recv_exact(s, 64)
        out["peer_greeting_hex"] = binascii.hexlify(peer).decode()
        out["peer_greeting_len"] = len(peer)
        if len(peer) >= 12 and peer[0] == 0xff and peer[9] == 0x7f:
            out["is_zmtp"] = True
            out["peer_version"] = f"{peer[10]}.{peer[11]}"
            if len(peer) >= 32:
                out["peer_mechanism"] = peer[12:32].split(b'\x00')[0].decode('latin1')
        else:
            out["is_zmtp"] = False
            out["note"] = "no valid ZMTP signature in reply"
            return out
        # Send our READY, read peer's READY command
        s.sendall(build_ready_command())
        hdr = recv_exact(s, 2)
        if len(hdr) == 2 and (hdr[0] & 0x04):
            clen = hdr[1]
            cbody = recv_exact(s, clen)
            out["peer_command_hex"] = binascii.hexlify(hdr + cbody).decode()
            if cbody[:6] == b'\x05READY':
                out["handshake"] = "READY received (unauthenticated NULL handshake completed)"
                out["peer_metadata"] = parse_metadata(cbody[6:])
            else:
                out["handshake"] = f"non-READY command: {binascii.hexlify(cbody[:8]).decode()}"
        else:
            out["handshake"] = f"unexpected frame hdr: {binascii.hexlify(hdr).decode()}"
    except Exception as e:
        out["error_after_greeting"] = f"{type(e).__name__}: {e}"
    finally:
        s.close()
    return out

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: zmtp_probe.py <host> <port[,port,...]>", file=sys.stderr)
        sys.exit(2)
    host = sys.argv[1]
    ports = [int(p) for p in sys.argv[2].split(',')]
    results = [probe(host, p) for p in ports]
    print(json.dumps(results, indent=2))
