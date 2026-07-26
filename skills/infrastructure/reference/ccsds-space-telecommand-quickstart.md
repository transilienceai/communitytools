# CCSDS Space Telecommand Quickstart

Satellite / space-protocol challenges expose a TCP "spacecraft" (or ground-station) service that only acts on a correctly-framed **CCSDS telecommand (TC)**. A skeleton client (often pwntools) ships with the frame-builder functions stubbed out — implementing the CCSDS framing per spec *is* the puzzle. The objective string is returned when the onboard command handler accepts a valid command (e.g. `GETFLAG`, `GETSECURECODE`).

## Recon

1. **Connect and read the banner.** It usually advertises the routing identifiers you must echo back exactly: `SCID` (spacecraft id), `VCID` (virtual channel id), `APID` (application process id). Copy them verbatim.
2. **Read the skeleton.** Note the two stubbed builders (`generate_space_packet`, `generate_tc_frame`), the payload command names, and their required order (`BEGIN` → `GETFLAG`, etc.).

## Two nested CCSDS layers — both must be byte-exact

### Layer 1 — Space Packet (CCSDS 133.0-B, 6-byte primary header)

Packed MSB-first into three 16-bit words:

- Packet Version Number — 3 bits = `000`
- Packet Type — 1 bit = `1` for Telecommand (TC), `0` for Telemetry (TM)
- Secondary Header Flag — 1 bit = `0` (none)
- APID — 11 bits (from banner)
- Sequence Flags — 2 bits = `11` (unsegmented / standalone packet)
- Packet Sequence Count — 14 bits (per-packet counter; increment across commands)
- Packet Data Length — 16 bits = **(payload length − 1)** ← the classic off-by-one
- Payload bytes follow.

```python
import struct

def space_packet(apid, seq_count, payload, tc=True):
    w1 = (0 << 13) | ((1 if tc else 0) << 12) | (0 << 11) | (apid & 0x7FF)
    w2 = (0b11 << 14) | (seq_count & 0x3FFF)
    w3 = len(payload) - 1                      # data length = N - 1
    return struct.pack('>HHH', w1, w2, w3) + payload
```

### Layer 2 — TC Transfer Frame (CCSDS 232.0-B, 5-byte primary header [+ CRC])

- TF Version Number — 2 bits = `00`
- Bypass Flag — 1 bit: `1` = BD / Type-B (bypass FARM checks; CRC/VCFC not enforced by many sims), `0` = AD / Type-A (sequence-controlled; CRC + VCFC **enforced**)
- Control Command Flag — 1 bit = `0` (data frame, not a control frame)
- Reserved Spare — 2 bits = `00`
- Spacecraft ID (SCID) — 10 bits (from banner)
- Virtual Channel ID (VCID) — 6 bits (from banner)
- Frame Length — 16 bits = **(total frame length − 1)**, counting the whole frame incl. header and CRC ← off-by-one again
- Frame Sequence Number (VCFC) — 8 bits: per-virtual-channel send counter (increment across AD commands)
- Data field = the Space Packet from Layer 1.
- **AD frames append a 2-byte CRC-16/CCITT-FALSE trailer** (poly `0x1021`, init `0xFFFF`, no reflect, no xorout). BD (bypass) frames typically omit it.

```python
def crc16_ccitt(data, crc=0xFFFF):
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc

def tc_frame(scid, vcid, vcfc, packet, bypass=False):
    crc_len = 0 if bypass else 2
    total = 5 + len(packet) + crc_len                       # whole frame incl. CRC
    w1 = (0 << 14) | ((1 if bypass else 0) << 13) | (0 << 12) | (0 << 10) | (scid & 0x3FF)
    w2 = ((vcid & 0x3F) << 10) | ((total - 1) & 0x3FF)      # frame length = total - 1
    frame = struct.pack('>HHB', w1, w2, vcfc & 0xFF) + packet
    return frame if bypass else frame + struct.pack('>H', crc16_ccitt(frame))
```

## The three enforcement points where solves silently fail

1. **Off-by-one length fields.** Both the Space Packet *Data Length* and the TC Frame *Frame Length* are `(value − 1)`. Either one wrong → silent drop or `invalid frame`.
2. **The command counter is an ASCII hex STRING, not a raw byte.** Payloads are commonly `"0x%02x:COMMAND"` — e.g. `0x00:BEGIN`, `0x02:GETFLAG`. The leading `0x00:` is literal ASCII text, **not** a `\x00` byte. Raw-byte and decimal variants come back `invalid payload or sequence state`; only the literal `0x%02x:` prefix is accepted. The service advances its own counter per message: send `0x00` → ACK `0x01` → send `0x02` → reply `0x03`.
3. **VCFC must increment across AD commands.** On AD-type (`bypass=0`) frames the server tracks the per-VC frame sequence number and rejects a stale one explicitly (`Expected TC frame with VCFC 1 but got 0`). Advance VCFC `0→1→2…` on the same TCP connection, in lockstep with the Space Packet sequence count.

## Send it

One TCP connection; write the raw frame bytes (no newline framing unless the skeleton adds one). If the skeleton's `main()` does `payload = frame + space_packet`, that double-append is usually a **red herring** — the transfer frame already embeds the packet, so send the frame alone.

```python
from pwn import remote
io = remote(HOST, PORT)
io.recvuntil(b'telecommand')                                        # consume the banner
io.send(tc_frame(SCID, VCID, 0, space_packet(APID, 0, b'0x00:BEGIN')))
print(io.recv())                                                    # -> 0x01:ACK
io.send(tc_frame(SCID, VCID, 1, space_packet(APID, 1, b'0x02:GETFLAG')))
print(io.recv())                                                    # -> 0x03:FLAG{...}
```

For a single-shot handler (no BEGIN/ACK handshake), a lone BD frame with VCFC 0 wrapping one Space Packet carrying the command is enough — start minimal, add AD/CRC/VCFC only when the server demands them.

## Verifying success

- The wire bytes match a hand-decoded reference: `w1`/`w2` bitfields split back to the banner's SCID/VCID/APID, and both length fields equal `N-1`.
- Server transitions from `invalid frame` / `invalid payload or sequence state` to an `ACK` or the flag string.

## Anti-patterns

- Don't send a raw counter byte where the service wants the ASCII `0x%02x:` prefix.
- Don't reuse VCFC 0 for the second AD command — the per-VC counter must advance.
- Don't omit the `(length − 1)` convention on either header, or the CRC-16/CCITT trailer on AD frames.
- Don't blindly concatenate `frame + space_packet` from the skeleton's `main()`; the frame already carries the packet.

## Tools

- `pwntools` (`remote`) for the TCP session; `struct` for framing; `binascii.hexlify` to eyeball wire bytes.
- Cross-check bitfields against CCSDS **133.0-B** (Space Packet) and **232.0-B** (TC Transfer Frame) blue books.
