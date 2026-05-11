# Physical — Badge Cloning

## When this applies

Authorized assessment to demonstrate the impact of unattended access badges. Used to validate whether the building uses readable / clonable card technology (low-frequency HID prox, MIFARE Classic) and to test whether badge replays grant access.

## Technique

Read the target badge with a portable reader (covert sleeve / stand-off device), then write the captured data to a writable credential and replay at the reader. Success depends on the card technology in use.

**MITRE ATT&CK**: T1078 (Valid Accounts), T1200 (Hardware Additions).

## Steps

1. Identify badge technology — visual cues + a quick read with Proxmark/Flipper at a coffee-shop bump-and-read or in a controlled "social" interaction.
2. Capture badge data; note facility code + card number (HID prox) or sector keys (MIFARE).
3. Write to compatible writable card (T55x7 for HID prox, MIFARE writable for legacy MIFARE Classic).
4. Test at the same reader the original card uses; document success / failure per door.
5. Return original / cloned material per ROE; debrief.

### LF (HID prox) with Proxmark3

```bash
pm3
> lf search
> lf hid fskdemod
> lf hid clone <facilitycode> <cardnumber>
```

### HF (NFC, MIFARE Classic)

```bash
nfc-mfclassic r a badge_dump.mfd
# then write to a writable MIFARE Classic with the appropriate keys
```

## Verifying success

- Cloned card opens the door / scanner accepts the same UID and grants the same access level.
- Logs captured by the building's PACS confirm a "valid badge" event matching the cloned data.

## Common pitfalls

- Modern HID iCLASS SE / SEOS / DESFire EV2 with diversified keys cannot be cloned via a simple read + write.
- Capturing through a wallet or bag — confirm the reader range you can rely on.
- Using cloned badge outside scope or hours — agree exact doors and time window in writing.

## Tools

- Proxmark3 (LF + HF) — flexible all-rounder
- Flipper Zero — fast LF reads, less capable on hardened HF
- iCopy-X / KeySy — quick LF clone
- Long-range readers for stand-off captures (within authorization)
