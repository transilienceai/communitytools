# Social Engineering Reference

Index of social-engineering scenarios. Each scenario file in `scenarios/` is self-contained: When this applies, Technique, Steps, Verifying success, Common pitfalls, Tools.

**MITRE ATT&CK** anchor techniques: T1566 (Phishing), T1598 (Phishing for Information), T1534 (Internal Spearphishing), T1189 (Drive-by), T1091 (Removable Media), T1078 (Valid Accounts), T1056.002 (GUI Input Capture), T1200 (Hardware Additions).

---

## Catalog

### Phishing — `scenarios/phishing/`

| Scenario | When |
|---|---|
| [email-phishing](scenarios/phishing/email-phishing.md) | Mass / spear / whaling / clone email campaigns; Gophish, SET, Evilginx2 (2FA bypass) |
| [smishing](scenarios/phishing/smishing.md) | SMS phishing via Twilio / AWS SNS with tracked links |
| [business-email-compromise](scenarios/phishing/business-email-compromise.md) | CEO fraud, attorney impersonation, vendor invoice scam, payroll diversion |
| [watering-hole](scenarios/phishing/watering-hole.md) | Compromise a third-party site frequented by employees |

### Vishing — `scenarios/vishing/`

| Scenario | When |
|---|---|
| [voice-phishing](scenarios/vishing/voice-phishing.md) | Spoofed-CID calls impersonating IT / HR / executive / vendor |

### Physical — `scenarios/physical/`

| Scenario | When |
|---|---|
| [tailgating](scenarios/physical/tailgating.md) | Following authorized people through controlled doors |
| [badge-cloning](scenarios/physical/badge-cloning.md) | Cloning HID prox / MIFARE Classic credentials with Proxmark/Flipper |
| [usb-drop-baiting](scenarios/physical/usb-drop-baiting.md) | Crafted USB devices / Bash Bunny / malicious QR cards |
| [dumpster-diving](scenarios/physical/dumpster-diving.md) | Discarded paper, hardware, and media in general waste |
| [shoulder-surfing](scenarios/physical/shoulder-surfing.md) | Observing screens, keyboards, and printed material |

### Pretexting — `scenarios/pretexting/`

| Scenario | When |
|---|---|
| [pretexting](scenarios/pretexting/pretexting.md) | Identity / scenario fabrication for info elicitation; includes quid-pro-quo variants |

---

## Choosing a scenario

| Goal | Scenarios to combine |
|---|---|
| Measure click / credential-capture rate | email-phishing → smishing for unreached targets |
| Test 2FA controls | email-phishing with Evilginx2 reverse proxy |
| Test high-value-action approval | business-email-compromise + voice-phishing callback |
| Test physical security | tailgating → shoulder-surfing → dumpster-diving |
| Test badge / PACS | badge-cloning |
| Test endpoint USB controls | usb-drop-baiting |
| Vendor-relationship trust gaps | pretexting (quid pro quo) |

---

## Cross-cutting principles

**Authorization first** — every scenario requires written ROE: target lists, allowed pretexts, time window, escalation contact, kill-switch.

**One ask per interaction** — split escalations across multiple touches rather than asking for everything at once.

**Out-of-band verification is the universal control** — every successful pretext exploits the absence of a callback / second-channel check. Frame findings around restoring that control.

**Debrief without blaming individuals** — social-engineering findings reflect process gaps; report them at the control level, not the person level.

**Evidence chain** — capture the minimum required to prove the control gap (timestamps, recordings, screenshots, photos), redact PII, and store under chain of custody.

---

## Detection and remediation themes

- Email authentication (SPF/DKIM/DMARC), gateway filtering, link-rewrite, attachment sandboxing.
- Out-of-band verification for any high-value request (wire, payroll change, password reset, gift card).
- Physical: visitor management, mantraps, badge visibility policy, clean-desk, lock-on-leave, document shredding.
- Endpoint: USB device control, AutoRun off, EDR application allow-listing.
- People: continuous awareness training, simulated exercises, easy reporting channel, no-blame culture.

---

## References

- *The Art of Deception* — Kevin Mitnick
- *No Tech Hacking* — Johnny Long
- FBI IC3 BEC reports (annual)
- FCC Truth in Caller ID Act (US legal framework)
- Cialdini, *Influence: The Psychology of Persuasion* (theory base for reciprocity, authority, scarcity, commitment, liking, social proof)
