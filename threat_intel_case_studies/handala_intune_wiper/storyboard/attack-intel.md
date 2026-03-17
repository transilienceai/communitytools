# Attack Intelligence — Handala / Void Manticore Intune MDM Wiper

## Incident Summary

| Field | Detail |
|-------|--------|
| Date | March 11, 2026, 3:30 AM EDT |
| Threat Actor | Handala (front for Void Manticore, MOIS Iran) |
| Target | Stryker Corporation — medical devices, 56,000 employees |
| Vector | Microsoft Intune MDM remote wipe via compromised Global Admin |
| Impact | 200,000+ devices wiped across 79 countries in <30 minutes |
| Trigger | Minab school strike (Feb 28, 2026) — 175 dead, retaliation ordered |

## Kill Chain (MITRE ATT&CK Mapped)

```
Initial Access     T1566.001  Spear-phishing link → fake M365 admin login
Credential Access  T1078.004  Global Administrator credentials harvested
Persistence        —          None needed — single-use destructive operation
Lateral Movement   T1072      Abuse of Intune MDM management plane
Impact             T1485      Data Destruction — remote wipe all enrolled devices
```

## Attack Timeline

| Time (EDT) | Event |
|------------|-------|
| Feb 28 | Minab school strike → MOIS orders retaliation against Stryker |
| Mar 1-8 | Phishing campaign: pixel-perfect M365 admin portal replicas |
| Mar 8-10 | Credential harvesting — IT admin credential captured |
| Mar 10 | Entra ID access established, Global Administrator role confirmed |
| Mar 11, 3:12 AM | Admin clicks phishing link (bleary, 3 AM alert response) |
| Mar 11, 3:25 AM | Kian accesses Intune console via compromised credential |
| Mar 11, 3:30 AM | Remote wipe command issued: scope ALL enrolled devices |
| Mar 11, 3:30-4:00 AM | 200,000+ devices wiped across 79 countries |
| Mar 11, 3:47 AM | Sarah Chen (CISO) receives first alert call |
| Mar 11, 4:15 AM | SOC war room activated — wall of red alerts |
| Mar 11, 6:00 AM | Cork, Ireland: 5,000+ workers sent home |
| Mar 11 morning | Lifenet EKG system offline — Maryland EMS falls back to radio |

## Technical Details for Visual Accuracy

### Phishing Infrastructure
- Pixel-perfect Microsoft 365 admin portal clone
- Domain: one character off from legitimate (subtle URL bar detail)
- Email template: "unusual sign-in activity" notification
- Blue "Review Activity" button — standard Microsoft styling

### Intune MDM Console
- Azure blue interface with device fleet management dashboards
- Device compliance policies, fleet inventories, enrollment status
- Remote wipe command: device scope selector → action type → confirmation
- Wipe propagation: near-instantaneous across all enrolled devices

### Impact Vectors
- **Corporate devices**: Factory reset — all data, configurations, applications destroyed
- **BYOD phones**: Personal data destroyed — photos, contacts, messages, 2FA codes
- **Lifenet EKG**: Stryker's ambulance cardiac telemetry transmission platform — offline
- **Recovery paradox**: Wiped devices can't authenticate to restore — 2FA codes were on wiped devices

### The "Living Off the Land" Principle
- Zero malware deployed
- Zero exploits used
- Legitimate administrative tools used as intended
- The management plane IS the weapon
- No forensic artifacts of "hacking" — just authorized admin actions

## Visual Reference Points

### Screens & Interfaces
- Microsoft 365 email client (phishing email display)
- Microsoft Entra ID portal (authentication/access management)
- Microsoft Intune console (device management dashboards)
- SIEM dashboard (cascading red alert windows)
- Handala logo: stylized hand silhouette, green on black

### Environments
- Tehran ministerial office: wood-paneled, Persian rug, mahogany desk
- Operations room: low ceiling, exposed cables, mismatched monitors, tea glasses
- Stryker HQ Kalamazoo: corporate campus, SOC with monitor wall
- Hospital OR: surgical lights, sterile, tablet on articulating arm
- Cork factory floor: manufacturing line, hi-vis vests, integrated laptops
- Ambulance interior: Lifenet mounted screen, stretcher, paramedic
