# Intro to Offshore Track — Engagement Plan

## Track ID 65 — 12 machines
- Difficulty: Medium / Hard / Insane (mostly AD Windows)
- Cover: Pro Lab Offshore prep — practice for full AD chains

## Already owned (6/12)
- Scrambled, StreamIO, Authority, Escape, Intelligence, Monteverde

## Remaining (6) — this engagement
1. Visual (568) — Medium — user owned, root needed
2. Cereal (299) — Hard — both flags (CURRENTLY ACTIVE)
3. Flight (510) — Hard — both flags
4. Napper (575) — Hard — both flags
5. Analysis (584) — Hard — both flags
6. Rebound (560) — Insane — both flags

## VPN
- Pool: dedivip_lab (server 704, EU VIP+)
- Status: connected, IP 10.10.15.143
- Test ping to 10.129.28.172: OK

## Strategy
- Sequential — only one machine slot active at a time on HTB
- Inline orchestration (no Agent spawn tool in this environment)
- Each machine: recon → source/banner analysis → escalation → flag submit → next
- Skill updates inline after each successful solve
- Final Slack notification once all are done (or partial summary if blocked)
