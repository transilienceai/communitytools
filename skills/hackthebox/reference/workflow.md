# HackTheBox Workflow — Detailed Steps

## 1. Get Credentials
```bash
python3 ./tools/env-reader.py HTB_USER HTB_PASS HTB_TOKEN ANTHROPIC_API_KEY SLACK_BOT_TOKEN HTB_SLACK_CHANNEL_ID
```

### HTB Credentials & API Token

| Variable | Purpose | Usage |
|----------|---------|-------|
| `HTB_USER` | HTB account email | Browser login at `app.hackthebox.com/login` |
| `HTB_PASS` | HTB account password | Browser login (with Turnstile) |
| `HTB_TOKEN` | HTB API Bearer token | API calls (`labs.hackthebox.com/api/v4/`) — flag submission, machine spawn/stop, challenge info |

- Use `HTB_USER`/`HTB_PASS` for browser-based login (Playwright headed mode)
- Use `HTB_TOKEN` as `Authorization: Bearer $HTB_TOKEN` for all HTB API calls (flag submission, machine management, challenge metadata)
- Only `AskUserQuestion` if a required variable returns `NOT_SET`
- Slack is enabled when BOTH `SLACK_BOT_TOKEN` and `HTB_SLACK_CHANNEL_ID` are set

### HTB API Examples (using HTB_TOKEN)
```bash
# Submit machine flag
curl -s -X POST -H "Authorization: Bearer $HTB_TOKEN" -H "Content-Type: application/json" \
  -d '{"id": MACHINE_ID, "flag": "FLAG_VALUE", "difficulty": 10}' \
  "https://labs.hackthebox.com/api/v4/machine/own"

# Submit challenge flag
curl -s -X POST -H "Authorization: Bearer $HTB_TOKEN" -H "Content-Type: application/json" \
  -d '{"id": CHALLENGE_ID, "flag": "FLAG_VALUE", "difficulty": 10}' \
  "https://labs.hackthebox.com/api/v4/challenge/own"

# Get active machine info
curl -s -H "Authorization: Bearer $HTB_TOKEN" \
  "https://labs.hackthebox.com/api/v4/machine/active"

# Spawn machine
curl -s -X POST -H "Authorization: Bearer $HTB_TOKEN" -H "Content-Type: application/json" \
  -d '{"machine_id": MACHINE_ID}' \
  "https://labs.hackthebox.com/api/v4/vm/spawn"

# Stop machine
curl -s -X POST -H "Authorization: Bearer $HTB_TOKEN" -H "Content-Type: application/json" \
  -d '{"machine_id": MACHINE_ID}' \
  "https://labs.hackthebox.com/api/v4/vm/terminate"
```

## 2. Check VPN
Only for "Machine" kind of competition -> Verify vpn is running, otherwise download the vpn file from HTB and instruct the user on how to enable it

This skill does NOT start VPN — the user manages it. Check if running:
```bash
ps aux | grep -v grep | grep openvpn && echo "VPN_RUNNING" || echo "VPN_NOT_RUNNING"
```
If not running → `AskUserQuestion` asking user to start it. Do NOT try to start VPN yourself.

## 3. Generate output dirs

```bash
mkdir -p YYMMDD_<name>/{recon,findings,logs,artifacts,reports}
```

## 4. Login hackthebox.com (headed browser, NEVER headless)
Navigate `https://app.hackthebox.com/login`, fill credentials, handle 2FA. Use headed mode + anti-detection flags + realistic viewport + persistent context for `cf_clearance`. If blocked: `reference/cloudflare-bypass.md`. Fallback: HTB API `https://labs.hackthebox.com/api/v4/` with Bearer token.

## 5. If necessary, start the machine
1. Navigate to the requested machine/challenge (or browse and present options via `AskUserQuestion`)
2. Start the machine if not running
3. Save challenge info to `YYMMDD_<name>/challenge-meta.json`

## 6. If necessary, check network connectivity to the machine
Only for those competition that requires machine to be started and connected through VPN

```bash
ping -c 3 {target_ip}
curl -s --connect-timeout 5 http://{target_ip}/
curl -s --connect-timeout 5 ifconfig.me
```
If any fails: check VPN, retry up to 3 times → `AskUserQuestion` if still failing.

Pre-configure `/etc/hosts`:
```bash
grep -v "{target_ip}" /etc/hosts | grep -v "{name}.htb" > /tmp/hosts.clean
sudo cp /tmp/hosts.clean /etc/hosts
echo "{target_ip} {name}.htb {name}" | sudo tee -a /etc/hosts
```
Add more entries if coordinator discovers additional vhosts later.

Record start time:
```bash
date -u +%Y-%m-%dT%H:%M:%SZ > YYMMDD_<name>/logs/start_time.txt
```

## 7. Spawn and manage coordinator agent pool

**Strict 1:1 mapping**: One coordinator agent per challenge, never shared.

**Pool management** (queue-based with cap N, default: 3 max concurrent):
1. Maintain a queue of challenges to solve
2. Start with min(N, total_challenges) coordinator agents from the queue
3. Each agent solves exactly ONE challenge, then terminates
4. When an agent completes, immediately spawn the next challenge from the queue
5. Never exceed N agents running simultaneously

**Example**: 5 challenges with max N=3:
- T0: Queue=[1,2,3,4,5]. Spawn agents for 1, 2, 3. Running: [1,2,3]
- T1: Agent 1 completes. Spawn agent for 4. Running: [2,3,4]. Queue=[5]
- T2: Agent 2 completes. Spawn agent for 5. Running: [3,4,5]. Queue=[]
- T3: Agents 3,4,5 complete. All done.

**Agent responsibility** (one challenge only):
- Analyze TARGET, plan exploitation
- Spawn executor agents (each in separate browser tab) as needed
- Extract flags, submit to HTB platform
- Generate completion report → `{OUTPUT_DIR}/reports/completion-report.md`
- Write stats → `{OUTPUT_DIR}/stats.json`
- Terminate when challenge is complete

Each agent writes to its own `OUTPUT_DIR` (unique per challenge).

**Reference**: See [coordinator-spawn.md](coordinator-spawn.md) for coordinator spawn prompt template.

## 8. Post-Solve Phase 3 (parent orchestrator — always runs this, not the coordinator)

The coordinator does NOT run skill-update or Slack — it only returns a `PHASE3_SUMMARY` block and writes `completion-report.md` + `stats.json`. The parent orchestrator always runs Phase 3 after each coordinator completes.

After each coordinator completes:

1. **Read coordinator return** — extract `PHASE3_SUMMARY` block (techniques, lessons, skills_to_update)
2. **Verify outputs exist** — `{OUTPUT_DIR}/reports/completion-report.md` + `{OUTPUT_DIR}/stats.json`
3. **Run `/skill-update`** — use techniques and lessons from the PHASE3_SUMMARY. Only generalizable patterns, no target-specific data.
4. **Send Slack notification** per [slack-notifications.md](slack-notifications.md):
   - `python3 tools/env-reader.py SLACK_BOT_TOKEN HTB_SLACK_CHANNEL_ID`
   - If both set: compose message from completion-report + stats + skill-update output, send via `python3 tools/slack-send.py`
   - If either NOT_SET: skip silently
5. **Spawn next** challenge from queue (if any remain)

If the completion report is missing (coordinator crashed), log a warning, skip skill-update/Slack for that challenge, do not block the queue.

## API Submission Notes

- **Rate limiting**: Add 2-2.5 second delays between API flag submissions. "Too Many Attempts" requires 2-3 minute cooldown.
- **Writeup PDF extraction**: Always use `pdftotext` CLI for exact text — visual PDF rendering causes font kerning errors (e.g., "ww" renders as "wu"). Never guess characters from images.
- **"Incorrect Flag" is ambiguous** — the `/machine/own` endpoint returns the same `{"message":"Incorrect Flag."}` for both a wrong flag AND a resubmission of an already-owned flag. Before burning cycles on "wrong flag" debugging, verify ownership:
  ```bash
  curl -s -H "Authorization: Bearer $HTB_TOKEN" \
    "https://labs.hackthebox.com/api/v4/machine/profile/$MACHINE_ID" \
    | python3 -c "import json,sys;d=json.load(sys.stdin)['info'];print('user_owned:',d.get('authUserInUserOwns'),'root_owned:',d.get('authUserInRootOwns'))"
  ```
  If both are `True`, the machine is already fully owned — skip resubmission and move to reporting.

## Flag Progression (Multi-Flag Machines)

HTB machines are designed as chains — each flag builds on the previous foothold.

1. **User flag first, always.** Establish stable access before attempting root.
2. **From user shell, enumerate for root.** The user context often reveals the root path (sudo -l, groups, SeBackupPrivilege, RODC access, etc.)
3. **Don't skip steps.** Advanced techniques (RODC golden tickets, kernel exploits) require prerequisites that earlier flags provide.
4. **AD machines: enumerate ACLs early.** Run `bloodyAD get writable` and BloodHound. Check ForceChangePassword, GenericWrite (scriptPath hijack), WriteDACL, RBCD paths, SeBackupPrivilege, MachineAccountQuota, **WriteSPN on multiple computers** (SPN jacking for constrained delegation redirect), **constrained delegation** (msDS-AllowedToDelegateTo). These are the most common HTB AD escalation vectors.
5. **Clock skew breaks Kerberos.** If any Kerberos tool fails, check skew and use `faketime` prefix.
6. **Internal subnets need tunneling.** If you find Hyper-V (port 2179), dual NICs, or internal IPs — set up Ligolo-ng or chisel to reach internal hosts.
