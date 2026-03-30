# HackTheBox Workflow — Detailed Steps

## 1. Read credentials

```bash
python3 tools/env-reader.py HTB_USER HTB_PASS ANTHROPIC_API_KEY SLACK_BOT_TOKEN HTB_SLACK_CHANNEL_ID
```
Use `HTB_USER`/`HTB_PASS` from `ENV_VALUES`. Only `AskUserQuestion` if `NOT_SET`.
Slack is enabled when BOTH `SLACK_BOT_TOKEN` and `HTB_SLACK_CHANNEL_ID` are set.

## 2. Check VPN

This skill does NOT start VPN — the user manages it. Check if running:
```bash
ps aux | grep -v grep | grep openvpn && echo "VPN_RUNNING" || echo "VPN_NOT_RUNNING"
```
If not running → `AskUserQuestion` asking user to start it. Do NOT try to start VPN yourself.

## 3. Create output directory

```bash
mkdir -p YYMMDD_<name>/{recon,findings,logs,artifacts,reports}
```

## 4. Log in to HTB (headed browser, NEVER headless)

Navigate `https://app.hackthebox.com/login`, fill credentials, handle 2FA. Use headed mode + anti-detection flags + realistic viewport + persistent context for `cf_clearance`. If blocked: `reference/cloudflare-bypass.md`. Fallback: HTB API `https://labs.hackthebox.com/api/v4/` with Bearer token.

## 5. Select and start machine

1. Navigate to the requested machine/challenge (or browse and present options via `AskUserQuestion`)
2. Start the machine if not running (click Start Machine in Tab 0)
3. Save challenge info to `YYMMDD_<name>/challenge-meta.json`

## 6. Verify connectivity and configure hosts

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
Add more entries if orchestrator discovers additional vhosts later.

Record start time:
```bash
date -u +%Y-%m-%dT%H:%M:%SZ > YYMMDD_<name>/logs/start_time.txt
```

## 7. Slack: challenge started (if enabled)

```bash
printf ':crossed_swords: *Starting HTB: %s*\n*Difficulty:* %s | *OS:* %s | *Target:* `%s`\n_Started at %s_' \
  "{name}" "{difficulty}" "{os}" "{ip}" "$(date -u '+%Y-%m-%d %H:%M UTC')" \
  | python3 tools/slack-send.py --token "{SLACK_BOT_TOKEN}" --channel "{HTB_SLACK_CHANNEL_ID}" -
```
If tool exits non-zero, log error but continue.

## 8. Run orchestrator to solve

See the "Orchestrator (Step 8)" section in the main SKILL.md.

## 9. Submit flags

1. Extract flags from orchestrator output → submit via Playwright on Tab 0
2. Save to `YYMMDD_<name>/flag.txt`
3. Write structured findings in `YYMMDD_<name>/findings/finding-NNN/`

## 10. Run skiller (MANDATORY, foreground)

Run `/skiller` to process all activities — successful techniques, failed attempts, key discoveries. Evaluate skill/reference updates. Constraints: generalizable only, no target-specific data, minimal footprint. Save output for report + Slack.

## 11. Collect stats and write completion report

Read `stats.json` + `start_time.txt`, compute duration. If `stats.json` missing, count from activity logs. Write `reports/completion-report.md`: challenge info, stats, attack chain, techniques, lessons, failed approaches.

## 12. Slack: challenge completed (if enabled)

Build from completion report. ALL sections required — do not send partial. Include a narrative "How it was hacked" (connected story, 3-6 sentences, not just bullets).

Format: `:trophy: PWNED — {name}` | difficulty/OS/time | flag status (:white_check_mark:/:x:) | Stats (experiments/findings/agents) | How it was hacked (narrative) | Key Techniques (bullets) | Skills Updated (skiller summary)

Send via `tools/slack-send.py`. If tool fails, log error but continue.
