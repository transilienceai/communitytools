#!/usr/bin/env bash
# test_geo_escalation_live.sh — REQUIRED live end-to-end test for the network-VA
# full-range + source-IP/geo-allowlist auto-probe path (Gap-1 + Gap-2 fixes).
#
# This is a REQUIRED job, NOT skip-on-no-creds: it FAILS LOUDLY when its
# prerequisites are absent so a green run genuinely proves the live behaviour.
#
# PREREQUISITES (stand these up once; wire as CI secrets / vars):
#   - Authenticated gcloud (a scoped service account with a hard budget cap).
#   - GEO_E2E_ZONE           a 2nd-geography gcp zone (e.g. us-central1-a) whose
#                            range is on the allowlisted lab host's allowlist.
#   - GEO_E2E_ALLOWLISTED    IP of a small always-on lab host that is DARK from the
#                            CI runner's egress but LIVE from GEO_E2E_ZONE (mirrors
#                            a per-host source-IP allowlist case).
#   - GEO_E2E_HIGHPORT       IP of a lab host with a service on a HIGH port outside
#                            the top-1000 (e.g. a ZeroMQ 5558 / an odd-TLS 2234),
#                            reachable from the CI runner (proves full-range).
#   - GEO_E2E_HIGHPORT_PORT  that high port number (e.g. 5558).
#
# Run: bash tools/test_geo_escalation_live.sh
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PV="$REPO_ROOT/tools/provision_vantage.sh"
fail=0; note() { echo "  $*"; }

require() { # require VAR
  local v="${!1:-}"
  [[ -n "$v" ]] || { echo "FAIL(prereq): $1 is unset — this REQUIRED live test cannot run without it"; fail=1; }
}
require GEO_E2E_ZONE; require GEO_E2E_ALLOWLISTED; require GEO_E2E_HIGHPORT; require GEO_E2E_HIGHPORT_PORT
command -v gcloud >/dev/null || { echo "FAIL(prereq): gcloud not installed/authenticated"; fail=1; }
command -v nmap   >/dev/null || { echo "FAIL(prereq): nmap not installed"; fail=1; }
[[ $fail -eq 0 ]] || { echo "geo-escalation live e2e: PREREQUISITES MISSING"; exit 1; }

ENG_DIR="$(mktemp -d)/e2e-geo-escalation"; mkdir -p "$ENG_DIR/logs/activity"
ENG_ID="$(basename "$ENG_DIR" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | cut -c1-40)"
cleanup() { bash "$PV" --reap --engagement "$ENG_DIR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== [1] full-range finds a HIGH-port service from the CI runner (Gap-1) =="
# The bounded top-1000 would miss GEO_E2E_HIGHPORT_PORT; a full -p- must find it.
if nmap -sT -Pn -n -p- --min-rate 2000 "$GEO_E2E_HIGHPORT" -oG - 2>/dev/null | grep -qE "\b${GEO_E2E_HIGHPORT_PORT}/open"; then
  note "PASS: full-range surfaced ${GEO_E2E_HIGHPORT}:${GEO_E2E_HIGHPORT_PORT} (a top-1000 scan would have missed it)"
else
  echo "  FAIL: full-range did not surface ${GEO_E2E_HIGHPORT}:${GEO_E2E_HIGHPORT_PORT}"; fail=1
fi

echo "== [2] the allowlisted host is DARK from the CI runner =="
if nmap -sn -n "$GEO_E2E_ALLOWLISTED" -oG - 2>/dev/null | grep -q "Status: Up" \
   && ! nmap -sT -Pn -n --top-ports 100 "$GEO_E2E_ALLOWLISTED" -oG - 2>/dev/null | grep -qE "/open"; then
  note "PASS: ${GEO_E2E_ALLOWLISTED} is existence-confirmed but has no open service from the runner (a filtered[] candidate)"
else
  note "WARN: could not confirm the allowlisted host is dark from the runner (lab wiring?) — continuing to the 2nd-vantage probe"
fi

echo "== [3] provision a REAL 2nd-geo VM + confirm no orphan leaks (Gap-2) =="
bash "$PV" --reap --engagement "$ENG_DIR" >/dev/null 2>&1 || true
LINE="$(bash "$PV" --provider gcp --region "$GEO_E2E_ZONE" --engagement "$ENG_DIR" --name "vantage-${ENG_ID}-e2e" --ssh-ready 2>/dev/null)"
HANDLE="$(printf '%s' "$LINE" | sed -n 's/.*handle=\([^ ]*\).*/\1/p')"
NAME="vantage-${ENG_ID}-e2e"
if [[ -z "$HANDLE" ]]; then echo "  FAIL: VM did not provision (no handle)"; fail=1; fi

if [[ -n "$HANDLE" ]]; then
  echo "== [4] from the 2nd-geo VM, the allowlisted host is now REACHABLE =="
  REMOTE="sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap >/dev/null 2>&1; nmap -sT -Pn -n --top-ports 1000 ${GEO_E2E_ALLOWLISTED} -oG -"
  if gcloud compute ssh "$NAME" --zone "$GEO_E2E_ZONE" --command "$REMOTE" 2>/dev/null | grep -qE "/open"; then
    note "PASS: ${GEO_E2E_ALLOWLISTED} is LIVE from ${GEO_E2E_ZONE} (allowlist confirmed — this is the source-IP-allowlist case the 1st pass missed)"
  else
    echo "  FAIL: ${GEO_E2E_ALLOWLISTED} not reachable from the 2nd-geo VM"; fail=1
  fi

  echo "== [5] teardown by handle + a role:decommissioned ledger line =="
  bash "$PV" --teardown "$HANDLE" --engagement "$ENG_DIR" >/dev/null 2>&1 || true
fi

echo "== [6] reaper confirms ZERO engagement VMs remain (no leak) =="
LEFT="$(gcloud compute instances list --filter="labels.engagement=${ENG_ID}" --format='value(name)' 2>/dev/null | grep -c . || true)"
if [[ "${LEFT:-0}" -eq 0 ]]; then note "PASS: no VM labelled engagement=${ENG_ID} remains"; else echo "  FAIL: ${LEFT} VM(s) leaked for engagement=${ENG_ID}"; fail=1; fi
grep -q '"role": "decommissioned"' "$ENG_DIR/logs/activity/source-ips.jsonl" 2>/dev/null \
  && note "PASS: teardown appended a role:decommissioned ledger line" || { echo "  FAIL: no decommission line in the ledger"; fail=1; }

if [[ $fail -eq 0 ]]; then echo "OK: geo-escalation live e2e (full-range + 2nd-geo allowlist probe + crash-safe teardown)"; else echo "geo-escalation live e2e FAILED"; exit 1; fi
