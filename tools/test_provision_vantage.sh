#!/usr/bin/env bash
# Tests the --dry-run path of tools/provision_vantage.sh for all three providers:
# a synthetic IP + handle is printed and an attack-vm source-ips line is registered
# offline. Real VM creation is not CI-testable. Run: bash tools/test_provision_vantage.sh
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/tools/provision_vantage.sh"
fail=0

for prov in gcp aws az; do
  tmp="$(mktemp -d)"
  if ! out="$(bash "$SCRIPT" --dry-run --provider "$prov" --region asia-south1 --engagement "$tmp" 2>&1)"; then
    echo "FAIL $prov: wrapper exited nonzero: $out"; fail=1; rm -rf "$tmp"; continue
  fi
  echo "$out" | grep -q "203.0.113.7" || { echo "FAIL $prov: no dry-run IP in output"; fail=1; }
  echo "$out" | grep -q "handle=dry-run:${prov}:" || { echo "FAIL $prov: no handle in output"; fail=1; }
  if python3 - "$tmp/logs/activity/source-ips.jsonl" "$prov" <<'PY'
import json, sys
rows = [json.loads(x) for x in open(sys.argv[1]) if x.strip()]
assert len(rows) == 1, rows
r = rows[0]
assert r["role"] == "attack-vm", r
assert r["provider"] == sys.argv[2], r
assert r["region"] == "asia-south1", r
assert r["ip"] == "203.0.113.7", r
# A dry run must never be able to manufacture a vantage: registration is intent,
# not proof. Two dry-runs with different --region values used to close a
# min_vantages:2 reachability cell having sent zero packets.
assert r["verified"] is False, f"dry-run must register verified:false, got {r}"
assert r.get("probe_evidence", "") == "", r
PY
  then echo "PASS $prov dry-run"; else echo "FAIL $prov: source-ips content wrong"; fail=1; fi
  rm -rf "$tmp"
done

# --- teardown --dry-run: appends a role:decommissioned ledger line ----------
tmp="$(mktemp -d)"
if out="$(bash "$SCRIPT" --teardown "gcp:us-central1-a:vantage-x" --engagement "$tmp" --dry-run 2>&1)"; then
  echo "$out" | grep -q "torn-down gcp:us-central1-a:vantage-x" || { echo "FAIL teardown: no torn-down line"; fail=1; }
  if python3 - "$tmp/logs/activity/source-ips.jsonl" <<'PY'
import json, sys
rows = [json.loads(x) for x in open(sys.argv[1]) if x.strip()]
assert len(rows) == 1 and rows[0]["role"] == "decommissioned", rows
assert "torn down" in rows[0]["note"], rows
PY
  then echo "PASS teardown dry-run (appends role:decommissioned)"; else echo "FAIL teardown: ledger line wrong"; fail=1; fi
else echo "FAIL teardown: wrapper exited nonzero: $out"; fail=1; fi
rm -rf "$tmp"

# --- reap --dry-run: no-op, prints a reaped count, never mutates the ledger --
tmp="$(mktemp -d)"
if out="$(bash "$SCRIPT" --reap --engagement "$tmp" --dry-run 2>&1)"; then
  echo "$out" | grep -qE "reaped 0 \(dry-run\)" || { echo "FAIL reap: no reaped-0 line"; fail=1; }
  [[ -f "$tmp/logs/activity/source-ips.jsonl" ]] && { echo "FAIL reap: dry-run must not write the ledger"; fail=1; }
  echo "PASS reap dry-run (idempotent no-op)"
else echo "FAIL reap: wrapper exited nonzero: $out"; fail=1; fi
rm -rf "$tmp"

if [[ $fail -eq 0 ]]; then
  echo "OK: provision_vantage dry-run (create gcp/aws/az + teardown + reap)"
else
  echo "provision_vantage tests FAILED"; exit 1
fi
