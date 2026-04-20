#!/bin/bash
# htb-skill-update-gate.sh — Enforces /skill-update after HTB challenge solve
#
# Handles 3 hook events:
# 1. SubagentStop      → inject reminder when coordinator completes
# 2. PreToolUse/Bash   → block slack-send.py if no .skill-update-done marker
# 3. PostToolUse/Skill → create .skill-update-done marker after /skill-update

HOOK_DATA=$(cat)
EVENT=$(echo "$HOOK_DATA" | jq -r '.hook_event_name')
TOOL=$(echo "$HOOK_DATA" | jq -r '.tool_name // ""')

case "$EVENT" in

  SubagentStop)
    # Coordinator completed — remind parent to run /skill-update
    CWD=$(echo "$HOOK_DATA" | jq -r '.cwd // ""')
    UNMARKED=""
    while IFS= read -r f; do
      DIR=$(dirname "$(dirname "$f")")
      [[ ! -f "$DIR/.skill-update-done" ]] && UNMARKED="$DIR" && break
    done < <(find "$CWD" -path "*/reports/completion-report.md" -maxdepth 5 2>/dev/null)

    if [[ -n "$UNMARKED" ]]; then
      cat <<EOJSON
{"systemMessage": "HTB coordinator completed. Completion report at $UNMARKED/reports/completion-report.md has no /skill-update. You MUST:\n1. Run /skill-update with techniques and lessons from this report\n2. Then send Slack notification using: python3 tools/slack-send.py (see skills/hackthebox/reference/slack-notifications.md for format)\nslack-send.py is blocked until /skill-update is done. Do NOT spawn the next coordinator until both steps complete."}
EOJSON
    else
      echo '{"continue": true}'
    fi
    ;;

  PostToolUse)
    # After /skill-update, create marker and remind to send Slack
    if [[ "$TOOL" == "Skill" ]]; then
      CWD=$(echo "$HOOK_DATA" | jq -r '.cwd // ""')
      MARKED_DIR=""
      while IFS= read -r f; do
        DIR=$(dirname "$(dirname "$f")")
        if [[ ! -f "$DIR/.skill-update-done" ]]; then
          touch "$DIR/.skill-update-done"
          MARKED_DIR="$DIR"
          break
        fi
      done < <(find "$CWD" -path "*/reports/completion-report.md" -maxdepth 5 2>/dev/null \
               | xargs ls -t 2>/dev/null)
      if [[ -n "$MARKED_DIR" ]]; then
        cat <<EOJSON
{"systemMessage": "/skill-update done for $MARKED_DIR. NOW send Slack notification: read $MARKED_DIR/reports/completion-report.md + $MARKED_DIR/stats.json, compose message per skills/hackthebox/reference/slack-notifications.md, send via python3 tools/slack-send.py. Then spawn next coordinator if queue has more."}
EOJSON
        exit 0
      fi
    fi
    echo '{"continue": true}'
    ;;

  PreToolUse)
    # Block slack-send.py if any completion report lacks marker
    COMMAND=$(echo "$HOOK_DATA" | jq -r '.tool_input.command // ""')
    if [[ "$COMMAND" =~ slack-send\.py ]]; then
      CWD=$(echo "$HOOK_DATA" | jq -r '.cwd // ""')
      UNMARKED=""
      while IFS= read -r f; do
        DIR=$(dirname "$(dirname "$f")")
        [[ ! -f "$DIR/.skill-update-done" ]] && UNMARKED="$DIR" && break
      done < <(find "$CWD" -path "*/reports/completion-report.md" -maxdepth 5 2>/dev/null)

      if [[ -n "$UNMARKED" ]]; then
        echo "{\"decision\": \"block\", \"reason\": \"Completion report at $UNMARKED needs /skill-update first. Run /skill-update to document learnings, then retry Slack.\"}"
        exit 0
      fi
    fi
    echo '{"continue": true}'
    ;;

esac
