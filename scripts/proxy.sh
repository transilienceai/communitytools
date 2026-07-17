#!/usr/bin/env bash
# Run the LiteLLM proxy locally on :4000 (override with LITELLM_PORT=xxxx).
#
# Bridges Claude Code's Anthropic /v1/messages to the GLM vLLM endpoint,
# authenticating to Modal with proxy-auth headers. Requires in .env:
#   LITELLM_MASTER_KEY, MODAL_PROXY_TOKEN_ID, MODAL_PROXY_TOKEN_SECRET
# (the GLM api_base + Modal-Key/Modal-Secret wiring lives in litellm_config.yaml).

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "ERROR: .env not found next to the repo root." >&2
  exit 1
fi

set -a
source .env
set +a

# Port must be explicit and immune to a stray PORT env var: litellm's --port has
# envvar="PORT", so an inherited/exported PORT would silently override 4000
# (this is why the proxy came up on 22006). Force it here.
PORT_TO_USE="${LITELLM_PORT:-4000}"
unset PORT

# Validate the vars the current litellm_config.yaml actually needs.
missing=()
for v in LITELLM_MASTER_KEY MODAL_PROXY_TOKEN_ID MODAL_PROXY_TOKEN_SECRET; do
  [[ -z "${!v:-}" ]] && missing+=("$v")
done
if (( ${#missing[@]} )); then
  echo "ERROR: missing in .env: ${missing[*]}" >&2
  exit 1
fi

# Free the target port if a previous proxy is still bound to it.
if lsof -tiTCP:"$PORT_TO_USE" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port $PORT_TO_USE already in use — stopping the existing listener..." >&2
  lsof -tiTCP:"$PORT_TO_USE" -sTCP:LISTEN | xargs kill 2>/dev/null || true
  sleep 1
fi

echo "Starting LiteLLM on 0.0.0.0:$PORT_TO_USE (config: litellm_config.yaml)"
exec .venv/bin/litellm --config litellm_config.yaml --host 0.0.0.0 --port "$PORT_TO_USE"
