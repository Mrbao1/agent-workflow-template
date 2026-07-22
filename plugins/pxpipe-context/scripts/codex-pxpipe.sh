#!/usr/bin/env bash
set -euo pipefail

# Run Codex for any project through this local pxpipe proxy.
#
# Usage:
#   /path/to/pxpipe/scripts/codex-pxpipe.sh
#   /path/to/pxpipe/scripts/codex-pxpipe.sh /path/to/project
#   /path/to/pxpipe/scripts/codex-pxpipe.sh /path/to/project -- --no-alt-screen
#
# Env overrides:
#   PXPIPE_PORT=47821
#   CODEX_MODEL=gpt-5.6-sol
#   CODEX_REASONING_EFFORT=high
#   PXPIPE_MODELS=gpt-5.6-sol  # defaults to CODEX_MODEL
#   CODEX_BIN=/path/to/codex
#   PXPIPE_NODE=/path/to/pxpipe-node.mjs

PXPIPE_PORT="${PXPIPE_PORT:-47821}"
CODEX_MODEL="${CODEX_MODEL:-gpt-5.6-sol}"
CODEX_REASONING_EFFORT="${CODEX_REASONING_EFFORT:-high}"
PXPIPE_MODELS="${PXPIPE_MODELS:-$CODEX_MODEL}"

resolve_codex_bin() {
  local requested="${CODEX_BIN:-}"
  local candidate

  if [[ -n "$requested" ]]; then
    candidate="$(command -v "$requested" 2>/dev/null || true)"
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    if [[ -x "$requested" ]]; then
      printf '%s\n' "$requested"
      return 0
    fi
    return 1
  fi

  for candidate in \
    "$(command -v codex 2>/dev/null || true)" \
    "/Applications/ChatGPT.app/Contents/Resources/codex" \
    "/Applications/Codex.app/Contents/Resources/codex"
  do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

if ! CODEX_BIN="$(resolve_codex_bin)"; then
  echo "Codex CLI not found in PATH or the ChatGPT/Codex macOS apps." >&2
  echo "Set CODEX_BIN to its executable path and retry." >&2
  exit 1
fi

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_SOURCE" ]]; do
  SCRIPT_SOURCE_DIR="$(cd -P -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
  SCRIPT_LINK_TARGET="$(readlink "$SCRIPT_SOURCE")"
  if [[ "$SCRIPT_LINK_TARGET" == /* ]]; then
    SCRIPT_SOURCE="$SCRIPT_LINK_TARGET"
  else
    SCRIPT_SOURCE="$SCRIPT_SOURCE_DIR/$SCRIPT_LINK_TARGET"
  fi
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
PXPIPE_DIR="${PXPIPE_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
if [[ -z "${PXPIPE_NODE:-}" ]]; then
  if [[ -f "$PXPIPE_DIR/dist/node.js" ]]; then
    PXPIPE_NODE="$PXPIPE_DIR/dist/node.js"
  else
    PXPIPE_NODE="$PXPIPE_DIR/proxy/vendor/pxpipe-node.mjs"
  fi
fi
PXPIPE_STATE_DIR="${PXPIPE_STATE_DIR:-$HOME/.pxpipe}"
PXPIPE_LOG="${PXPIPE_LOG:-$PXPIPE_STATE_DIR/events.jsonl}"
PXPIPE_SERVER_LOG="${PXPIPE_SERVER_LOG:-$PXPIPE_STATE_DIR/server-${PXPIPE_PORT}.log}"
PXPIPE_PID_FILE="${PXPIPE_PID_FILE:-$PXPIPE_STATE_DIR/server-${PXPIPE_PORT}.pid}"
PXPIPE_OWNED_PID=""
CODEX_CHILD_PID=""

TARGET_DIR="$PWD"
if [[ $# -gt 0 && "$1" != "--" && -d "$1" ]]; then
  TARGET_DIR="$(cd -- "$1" && pwd)"
  shift
fi
if [[ $# -gt 0 && "$1" == "--" ]]; then
  shift
fi

PXPIPE_BASE_URL="http://127.0.0.1:${PXPIPE_PORT}"
OPENAI_BASE_URL_VALUE="${PXPIPE_BASE_URL}/v1"

pxpipe_alive() {
  curl -fsS --max-time 2 "${PXPIPE_BASE_URL}/proxy-stats" >/dev/null 2>&1
}

port_has_listener() {
  lsof -nP -iTCP:"${PXPIPE_PORT}" -sTCP:LISTEN >/dev/null 2>&1
}

cleanup_owned_pxpipe() {
  local recorded_pid=""

  if [[ -z "$PXPIPE_OWNED_PID" ]]; then
    return 0
  fi
  if kill -0 "$PXPIPE_OWNED_PID" 2>/dev/null; then
    kill "$PXPIPE_OWNED_PID" 2>/dev/null || true
    wait "$PXPIPE_OWNED_PID" 2>/dev/null || true
  fi
  if [[ -f "$PXPIPE_PID_FILE" ]]; then
    recorded_pid="$(tr -d '[:space:]' <"$PXPIPE_PID_FILE")"
    if [[ "$recorded_pid" == "$PXPIPE_OWNED_PID" ]]; then
      rm -f "$PXPIPE_PID_FILE"
    fi
  fi
  PXPIPE_OWNED_PID=""
}

forward_signal() {
  local signal="$1"
  if [[ -n "$CODEX_CHILD_PID" ]] && kill -0 "$CODEX_CHILD_PID" 2>/dev/null; then
    kill -s "$signal" "$CODEX_CHILD_PID" 2>/dev/null || true
  fi
}

trap cleanup_owned_pxpipe EXIT
trap 'forward_signal HUP' HUP
trap 'forward_signal INT' INT
trap 'forward_signal TERM' TERM

enable_codex_model_compression() {
  # The server may already be running with a different PXPIPE_MODELS. Enforce
  # this Codex model in the live compression scope before starting the CLI.
  if ! curl -fsS --max-time 2 \
    -X POST "${PXPIPE_BASE_URL}/fragments/models" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "model=${CODEX_MODEL}" \
    --data-urlencode "on=true" \
    >/dev/null; then
    echo "Could not enable image compression for ${CODEX_MODEL}." >&2
    echo "Check pxpipe at ${PXPIPE_BASE_URL} and retry." >&2
    exit 1
  fi
}

start_pxpipe() {
  if [[ ! -f "$PXPIPE_NODE" ]]; then
    echo "pxpipe build output not found: $PXPIPE_NODE" >&2
    echo "Run this once in $PXPIPE_DIR: pnpm run build" >&2
    exit 1
  fi

  mkdir -p "$PXPIPE_STATE_DIR"

  (
    cd "$PXPIPE_DIR"
    exec env \
      PORT="$PXPIPE_PORT" \
      HOST="127.0.0.1" \
      PXPIPE_MODELS="$PXPIPE_MODELS" \
      PXPIPE_LOG="$PXPIPE_LOG" \
      node "$PXPIPE_NODE"
  ) >>"$PXPIPE_SERVER_LOG" 2>&1 &
  PXPIPE_OWNED_PID="$!"
  printf '%s\n' "$PXPIPE_OWNED_PID" >"$PXPIPE_PID_FILE"

  for _ in {1..40}; do
    if pxpipe_alive; then
      return 0
    fi
    sleep 0.25
  done

  echo "pxpipe did not become ready on ${PXPIPE_BASE_URL}" >&2
  echo "Log: $PXPIPE_SERVER_LOG" >&2
  exit 1
}

if pxpipe_alive; then
  echo "pxpipe already running: ${PXPIPE_BASE_URL}"
elif port_has_listener; then
  echo "Port ${PXPIPE_PORT} is already in use, but it does not look like pxpipe." >&2
  lsof -nP -iTCP:"${PXPIPE_PORT}" -sTCP:LISTEN >&2 || true
  exit 1
else
  echo "starting pxpipe on ${PXPIPE_BASE_URL} with PXPIPE_MODELS=${PXPIPE_MODELS}"
  start_pxpipe
fi

enable_codex_model_compression

echo "starting Codex in: ${TARGET_DIR}"
echo "Codex model: ${CODEX_MODEL} (${CODEX_REASONING_EFFORT})"
echo "image compression models: ${PXPIPE_MODELS}"
echo "Codex openai_base_url: ${OPENAI_BASE_URL_VALUE}"
"$CODEX_BIN" \
  -C "$TARGET_DIR" \
  -m "$CODEX_MODEL" \
  -c "model_reasoning_effort=\"${CODEX_REASONING_EFFORT}\"" \
  -c "openai_base_url=\"${OPENAI_BASE_URL_VALUE}\"" \
  "$@" &
CODEX_CHILD_PID="$!"
set +e
wait "$CODEX_CHILD_PID"
CODEX_STATUS="$?"
set -e
CODEX_CHILD_PID=""
exit "$CODEX_STATUS"
