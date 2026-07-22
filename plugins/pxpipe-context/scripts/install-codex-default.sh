#!/usr/bin/env bash
set -euo pipefail

PXPIPE_PORT="${PXPIPE_PORT:-47821}"
CODEX_MODEL="${CODEX_MODEL:-gpt-5.6-sol}"
PXPIPE_MODELS="${PXPIPE_MODELS:-$CODEX_MODEL}"
CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
PXPIPE_STATE_DIR="${PXPIPE_STATE_DIR:-$HOME/.pxpipe}"
LAUNCH_AGENTS_DIR="${LAUNCH_AGENTS_DIR:-$HOME/Library/LaunchAgents}"
LAUNCH_LABEL="${PXPIPE_LAUNCH_LABEL:-com.pxpipe.codex-default}"
PLIST_PATH="$LAUNCH_AGENTS_DIR/$LAUNCH_LABEL.plist"
CONFIG_PATH="$CODEX_HOME_DIR/config.toml"
MANAGED_STATE="$PXPIPE_STATE_DIR/codex-default.json"
BASE_URL="http://127.0.0.1:${PXPIPE_PORT}"
PLIST_ORIGINAL="$PXPIPE_STATE_DIR/codex-default.plist-before"
PLIST_ORIGIN_ABSENT="$PXPIPE_STATE_DIR/codex-default.plist-absent-before"
PLIST_TRANSACTION="$PXPIPE_STATE_DIR/codex-default.plist-transaction-$$"

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_SOURCE" ]]; do
  SOURCE_DIR="$(cd -P -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
  LINK_TARGET="$(readlink "$SCRIPT_SOURCE")"
  [[ "$LINK_TARGET" == /* ]] && SCRIPT_SOURCE="$LINK_TARGET" || SCRIPT_SOURCE="$SOURCE_DIR/$LINK_TARGET"
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
PXPIPE_DIR="${PXPIPE_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
CONFIG_TOOL="$SCRIPT_DIR/codex-default-config.mjs"

if [[ "$(uname -s)" != "Darwin" && "${PXPIPE_TEST_MODE:-0}" != "1" ]]; then
  echo "Default Codex installation currently supports macOS launchd only." >&2
  exit 1
fi
if [[ "$CODEX_MODEL" != "gpt-5.6-sol" || "$PXPIPE_MODELS" != "gpt-5.6-sol" ]]; then
  echo "Default compression is restricted to exact model gpt-5.6-sol." >&2
  exit 1
fi
if ! [[ "$PXPIPE_PORT" =~ ^[0-9]+$ ]] || (( PXPIPE_PORT < 1024 || PXPIPE_PORT > 65535 )); then
  echo "PXPIPE_PORT must be an integer from 1024 to 65535." >&2
  exit 1
fi

NODE_BIN="${PXPIPE_NODE_BIN:-$(command -v node 2>/dev/null || true)}"
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "An absolute executable Node.js path is required." >&2
  exit 1
fi
NODE_BIN="$(cd -P -- "$(dirname -- "$NODE_BIN")" && pwd)/$(basename -- "$NODE_BIN")"

if [[ "${PXPIPE_TEST_MODE:-0}" == "1" ]]; then
  LAUNCHCTL_BIN="${PXPIPE_LAUNCHCTL_BIN:-/bin/launchctl}"
  CURL_BIN="${PXPIPE_CURL_BIN:-/usr/bin/curl}"
  LSOF_BIN="${PXPIPE_LSOF_BIN:-/usr/sbin/lsof}"
  ID_BIN="${PXPIPE_ID_BIN:-/usr/bin/id}"
else
  LAUNCHCTL_BIN="/bin/launchctl"
  CURL_BIN="/usr/bin/curl"
  LSOF_BIN="/usr/sbin/lsof"
  ID_BIN="/usr/bin/id"
fi
for executable in "$LAUNCHCTL_BIN" "$CURL_BIN" "$LSOF_BIN" "$ID_BIN"; do
  if [[ ! -x "$executable" ]]; then
    echo "Required absolute executable is missing: $executable" >&2
    exit 1
  fi
done
LAUNCH_DOMAIN="gui/$($ID_BIN -u)"

if [[ -n "${PXPIPE_NODE:-}" ]]; then
  PXPIPE_BUNDLE="$PXPIPE_NODE"
elif [[ -f "$PXPIPE_DIR/dist/node.js" ]]; then
  PXPIPE_BUNDLE="$PXPIPE_DIR/dist/node.js"
else
  PXPIPE_BUNDLE="$PXPIPE_DIR/proxy/vendor/pxpipe-node.mjs"
fi
if [[ ! -f "$PXPIPE_BUNDLE" ]]; then
  echo "pxpipe proxy build output is missing: $PXPIPE_BUNDLE" >&2
  echo "Run pnpm run build in $PXPIPE_DIR first." >&2
  exit 1
fi
PXPIPE_BUNDLE="$(cd -P -- "$(dirname -- "$PXPIPE_BUNDLE")" && pwd)/$(basename -- "$PXPIPE_BUNDLE")"

xml_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  value="${value//\"/&quot;}"
  value="${value//\'/&apos;}"
  printf '%s' "$value"
}

mkdir -p "$PXPIPE_STATE_DIR" "$LAUNCH_AGENTS_DIR" "$CODEX_HOME_DIR"
chmod 700 "$PXPIPE_STATE_DIR" "$CODEX_HOME_DIR" 2>/dev/null || true

origin_record_created=0
if [[ ! -f "$PLIST_ORIGINAL" && ! -f "$PLIST_ORIGIN_ABSENT" ]]; then
  if [[ -f "$PLIST_PATH" ]]; then
    if [[ -f "$MANAGED_STATE" ]] \
      && /usr/bin/grep -Fq "<key>Label</key><string>$LAUNCH_LABEL</string>" "$PLIST_PATH" \
      && /usr/bin/grep -Fq '<key>HOST</key><string>127.0.0.1</string>' "$PLIST_PATH" \
      && /usr/bin/grep -Fq '<key>PXPIPE_MODELS</key><string>gpt-5.6-sol</string>' "$PLIST_PATH"; then
      : >"$PLIST_ORIGIN_ABSENT"
      chmod 600 "$PLIST_ORIGIN_ABSENT"
    else
      cp "$PLIST_PATH" "$PLIST_ORIGINAL"
      chmod 600 "$PLIST_ORIGINAL"
    fi
  else
    : >"$PLIST_ORIGIN_ABSENT"
    chmod 600 "$PLIST_ORIGIN_ABSENT"
  fi
  origin_record_created=1
fi
if [[ -f "$PLIST_PATH" ]]; then
  cp "$PLIST_PATH" "$PLIST_TRANSACTION"
  chmod 600 "$PLIST_TRANSACTION"
fi

PLIST_TEMP="$PLIST_PATH.tmp-$$"
service_touched=0

is_pxpipe_healthy() {
  local payload
  payload="$($CURL_BIN -fsS --max-time 2 "$BASE_URL/proxy-stats" 2>/dev/null)" || return 1
  printf '%s' "$payload" | "$NODE_BIN" -e '
    let body="";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => { body += chunk; });
    process.stdin.on("end", () => {
      try {
        const value = JSON.parse(body);
        process.exit(Number.isFinite(value.requests) && Number.isFinite(value.compressed_requests) ? 0 : 1);
      } catch { process.exit(1); }
    });
  ' >/dev/null 2>&1
}

port_has_listener() {
  "$LSOF_BIN" -nP -iTCP:"$PXPIPE_PORT" -sTCP:LISTEN >/dev/null 2>&1
}

bootstrap_plist() {
  local target="$1"
  for _ in 1 2 3 4; do
    if "$LAUNCHCTL_BIN" bootstrap "$LAUNCH_DOMAIN" "$target"; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

rollback_install() {
  if [[ "$service_touched" == "1" && "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
    "$LAUNCHCTL_BIN" bootout "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1 || true
  fi
  rm -f "$PLIST_PATH"
  if [[ -f "$PLIST_TRANSACTION" ]]; then
    cp "$PLIST_TRANSACTION" "$PLIST_PATH"
    chmod 600 "$PLIST_PATH"
    if [[ "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
      bootstrap_plist "$PLIST_PATH" >/dev/null 2>&1 || true
    fi
  fi
}

install_in_progress=1
on_exit() {
  local status="$?"
  rm -f "$PLIST_TEMP"
  if [[ "$status" != "0" && "$install_in_progress" == "1" ]]; then
    rollback_install
    if [[ "$origin_record_created" == "1" && ! -f "$MANAGED_STATE" ]]; then
      rm -f "$PLIST_ORIGINAL" "$PLIST_ORIGIN_ABSENT"
    fi
  fi
  rm -f "$PLIST_TRANSACTION"
}
trap on_exit EXIT

if [[ "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]] && port_has_listener; then
  if is_pxpipe_healthy && "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1; then
    : # idempotent reinstall of the managed service
  elif is_pxpipe_healthy; then
    echo "An unmanaged pxpipe already occupies $BASE_URL; stop it before installing the default service." >&2
    exit 1
  else
    echo "Port $PXPIPE_PORT is occupied by a service that does not look like pxpipe." >&2
    exit 1
  fi
fi

{
  printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
  printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
  printf '%s\n' '<plist version="1.0"><dict>'
  printf '  <key>Label</key><string>%s</string>\n' "$(xml_escape "$LAUNCH_LABEL")"
  printf '  <key>ProgramArguments</key><array><string>%s</string><string>%s</string></array>\n' "$(xml_escape "$NODE_BIN")" "$(xml_escape "$PXPIPE_BUNDLE")"
  printf '%s\n' '  <key>EnvironmentVariables</key><dict>'
  printf '    <key>PORT</key><string>%s</string>\n' "$PXPIPE_PORT"
  printf '%s\n' '    <key>HOST</key><string>127.0.0.1</string>'
  printf '    <key>PXPIPE_MODELS</key><string>%s</string>\n' "$(xml_escape "$PXPIPE_MODELS")"
  printf '    <key>PXPIPE_LOG</key><string>%s</string>\n' "$(xml_escape "$PXPIPE_STATE_DIR/events.jsonl")"
  printf '%s\n' '    <key>OPENAI_UPSTREAM</key><string>https://chatgpt.com/backend-api/codex</string>'
  printf '%s\n' '    <key>OPENAI_STRIP_V1</key><string>1</string>'
  printf '%s\n' '  </dict>'
  printf '%s\n' '  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ProcessType</key><string>Background</string><key>ThrottleInterval</key><integer>5</integer>'
  printf '  <key>StandardOutPath</key><string>%s</string>\n' "$(xml_escape "$PXPIPE_STATE_DIR/codex-default.stdout.log")"
  printf '  <key>StandardErrorPath</key><string>%s</string>\n' "$(xml_escape "$PXPIPE_STATE_DIR/codex-default.stderr.log")"
  printf '%s\n' '</dict></plist>'
} >"$PLIST_TEMP"
chmod 600 "$PLIST_TEMP"
mv "$PLIST_TEMP" "$PLIST_PATH"

if [[ "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
  service_touched=1
  "$LAUNCHCTL_BIN" bootout "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1 || true
  stopped=0
  for _ in {1..40}; do
    if ! "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1 && ! port_has_listener; then
      stopped=1
      break
    fi
    sleep 0.25
  done
  if [[ "$stopped" != "1" ]]; then
    echo "The previous pxpipe service did not stop cleanly; refusing to replace it." >&2
    exit 1
  fi
  bootstrap_plist "$PLIST_PATH"
  ready=0
  for _ in {1..40}; do
    if is_pxpipe_healthy; then ready=1; break; fi
    sleep 0.25
  done
  if [[ "$ready" != "1" ]]; then
    echo "pxpipe default service did not become healthy at $BASE_URL" >&2
    echo "See $PXPIPE_STATE_DIR/codex-default.stderr.log" >&2
    exit 1
  fi
fi

if ! "$NODE_BIN" "$CONFIG_TOOL" install --config "$CONFIG_PATH" --state "$MANAGED_STATE" --base-url "$BASE_URL/v1"; then
  "$NODE_BIN" "$CONFIG_TOOL" uninstall --config "$CONFIG_PATH" --state "$MANAGED_STATE" >/dev/null 2>&1 || true
  exit 1
fi

install_in_progress=0
rm -f "$PLIST_TRANSACTION"
echo "pxpipe is now the default provider path for new Codex Local sessions."
echo "Restart Codex Local before opening the first new session."
