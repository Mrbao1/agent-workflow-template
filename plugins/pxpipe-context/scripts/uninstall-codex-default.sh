#!/usr/bin/env bash
set -euo pipefail

PXPIPE_PORT="${PXPIPE_PORT:-47821}"
CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
PXPIPE_STATE_DIR="${PXPIPE_STATE_DIR:-$HOME/.pxpipe}"
LAUNCH_AGENTS_DIR="${LAUNCH_AGENTS_DIR:-$HOME/Library/LaunchAgents}"
LAUNCH_LABEL="${PXPIPE_LAUNCH_LABEL:-com.pxpipe.codex-default}"
PLIST_PATH="$LAUNCH_AGENTS_DIR/$LAUNCH_LABEL.plist"
PLIST_ORIGINAL="$PXPIPE_STATE_DIR/codex-default.plist-before"
PLIST_ORIGIN_ABSENT="$PXPIPE_STATE_DIR/codex-default.plist-absent-before"

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_SOURCE" ]]; do
  SOURCE_DIR="$(cd -P -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
  LINK_TARGET="$(readlink "$SCRIPT_SOURCE")"
  [[ "$LINK_TARGET" == /* ]] && SCRIPT_SOURCE="$LINK_TARGET" || SCRIPT_SOURCE="$SOURCE_DIR/$LINK_TARGET"
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
NODE_BIN="${PXPIPE_NODE_BIN:-$(command -v node 2>/dev/null || true)}"
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "Node.js is required to restore the Codex configuration." >&2
  exit 1
fi
NODE_BIN="$(cd -P -- "$(dirname -- "$NODE_BIN")" && pwd)/$(basename -- "$NODE_BIN")"
if [[ "${PXPIPE_TEST_MODE:-0}" == "1" ]]; then
  LAUNCHCTL_BIN="${PXPIPE_LAUNCHCTL_BIN:-/bin/launchctl}"
  ID_BIN="${PXPIPE_ID_BIN:-/usr/bin/id}"
else
  LAUNCHCTL_BIN="/bin/launchctl"
  ID_BIN="/usr/bin/id"
fi
if [[ ! -x "$LAUNCHCTL_BIN" || ! -x "$ID_BIN" ]]; then
  echo "Absolute launchctl/id executables are required for rollback." >&2
  exit 1
fi
LAUNCH_DOMAIN="gui/$($ID_BIN -u)"

"$NODE_BIN" "$SCRIPT_DIR/codex-default-config.mjs" uninstall \
  --config "$CODEX_HOME_DIR/config.toml" \
  --state "$PXPIPE_STATE_DIR/codex-default.json"

if [[ "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
  "$LAUNCHCTL_BIN" bootout "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1 || true
fi
rm -f "$PLIST_PATH"
if [[ -f "$PLIST_ORIGINAL" ]]; then
  cp "$PLIST_ORIGINAL" "$PLIST_PATH"
  chmod 600 "$PLIST_PATH"
  if [[ "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
    "$LAUNCHCTL_BIN" bootstrap "$LAUNCH_DOMAIN" "$PLIST_PATH"
  fi
fi
rm -f "$PLIST_ORIGINAL" "$PLIST_ORIGIN_ABSENT"
echo "pxpipe default Codex service removed. Existing pxpipe logs were preserved."
