#!/usr/bin/env bash
set -euo pipefail

PXPIPE_PORT="${PXPIPE_PORT:-47821}"
CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
PXPIPE_STATE_DIR="${PXPIPE_STATE_DIR:-$HOME/.pxpipe}"
LAUNCH_LABEL="${PXPIPE_LAUNCH_LABEL:-com.pxpipe.codex-default}"
SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${PXPIPE_NODE_BIN:-$(command -v node 2>/dev/null || true)}"
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "Node.js is required to inspect the default service." >&2
  exit 1
fi
NODE_BIN="$(cd -P -- "$(dirname -- "$NODE_BIN")" && pwd)/$(basename -- "$NODE_BIN")"
if [[ "${PXPIPE_TEST_MODE:-0}" == "1" ]]; then
  LAUNCHCTL_BIN="${PXPIPE_LAUNCHCTL_BIN:-/bin/launchctl}"
  CURL_BIN="${PXPIPE_CURL_BIN:-/usr/bin/curl}"
  ID_BIN="${PXPIPE_ID_BIN:-/usr/bin/id}"
else
  LAUNCHCTL_BIN="/bin/launchctl"
  CURL_BIN="/usr/bin/curl"
  ID_BIN="/usr/bin/id"
fi
for executable in "$LAUNCHCTL_BIN" "$CURL_BIN" "$ID_BIN"; do
  [[ -x "$executable" ]] || { echo "Required absolute executable is missing: $executable" >&2; exit 1; }
done
LAUNCH_DOMAIN="gui/$($ID_BIN -u)"

"$NODE_BIN" "$SCRIPT_DIR/codex-default-config.mjs" status \
  --config "$CODEX_HOME_DIR/config.toml" \
  --state "$PXPIPE_STATE_DIR/codex-default.json"
"$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null
payload="$($CURL_BIN -fsS --max-time 2 "http://127.0.0.1:${PXPIPE_PORT}/proxy-stats")"
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
' >/dev/null
echo "LaunchAgent loaded: $LAUNCH_LABEL"
echo "pxpipe healthy: http://127.0.0.1:${PXPIPE_PORT}"
