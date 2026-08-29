#!/bin/bash
set -euo pipefail

CALLER_PATH_OVERRIDES=""
for override_name in CODEX_HOME PXPIPE_STATE_DIR LAUNCH_AGENTS_DIR PXPIPE_LAUNCH_LABEL PXPIPE_DASHBOARD_TOKEN_FILE PXPIPE_NODE_BIN; do
  if declare -p "$override_name" >/dev/null 2>&1; then CALLER_PATH_OVERRIDES="$CALLER_PATH_OVERRIDES $override_name"; fi
done

PXPIPE_PORT="${PXPIPE_PORT:-47821}"
CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
PXPIPE_STATE_DIR="${PXPIPE_STATE_DIR:-$HOME/.pxpipe}"
LAUNCH_AGENTS_DIR="${LAUNCH_AGENTS_DIR:-$HOME/Library/LaunchAgents}"
DASHBOARD_TOKEN_FILE="${PXPIPE_DASHBOARD_TOKEN_FILE:-$PXPIPE_STATE_DIR/dashboard-token}"
LAUNCH_LABEL="${PXPIPE_LAUNCH_LABEL:-com.pxpipe.codex-default}"
INSTALL_OWNERSHIP="$PXPIPE_STATE_DIR/codex-default-install.json"
PLIST_PATH="$LAUNCH_AGENTS_DIR/$LAUNCH_LABEL.plist"
PLIST_ORIGINAL="$PXPIPE_STATE_DIR/codex-default.plist-before"
PLIST_ORIGIN_ABSENT="$PXPIPE_STATE_DIR/codex-default.plist-absent-before"
if [[ -n "${CALLER_PATH_OVERRIDES// /}" ]]; then
  echo "Caller path overrides are unavailable in production status:$CALLER_PATH_OVERRIDES" >&2
  exit 1
fi
for name in PXPIPE_TEST_MODE PXPIPE_LIFECYCLE_TEST_ROOT PXPIPE_LAUNCHCTL_BIN PXPIPE_CURL_BIN PXPIPE_ID_BIN PXPIPE_SKIP_LAUNCHCTL; do
  if declare -p "$name" >/dev/null 2>&1; then echo "$name override is unavailable in production status." >&2; exit 1; fi
done
[[ "$LAUNCH_LABEL" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,126}[A-Za-z0-9]$ ]] || { echo "PXPIPE launch label is invalid." >&2; exit 1; }
stat_owner_mode() {
  local target="$1"
  if [[ "$(/usr/bin/uname -s)" == "Darwin" ]]; then
    /usr/bin/stat -f '%u %Lp' "$target"
  else
    /usr/bin/stat -c '%u %a' "$target"
  fi
}
SCRIPT_DIR="$(cd -P -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${PXPIPE_NODE_BIN:-$(command -v node 2>/dev/null || true)}"
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "Node.js is required to inspect the default service." >&2
  exit 1
fi
NODE_BIN="$(cd -P -- "$(/usr/bin/dirname -- "$NODE_BIN")" && pwd)/$(/usr/bin/basename -- "$NODE_BIN")"
if [[ "${PXPIPE_TEST_MODE:-0}" != "1" ]]; then
  [[ "$NODE_BIN" == /* && ! -L "$NODE_BIN" ]] || { echo "Production Node.js must be one canonical non-symlink executable." >&2; exit 1; }
  protected_component="$NODE_BIN"
  while :; do
    read -r component_owner component_mode < <(stat_owner_mode "$protected_component")
    [[ "$component_owner" == "0" && ! -L "$protected_component" ]] || { echo "Production Node.js path must be root-owned and symlink-free: $protected_component" >&2; exit 1; }
    (( (8#$component_mode & 8#22) == 0 )) || { echo "Production Node.js path is group/other writable: $protected_component" >&2; exit 1; }
    [[ "$protected_component" == "/" ]] && break
    protected_component="$(/usr/bin/dirname -- "$protected_component")"
  done
fi
if [[ "${PXPIPE_TEST_MODE:-0}" != "1" ]]; then PATH="/usr/bin:/bin:/usr/sbin:/sbin"; export PATH; fi
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

verify_install_ownership() {
  "$NODE_BIN" - "$INSTALL_OWNERSHIP" "$DASHBOARD_TOKEN_FILE" "$PLIST_PATH" "$LAUNCH_LABEL" "$PLIST_ORIGINAL" "$PLIST_ORIGIN_ABSENT" <<'NODE'
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const [statePath,tokenPath,plistPath,label,priorPresent,priorAbsent]=process.argv.slice(2),owner=typeof process.getuid==="function"?process.getuid():null;
function snapshot(target,expected){const before=fs.lstatSync(target);if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||(before.mode&0o777)!==0o600||(owner!==null&&before.uid!==owner))throw new Error("managed artifact is unsafe");const fd=fs.openSync(target,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const opened=fs.fstatSync(fd),raw=fs.readFileSync(fd),value={path:path.resolve(target),dev:opened.dev,ino:opened.ino,bytes:raw.length,sha256:crypto.createHash("sha256").update(raw).digest("hex")};if(opened.dev!==before.dev||opened.ino!==before.ino||opened.nlink!==1)throw new Error("managed artifact changed while opening");if(expected&&(!expected||Object.keys(expected).sort().join(",")!=="bytes,dev,ino,path,sha256"||Object.keys(value).some(k=>value[k]!==expected[k])))throw new Error("managed artifact no longer matches authenticated install ownership");return raw;}finally{fs.closeSync(fd);}}
const state=snapshot(statePath);let value;try{value=JSON.parse(state);}catch{throw new Error("install ownership state is invalid JSON");}
if(!value||value.schema!=="pxpipe-codex-default-install/v2"||value.label!==label||Object.keys(value).sort().join(",")!=="label,plist,prior_plist,schema,token")throw new Error("install ownership state is invalid");
if(!value.prior_plist||Object.keys(value.prior_plist).sort().join(",")!=="artifact,kind"||!["present","absent"].includes(value.prior_plist.kind))throw new Error("prior plist ownership state is invalid");
function requireMissing(target){try{fs.lstatSync(target);throw new Error("unexpected prior plist artifact exists");}catch(error){if(error.code!=="ENOENT")throw error;}}
snapshot(tokenPath,value.token);snapshot(plistPath,value.plist);
if(value.prior_plist.kind==="present"){snapshot(priorPresent,value.prior_plist.artifact);requireMissing(priorAbsent);}else{snapshot(priorAbsent,value.prior_plist.artifact);requireMissing(priorPresent);}
NODE
}
verify_install_ownership

"$NODE_BIN" "$SCRIPT_DIR/codex-default-config.mjs" status \
  --config "$CODEX_HOME_DIR/config.toml" \
  --state "$PXPIPE_STATE_DIR/codex-default.json"
"$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null
if [[ -L "$DASHBOARD_TOKEN_FILE" || ! -f "$DASHBOARD_TOKEN_FILE" ]]; then
  echo "Managed dashboard token is missing or unsafe: $DASHBOARD_TOKEN_FILE" >&2
  exit 1
fi
IFS= read -r dashboard_token <"$DASHBOARD_TOKEN_FILE"
if ! printf '%s' "$dashboard_token" | "$NODE_BIN" -e 'let value="";process.stdin.setEncoding("utf8");process.stdin.on("data",chunk=>value+=chunk);process.stdin.on("end",()=>process.exit(/^[0-9a-f]{64}$/.test(value)?0:1));'; then
  echo "Managed dashboard token is malformed." >&2
  exit 1
fi
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
dashboard_status="$(printf 'user = "pxpipe:%s"\n' "$dashboard_token" | "$CURL_BIN" --config - -sS -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:${PXPIPE_PORT}/")"
[[ "$dashboard_status" == "200" ]] || { echo "Authenticated dashboard check failed: HTTP $dashboard_status" >&2; exit 1; }
echo "LaunchAgent loaded: $LAUNCH_LABEL"
echo "pxpipe healthy with authenticated dashboard: http://127.0.0.1:${PXPIPE_PORT}"
