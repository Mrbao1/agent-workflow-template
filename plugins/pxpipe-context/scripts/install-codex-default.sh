#!/bin/bash
set -euo pipefail

CALLER_PATH_OVERRIDES=""
for override_name in CODEX_HOME PXPIPE_STATE_DIR LAUNCH_AGENTS_DIR PXPIPE_LAUNCH_LABEL PXPIPE_DASHBOARD_TOKEN_FILE PXPIPE_DIR PXPIPE_NODE PXPIPE_NODE_BIN; do
  if declare -p "$override_name" >/dev/null 2>&1; then CALLER_PATH_OVERRIDES="$CALLER_PATH_OVERRIDES $override_name"; fi
done

PXPIPE_PORT="${PXPIPE_PORT:-47821}"
CODEX_MODEL="${CODEX_MODEL:-}"
PXPIPE_MODELS="${PXPIPE_MODELS:-${CODEX_MODEL:-off}}"
CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
PXPIPE_STATE_DIR="${PXPIPE_STATE_DIR:-$HOME/.pxpipe}"
LAUNCH_AGENTS_DIR="${LAUNCH_AGENTS_DIR:-$HOME/Library/LaunchAgents}"
LAUNCH_LABEL="${PXPIPE_LAUNCH_LABEL:-com.pxpipe.codex-default}"
PLIST_PATH="$LAUNCH_AGENTS_DIR/$LAUNCH_LABEL.plist"
CONFIG_PATH="$CODEX_HOME_DIR/config.toml"
MANAGED_STATE="$PXPIPE_STATE_DIR/codex-default.json"
DASHBOARD_TOKEN_FILE="${PXPIPE_DASHBOARD_TOKEN_FILE:-$PXPIPE_STATE_DIR/dashboard-token}"
BASE_URL="http://127.0.0.1:${PXPIPE_PORT}"
PLIST_ORIGINAL="$PXPIPE_STATE_DIR/codex-default.plist-before"
PLIST_ORIGIN_ABSENT="$PXPIPE_STATE_DIR/codex-default.plist-absent-before"
PLIST_TRANSACTION=""
INSTALL_OWNERSHIP="$PXPIPE_STATE_DIR/codex-default-install.json"
CONFIG_BACKUP_PATH="$MANAGED_STATE.config-before"
CONFIG_TRANSACTION=""
config_transaction_armed=0
if [[ -n "${CALLER_PATH_OVERRIDES// /}" ]]; then
  echo "Caller path overrides are unavailable in production installation:$CALLER_PATH_OVERRIDES" >&2
  exit 1
fi
for name in PXPIPE_TEST_MODE PXPIPE_LIFECYCLE_TEST_ROOT PXPIPE_SKIP_LAUNCHCTL PXPIPE_LAUNCHCTL_BIN PXPIPE_CURL_BIN PXPIPE_LSOF_BIN PXPIPE_ID_BIN; do
  if declare -p "$name" >/dev/null 2>&1; then echo "$name override is unavailable in production installation." >&2; exit 1; fi
done
[[ "$LAUNCH_LABEL" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,126}[A-Za-z0-9]$ ]] || { echo "PXPIPE launch label is invalid." >&2; exit 1; }

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_SOURCE" ]]; do
  SOURCE_DIR="$(cd -P -- "$(/usr/bin/dirname -- "$SCRIPT_SOURCE")" && pwd)"
  LINK_TARGET="$(/usr/bin/readlink "$SCRIPT_SOURCE")"
  [[ "$LINK_TARGET" == /* ]] && SCRIPT_SOURCE="$LINK_TARGET" || SCRIPT_SOURCE="$SOURCE_DIR/$LINK_TARGET"
done
SCRIPT_DIR="$(cd -P -- "$(/usr/bin/dirname -- "$SCRIPT_SOURCE")" && pwd)"
PXPIPE_DIR="${PXPIPE_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
INTEGRITY_TOOL="$SCRIPT_DIR/verify-integrity.mjs"
CONFIG_TOOL="$SCRIPT_DIR/codex-default-config.mjs"

if [[ "$(/usr/bin/uname -s)" != "Darwin" && "${PXPIPE_TEST_MODE:-0}" != "1" ]]; then
  echo "Default Codex installation currently supports macOS launchd only." >&2
  exit 1
fi
if ! [[ "$PXPIPE_PORT" =~ ^[0-9]+$ ]] || (( PXPIPE_PORT < 1024 || PXPIPE_PORT > 65535 )); then
  echo "PXPIPE_PORT must be an integer from 1024 to 65535." >&2
  exit 1
fi

NODE_BIN="${PXPIPE_NODE_BIN:-}"
if [[ -z "$NODE_BIN" ]]; then
  if ! NODE_BIN="$(command -v node 2>/dev/null)"; then NODE_BIN=""; fi
fi
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "An absolute executable Node.js path is required." >&2
  exit 1
fi
NODE_BIN="$(cd -P -- "$(/usr/bin/dirname -- "$NODE_BIN")" && pwd)/$(/usr/bin/basename -- "$NODE_BIN")"
if [[ "${PXPIPE_TEST_MODE:-0}" != "1" ]]; then
  [[ "$NODE_BIN" == /* && ! -L "$NODE_BIN" ]] || { echo "Production Node.js must be one canonical non-symlink executable." >&2; exit 1; }
  protected_component="$NODE_BIN"
  while :; do
    read -r component_owner component_mode < <(/usr/bin/stat -f '%u %Lp' "$protected_component")
    [[ "$component_owner" == "0" && ! -L "$protected_component" ]] || { echo "Production Node.js path must be root-owned and symlink-free: $protected_component" >&2; exit 1; }
    (( (8#$component_mode & 8#22) == 0 )) || { echo "Production Node.js path is group/other writable: $protected_component" >&2; exit 1; }
    [[ "$protected_component" == "/" ]] && break
    protected_component="$(/usr/bin/dirname -- "$protected_component")"
  done
fi
if [[ "${PXPIPE_TEST_MODE:-0}" != "1" ]]; then PATH="/usr/bin:/bin:/usr/sbin:/sbin"; export PATH; fi
"$NODE_BIN" "$INTEGRITY_TOOL"

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
PXPIPE_BUNDLE="$(cd -P -- "$(/usr/bin/dirname -- "$PXPIPE_BUNDLE")" && pwd)/$(/usr/bin/basename -- "$PXPIPE_BUNDLE")"

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
chmod 700 "$PXPIPE_STATE_DIR" "$CODEX_HOME_DIR"

if ! "$NODE_BIN" -e '
  const value = process.argv[1];
  if (value !== "off" && !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}(,[A-Za-z0-9][A-Za-z0-9._:/-]{0,127})*$/.test(value)) process.exit(1);
' "$PXPIPE_MODELS"; then
  echo "PXPIPE_MODELS must be off or a comma-separated list of bounded exact model IDs." >&2
  exit 1
fi
if [[ -e "$INSTALL_OWNERSHIP" || -L "$INSTALL_OWNERSHIP" ]]; then
  echo "An existing pxpipe install must be authenticated and uninstalled before reinstalling." >&2
  exit 1
fi
token_preexisting=0
if [[ -e "$DASHBOARD_TOKEN_FILE" || -L "$DASHBOARD_TOKEN_FILE" ]]; then token_preexisting=1; fi
if [[ "$token_preexisting" == "1" && -n "${PXPIPE_DASHBOARD_TOKEN:-}" ]]; then
  echo "In-place dashboard token rotation is refused; uninstall the authenticated installation first." >&2
  exit 1
fi
token_cleanup_armed=1
cleanup_early_token() {
  local status="$?"
  if [[ "$status" != "0" && "$token_cleanup_armed" == "1" && "$token_preexisting" == "0" ]]; then
    /bin/rm -f -- "$DASHBOARD_TOKEN_FILE"
  fi
  if [[ "$status" != "0" && "${origin_record_created:-0}" == "1" ]]; then /bin/rm -f -- "$PLIST_ORIGINAL" "$PLIST_ORIGIN_ABSENT"; fi
  return "$status"
}
trap cleanup_early_token EXIT
dashboard_token="$("$NODE_BIN" - "$DASHBOARD_TOKEN_FILE" 3<<<"${PXPIPE_DASHBOARD_TOKEN:-}" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const target = process.argv[2];
const supplied = fs.readFileSync(3,"utf8").replace(/\n$/,"");
const parent = path.dirname(target);
const owner = typeof process.getuid === "function" ? process.getuid() : null;
const parentStat = fs.lstatSync(parent);
if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || (owner !== null && parentStat.uid !== owner) || (parentStat.mode & 0o077) !== 0) {
  throw new Error("dashboard token parent must be an owner-only real directory");
}
let existing = null;
try { existing = fs.lstatSync(target); } catch (error) { if (error.code !== "ENOENT") throw error; }
if (supplied && existing !== null) throw new Error("in-place dashboard token rotation is refused");
const flags = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW;
let token = supplied;
if (!token && existing !== null) {
  if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1 || (existing.mode & 0o777) !== 0o600 || (owner !== null && existing.uid !== owner)) {
    throw new Error("existing dashboard token must be an owner-controlled single-link regular file");
  }
  const descriptor = fs.openSync(target, flags);
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== existing.dev || opened.ino !== existing.ino || opened.nlink !== 1 || opened.size > 129) {
      throw new Error("dashboard token changed while opening");
    }
    token = fs.readFileSync(descriptor, "utf8").replace(/\n$/, "");
  } finally { fs.closeSync(descriptor); }
}
if (!token) token = crypto.randomBytes(32).toString("hex");
if (!/^[0-9a-f]{64}$/.test(token)) throw new Error("dashboard token must be exactly 64 lowercase hexadecimal characters");
if (existing === null) {
  let temporary;
  let descriptor;
  try {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      temporary = `${target}.tmp-${crypto.randomBytes(16).toString("hex")}`;
      try {
        descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
        break;
      } catch (error) { if (error.code !== "EEXIST") throw error; }
    }
    if (descriptor === undefined) throw new Error("could not allocate an exclusive dashboard token temporary file");
    fs.writeFileSync(descriptor, `${token}\n`, "utf8");
    fs.fsyncSync(descriptor);
    const staged = fs.fstatSync(descriptor);
    if (!staged.isFile() || staged.nlink !== 1 || (staged.mode & 0o777) !== 0o600 || (owner !== null && staged.uid !== owner)) {
      throw new Error("dashboard token temporary identity is unsafe");
    }
    fs.closeSync(descriptor); descriptor = undefined;
    fs.renameSync(temporary, target); temporary = undefined;
    const parentDescriptor=fs.openSync(parent,fs.constants.O_RDONLY);
    try { fs.fsyncSync(parentDescriptor); } finally { fs.closeSync(parentDescriptor); }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (temporary) { try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== "ENOENT") throw error; } }
  }
}
const final = fs.lstatSync(target);
if (!final.isFile() || final.isSymbolicLink() || final.nlink !== 1 || (final.mode & 0o777) !== 0o600 || (owner !== null && final.uid !== owner)) {
  throw new Error("dashboard token final identity is unsafe");
}
process.stdout.write(token);
NODE
)"

origin_record_created=1
"$NODE_BIN" - "$PLIST_PATH" "$PLIST_ORIGINAL" "$PLIST_ORIGIN_ABSENT" <<'NODE'
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const [source,presentTarget,absentTarget]=process.argv.slice(2),owner=typeof process.getuid==="function"?process.getuid():null;
const parent=path.dirname(presentTarget),parentStat=fs.lstatSync(parent);
if(path.dirname(absentTarget)!==parent||!parentStat.isDirectory()||parentStat.isSymbolicLink()||(owner!==null&&parentStat.uid!==owner)||(parentStat.mode&0o077)!==0)throw new Error("prior plist state parent is unsafe");
for(const target of [presentTarget,absentTarget]){try{fs.lstatSync(target);throw new Error("orphaned prior plist state already exists");}catch(error){if(error.code!=="ENOENT")throw error;}}
let sourceStat=null;try{sourceStat=fs.lstatSync(source);}catch(error){if(error.code!=="ENOENT")throw error;}
let raw=Buffer.alloc(0),target=absentTarget;
if(sourceStat!==null){
  if(!sourceStat.isFile()||sourceStat.isSymbolicLink()||sourceStat.nlink!==1||sourceStat.size>2*1024*1024||(owner!==null&&sourceStat.uid!==owner)||(sourceStat.mode&0o022)!==0)throw new Error("prior plist is unsafe");
  const input=fs.openSync(source,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const opened=fs.fstatSync(input);if(opened.dev!==sourceStat.dev||opened.ino!==sourceStat.ino||opened.nlink!==1)throw new Error("prior plist changed while opening");raw=fs.readFileSync(input);if(raw.length!==opened.size)throw new Error("prior plist changed while reading");}finally{fs.closeSync(input);}target=presentTarget;
}
const temporary=target+".tmp-"+crypto.randomBytes(16).toString("hex");let output;
try{output=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);fs.writeFileSync(output,raw);fs.fsyncSync(output);fs.closeSync(output);output=undefined;fs.renameSync(temporary,target);const parentFd=fs.openSync(parent,fs.constants.O_RDONLY);try{fs.fsyncSync(parentFd);}finally{fs.closeSync(parentFd);}}finally{if(output!==undefined)fs.closeSync(output);try{fs.unlinkSync(temporary);}catch(error){if(error.code!=="ENOENT")throw error;}}
NODE
PLIST_TRANSACTION=""
prior_service_loaded=0
if [[ "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
  if "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1; then prior_service_loaded=1
  elif ! "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN" >/dev/null 2>&1; then
    echo "Cannot prove the prior launchd service state." >&2; exit 1
  fi
fi
prior_plist_present=0
if [[ -e "$PLIST_PATH" ]]; then
  prior_plist_present=1
elif [[ "$prior_service_loaded" == "1" ]]; then
  echo "A loaded prior service has no recoverable plist; refusing installation." >&2; exit 1
fi

PLIST_TEMP="$(/usr/bin/mktemp "$LAUNCH_AGENTS_DIR/.${LAUNCH_LABEL}.plist.XXXXXXXX")"
service_touched=0
managed_plist_installed=0

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
  local failed=0
  if [[ "$service_touched" == "1" && "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
    if "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1; then
      if ! "$LAUNCHCTL_BIN" bootout "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1; then failed=1; fi
    fi
    if "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1; then failed=1; fi
  fi
  if [[ "$failed" == "0" && "$managed_plist_installed" == "1" && ( -e "$PLIST_PATH" || -L "$PLIST_PATH" ) ]]; then
    if [[ -f "$PLIST_PATH" && ! -L "$PLIST_PATH" ]]; then rm -- "$PLIST_PATH" || failed=1; else failed=1; fi
  fi
  if [[ "$failed" == "0" && -n "$PLIST_TRANSACTION" ]]; then
    if [[ -f "$PLIST_TRANSACTION" && ! -L "$PLIST_TRANSACTION" && ! -e "$PLIST_PATH" && ! -L "$PLIST_PATH" ]]; then
      mv -- "$PLIST_TRANSACTION" "$PLIST_PATH" || failed=1
      if [[ "$failed" == "0" ]]; then PLIST_TRANSACTION=""; fi
    else failed=1; fi
  fi
  if [[ "$failed" == "0" && "$prior_service_loaded" == "1" && "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
    if ! bootstrap_plist "$PLIST_PATH" >/dev/null 2>&1; then failed=1
    elif ! "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1; then failed=1; fi
  fi
  [[ "$failed" == "0" ]]
}

begin_config_transaction() {
  CONFIG_TRANSACTION="$("$NODE_BIN" - "$PXPIPE_STATE_DIR" "$CONFIG_PATH" "$MANAGED_STATE" "$CONFIG_BACKUP_PATH" <<'NODE'
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const [journalParent,...targets]=process.argv.slice(2),owner=typeof process.getuid==="function"?process.getuid():null;
const MAX=2*1024*1024;
function parentOk(target){const parent=path.dirname(target),s=fs.lstatSync(parent);if(!s.isDirectory()||s.isSymbolicLink()||(owner!==null&&s.uid!==owner)||(s.mode&0o077)!==0)throw new Error("config transaction parent is unsafe: "+parent);return parent;}
function snapshot(target){parentOk(target);let before;try{before=fs.lstatSync(target);}catch(error){if(error.code==="ENOENT")return {path:target,kind:"absent"};throw error;}if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.size>MAX||(before.mode&0o777)!==0o600||(owner!==null&&before.uid!==owner))throw new Error("config transaction source is unsafe: "+target);const fd=fs.openSync(target,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const opened=fs.fstatSync(fd);if(opened.dev!==before.dev||opened.ino!==before.ino||opened.nlink!==1||opened.size!==before.size||(opened.mode&0o777)!==0o600)throw new Error("config transaction source changed while opening: "+target);const raw=fs.readFileSync(fd);if(raw.length!==opened.size)throw new Error("config transaction source changed while reading: "+target);return {path:target,kind:"present",mode:0o600,bytes:raw.length,sha256:crypto.createHash("sha256").update(raw).digest("hex"),content:raw.toString("base64")};}finally{fs.closeSync(fd);}}
const parent=parentOk(path.join(journalParent,"placeholder"));if(path.resolve(parent)!==path.resolve(journalParent)||new Set(targets).size!==3)throw new Error("config transaction paths are invalid");
const payload=Buffer.from(JSON.stringify({schema:"pxpipe-config-install-transaction/v1",entries:targets.map(snapshot)})+"\n");
let journal,fd;for(let attempt=0;attempt<8;attempt++){journal=path.join(parent,".codex-default-config-transaction."+crypto.randomBytes(16).toString("hex"));try{fd=fs.openSync(journal,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);break;}catch(error){if(error.code!=="EEXIST")throw error;}}if(fd===undefined)throw new Error("could not allocate config transaction journal");
try{fs.writeFileSync(fd,payload);fs.fchmodSync(fd,0o600);fs.fsyncSync(fd);const staged=fs.fstatSync(fd);if(!staged.isFile()||staged.nlink!==1||(staged.mode&0o777)!==0o600||(owner!==null&&staged.uid!==owner))throw new Error("config transaction journal is unsafe");fs.closeSync(fd);fd=undefined;const parentFd=fs.openSync(parent,fs.constants.O_RDONLY);try{fs.fsyncSync(parentFd);}finally{fs.closeSync(parentFd);}process.stdout.write(journal);}catch(error){if(fd!==undefined)fs.closeSync(fd);try{if(journal)fs.unlinkSync(journal);}catch(cleanupError){if(cleanupError.code!=="ENOENT")throw cleanupError;}throw error;}
NODE
)"
  config_transaction_armed=1
}

finish_config_transaction() {
  local action="$1"
  if "$NODE_BIN" - "$action" "$CONFIG_TRANSACTION" "$CONFIG_PATH" "$MANAGED_STATE" "$CONFIG_BACKUP_PATH" <<'NODE'
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const [action,journal,...targets]=process.argv.slice(2),owner=typeof process.getuid==="function"?process.getuid():null,MAX=2*1024*1024;
if(!["restore","discard"].includes(action)||!path.isAbsolute(journal)||new Set(targets).size!==3)throw new Error("config transaction request is invalid");
function privateParent(target){const parent=path.dirname(target),s=fs.lstatSync(parent);if(!s.isDirectory()||s.isSymbolicLink()||(owner!==null&&s.uid!==owner)||(s.mode&0o077)!==0)throw new Error("config transaction parent is unsafe: "+parent);return parent;}
function readSafe(target,label,allowMissing=false,max=MAX){let before;try{before=fs.lstatSync(target);}catch(error){if(allowMissing&&error.code==="ENOENT")return null;throw error;}if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.size>max||(before.mode&0o777)!==0o600||(owner!==null&&before.uid!==owner))throw new Error(label+" is unsafe");const fd=fs.openSync(target,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const opened=fs.fstatSync(fd);if(opened.dev!==before.dev||opened.ino!==before.ino||opened.nlink!==1||opened.size!==before.size||(opened.mode&0o777)!==0o600)throw new Error(label+" changed while opening");const raw=fs.readFileSync(fd);if(raw.length!==opened.size)throw new Error(label+" changed while reading");return {raw,dev:opened.dev,ino:opened.ino};}finally{fs.closeSync(fd);}}
privateParent(journal);const journalSnapshot=readSafe(journal,"config transaction journal",false,8*1024*1024);let value;try{value=JSON.parse(journalSnapshot.raw.toString("utf8"));}catch{throw new Error("config transaction journal is invalid JSON");}
if(!value||Array.isArray(value)||JSON.stringify(Object.keys(value).sort())!==JSON.stringify(["entries","schema"])||value.schema!=="pxpipe-config-install-transaction/v1"||!Array.isArray(value.entries)||value.entries.length!==3)throw new Error("config transaction journal shape is invalid");
const entries=value.entries.map((entry,index)=>{if(!entry||Array.isArray(entry)||entry.path!==targets[index]||!path.isAbsolute(entry.path))throw new Error("config transaction path binding is invalid");if(entry.kind==="absent"){if(JSON.stringify(Object.keys(entry).sort())!==JSON.stringify(["kind","path"]))throw new Error("config transaction absence record is invalid");return {...entry,raw:null};}if(entry.kind!=="present"||JSON.stringify(Object.keys(entry).sort())!==JSON.stringify(["bytes","content","kind","mode","path","sha256"])||entry.mode!==0o600||!Number.isSafeInteger(entry.bytes)||entry.bytes<0||entry.bytes>MAX||!/^[0-9a-f]{64}$/.test(entry.sha256)||typeof entry.content!=="string")throw new Error("config transaction preimage is invalid");const raw=Buffer.from(entry.content,"base64");if(raw.length!==entry.bytes||raw.toString("base64")!==entry.content||crypto.createHash("sha256").update(raw).digest("hex")!==entry.sha256)throw new Error("config transaction preimage digest is invalid");return {...entry,raw};});
function syncParent(target){const fd=fs.openSync(path.dirname(target),fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function atomicWrite(target,raw){const parent=privateParent(target);const current=readSafe(target,"config transaction target",true);const temporary=path.join(parent,".pxpipe-restore-"+crypto.randomBytes(16).toString("hex"));let fd;try{fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);fs.writeFileSync(fd,raw);fs.fchmodSync(fd,0o600);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;fs.renameSync(temporary,target);syncParent(target);}finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temporary);}catch(error){if(error.code!=="ENOENT")throw error;}}void current;}
if(action==="restore"){for(const entry of entries){privateParent(entry.path);const current=readSafe(entry.path,"config transaction target",true);if(entry.raw===null){if(current!==null){fs.unlinkSync(entry.path);syncParent(entry.path);}}else atomicWrite(entry.path,entry.raw);}for(const entry of entries){const final=readSafe(entry.path,"restored config transaction target",true);if(entry.raw===null?final!==null:final===null||!final.raw.equals(entry.raw))throw new Error("config transaction restoration did not reproduce the preimage");}}
const currentJournal=readSafe(journal,"config transaction journal",false,8*1024*1024);if(currentJournal.dev!==journalSnapshot.dev||currentJournal.ino!==journalSnapshot.ino||!currentJournal.raw.equals(journalSnapshot.raw))throw new Error("config transaction journal changed before completion");fs.unlinkSync(journal);syncParent(journal);
NODE
  then
    CONFIG_TRANSACTION=""
    config_transaction_armed=0
    return 0
  fi
  return 1
}

install_in_progress=1
on_exit() {
  local status="$?" cleanup_failed=0
  trap - EXIT
  if [[ -e "$PLIST_TEMP" || -L "$PLIST_TEMP" ]]; then rm -- "$PLIST_TEMP" || cleanup_failed=1; fi
  if [[ "$status" != "0" && "$install_in_progress" == "1" ]]; then
    if ! rollback_install; then
      echo "pxpipe install recovery incomplete; exact predecessor and managed artifacts were preserved." >&2
      cleanup_failed=1
    fi
    if [[ "$config_transaction_armed" == "1" ]] && ! finish_config_transaction restore; then
      echo "pxpipe config/state recovery incomplete; exact preimage journal was preserved." >&2
      cleanup_failed=1
    fi
    if [[ "$cleanup_failed" == "0" ]]; then
      if [[ -e "$INSTALL_OWNERSHIP" || -L "$INSTALL_OWNERSHIP" ]]; then /bin/rm -- "$INSTALL_OWNERSHIP" || cleanup_failed=1; fi
      if [[ "$token_cleanup_armed" == "1" && "$token_preexisting" == "0" && ( -e "$DASHBOARD_TOKEN_FILE" || -L "$DASHBOARD_TOKEN_FILE" ) ]]; then /bin/rm -- "$DASHBOARD_TOKEN_FILE" || cleanup_failed=1; fi
      if [[ "$origin_record_created" == "1" ]]; then
        for artifact in "$PLIST_ORIGINAL" "$PLIST_ORIGIN_ABSENT"; do if [[ -e "$artifact" || -L "$artifact" ]]; then rm -- "$artifact" || cleanup_failed=1; fi; done
      fi
    fi
  elif [[ -n "$PLIST_TRANSACTION" && ( -e "$PLIST_TRANSACTION" || -L "$PLIST_TRANSACTION" ) ]]; then
    rm -- "$PLIST_TRANSACTION" || cleanup_failed=1
  fi
  if [[ "$cleanup_failed" != "0" ]]; then echo "pxpipe install cleanup incomplete; recovery evidence was preserved." >&2; exit 75; fi
  exit "$status"
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
  printf '    <key>PXPIPE_DASHBOARD_TOKEN</key><string>%s</string>\n' "$(xml_escape "$dashboard_token")"
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
if [[ "$prior_plist_present" == "1" ]]; then
  read -r prior_links prior_owner prior_mode < <(/usr/bin/stat -f '%l %u %Lp' "$PLIST_PATH")
  [[ -f "$PLIST_PATH" && ! -L "$PLIST_PATH" && "$prior_links" == "1" && "$prior_owner" == "$($ID_BIN -u)" ]] || { echo "Prior plist identity changed before replacement." >&2; exit 1; }
  (( (8#$prior_mode & 8#22) == 0 )) || { echo "Prior plist permissions changed before replacement." >&2; exit 1; }
  PLIST_TRANSACTION="$(/usr/bin/mktemp "$PXPIPE_STATE_DIR/.codex-default.plist-transaction.XXXXXXXX")"
  rm -- "$PLIST_TRANSACTION"
  mv -- "$PLIST_PATH" "$PLIST_TRANSACTION"
  /usr/bin/cmp -s -- "$PLIST_TRANSACTION" "$PLIST_ORIGINAL" || { echo "Prior plist bytes changed after authenticated capture." >&2; exit 1; }
fi
mv "$PLIST_TEMP" "$PLIST_PATH"
managed_plist_installed=1

if [[ "${PXPIPE_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
  service_touched=1
  if "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1; then
    "$LAUNCHCTL_BIN" bootout "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1
  elif ! "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN" >/dev/null 2>&1; then
    echo "Cannot prove launchd domain availability before replacement." >&2; exit 1
  fi
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

"$NODE_BIN" - "$INSTALL_OWNERSHIP" "$DASHBOARD_TOKEN_FILE" "$PLIST_PATH" "$LAUNCH_LABEL" "$PLIST_ORIGINAL" "$PLIST_ORIGIN_ABSENT" <<'NODE'
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const [statePath,tokenPath,plistPath,label,priorPresent,priorAbsent]=process.argv.slice(2);
const owner=typeof process.getuid==="function"?process.getuid():null;
function ownedFile(target,mode){
  const before=fs.lstatSync(target);
  if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||(before.mode&0o777)!==mode||(owner!==null&&before.uid!==owner)) throw new Error("managed install artifact is unsafe");
  const fd=fs.openSync(target,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try{const opened=fs.fstatSync(fd);if(opened.dev!==before.dev||opened.ino!==before.ino||opened.nlink!==1)throw new Error("managed install artifact changed while opening");const raw=fs.readFileSync(fd);return {path:path.resolve(target),dev:opened.dev,ino:opened.ino,bytes:raw.length,sha256:crypto.createHash("sha256").update(raw).digest("hex")};}finally{fs.closeSync(fd);}
}
const present=fs.existsSync(priorPresent),absent=fs.existsSync(priorAbsent);
if(present===absent)throw new Error("exactly one prior plist state artifact is required");
const prior_plist=present?{kind:"present",artifact:ownedFile(priorPresent,0o600)}:{kind:"absent",artifact:ownedFile(priorAbsent,0o600)};
const payload={schema:"pxpipe-codex-default-install/v2",label,token:ownedFile(tokenPath,0o600),plist:ownedFile(plistPath,0o600),prior_plist};
const raw=Buffer.from(JSON.stringify(payload)+"\n");
const parent=path.dirname(statePath),parentStat=fs.lstatSync(parent);
if(!parentStat.isDirectory()||parentStat.isSymbolicLink()||(owner!==null&&parentStat.uid!==owner)||(parentStat.mode&0o077)!==0)throw new Error("install ownership parent is unsafe");
try{fs.lstatSync(statePath);throw new Error("install ownership state already exists");}catch(error){if(error.code!=="ENOENT")throw error;}
const temporary=statePath+".tmp-"+crypto.randomBytes(16).toString("hex");let fd;
try{
  fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  fs.writeFileSync(fd,raw);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;fs.renameSync(temporary,statePath);
  const parentFd=fs.openSync(parent,fs.constants.O_RDONLY);try{fs.fsyncSync(parentFd);}finally{fs.closeSync(parentFd);}
}finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temporary);}catch(error){if(error.code!=="ENOENT")throw error;}}
NODE

begin_config_transaction
"$NODE_BIN" "$CONFIG_TOOL" install --config "$CONFIG_PATH" --state "$MANAGED_STATE" --base-url "$BASE_URL/v1"
if [[ -n "$PLIST_TRANSACTION" ]]; then rm -- "$PLIST_TRANSACTION"; PLIST_TRANSACTION=""; fi
finish_config_transaction discard
install_in_progress=0
token_cleanup_armed=0
echo "pxpipe is now the default provider path for new Codex Local sessions."
echo "Authenticated dashboard token stored at $DASHBOARD_TOKEN_FILE (mode 0600)."
echo "Restart Codex Local before opening the first new session."
