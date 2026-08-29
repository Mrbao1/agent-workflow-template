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
LAUNCH_LABEL="${PXPIPE_LAUNCH_LABEL:-com.pxpipe.codex-default}"
PLIST_PATH="$LAUNCH_AGENTS_DIR/$LAUNCH_LABEL.plist"
PLIST_ORIGINAL="$PXPIPE_STATE_DIR/codex-default.plist-before"
PLIST_ORIGIN_ABSENT="$PXPIPE_STATE_DIR/codex-default.plist-absent-before"
DASHBOARD_TOKEN_FILE="${PXPIPE_DASHBOARD_TOKEN_FILE:-$PXPIPE_STATE_DIR/dashboard-token}"
INSTALL_OWNERSHIP="$PXPIPE_STATE_DIR/codex-default-install.json"
TOKEN_STAGED="$DASHBOARD_TOKEN_FILE.pxpipe-uninstall-staged"
PLIST_STAGED="$PLIST_PATH.pxpipe-uninstall-staged"
OWNERSHIP_STAGED="$INSTALL_OWNERSHIP.pxpipe-uninstall-staged"
PRIOR_PRESENT_STAGED="$PLIST_ORIGINAL.pxpipe-uninstall-staged"
PRIOR_ABSENT_STAGED="$PLIST_ORIGIN_ABSENT.pxpipe-uninstall-staged"
RECOVERY_JOURNAL="$PXPIPE_STATE_DIR/codex-default-uninstall-recovery.json"
RECOVERY_EXIT=75
UNINSTALL_MODE="uninstall"
case "${1:-}" in
  "") ;;
  --recover) UNINSTALL_MODE="recover" ;;
  *) echo "Usage: $0 [--recover]" >&2; exit 64 ;;
esac
if [[ $# -gt 1 ]]; then echo "Usage: $0 [--recover]" >&2; exit 64; fi
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_SOURCE" ]]; do
  SOURCE_DIR="$(cd -P -- "$(/usr/bin/dirname -- "$SCRIPT_SOURCE")" && pwd)"
  LINK_TARGET="$(/usr/bin/readlink "$SCRIPT_SOURCE")"
  [[ "$LINK_TARGET" == /* ]] && SCRIPT_SOURCE="$LINK_TARGET" || SCRIPT_SOURCE="$SOURCE_DIR/$LINK_TARGET"
done
SCRIPT_DIR="$(cd -P -- "$(/usr/bin/dirname -- "$SCRIPT_SOURCE")" && pwd)"
if [[ "${PXPIPE_TEST_MODE:-0}" == "1" ]]; then
  [[ -n "${PXPIPE_LIFECYCLE_TEST_ROOT:-}" && "$PXPIPE_LIFECYCLE_TEST_ROOT" == /* ]] || { echo "test mode requires an absolute isolated PXPIPE_LIFECYCLE_TEST_ROOT." >&2; exit 1; }
  TEST_ROOT="$(cd -P -- "$PXPIPE_LIFECYCLE_TEST_ROOT" && pwd)"
  if [[ "$(/usr/bin/uname -s)" == "Darwin" ]]; then SYSTEM_TEMP_RAW="$(/usr/bin/getconf DARWIN_USER_TEMP_DIR)"; else SYSTEM_TEMP_RAW="/tmp"; fi
  SYSTEM_TEMP="$(cd -P -- "$SYSTEM_TEMP_RAW" && pwd)"
  [[ "$TEST_ROOT" == "$SYSTEM_TEMP"/pxpipe-lifecycle-fixture-* && -O "$TEST_ROOT" && ! -L "$TEST_ROOT" ]] || { echo "test root is not an owner-controlled system-temporary fixture." >&2; exit 1; }
  [[ "$SCRIPT_DIR" == "$TEST_ROOT/scripts" ]] || { echo "test mode is allowed only from an isolated copied fixture." >&2; exit 1; }
  for name in CODEX_HOME PXPIPE_STATE_DIR LAUNCH_AGENTS_DIR PXPIPE_DASHBOARD_TOKEN_FILE PXPIPE_LAUNCHCTL_BIN PXPIPE_LSOF_BIN PXPIPE_PS_BIN; do
    declare -p "$name" >/dev/null 2>&1 || { echo "test fixture omitted $name." >&2; exit 1; }
    value="${!name}"
    canonical_value="$(cd -P -- "$(/usr/bin/dirname -- "$value")" && pwd)/$(/usr/bin/basename -- "$value")"
    [[ "$canonical_value" == "$TEST_ROOT"/* ]] || { echo "test fixture path escapes PXPIPE_LIFECYCLE_TEST_ROOT: $name" >&2; exit 1; }
  done
  for name in PXPIPE_SKIP_LAUNCHCTL PXPIPE_ID_BIN; do
    if declare -p "$name" >/dev/null 2>&1; then echo "$name is never permitted." >&2; exit 1; fi
  done
else
  if [[ -n "${CALLER_PATH_OVERRIDES// /}" ]]; then
    echo "Caller path overrides are unavailable in production uninstall:$CALLER_PATH_OVERRIDES" >&2
    exit 1
  fi
  for name in PXPIPE_TEST_MODE PXPIPE_LIFECYCLE_TEST_ROOT PXPIPE_LAUNCHCTL_BIN PXPIPE_LSOF_BIN PXPIPE_PS_BIN PXPIPE_ID_BIN PXPIPE_SKIP_LAUNCHCTL; do
    if declare -p "$name" >/dev/null 2>&1; then echo "$name override is unavailable in production uninstall." >&2; exit 1; fi
  done
fi
[[ "$LAUNCH_LABEL" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,126}[A-Za-z0-9]$ ]] || { echo "PXPIPE launch label is invalid." >&2; exit 1; }
stat_owner_mode() {
  local target="$1"
  if [[ "$(/usr/bin/uname -s)" == "Darwin" ]]; then
    /usr/bin/stat -f '%u %Lp' "$target"
  else
    /usr/bin/stat -c '%u %a' "$target"
  fi
}
stat_links_owner_mode() {
  local target="$1"
  if [[ "$(/usr/bin/uname -s)" == "Darwin" ]]; then
    /usr/bin/stat -f '%l %u %Lp' "$target"
  else
    /usr/bin/stat -c '%h %u %a' "$target"
  fi
}
NODE_BIN="${PXPIPE_NODE_BIN:-}"
if [[ -z "$NODE_BIN" ]]; then
  if ! NODE_BIN="$(command -v node 2>/dev/null)"; then NODE_BIN=""; fi
fi
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "Node.js is required to restore the Codex configuration." >&2
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
  LSOF_BIN="${PXPIPE_LSOF_BIN:-/usr/sbin/lsof}"
  PS_BIN="${PXPIPE_PS_BIN:-/bin/ps}"
  ID_BIN="${PXPIPE_ID_BIN:-/usr/bin/id}"
else
  LAUNCHCTL_BIN="/bin/launchctl"
  LSOF_BIN="/usr/sbin/lsof"
  PS_BIN="/bin/ps"
  ID_BIN="/usr/bin/id"
fi
if [[ ! -x "$LAUNCHCTL_BIN" || ! -x "$LSOF_BIN" || ! -x "$PS_BIN" || ! -x "$ID_BIN" ]]; then
  echo "Absolute launchctl/lsof/ps/id executables are required for rollback." >&2
  exit 1
fi
LAUNCH_DOMAIN="gui/$($ID_BIN -u)"

verify_install_ownership() {
  local operation="$1"
  "$NODE_BIN" - "$operation" "$INSTALL_OWNERSHIP" "$DASHBOARD_TOKEN_FILE" "$PLIST_PATH" "$LAUNCH_LABEL" "$TOKEN_STAGED" "$PLIST_STAGED" "$OWNERSHIP_STAGED" "$PLIST_ORIGINAL" "$PLIST_ORIGIN_ABSENT" "$PRIOR_PRESENT_STAGED" "$PRIOR_ABSENT_STAGED" <<'NODE'
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const [operation,statePath,tokenPath,plistPath,label,tokenStaged,plistStaged,stateStaged,priorPresent,priorAbsent,priorPresentStaged,priorAbsentStaged]=process.argv.slice(2);const owner=typeof process.getuid==="function"?process.getuid():null;
function snapshot(target,expected,logical=target){const before=fs.lstatSync(target);if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||(before.mode&0o777)!==0o600||(owner!==null&&before.uid!==owner))throw new Error("managed artifact is unsafe");const fd=fs.openSync(target,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const opened=fs.fstatSync(fd),raw=fs.readFileSync(fd);if(opened.dev!==before.dev||opened.ino!==before.ino||opened.nlink!==1||raw.length!==opened.size)throw new Error("managed artifact changed while opening");const value={path:path.resolve(logical),dev:opened.dev,ino:opened.ino,bytes:raw.length,sha256:crypto.createHash("sha256").update(raw).digest("hex")};if(expected&&(Object.keys(expected).sort().join(",")!=="bytes,dev,ino,path,sha256"||Object.keys(value).some(k=>value[k]!==expected[k])))throw new Error("managed artifact no longer matches authenticated install ownership");return {value,raw};}finally{fs.closeSync(fd);}}
function exists(target){try{return fs.lstatSync(target),true;}catch(error){if(error.code==="ENOENT")return false;throw error;}}
function choose(live,staged){const liveExists=exists(live),stagedExists=exists(staged);if(liveExists===stagedExists)throw new Error("recovery artifact location is ambiguous");return liveExists?live:staged;}
function requireMissingBoth(live,staged){if(exists(live)||exists(staged))throw new Error("unexpected prior plist artifact exists");}
const recovering=operation==="recover";const stateActual=recovering?choose(statePath,stateStaged):statePath;
const stateSnapshot=snapshot(stateActual,null,statePath),state=stateSnapshot.raw;let value;try{value=JSON.parse(state);}catch{throw new Error("install ownership state is invalid JSON");}
if(!value||value.schema!=="pxpipe-codex-default-install/v2"||value.label!==label||Object.keys(value).sort().join(",")!=="label,plist,prior_plist,schema,token")throw new Error("install ownership state is invalid");
if(!value.prior_plist||Object.keys(value.prior_plist).sort().join(",")!=="artifact,kind"||!["present","absent"].includes(value.prior_plist.kind))throw new Error("prior plist ownership state is invalid");
const tokenActual=recovering?choose(tokenPath,tokenStaged):tokenPath;
const plistActual=recovering&&exists(plistStaged)?plistStaged:(recovering?choose(plistPath,plistStaged):plistPath);
const token=snapshot(tokenActual,value.token,tokenPath),plist=snapshot(plistActual,value.plist,plistPath);let prior,priorActual;
if(value.prior_plist.kind==="present"){
  if(recovering&&!exists(priorPresent)&&!exists(priorPresentStaged)&&exists(plistPath)&&exists(plistStaged))priorActual=plistPath;
  else priorActual=recovering?choose(priorPresent,priorPresentStaged):priorPresent;
  prior=snapshot(priorActual,value.prior_plist.artifact,priorPresent);requireMissingBoth(priorAbsent,priorAbsentStaged);
}else{priorActual=recovering?choose(priorAbsent,priorAbsentStaged):priorAbsent;prior=snapshot(priorActual,value.prior_plist.artifact,priorAbsent);requireMissingBoth(priorPresent,priorPresentStaged);}
if(operation==="stage"){
  const priorMove=value.prior_plist.kind==="present"?[priorPresent,priorPresentStaged,prior.value]:[priorAbsent,priorAbsentStaged,prior.value];
  const moves=[[tokenPath,tokenStaged,token.value],[plistPath,plistStaged,plist.value],[statePath,stateStaged,stateSnapshot.value],priorMove];
  for(const [target,staged,expected] of moves){
    if(staged!==target+".pxpipe-uninstall-staged")throw new Error("uninstall staging path is unsafe");
    if(exists(staged))throw new Error("uninstall staging path already exists");
    const current=fs.lstatSync(target);if(current.dev!==expected.dev||current.ino!==expected.ino)throw new Error("managed artifact identity changed before removal");
  }
  for(const [target,staged] of moves)fs.renameSync(target,staged);
  for(const parent of new Set(moves.map(([,staged])=>path.dirname(staged)))){const fd=fs.openSync(parent,fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
}else if(operation!=="check"&&operation!=="recover")throw new Error("unknown ownership operation");
NODE
}
CONFIG_PATH="$CODEX_HOME_DIR/config.toml"
CONFIG_STATE="$PXPIPE_STATE_DIR/codex-default.json"
CONFIG_BACKUP="$CONFIG_STATE.config-before"
ROLLBACK_DIR=""

journal_op() {
  local operation="$1" argument="${2:-}" primary="${3:-}" detail="${4:-}"
  "$NODE_BIN" - "$operation" "$argument" "$primary" "$detail" "$RECOVERY_JOURNAL" "$LAUNCH_LABEL" "$LAUNCH_DOMAIN" "$ROLLBACK_DIR" \
    "$CONFIG_PATH" "$CONFIG_STATE" "$CONFIG_BACKUP" "$DASHBOARD_TOKEN_FILE" "$PLIST_PATH" "$INSTALL_OWNERSHIP" \
    "$PLIST_ORIGINAL" "$PLIST_ORIGIN_ABSENT" "$TOKEN_STAGED" "$PLIST_STAGED" "$OWNERSHIP_STAGED" \
    "$PRIOR_PRESENT_STAGED" "$PRIOR_ABSENT_STAGED" "$SERVICE_PID" "$SERVICE_PGID" "$SERVICE_LISTENERS" <<'NODE'
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const [op,arg,primary,detail,journal,label,domain,rollbackArg,config,state,backup,token,plist,ownership,priorPresent,priorAbsent,tokenStaged,plistStaged,ownershipStaged,priorPresentStaged,priorAbsentStaged,servicePid,servicePgid,serviceListeners]=process.argv.slice(2);
const uid=typeof process.getuid==="function"?process.getuid():null,MAX=2*1024*1024;
function canonical(v){if(Array.isArray(v))return "["+v.map(canonical).join(",")+"]";if(v&&typeof v==="object")return "{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}";return JSON.stringify(v);}
function digest(v){return crypto.createHash("sha256").update(canonical(v)).digest("hex");}
function exists(p){try{return fs.lstatSync(p),true;}catch(e){if(e.code==="ENOENT")return false;throw e;}}
function assertParent(p){const s=fs.lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink()||(uid!==null&&s.uid!==uid)||(s.mode&0o022))throw new Error("transaction parent is unsafe");}
function fileRecord(actual,logical=actual){const before=fs.lstatSync(actual);if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||(uid!==null&&before.uid!==uid)||(before.mode&0o022)||before.size>MAX)throw new Error("transaction artifact is unsafe");const fd=fs.openSync(actual,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const opened=fs.fstatSync(fd),raw=fs.readFileSync(fd);if(opened.dev!==before.dev||opened.ino!==before.ino||opened.nlink!==1||raw.length!==opened.size)throw new Error("transaction artifact changed while reading");return {path:path.resolve(logical),dev:opened.dev,ino:opened.ino,bytes:raw.length,sha256:crypto.createHash("sha256").update(raw).digest("hex"),mode:opened.mode&0o777,uid:opened.uid};}finally{fs.closeSync(fd);}}
function same(actual,record,logical=record.path){try{return canonical(fileRecord(actual,logical))===canonical(record);}catch{return false;}}
function snapshotSet(root,prefix=""){const result={};for(const [key,target] of Object.entries({config,state,backup})){const present=path.join(root,prefix+key),absent=present+".absent",p=exists(present),a=exists(absent);if(p===a)throw new Error("config snapshot topology is invalid");result[key]=p?{kind:"present",artifact:fileRecord(present,target)}:{kind:"absent"};}return result;}
function expectedPaths(rollback){const absolute=path.resolve(rollback);if(path.dirname(absolute)!==path.resolve(path.dirname(journal))||!/^\.codex-uninstall-rollback\.[A-Za-z0-9]{8}$/.test(path.basename(absolute)))throw new Error("rollback path is outside the bounded transaction namespace");return {config:path.resolve(config),config_state:path.resolve(state),config_backup:path.resolve(backup),token:path.resolve(token),plist:path.resolve(plist),ownership:path.resolve(ownership),prior_present:path.resolve(priorPresent),prior_absent:path.resolve(priorAbsent),token_staged:path.resolve(tokenStaged),plist_staged:path.resolve(plistStaged),ownership_staged:path.resolve(ownershipStaged),prior_present_staged:path.resolve(priorPresentStaged),prior_absent_staged:path.resolve(priorAbsentStaged),rollback_dir:absolute};}
function artifactSet(){const present=exists(priorPresent);if(present===exists(priorAbsent))throw new Error("prior plist topology is invalid");return {token:fileRecord(token),plist:fileRecord(plist),ownership:fileRecord(ownership),prior:present?fileRecord(priorPresent):fileRecord(priorAbsent),prior_kind:present?"present":"absent"};}
function atomicWrite(value,create=false){assertParent(path.dirname(journal));const payload={...value};delete payload.journal_sha256;payload.journal_sha256=digest(payload);const temp=journal+".tmp-"+crypto.randomBytes(16).toString("hex"),fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,canonical(payload)+"\n");fs.fsyncSync(fd);}finally{fs.closeSync(fd);}if(create){try{fs.linkSync(temp,journal);}finally{fs.unlinkSync(temp);}}else fs.renameSync(temp,journal);const parent=fs.openSync(path.dirname(journal),fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}}
function validateArtifacts(value){const a=value.artifacts,committed=value.phase==="committed";if(!a||!["present","absent"].includes(a.prior_kind))throw new Error("journal artifact set is invalid");for(const [role,places] of Object.entries({token:[token,tokenStaged],ownership:[ownership,ownershipStaged]})){const found=places.filter(exists);if((!committed&&found.length!==1)||found.length>1||found.some(p=>!same(p,a[role])))throw new Error(role+" artifact drifted");}const managed=[plist,plistStaged].filter(p=>exists(p)&&same(p,a.plist));if((!committed&&managed.length!==1)||managed.length>1)throw new Error("managed plist drifted");const priorPlaces=a.prior_kind==="present"?[priorPresent,priorPresentStaged,plist]:[priorAbsent,priorAbsentStaged];const priorFound=priorPlaces.filter(p=>exists(p)&&same(p,a.prior));if((!committed&&priorFound.length!==1)||priorFound.length>1)throw new Error("prior plist drifted");}
function load(full=true){const before=fs.lstatSync(journal);if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||(before.mode&0o777)!==0o600||(uid!==null&&before.uid!==uid)||before.size>262144)throw new Error("recovery journal is unsafe");const fd=fs.openSync(journal,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);let raw,opened;try{opened=fs.fstatSync(fd);raw=fs.readFileSync(fd);}finally{fs.closeSync(fd);}if(opened.dev!==before.dev||opened.ino!==before.ino||opened.nlink!==1)throw new Error("recovery journal changed while reading");let value;try{value=JSON.parse(raw);}catch{throw new Error("recovery journal is invalid JSON");}const keys="artifacts,config_snapshots,journal_sha256,label,launch_domain,paths,phase,post_config_snapshots,primary_status,recovery_errors,schema,service_listeners,service_pgid,service_pid,service_was_loaded,transaction_id";if(!value||value.post_config_snapshots===null||Object.keys(value).sort().join(",")!==keys||value.schema!=="pxpipe-codex-default-uninstall-recovery/v2"||value.label!==label||value.launch_domain!==domain||!/[0-9a-f]{64}/.test(value.transaction_id)||!["prepared","config-mutated","service-stopped","artifacts-staged","prior-restored","recovering","recovery-required","committed"].includes(value.phase)||typeof value.service_was_loaded!=="boolean"||(value.service_was_loaded&&(!/^[1-9][0-9]*$/.test(value.service_pid)||!/^[1-9][0-9]*$/.test(value.service_pgid)||!/^[1-9][0-9]*(,[1-9][0-9]*)*$/.test(value.service_listeners)))||(!value.service_was_loaded&&![value.service_pid,value.service_pgid,value.service_listeners].every(v=>v===null))||!Array.isArray(value.recovery_errors)||value.recovery_errors.length>32)throw new Error("recovery journal fields are invalid");const payload={...value};delete payload.journal_sha256;if(value.journal_sha256!==digest(payload))throw new Error("recovery journal digest is invalid");const rollback=value.paths&&value.paths.rollback_dir;if(!rollback||canonical(value.paths)!==canonical(expectedPaths(rollback)))throw new Error("recovery journal paths drifted");if(full){const rs=fs.lstatSync(rollback);if(!rs.isDirectory()||rs.isSymbolicLink()||(uid!==null&&rs.uid!==uid)||(rs.mode&0o077))throw new Error("rollback directory is unsafe");if(canonical(snapshotSet(rollback))!==canonical(value.config_snapshots))throw new Error("config rollback snapshots drifted");if(canonical(snapshotSet(rollback,"post-"))!==canonical(value.post_config_snapshots))throw new Error("post-config snapshots drifted");validateArtifacts(value);}return value;}
if(op==="create"){if(!rollbackArg)throw new Error("rollback path required");const value={schema:"pxpipe-codex-default-uninstall-recovery/v2",transaction_id:crypto.randomBytes(32).toString("hex"),phase:"prepared",label,launch_domain:domain,primary_status:null,service_was_loaded:arg==="1",service_pid:arg==="1"?servicePid:null,service_pgid:arg==="1"?servicePgid:null,service_listeners:arg==="1"?serviceListeners:null,paths:expectedPaths(rollbackArg),artifacts:artifactSet(),config_snapshots:snapshotSet(rollbackArg),post_config_snapshots:snapshotSet(rollbackArg,"post-"),recovery_errors:[]};atomicWrite(value,true);}
else if(op==="update"){const value=load();if(!["prepared","config-mutated","service-stopped","artifacts-staged","prior-restored","recovering","recovery-required","committed"].includes(arg))throw new Error("unknown transaction phase");value.phase=arg;if(primary)value.primary_status=Number(primary);if(detail)value.recovery_errors.push(String(detail).slice(0,512));atomicWrite(value);}
else if(op==="cleanup"){const value=load(),root=value.paths.rollback_dir,names=[];for(const [key,record] of Object.entries(value.config_snapshots))names.push(key+(record.kind==="absent"?".absent":""));for(const [key,record] of Object.entries(value.post_config_snapshots))names.push("post-"+key+(record.kind==="absent"?".absent":""));const actual=fs.readdirSync(root).sort(),expected=names.sort();if(canonical(actual)!==canonical(expected))throw new Error("rollback directory contains an unexpected entry");for(const name of expected)fs.unlinkSync(path.join(root,name));const descriptor=fs.openSync(root,fs.constants.O_RDONLY);try{fs.fsyncSync(descriptor);}finally{fs.closeSync(descriptor);}fs.rmdirSync(root);const parent=fs.openSync(path.dirname(root),fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}}
else if(op==="field"){const value=load();const field=arg==="rollback_dir"?value.paths.rollback_dir:value[arg];if(typeof field!=="string"&&typeof field!=="boolean")throw new Error("journal field unavailable");process.stdout.write(String(field));}
else if(op==="remove"){load(false);fs.unlinkSync(journal);const parent=fs.openSync(path.dirname(journal),fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}}
else throw new Error("unknown journal operation");
NODE
}

safe_regular_file() {
  local target="$1" expected_owner
  [[ -f "$target" && ! -L "$target" ]] || return 1
  expected_owner="$($ID_BIN -u)" || return 1
  "$NODE_BIN" - "$target" "$expected_owner" <<'NODE'
const fs = require("node:fs");
const [target, expectedOwner] = process.argv.slice(2);
try {
  const observed = fs.lstatSync(target);
  if (!observed.isFile() || observed.isSymbolicLink() || observed.nlink !== 1
      || String(observed.uid) !== expectedOwner || (observed.mode & 0o022) !== 0) process.exit(1);
} catch { process.exit(1); }
NODE
}

capture_config_path() {
  local source="$1" key="$2" prefix="${3:-}" destination
  destination="$ROLLBACK_DIR/${prefix}${key}"
  if [[ -e "$source" || -L "$source" ]]; then
    safe_regular_file "$source" || { echo "Unsafe config transaction input: $source" >&2; return 1; }
    cp -p -- "$source" "$destination"
  else
    : >"$destination.absent"; chmod 600 "$destination.absent"
  fi
}

matches_file() {
  safe_regular_file "$1" && safe_regular_file "$2" && /usr/bin/cmp -s -- "$1" "$2"
}

preflight_config_restore() {
  local target="$1" key="$2" pre post
  pre="$ROLLBACK_DIR/$key"; post="$ROLLBACK_DIR/post-$key"
  if [[ -f "$pre.absent" ]]; then
    [[ ! -e "$target" && ! -L "$target" ]] && return 0
    [[ -f "$post" && ! -L "$target" ]] && matches_file "$target" "$post"
    return
  fi
  matches_file "$target" "$pre" && return 0
  if [[ -f "$post.absent" ]]; then [[ ! -e "$target" && ! -L "$target" ]]; return; fi
  [[ -f "$post" ]] && matches_file "$target" "$post"
}

restore_config_path() {
  local target="$1" key="$2" pre post parent temporary
  pre="$ROLLBACK_DIR/$key"; post="$ROLLBACK_DIR/post-$key"
  if [[ -f "$pre.absent" ]]; then
    if [[ ! -e "$target" && ! -L "$target" ]]; then return 0; fi
    [[ -f "$post" && ! -L "$target" ]] && matches_file "$target" "$post" || return 1
    rm -- "$target"; return 0
  fi
  matches_file "$target" "$pre" && return 0
  if [[ -f "$post.absent" ]]; then
    [[ ! -e "$target" && ! -L "$target" ]] || return 1
  else
    [[ -f "$post" ]] && matches_file "$target" "$post" || return 1
  fi
  parent="$(/usr/bin/dirname -- "$target")"; [[ -d "$parent" && ! -L "$parent" ]] || return 1
  temporary="$(/usr/bin/mktemp "$parent/.pxpipe-config-restore.XXXXXXXX")"
  if ! cp -p -- "$pre" "$temporary"; then rm -- "$temporary"; return 1; fi
  mv -- "$temporary" "$target"
}

restore_staged_artifact() {
  local staged="$1" target="$2"
  [[ -e "$staged" || -L "$staged" ]] || return 0
  safe_regular_file "$staged" || return 1
  [[ ! -e "$target" && ! -L "$target" ]] || return 1
  mv -- "$staged" "$target"
}

service_loaded() { "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1; }
prove_service_absent() { if service_loaded; then return 1; fi; "$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN" >/dev/null 2>&1; }
service_was_loaded=0
SERVICE_PID=""; SERVICE_PGID=""; SERVICE_LISTENERS=""
listener_pids() {
  local output status
  set +e
  output="$("$LSOF_BIN" -nP -a -iTCP:"$PXPIPE_PORT" -sTCP:LISTEN -t 2>/dev/null)"; status=$?
  set -e
  if (( status == 1 )); then return 1; fi
  (( status == 0 )) || return 2
  printf '%s\n' "$output" | /usr/bin/awk '/^[0-9]+$/ {print}' | /usr/bin/sort -n -u
}
process_pgid() {
  local value
  value="$("$PS_BIN" -o pgid= -p "$1")" || return 1
  value="$(printf '%s' "$value" | /usr/bin/tr -d '[:space:]')"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s' "$value"
}
process_group_present() {
  local rows
  rows="$("$PS_BIN" -axo pid=,pgid=)" || return 2
  if printf '%s\n' "$rows" | /usr/bin/awk -v group="$SERVICE_PGID" '$2==group {found=1} END {exit !found}'; then return 0; fi
  return 1
}
capture_service_identity() {
  local launch_record listener pid group listener_group
  launch_record="$("$LAUNCHCTL_BIN" print "$LAUNCH_DOMAIN/$LAUNCH_LABEL")" || return 1
  pid="$(printf '%s\n' "$launch_record" | /usr/bin/awk -F'= ' '$1 ~ /^[[:space:]]*pid[[:space:]]*$/ && $2 ~ /^[0-9]+$/ {print $2}')"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  group="$(process_pgid "$pid")" || return 1
  listener="$(listener_pids)" || return 1
  [[ -n "$listener" ]] || return 1
  while IFS= read -r listener_pid; do
    listener_group="$(process_pgid "$listener_pid")" || return 1
    [[ "$listener_group" == "$group" ]] || return 1
  done <<<"$listener"
  SERVICE_PID="$pid"; SERVICE_PGID="$group"; SERVICE_LISTENERS="$(printf '%s\n' "$listener" | /usr/bin/paste -sd, -)"
}
probe_service_state() {
  service_was_loaded=0
  if service_loaded; then service_was_loaded=1; capture_service_identity; return; fi
  prove_service_absent
  set +e; listener_pids >/dev/null; local listener_status=$?; set -e
  [[ "$listener_status" == "1" ]]
}
wait_service_disappearance() {
  local listener_status group_status stable=0
  for _ in {1..40}; do
    prove_service_absent || { sleep 0.25; continue; }
    set +e; listener_pids >/dev/null; listener_status=$?; process_group_present; group_status=$?; set -e
    if [[ "$listener_status" == "1" && "$group_status" == "1" ]]; then
      stable=$((stable + 1)); [[ "$stable" == "4" ]] && return 0
    else
      stable=0
    fi
    if [[ "$listener_status" == "2" || "$group_status" == "2" ]]; then return 1; fi
    sleep 0.25
  done
  return 1
}
stop_service() {
  if service_loaded; then
    [[ "$service_was_loaded" == "1" ]] || { echo "Service appeared after the authenticated absence probe; refusing unbound bootout." >&2; return 1; }
    "$LAUNCHCTL_BIN" bootout "$LAUNCH_DOMAIN/$LAUNCH_LABEL" >/dev/null 2>&1 || return 1
  fi
  if [[ "$service_was_loaded" == "1" ]]; then wait_service_disappearance; else prove_service_absent; fi
}
bootstrap_and_prove() {
  safe_regular_file "$1" || return 1
  "$LAUNCHCTL_BIN" bootstrap "$LAUNCH_DOMAIN" "$1" >/dev/null 2>&1 || return $?
  service_loaded
}

cleanup_committed() {
  journal_op field phase >/dev/null || return 1
  for artifact in "$TOKEN_STAGED" "$PLIST_STAGED" "$PRIOR_PRESENT_STAGED" "$PRIOR_ABSENT_STAGED"; do
    if [[ -e "$artifact" || -L "$artifact" ]]; then safe_regular_file "$artifact" || return 1; rm -- "$artifact" || return 1; fi
  done
  if [[ -e "$OWNERSHIP_STAGED" || -L "$OWNERSHIP_STAGED" ]]; then safe_regular_file "$OWNERSHIP_STAGED" || return 1; rm -- "$OWNERSHIP_STAGED" || return 1; fi
  journal_op cleanup || return 1
  journal_op remove
}

recovery_step_failed() { echo "Recovery step failed: $1 (exit $2)." >&2; }
recover_uninstall() {
  local phase loaded step_status
  phase="$(journal_op field phase)" || { step_status=$?; recovery_step_failed "read phase" "$step_status"; return "$step_status"; }
  if [[ "$phase" == "committed" ]]; then cleanup_committed; return; fi
  journal_op update recovering || { step_status=$?; recovery_step_failed "mark recovering" "$step_status"; return "$step_status"; }
  loaded="$(journal_op field service_was_loaded)" || { step_status=$?; recovery_step_failed "read service state" "$step_status"; return "$step_status"; }
  if [[ "$loaded" == "true" ]]; then
    service_was_loaded=1
    SERVICE_PID="$(journal_op field service_pid)" || { step_status=$?; recovery_step_failed "read service pid" "$step_status"; return "$step_status"; }
    SERVICE_PGID="$(journal_op field service_pgid)" || { step_status=$?; recovery_step_failed "read service group" "$step_status"; return "$step_status"; }
    SERVICE_LISTENERS="$(journal_op field service_listeners)" || { step_status=$?; recovery_step_failed "read service listeners" "$step_status"; return "$step_status"; }
  fi
  verify_install_ownership recover || { step_status=$?; recovery_step_failed "verify staged ownership" "$step_status"; return "$step_status"; }
  preflight_config_restore "$CONFIG_PATH" config || { step_status=$?; recovery_step_failed "preflight config" "$step_status"; return "$step_status"; }
  preflight_config_restore "$CONFIG_STATE" state || { step_status=$?; recovery_step_failed "preflight state" "$step_status"; return "$step_status"; }
  preflight_config_restore "$CONFIG_BACKUP" backup || { step_status=$?; recovery_step_failed "preflight backup" "$step_status"; return "$step_status"; }
  if service_loaded; then stop_service || { step_status=$?; recovery_step_failed "stop service" "$step_status"; return "$step_status"; }
  elif [[ "$service_was_loaded" == "1" ]]; then wait_service_disappearance || { step_status=$?; recovery_step_failed "wait for service" "$step_status"; return "$step_status"; }
  else prove_service_absent || { step_status=$?; recovery_step_failed "prove service absent" "$step_status"; return "$step_status"; }; fi
  if [[ -e "$PLIST_STAGED" && -e "$PLIST_PATH" && ! -e "$PRIOR_PRESENT_STAGED" && ! -e "$PLIST_ORIGINAL" ]]; then
    safe_regular_file "$PLIST_PATH" || { step_status=$?; recovery_step_failed "verify prior plist" "$step_status"; return "$step_status"; }
    mv -- "$PLIST_PATH" "$PRIOR_PRESENT_STAGED" || { step_status=$?; recovery_step_failed "restage prior plist" "$step_status"; return "$step_status"; }
  fi
  restore_staged_artifact "$TOKEN_STAGED" "$DASHBOARD_TOKEN_FILE" || { step_status=$?; recovery_step_failed "restore token" "$step_status"; return "$step_status"; }
  restore_staged_artifact "$PLIST_STAGED" "$PLIST_PATH" || { step_status=$?; recovery_step_failed "restore managed plist" "$step_status"; return "$step_status"; }
  restore_staged_artifact "$OWNERSHIP_STAGED" "$INSTALL_OWNERSHIP" || { step_status=$?; recovery_step_failed "restore ownership" "$step_status"; return "$step_status"; }
  restore_staged_artifact "$PRIOR_PRESENT_STAGED" "$PLIST_ORIGINAL" || { step_status=$?; recovery_step_failed "restore prior plist" "$step_status"; return "$step_status"; }
  restore_staged_artifact "$PRIOR_ABSENT_STAGED" "$PLIST_ORIGIN_ABSENT" || { step_status=$?; recovery_step_failed "restore prior-absent marker" "$step_status"; return "$step_status"; }
  restore_config_path "$CONFIG_PATH" config || { step_status=$?; recovery_step_failed "restore config" "$step_status"; return "$step_status"; }
  restore_config_path "$CONFIG_STATE" state || { step_status=$?; recovery_step_failed "restore state" "$step_status"; return "$step_status"; }
  restore_config_path "$CONFIG_BACKUP" backup || { step_status=$?; recovery_step_failed "restore backup" "$step_status"; return "$step_status"; }
  verify_install_ownership check || { step_status=$?; recovery_step_failed "verify restored ownership" "$step_status"; return "$step_status"; }
  if [[ "$loaded" == "true" ]]; then bootstrap_and_prove "$PLIST_PATH" || { step_status=$?; recovery_step_failed "restart service" "$step_status"; return "$step_status"; }
  else prove_service_absent || { step_status=$?; recovery_step_failed "verify service remains absent" "$step_status"; return "$step_status"; }; fi
  journal_op cleanup || { step_status=$?; recovery_step_failed "clean journal artifacts" "$step_status"; return "$step_status"; }
  journal_op remove || { step_status=$?; recovery_step_failed "remove journal" "$step_status"; return "$step_status"; }
}

transaction_active=0
rollback_uninstall() {
  local status=$?
  trap - EXIT
  if (( status != 0 && transaction_active == 1 )); then
    local recovery_status
    if recover_uninstall; then exit "$status"; else recovery_status=$?; fi
    if ! journal_op update recovery-required "$recovery_status" "automatic compensation incomplete"; then
      echo "Recovery journal update also failed; retained all available artifacts." >&2
    fi
    echo "Recovery incomplete; authenticated artifacts and journal retained. Run --recover." >&2
    exit "$RECOVERY_EXIT"
  fi
  exit "$status"
}

if [[ "$UNINSTALL_MODE" == "recover" ]]; then
  [[ -e "$RECOVERY_JOURNAL" && ! -L "$RECOVERY_JOURNAL" ]] || { echo "No safe pxpipe uninstall recovery journal exists." >&2; exit "$RECOVERY_EXIT"; }
  ROLLBACK_DIR="$(journal_op field rollback_dir)" || exit "$RECOVERY_EXIT"
  transaction_active=1
  if recover_uninstall; then transaction_active=0; echo "pxpipe uninstall recovery completed; the managed installation was restored."; exit 0; fi
  if ! journal_op update recovery-required "$RECOVERY_EXIT" "explicit recovery incomplete"; then echo "Recovery journal update failed." >&2; fi
  echo "Recovery incomplete; authenticated artifacts and journal retained." >&2
  exit "$RECOVERY_EXIT"
fi

if [[ -e "$RECOVERY_JOURNAL" || -L "$RECOVERY_JOURNAL" ]]; then echo "Incomplete pxpipe uninstall exists; run --recover." >&2; exit "$RECOVERY_EXIT"; fi
verify_install_ownership check
probe_service_state || { echo "Cannot prove launchd service state." >&2; exit 1; }
ROLLBACK_DIR="$(/usr/bin/mktemp -d "$PXPIPE_STATE_DIR/.codex-uninstall-rollback.XXXXXXXX")"; chmod 700 "$ROLLBACK_DIR"
capture_config_path "$CONFIG_PATH" config
capture_config_path "$CONFIG_STATE" state
capture_config_path "$CONFIG_BACKUP" backup
"$NODE_BIN" "$SCRIPT_DIR/codex-default-config.mjs" plan-uninstall --config "$CONFIG_PATH" --state "$CONFIG_STATE" --output-dir "$ROLLBACK_DIR"
journal_op create "$service_was_loaded"
transaction_active=1
trap rollback_uninstall EXIT

"$NODE_BIN" "$SCRIPT_DIR/codex-default-config.mjs" apply-uninstall --config "$CONFIG_PATH" --state "$CONFIG_STATE" --plan-dir "$ROLLBACK_DIR"
journal_op update config-mutated
stop_service
journal_op update service-stopped
verify_install_ownership stage
journal_op update artifacts-staged
if [[ "$service_was_loaded" == "1" ]]; then wait_service_disappearance || exit 1; fi
if [[ -f "$PRIOR_PRESENT_STAGED" ]]; then
  [[ ! -e "$PLIST_PATH" && ! -L "$PLIST_PATH" ]] || exit 1
  mv -- "$PRIOR_PRESENT_STAGED" "$PLIST_PATH"
  if [[ "$service_was_loaded" == "1" ]]; then bootstrap_and_prove "$PLIST_PATH"; fi
elif [[ ! -f "$PRIOR_ABSENT_STAGED" ]]; then echo "Authenticated prior plist staging artifact is missing." >&2; exit 1; fi
journal_op update prior-restored
journal_op update committed
cleanup_committed
transaction_active=0
trap - EXIT
echo "pxpipe default Codex service and dashboard credential removed. Existing pxpipe logs were preserved."
