#!/bin/bash
set -euo pipefail

# This compatibility entrypoint intentionally cannot activate the quarantined
# distribution. A reviewed release must replace this launcher together with the
# exact integrity receipt; no local dist/vendor/override path is accepted.
for override_name in PXPIPE_DIR PXPIPE_NODE PXPIPE_NODE_BIN; do
  if declare -p "$override_name" >/dev/null 2>&1; then
    echo "$override_name override is unavailable while pxpipe is quarantined." >&2
    exit 1
  fi
done

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_SOURCE" ]]; do
  SOURCE_DIR="$(cd -P -- "$(/usr/bin/dirname -- "$SCRIPT_SOURCE")" && pwd)"
  LINK_TARGET="$(/usr/bin/readlink "$SCRIPT_SOURCE")"
  [[ "$LINK_TARGET" == /* ]] && SCRIPT_SOURCE="$LINK_TARGET" || SCRIPT_SOURCE="$SOURCE_DIR/$LINK_TARGET"
done
SCRIPT_DIR="$(cd -P -- "$(/usr/bin/dirname -- "$SCRIPT_SOURCE")" && pwd)"
NODE_BIN="$(command -v node 2>/dev/null || true)"
[[ -n "$NODE_BIN" && -x "$NODE_BIN" ]] || { echo "Node.js is required to verify pxpipe quarantine." >&2; exit 1; }

"$NODE_BIN" "$SCRIPT_DIR/verify-integrity.mjs"
echo "pxpipe activation is unavailable: quarantined integrity verifier returned unexpectedly." >&2
exit 1
