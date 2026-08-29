# pxpipe for Codex Plugin (quarantined compatibility asset)

This optional Codex integration is **not published by the marketplace and must not
be installed from the current snapshot**. The historical compiled runtime/proxy files
did not retain an exact upstream commit/tree, lock/toolchain chain, or complete
transitive-license inventory. Those opaque distributable files were removed rather
than redistributed under unverifiable provenance. `integrity.json` therefore uses
`provenance_status: quarantined`, and the installer and MCP fail closed.

The adaptive Agent Workflow does not depend on pxpipe. New projects have pxpipe
disabled. This directory retains only migration metadata, project-owned fail-closed
integration/rebuild scaffolding, and the known upstream notice until a maintainer
performs a verified source, dependency-license, and toolchain rebuild.

## This snapshot cannot remove quarantine

The distributed `scripts/build-runtime.mjs` intentionally refuses every build. It is
a fail-closed marker, not a working unquarantine command. No command in this tree can
create a verified runtime, change `provenance_status`, or restore the marketplace
entry.

Only an external, pinned and independently reviewed release process may produce
candidate artifacts in a separate reviewed change. That process must start from a
clean canonical `teamchong/pxpipe` checkout and bind the complete 40-hex commit,
Git tree, committed dependency lock, exact reviewed build toolchain and entry hashes,
reproducible outputs, authenticated-dashboard controls, and a complete dependency/
SBOM license inventory. The candidate change must then pass integrity, dashboard,
provider-integration, runtime, security, and license review before any marketplace
entry can be considered. Auditing the current quarantined tree, including use of an
explicit `verify-integrity.mjs --allow-quarantined` check, never authorizes activation.
Every activation entrypoint recomputes the exact whole-tree digest twice before loading code, using stable `O_NOFOLLOW` descriptors with pre/open/post identity checks. A future MCP activation also accepts only an exact `agent-workflow-install/v5` manifest whose canonical source-tree digest binds version, migration, managed file hashes/modes, both bootstrap hashes, the verified plugin file map, and the unique marketplace entry. The loaded plugin must be the real `plugins/pxpipe-context` path beneath that project. v2/v3 compatibility attestations, disabled/malformed bindings, source-tree drift, and missing or duplicate marketplace entries are rejected.
The direct `codex-pxpipe.sh` compatibility launcher is a refusal-only stub: it rejects
`PXPIPE_DIR`, `PXPIPE_NODE`, and Node-path overrides and never searches `dist/` or
`vendor/` while this distribution is quarantined. MCP initialization imports the same
whole-tree verifier, so a stale digest, extra executable, symlink, or modified
unselected file fails before tool publication.

A future verified uninstall must authenticate the launchd PID, its exact process group,
and every TCP listener on the managed loopback port before bootout. It must wait for both
the captured process group and port listener to remain absent across consecutive probes, treat `ps`/`lsof` ambiguity
as failure, reject a service that appears after an authenticated absence probe, and recheck before removing the dashboard credential, plist, ownership
record, or recovery journal. The v2 transaction journal binds that process identity plus
authenticated pre/post Codex config/state/backup snapshots; recovery globally preflights
all three live images before its first artifact/config mutation. A crash immediately after
config mutation remains recoverable, and failed compensation retains the private
credential and journal for explicit recovery. Legacy v1 recovery journals lack process
identity and are intentionally rejected without mutation for manual quarantine.

## Dashboard boundary

Sensitive dashboard routes are disabled when `PXPIPE_DASHBOARD_TOKEN` is absent.
When enabled, the token must contain 32–128 visible ASCII characters and HTTP Basic
authentication uses username `pxpipe` with that token as the password. Mutating
browser requests additionally require an exact loopback Origin. Responses containing
captured context are `no-store`. `/proxy-stats` remains a non-sensitive loopback
health endpoint.

A future verified macOS installer is required to generate a random 256-bit token,
store it in `~/.pxpipe/dashboard-token` with mode 0600, and place it in a 0600
LaunchAgent configuration. Its status command must verify authenticated access and
its uninstall must remove the credential. The current quarantined snapshot is not
installable. Loopback plus authentication reduces browser and unrelated-process
exposure but does not create isolation from a fully compromised same-user account.

## Model policy

No project model is forced by the generic template. `PXPIPE_MODELS` controls the
proxy exact allowlist and defaults to `off`; a future verified MCP must receive an
explicit nonblank `PXPIPE_MCP_MODELS` exact allowlist and has no model fallback. A verified compatibility release may document tested model
profiles, but it must not change the project Blueprint or host model choice.

## Third-party boundary

The known upstream project MIT notice remains in
`THIRD_PARTY_LICENSES/pxpipe-MIT.txt`. That notice does not license unknown transitive
bundle contents, which is why the historical bundles are absent. A future rebuild must
produce and review a complete dependency/SBOM license inventory before quarantine can
be removed. This compatibility asset is not an authority for project architecture,
CI, acceptance, credentials, or user decisions.
