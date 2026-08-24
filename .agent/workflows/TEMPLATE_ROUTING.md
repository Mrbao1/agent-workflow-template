# Template Router

Templates are data, not implicit instructions. `templates/manifest.json` is the only registry and defines source, canonical generated output, supported modes, capabilities, dependencies, owning nodes and exact variables.

Routing is allowed only after the requirement contract is clarified and hash-bound. It is a deterministic function of:

1. approved requirement contract;
2. canonical task type and its projection family;
3. selected `fast`, `standard` or `release` mode;
4. explicit capability set;
5. capability dependencies such as `ci-provider-github → delivery`;
6. implemented acceptance-adapter registry.

Mode projection:

- Fast: requirement contract, one fast-projection contract, node-6 execution receipt, targeted acceptance and retrospective. It does not select or fabricate standard `task-plan`, `acceptance-matrix` or `node-acceptance` artifacts.
- Lightweight standard: governance, documentation and maintenance select only requirement contract, Node 6 implementation, Node 7 acceptance and retrospective templates. This is a task-type projection, not a mode downgrade.
- Standard: structured requirement, deliverables, solution, task plan, acceptance matrix, standard node receipts and retrospective; solution and final acceptance remain human decisions.
- Release: full standard set plus review policy, exactly one implemented live acceptance adapter, delivery/environment templates when selected, and CI/CD provider templates only when selected. A release governance/documentation/maintenance task records `lightweight-release` in route identity but does not omit release controls.

Rendering rules:

- The manifest owns the only legal output path; caller-selected paths are rejected.
- Generated outputs stay under `.agent/state/artifacts`; the requirement contract is human-governed and non-renderable.
- Each `agent-template-route/v2` receipt binds task type, projection, mode, capabilities, requirement contract and manifest. Each render receipt additionally binds route, source and output hashes/bytes.
- A changed contract, manifest, route, template source or output makes validation fail until an intentional re-route/re-render.
- A transaction restores TASK, CONTEXT and output bytes if context synchronization fails.
- CI provider is part of the capability/route hash. `ci-provider-github` selects GitHub assets and `ci-contract.provider` must equal `github`; a generic `ci-cd` label or free-text provider cannot silently route all providers.
- The plugin's primary whole-session behavior is outside this template route: its lifecycle installs a loopback LaunchAgent and user-level custom `model_provider` so future Codex Local conversations use pxpipe by default. `cpx` is only a one-run diagnostic override. The current chat cannot hot-swap into that transport, and an MCP render is not evidence that provider traffic used pxpipe.
- `context-transport-pxpipe` selects only the optional provenance-bound v2 cold-file MCP profile after clarification. The plugin being available in a template or catalog does not prove it is installed, loaded, enabled or user-approved. The route remains disabled until explicit opt-in and a successful `analyze` receipt. The MCP must bind `workspace_root` to host MCP Roots (or an explicit startup allowlist when Roots are unavailable), verify the project's v2 or later workflow manifest and installed plugin hashes, and persist the structured analyze result under `.agent/state/evidence/context-transport/<analyze_receipt_sha256>.json`. Rendering is restricted to newly introduced cold references; it never changes canonical TASK/CONTEXT truth or permits byte-exact fields to exist only in images.
- Unselected templates are not loaded or validated. A template may add requirements but cannot remove clarification, cleanup, human solution/acceptance, production approval or root-cause rollback gates.

Use `templatectl.py route`, `render` and `validate`; never copy a universal fixed bundle into task context.
