# Template Router

Templates are data, not implicit instructions. `templates/manifest.json` is the only registry and defines source, canonical generated output, supported modes, capabilities, dependencies, owning nodes and exact variables.

Routing is allowed only after the requirement contract is clarified and hash-bound. It is a deterministic function of:

1. approved requirement contract;
2. canonical task type and its projection family;
3. selected `fast`, `standard` or `release` mode;
4. explicit capability set from the approved requirement and, for project/domain capabilities, the exact user-confirmed project blueprint;
5. capability dependencies such as `ci-provider-github → delivery`;
6. either an optional implemented legacy acceptance adapter or the complete executable acceptance coverage in a confirmed blueprint.

Mode projection:

- Fast: requirement contract, one fast-projection contract, node-6 execution receipt, targeted acceptance and retrospective. It does not select or fabricate standard `task-plan`, `acceptance-matrix` or `node-acceptance` artifacts.
- Lightweight standard: governance, documentation and maintenance select only requirement contract, Node 6 implementation, Node 7 acceptance and retrospective templates. This is a task-type projection, not a mode downgrade.
- Standard: structured requirement, deliverables, solution, task plan, acceptance matrix, standard node receipts and retrospective; solution and final acceptance remain human decisions.
- Release: full standard set plus review policy and either one optional legacy live adapter or a confirmed blueprint acceptance contract with complete command coverage; delivery/environment and provider templates remain explicit choices. A release governance/documentation/maintenance task records `lightweight-release` in route identity but does not omit release controls.

Rendering rules:

- The manifest owns the only legal output path; caller-selected paths are rejected.
- Generated outputs stay under `.agent/state/artifacts`; the requirement contract is human-governed and non-renderable.
- Each `agent-template-route/v3` receipt binds task type, projection, mode, capabilities, requirement contract and manifest; project capabilities additionally bind the confirmed blueprint and verified Skill lock digests. Each render receipt additionally binds route, source and output hashes/bytes.
- A changed contract, manifest, route, template source or output makes validation fail until an intentional re-route/re-render.
- A transaction restores TASK, CONTEXT and output bytes if context synchronization fails.
- Legacy task-local `ci-provider-github` remains digest-bound for compatible installations. New project-level GitHub/GitLab Issue and CI templates come only from providers explicitly confirmed in `.agent/project/BLUEPRINT.json` and are emitted by `providerctl.py`; no provider or stack command is inferred.
- Legacy optional context transports are compatibility adapters, never universal defaults or project technology choices. They remain disabled until explicit opt-in and verified provenance; native context remains sufficient for the generic route.
- Unselected templates are not loaded or validated. A template may add requirements but cannot remove clarification, cleanup, human solution/acceptance, production approval or root-cause rollback gates.

Use `templatectl.py route`, `render` and `validate` for the generic task control plane. Use `blueprintctl.py` and `skillctl.py` for project/domain adaptation; never copy a universal fixed technology bundle into task context.
