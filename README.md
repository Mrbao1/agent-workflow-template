# Agent Workflow Template

Requires Python 3.9 or newer.

This repository is the canonical mother template used to start or upgrade projects. Version 3.1.41 implements a clarification-first, template-driven AI Coding pipeline with adaptive `fast`, `standard`, and `release` modes. Project-private config, policies, task state, runtime state and evidence are never copied between the template and an installed project.

## Install

```bash
python3 install.py /path/to/project --project-name my-project --project-type web-app
cd /path/to/project
cp .agent/policies/PROJECT_GUARDRAILS.md project-guardrails.md
# Complete every required fact and remove the uninitialized marker/TODO values.
python3 .agent/scripts/agentctl.py project-init \
  --guardrails-file project-guardrails.md
python3 .agent/scripts/agentctl.py validate
python3 .agent/scripts/agentctl.py bootstrap-check
python3 .agent/scripts/agentctl.py start --title 'first requirement' --mode auto
```

A fresh install deliberately leaves `guardrails_ready=false` and prints `BOOTSTRAP NOT READY`. The project-local `agentctl.py project-init --guardrails-file` command validates a completed UTF-8 guardrails document, content-addresses its exact bytes, and atomically commits the document, readiness binding, and fresh context. Alternatively, pass `--guardrails-file` to the initial install to commit the workflow and completed guardrails in the installer transaction. Do not interpret a successful file copy as project readiness.

Fresh private state comes only from the managed, content-addressed `.agent/assets/fresh-state/v1` seed. The installer never reads or copies the template checkout's live `.agent/config.json`, `.agent/policies/`, `.agent/state/TASK.json`, `.agent/state/CONTEXT.json`, Agent ledger, runtime state, evidence, or adapter configuration. Update, adopt, and migration preserve the installed project's private state while taking defaults only from that seed. Source-private links and pollution are outside the release input boundary.

Every task starts in clarification. A fresh project may enter Node 1 and maintain its non-authoritative draft without a provider adapter. Local non-deploy fast/standard work may leave clarification after an explicit current-chat decision recorded with lower local assurance. Projects running inside Codex may explicitly enable that same boundary for local, reversible and non-external release-mode implementation with `--allow-current-chat-local-release`; protected environment and side-effect routes remain blocked. `bootstrap-check` reports the effective tier instead of making ordinary local work unusable. The thought tree routes the current 0–8 stage from canonical TASK plus the bounded context capsule; `STAGE_INDEX.md` is a generated compatibility projection, not another input authority. Templates are selected from the requirement, mode and capabilities instead of applying one fixed bundle to every task.

`fast` is for tiny reversible local work, `standard` for bounded features and bugs, and `release` for cross-system, security, data, migration, deployment or production work. Local development, test promotion and production promotion have separate branch/environment policies and separate CI/test-CD/production-CD templates. Installing the workflow does not create provider credentials, protect branches or deploy a product.

Governance, documentation and maintenance tasks may use the task-type-aware lightweight projection in fast/standard mode. That projection keeps clarification, one provenance-bound Node 6 implementation receipt, Node 7 acceptance and retrospective while omitting product-only planning artifacts. Release-mode work is not weakened by this projection. The `agent-template-route/v2` receipt binds task type, mode, projection, capabilities, contract and manifest so changing any of them requires a new route.

Node 6 and Node 7 cannot advance on schema validity alone. Their mode-selected dynamic template must first produce one current provenance record binding the canonical output path and bytes to the template source, manifest, deterministic route and requirement contract. Missing or stale render provenance fails before accepted state is mutated.

## Context, Tokens and resume

The workflow keeps one bounded `agent-context/v2` capsule, but capsule size is not the total task budget. The unified `agent-total-token-budget/v1` account combines root usage, loaded-reference reservations, child reservations and settled child charges. Each child charge includes sealed input, inherited fork-window cost, system/tool margin and output margin. Fast, standard and release ceilings are 6k, 20k and 40k Tokens; they are routing ceilings, not spending targets or provider billing limits. Without a configured usage observer, the account is explicitly `best-effort-estimate`, allows for unmetered direct reads and reports the configured estimation-error ratio.

Every context checkpoint binds a `policy_bundle_sha256` over `.agent/config.json`, `.agent/INDEX.md`, all workflow rules, `templates/manifest.json` and the active Skill. Policy drift therefore invalidates the capsule instead of silently resuming under different rules. At the compact watermark, the capsule publishes an exact `agent-context-resume/v1` contract binding task status, current node, next action, budget state and TASK digest. Expansion is blocked until that compact handoff validates.

After every compaction or child terminal event, the host calls:

```bash
python3 .agent/scripts/workflowctl.py route-resume
```

A child PASS, child FAIL, reviewer FAIL, context compaction or zero active children never completes the root task. `route-resume` emits `agent-workflow-route/v2` and must also run immediately before every final reply; `terminal=false` forbids presenting the root task as complete. When no signed scheduler adapter is configured, a non-terminal continuation becomes `waiting_host_resume` and the receipt carries a cursor-bound recovery command instead of claiming automatic continuation. Only explicit `complete-task`, after the mode terminal node, required human gates, a fresh empty orchestration observation, a provider-observed final completion decision and zero runtime residuals, may produce `status=accepted,current_node=idle`.

## Child Agents and independent review

All child Agents use `gpt-5.6-sol`, a bounded content-addressed `agent-task-payload/v2` and a fresh identity-bearing `agent-handoff-envelope/v3`. The default fork window is zero turns and an explicitly requested window must remain within `0..max_fork_turns` (currently 10); inherited turns are charged by the unified budget. No smaller-model fallback is allowed. A capacity error permits one same-model retry; the second failure stops dispatch. One root slot is always reserved and dependent formal reviews run serially.

Inputs are sealed before spawn. `prepare` publishes payload and envelope evidence and reserves capacity; `register` consumes the exact preparation; only the `LEDGER_REGISTERED` barrier releases the child. Payloads allow at most 24 inputs, 131072 bytes per file, 262144 bytes total and 65536 estimated Tokens. Dispatch identity, role, model, schedule, retry, output path and review-chain controls belong only to the envelope.

Release review is strictly:

1. independent adversarial review with zero-severity PASS;
2. cross review with the exact six product, architecture, QA, security, operations and new-project-adopter lenses;
3. integrator review with the only preflighted, ledger-executed clean replay of every current Node 6 check.

Cross review must publish a canonical third-line `SCENARIO_RECEIPT`; `finish` parses its six ordered scenarios and content-addressed evidence before cross PASS can admit the integrator. `agent-terminal-marker/v6` binds the result, exact first supervision-debt timestamp and terminal observation. The implementer and three formal reviewers are distinct identities.

Integrator replay plans are checked before execution against the managed runner's deterministic `<receipt-stem>-<case-id>.log` output contract. The dispatch envelope binds the exact environment/authority and a fresh capability preflight before spawn. Every implemented acceptance adapter exposes `preflight`, `run`, and `verify`: the integrator alone owns the one `run`; artifact validation and Node 7 completion call only the read-only `verify`, never tests or cleanup. Workflow governance wraps the same `agent-test-receipt/v2` into `workflow-release-gate/v4`; Web/Docker wraps the report's unique integrator runtime receipt into `acceptance-live-gate/v2`. Both bind the current candidate and preflight and recheck `agentctl assert-clean` baseline-delta state.

The canonical candidate fingerprint is owned by `testrun.py` and reused by acceptance gates. It combines every explicitly configured `scope.fingerprint_paths` path with strictly discovered product-owned bytes under `scope.product_roots` for Xcode/SwiftPM, Android, Web, API, CLI and common source layouts. A missing configured path, unsafe symlink, product manifest without owned source, empty scope or candidate drift fails closed. Managed control scripts, Skills, fresh-state assets, templates, workflow contracts and governed task/guardrail bytes are included when configured. The configured future reviewer ceiling is three targeted Cases, but the current attestation schema mechanically permits zero until each Case is bound to the envelope, controlled runner receipt and Agent identity. If an integrator terminates without success, `finish` atomically aborts every remaining prepared replay so no inactive child can leave the ledger invalid or the root task stuck.

Test work is bounded separately from the overall task: fast uses affected checks with a 5-minute cap, standard uses impact-selected checks with a 15-minute cap, and release uses impacted checks plus one full chain with a 45-minute cap. `testrun.py` reserves the remaining wall-clock budget under a cross-process lock before launch, settles monotonic elapsed time afterward, and emits a content-addressed budget receipt bound to the governed candidate fingerprint. Multiple invocations share that same cap and one automatic code-attempt identity; a dead runner is charged its full reservation. Only runner-observed launch/cleanup infrastructure failures are classified separately, and they fail closed instead of accepting a caller label. Workflow preflight is read-only and capped at 60 seconds in total. Candidate changes never auto-resume from a prior Case without a project-specific dependency proof.

Every context checkpoint carries an `agent-context-usage/v1` explicit estimate bound to the current checkpoint sequence and TASK invariant. Expansion gates use the stricter of canonical TASK usage and that fresh checkpoint estimate; compact and hard watermarks therefore cannot be bypassed by leaving TASK counters stale. A provider-measured baseline is accepted only as a content-addressed `agent-usage-receipt/v2` verified by a host-owned adapter, and the following checkpoint remains explicitly labelled estimated. Context repair approval similarly requires a provider-verified human-decision receipt bound to the exact pre-approval repair capsule SHA-256; a `user:` string alone has no authority.

Hot state is bounded independently from immutable evidence. TASK keeps four recent rollback entries, eight recent failure signatures, and one content-addressed head for each cumulative history. Older entries move into verified hash-linked evidence chunks; the cumulative failure count still triggers the third-repeat human gate. Human gates print a decision packet describing what is being approved, what the approval enables and what it explicitly does not enable, while the SHA remains only the integrity binding.

Active evidence is also bounded. Referenced evidence remains active; only old, unreachable evidence is placed in a deterministic content-addressed archive after deep verification. The index is bounded and every archive is exactly restorable. Use:

```bash
python3 .agent/scripts/evidencectl.py status
python3 .agent/scripts/evidencectl.py compact --dry-run
python3 .agent/scripts/evidencectl.py compact
python3 .agent/scripts/evidencectl.py verify --deep
python3 .agent/scripts/evidencectl.py restore --archive <sha256>
```

An expired but otherwise exact context checkpoint can renew through ordinary `contextctl sync`, which may preserve or increase the active-window estimate but cannot lower it. A strictly lower estimate uses the explicit `handoff_written → awaiting_host_compaction → resumed` state sequence and requires a current `host-compaction-receipt/v1` verified by `context.host_compaction_observer.signed_adapter`. With the default `signed_adapter: null`, lowering fails closed; a caller assertion that compaction occurred is not evidence. Actual TASK, contract, policy-bundle, integrity or budget drift still requires fail-closed repair and review.

### Optional pxpipe context plugin

The template can distribute the separate `pxpipe-context` plugin. Its primary capability installs a loopback LaunchAgent and a user-level custom `model_provider` so every future Codex Local conversation uses the pxpipe Responses proxy without invoking `cpx`. This is what performs eligible whole-request history compression; it cannot retrofit a running chat. The `cpx` launcher remains an explicit one-session diagnostic override.

The workflow capability `context-transport-pxpipe` refers only to the plugin's optional cold-file MCP auxiliary. `AVAILABLE` is not the same as installed, loaded, enabled or approved. Native text remains the default. The workflow may select this optional route only after the plugin is installed, project config is explicitly enabled, the user-approved requirement contract contains `Context transport: pxpipe-plugin-explicit-opt-in`, and the MCP has produced an `analyze` receipt for the newly introduced cold reference.

The rendered optional-MCP v2 profile binds the plugin name and version, runtime bundle SHA-256, exact source SHA-256, content-addressed analyze-receipt path/SHA-256, requirement contract, task invariant and provider-verified approval. The profile is deliberately separate from provider-proxy evidence: it contains no upstream endpoint, listener port or proxy runner and cannot prove whole-session compression. Installing or updating the plugin requires a new chat to load changed skills and MCP tools. Canonical state, active protocol state and byte-exact values stay native, and any failed or unprofitable MCP analysis falls back to native text.

The canonical template marketplace is non-default and the installer deliberately does not mutate user-level plugin state. Install the Plugin once from the canonical template; subsequent new chats can use its Skill and STDIO MCP against any host-provided MCP Root, without Git metadata or a project-local plugin copy. Agent Workflow projects add stricter content attestation when their workflow anchor is present:

```bash
codex plugin marketplace add /absolute/path/to/agent-workflow-template
codex plugin add pxpipe-context@agent-workflow-template
node plugins/pxpipe-context/scripts/provider-integration-self-test.mjs
node plugins/pxpipe-context/scripts/self-test.mjs
codex plugin list
```

The marketplace install makes both plugin surfaces available but deliberately does not rewrite the user's provider configuration. To make pxpipe the default for future Codex Local conversations, install and verify the loopback provider lifecycle once:

```bash
plugins/pxpipe-context/scripts/install-codex-default.sh
plugins/pxpipe-context/scripts/status-codex-default.sh
```

Then restart Codex Local, start a new chat, and confirm that `use-pxpipe-proxy` is loaded. The optional cold-file surface separately exposes `use-pxpipe-context`, `pxpipe_analyze_files`, and `pxpipe_render_files`. Existing chats do not hot-load changed plugin Skills, MCP tools, or provider transport. The MCP self-test uses one bounded disposable STDIO child, must report a clean EOF exit, registers nothing, binds no listener, and leaves no background process.

## Observation trust and supervision

`agent-team/v9` ingests every caller-authored orchestration observation into immutable SHA-addressed evidence and reserves each sealed child payload against the live mode Token budget before dispatch. This protects integrity, replay consistency and cumulative child-context accounting, but it does not independently authenticate orchestration JSON as provider-originated. Therefore the default `platform_observer` policy disables automatic release trust. Node 7 publishes the complete current-delivery observation set, its digest, the exact supervision-debt set—including failed or replaced attempts—and its digest. Human release approval must explicitly bind both:

- the observation-set digest after comparison with the real orchestration transcript;
- the supervision-debt digest as an explicit control waiver.

The repository defaults intentionally leave the platform, provider-preflight, usage, scheduler and host-compaction signed adapters unset. Consequently, platform snapshots, remote provider controls, provider Token measurement, automatic host resume and host compaction are unverified until independently configured adapters validate them. Acceptance adapter code being marked implemented proves only that a receipt protocol and runner exist; it does not prove Docker, Xcode, a simulator, device hardware, browser support, credentials or remote provider state on the current host. Those capabilities remain unverified and their preflight gates fail closed when required.

A fresh install may run `bootstrap-check` and `start` without a provider adapter. Local, non-deploy fast/standard tasks then use decision policy v2: an explicit current-chat `user:` decision is stored with `local-only;not-provider-verified` assurance. `--allow-current-chat-local-release` explicitly extends only that local boundary to reversible, non-external release-mode implementation; it does not authorize test, production, deployment, irreversible actions or external effects. Those protected routes use policy v1 and remain fail-closed until `agent_control.human_decision_observer.signed_adapter` points to a healthy provider-owned executable. When `--human-decision-adapter` is supplied, the installer validates its canonical protected ownership chain and runs `<adapter> health` before writing any project surface. A project-local executable, Agent-created `/tmp` helper or local self-sign assertion is rejected. `signed_adapter: null` therefore means “no external provider trust root configured”, not “all local work is broken”.

Starting a new requirement while an unfinished local task exists is explicit and recoverable: pass `start --archive-active --archive-source user:<decision> --archive-reason <reason>`. The controller atomically stores the exact prior TASK and requirement contract in the content-addressed task archive chain before opening the new clarification. Test, production or deploy task replacement additionally requires a provider-signed archive decision. The old misleading “archive it first” dead end has no manual TASK-edit escape hatch.

CI/CD templates require a provider-preflight receipt that binds repository identity, effective branch protection or rulesets, required checks and production-environment reviewers. Repository templates cannot prove provider-side configuration by themselves: the CI provider integration must create and verify this receipt before test or production promotion. Production approval and final workflow completion are separate provider-observed human decisions.

Polling targets 30 seconds with 30 seconds of scheduler grace. A longer gap records immutable supervisor debt; it does not prove the child died and never auto-ends the child or root task. Only a real deadline or an actually observed unchanged progress gap beyond the 300-second stall timeout requires interruption. A later new cursor proves current progress but cannot rewrite previously observed facts. The ledger re-derives the exact first debt timestamp from registration, monitor and terminal observations.

## Local runtime cleanup

Do not leave dev servers, workers, browsers, simulators or containers running. Use bounded `managed-run`, or register the exact process group, Docker project and port. Review foreground commands use an expiring `tool-run` lease. Success, failure, timeout and interruption paths must finish with:

```bash
python3 .agent/scripts/agentctl.py cleanup
python3 .agent/scripts/agentctl.py assert-clean
```

## Check and update

```bash
python3 install.py /path/to/project --check
python3 install.py /path/to/project --update --dry-run
python3 install.py /path/to/project --update
```

The repeatable install lifecycle test exercises idle and deliberately polluted template checkouts, installed-project private state, install/update/adopt/migration isolation, project-init consistency, and crash recovery rollback:

```bash
python3 tests/test_install_lifecycle.py --template-root .
```

CI runs the same command from `.github/workflows/install-lifecycle.yml`; it uses only disposable temporary directories.

Migration 28 separates decision assurance by risk: adapterless local non-deploy fast/standard tasks use an honestly labeled current-chat decision record, while release/test/production/deploy routes still require the external provider trust root. It also adds an atomic, content-addressed active-task archive to `start`, so changing direction no longer requires an impossible manual state edit.

Migration 29 rebinds active context capsules after all task-state migrations have settled. This prevents a newly added invariant field from leaving an otherwise valid upgraded task permanently blocked by a stale capsule hash.

Migration 30 separates cost discipline from active-window capacity. Fast, standard and release routing ceilings become 6k, 20k and 40k tokens while the same 60/75/90 percent watermarks, reference limits, single automatic retry and test-time limits remain in force. The higher hard ceilings prevent normal staged work on long-context models from deadlocking; they are not spending targets. Existing tasks using the old defaults are migrated and their context capsules are rebound, including idle tasks.

Migration 31 adds an explicit Codex current-chat trust option for local release-mode implementation. It is disabled by default, can be enabled at install/update with `--allow-current-chat-local-release`, and never applies to test, production, deployment, irreversible or external-impact routes. Eligible unapproved active local tasks are rebound to decision policy v2; already approved provider-bound tasks retain their original authority.

Version 3.1.34 makes node-7 acceptance rendering mode-aware. Standard tasks provide only common acceptance variables and the renderer omits every release-only authority field; release tasks still require the complete reviewer, scenario, platform and live-gate chain. This removes an impossible template/validator contradiction without weakening release gates.

Version 3.1.39 raises only the fast context capsule ceiling from 600 to 1000 tokens. A valid fresh-install fast task already needs more than 600 tokens for its integrity, checkpoint and resume envelope; the new ceiling retains a stricter bound than standard mode while adding measured headroom. Migration 32 upgrades only the exact old default and preserves project-owned custom limits. Template lifecycle coverage now proves explicit fast, qualifying auto-fast and approved Node 2 startup on a fresh install.

Version 3.1.41 / Migration 34 validates an active predecessor capsule before update, rebinds unchanged loaded managed references to their new bytes, and then creates one final policy-bound context checkpoint without mutating canonical task intent. Version 3.1.40 / Migration 33 separates the release-managed workflow from all live template-private state. New projects are created from the immutable fresh-state seed; migration defaults use the same seed; project guardrails become ready only through the atomic content-addressed project-init operation. Install output stays fail-closed until that operation succeeds, and lifecycle CI covers polluted-source isolation and transaction rollback.

Version 3.1.36 makes every template manifest entry an executable variable contract: `templatectl` now fails closed when a template's declared `required` variables differ from its source placeholders. It also repairs the backend and iOS profile contracts so both adapters can be rendered through the deterministic route.

Version 3.1.35 separates read-only terminal template validation from route/render mutation gates. An accepted task can now replay its provenance-bound template state during final validation, while terminal routing and rendering remain blocked.

Migration 27 makes child-context cost mechanical: `agent-team/v9` seals an estimated Token charge into every payload, reserves it before dispatch, settles it exactly once at every terminal state, and enforces the live fast/standard/release budget across serial reviewers. It also separates the globally installed `pxpipe-context` Plugin from project installation: the workflow installer no longer copies or registers Plugin files, and new chats bind the MCP to host-provided Roots without Git metadata. Explicit host compaction is now the only operation allowed to lower active-context estimates, while runtime cleanup derives its trusted process chain from live OS inspection rather than caller-supplied PID environment variables. Migration 26 adds a production-only provider preflight trust boundary: the human-approved requirement contract owns the exact repository/default branch/environments/checks/reviewer target; a dedicated OS-protected read-only provider adapter proves branch reachability and successful check runs for the exact candidate; and human release approval signs the complete content-addressed deployment packet. Local/test delivery stays lightweight. Delivery v2 is migrated losslessly: pending production returns to fresh preflight, while old promoted/failed/rolled-back state becomes non-reusable `assurance=legacy` history with a historical Node8 v3 projection and can never redeploy. Migration 25 adds the common acceptance `preflight/run/verify` boundary, Web/Docker receipt-only Node 7 verification, provider-adapter fresh-install preflight, and a transactionally managed `AGENTS.md` bootstrap recorded by install manifest v3. Migration 24 adds the optional `pxpipe-context` plugin and resets legacy Git/proxy context-transport settings to the disabled, explicit-opt-in plugin contract. It retains Migration 23's bounded rollback/failure hot state, hash-linked archives, reachability-aware evidence retention and safe context renewal, plus Migration 22's single workflow full-chain execution, profile-bound preflight, managed-code candidate fingerprint and readable decision packets. An empty legacy v8 Agent ledger migrates to v9 only when `members`, `prepared_dispatches`, `capacity_failures` and `replay_runs` are all empty and a fresh empty `agent-platform-snapshot/v3` is supplied:

```bash
python3 install.py /path/to/project --update \
  --agent-platform-snapshot /path/to/fresh-platform-empty.json
```

Any legacy history fails transactionally. Finish or interrupt all children, compare the actual platform state, archive the old ledger explicitly, and use `agentledger init --archive-existing`. The migration retains the immutable snapshot receipt but deliberately leaves `platform_empty_verified=false`: a caller-supplied snapshot is integrity evidence, not authenticated provider proof. A compatible, empty current v9 ledger is preserved during an idempotent update and rebound to the current mode budget when necessary. Observer key sets and fixed security fields are canonical; a configured `signed_adapter` is accepted only when its full canonical path forms an OS-protected, non-temporary, non-Agent-writable trust boundary.

An exact unmanaged copy may be adopted only after its managed tree matches:

```bash
python3 install.py /path/to/project --adopt --dry-run
python3 install.py /path/to/project --adopt
```
