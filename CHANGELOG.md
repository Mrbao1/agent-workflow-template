# Changelog

All notable changes to this project are documented here. The format follows Keep a
Changelog 1.1.0 and releases use Semantic Versioning 2.0.0.

## [Unreleased]

## [4.0.2] - 2026-08-29

### Fixed

- Corrected failures observed in both live v4.0.1 forge pipelines. GitHub now copies the setup-selected Node executable into an owner-only path accepted by the self-suite's executable trust checks and uses the published Python 3.9.13 ARM64 build on the `macos-14` runner; the selected setup-python interpreter still launches every shard. GitLab now stages the verified Node executable under a root-owned, non-group-writable `/opt` path instead of the group-writable checkout hierarchy.
- Preserved immutable v4.0.1 refs and added v4.0.1/42 to the installer's released-manifest compatibility window before publishing this follow-up patch.

## [4.0.1] - 2026-08-29

### Fixed

- Same-migration patch updates now validate an existing active context before mutation and rebind its checkpoint after managed policy bytes change, so a v4.0.0 active task remains valid after updating to v4.0.1.
- Candidate-evidence CI no longer depends on separately managed protected-authority variables: GitHub no longer duplicates the complete matrix for an equivalent tag push, serializes all three contexts within eight bounded OS/toolchain/shard jobs, and caps parallelism at four; GitLab uses the verified online `hk-cluster-devops-cicd` Linux/amd64 shared Runner in two sharded jobs instead of scheduling 24 jobs per ref against unavailable untagged and host-specific Runner pools. Missing external authority remains unavailable/pending rather than being fabricated, and generated release verification still fails closed without its authenticated provider receipt.

## [4.0.0] - 2026-08-25

### Added

- MIT license, security policy, contributor guide, support matrix, canonical-mirror
  policy, and reproducible release checklist.
- Provider-verifiable human-decision receipts and a documented OS-protected adapter
  contract for every authoritative Blueprint, gate, Skill, provider, and evolution
  mutation. Receipts are project-identity and task-generation bound; exact-binding revalidation is the only bounded reuse, and installer updates revoke prior gate authority.
- Runtime-enforced JSON Schema contracts for Blueprint, Skill policy/candidates, and
  knowledge registry data, including differential and malformed-schema tests.
- GitLab candidate-evidence CI with an immutable Git-capable Python image and Node archive hashes, plus
  a GitHub Linux/macOS × minimum/modern-pinned context-by-shard toolchain matrix. Protected required-check
  authority remains outside candidate-controlled YAML: GitLab requires a Pipeline Execution Policy or
  compliance pipeline, and GitHub requires an immutable external or protected-default-branch verifier.
- Adversarial control-plane, provider transaction, schema, CI isolation, installer
  migration, pxpipe quarantine, and supply-chain regressions.

### Changed

- **Breaking:** local/current-chat text is advisory only and can no longer authorize
  state or gate changes; projects must configure a provider-owned decision adapter.
- **Breaking:** GitLab project generation now emits the composable
  `.gitlab/agent-workflow.yml` component and an include snippet without owning or
  replacing the adopter's root `.gitlab-ci.yml`.
- Blueprint confirmation is revalidated on every load; command launch, revocation,
  acceptance receipt emission, and mutations are serialized under shared locks.
- Acceptance v4 requires one bounded exact candidate snapshot, binds path/SHA-256/byte-count/canonical mode from one descriptor capture, records the explicit no-filesystem/no-network-confinement execution limitation, and runs commands only in a private materialization of those bytes. Executable and canonical shebang-interpreter bytes are rechecked across preflight/run/replay. On macOS, unprotected reviewed executable/interpreter bytes are privately materialized; the lifecycle observer follows exact PID/start identities, launch sessions, descendants, and an unguessable inherited launch token. Unrelated same-UID processes are never signaled or treated as launch evidence. This is bounded lifecycle observation, not hostile-command containment.
- GitHub Skill discovery treats goals, technologies, architecture, constraints, and acceptance
  as advisory search context; only explicit confirmed capabilities require Skill coverage. Queries are
  privacy-safe and deduplicated. Generic providers disclose only explicit public discovery aliases;
  provider-specific coverage cannot be satisfied by generic wording. Discovery considers multiple `SKILL.md` paths across repositories,
  and uses strict HTTPS/redirect/base64 handling,
  bounded retries, request accounting, and a process-local cache.
- License classification now requires complete, unambiguous clause fingerprints.
  External Skills remain content-only CAS bundles; activation binds human-reviewed exact
  `SKILL.md` and `LICENSE.txt` digests, their scripts are never installed or executed,
  and Skills that reference unavailable relative assets are rejected.
- Installer migration 42 executes only trusted source code, creates the fail-closed scheduler
  nonce registry for pre-v42 projects, revokes unverifiable prior authority, detects candidate
  validation mutation, and upgrades transaction journals to v4 full predecessor/candidate tree
  content identities. It binds managed POSIX modes, excludes
  untrusted writable target namespaces, uses no-follow descriptor-relative transaction
  traversal and anchors operations to the locked parent inode. It quarantines idle v1 Skill
  authority/content exactly without inventing v2 legal approval, blocks active/journaled Skill
  migration, and removes only exact legacy-managed pxpipe trees/entries. An enabled verified
  pxpipe policy is retired to native only when both plugin and marketplace ownership are proven,
  with a private evidence receipt; unrelated project files and policy keys are preserved.
- Child-agent model selection is explicit and validated instead of being silently tied
  to one model; optional pxpipe model lists remain user-controlled.
- Confirmed Blueprint providers may use a bounded generic `id/kind/configuration`
  contract with secret-bearing settings rejected and opt-in public discovery aliases. Generated
  provider artifacts bind only the Blueprint digest and redact configuration/argv values.
  GitHub/GitLab remain optional built-in emitters rather than a closed stack; GitHub CD runner
  and default branch values are derived from confirmed provider authority.
- CI children receive isolated minimal environments, exact stage-0 Git-index object fixtures,
  sealed tool identities, bounded streaming output, audited exit-77 not-applicable accounting, and TERM-to-KILL cleanup
  that identity-tracks direct setsid descendants. Both pinned lanes fail on unapproved skips.
- Provider output uses descriptor-rooted, no-follow, crash-recoverable transactions and
  verifies exact final inventories before deleting its journal.

### Security

- Scheduler receipts require provider-side atomic nonce consumption in a durable monotonic
  store; the owner-only local registry is defense-in-depth audit state, and rollback of it cannot replay a provider-consumed nonce.
- Acceptance preflight binds the sealed environment and rejects argv/environment filesystem
  references outside the exact private candidate materialization before execution; this is bounded integrity isolation, not OS filesystem or network confinement.
- Quarantined `pxpipe-context` because its exact upstream commit/tree/lock/toolchain
  provenance and transitive-license inventory cannot be reproduced. Opaque compiled
  runtime/proxy artifacts were removed rather than redistributed; it is unpublished,
  disabled in installs, and rejects self-attested “verified” metadata. Any future MCP activation
  additionally requires one exact `agent-workflow-install/v5` source-tree/mode/bootstrap/plugin/
  marketplace anchor at the real installer-owned plugin path; v2/v3 manifests and source-tree drift
  are rejected. Activation requires a future external reproducible-build and transitive-license review trust root.
- Quarantined pxpipe lifecycle helpers additionally require root-owned, symlink-free Node,
  seal production PATH, keep dashboard credentials out of argv, bind owner-private single-link
  Codex state/backup paths, and transactionally compensate configuration, service, token,
  ownership, and authenticated prior-plist changes when install or uninstall cannot commit.
  Uninstall compensation uses an authenticated marker-last recovery journal, exit status 75,
  launchd presence/absence proof, and explicit idempotent `--recover`.
- Any future externally reviewed pxpipe release requires authenticated dashboard routes,
  constant-time credential checks, same-origin mutation enforcement, generated
  256-bit credentials, and no-store/nosniff response headers before publication.
- Pinned GitHub Actions, source CI images, Node archives, generated provider images,
  Skill commits/files/licenses, and all managed manifests to immutable identities.
- Deployment templates validate dispatch inputs from environment variables and never
  interpolate untrusted expressions directly into shell scripts.
- Removed stale runtime evidence, generated reports, IDE metadata, and the obsolete
  remediation plan from the release tree.

[Unreleased]: https://github.com/Mrbao1/agent-workflow-template/compare/v4.0.2...HEAD
[4.0.2]: https://github.com/Mrbao1/agent-workflow-template/compare/v4.0.1...v4.0.2
[4.0.1]: https://github.com/Mrbao1/agent-workflow-template/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/Mrbao1/agent-workflow-template/releases/tag/v4.0.0
