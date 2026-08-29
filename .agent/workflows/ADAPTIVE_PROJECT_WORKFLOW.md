# Adaptive Project Workflow

## Authority rule

The workflow does **not** choose a technology stack. The only authority for project-specific Skill matching is the exact `.agent/project/BLUEPRINT.json.design` digest confirmed by a policy-valid human-decision receipt. Moreover, the authoritative router binds arbitrary project capability IDs to that digest and the current verified dynamic Skill lock. Repository manifests, generated suggestions, popularity, existing code, GitHub metadata, and Agent inference may inform a discussion, but cannot populate or confirm the design on the user's behalf.

Built-in Skills implement the generic control plane (clarification, routing, runtime, evidence, review, delivery). Every design, framework, language, product, infrastructure, test, or provider-specific Skill is a dynamic project dependency.

## State machine

`missing → draft → confirmed → discovered-untrusted → eligible/scored → user-approved → locked → active → deprecated → retired`

Security incidents may move an active Skill directly to `quarantined`. Changing any confirmed design field returns project-specific Skills to stale until a new blueprint confirmation and selection pass completes.

## Blueprint gate

The user supplies:

- goals and users;
- architecture decisions;
- technology choices with reasons;
- stable capability IDs and descriptions, or an explicit empty list;
- constraints plus stable acceptance IDs, criteria, and executable/evidence/manual methods;
- project-owned commands as argv arrays, stage, timeout, acceptance IDs covered, and an explicit inherited-environment variable allowlist;
- when and only when Web/Docker acceptance is selected, an exact non-empty `application_services` Compose service set; this optional field remains absent for other stacks and cannot be supplied by a runtime CLI;
- Any user-confirmed provider record; GitHub/GitLab additionally have built-in runner, image/container, and tag emitters.

The CLI rejects duplicate, empty, oversized, shell-based, or unconfirmed records. It runs project commands with `shell=False`, a separate process group, bounded timeout/interrupt cleanup, and a minimal environment plus only user-allowlisted inherited variables. Executable receipt verification replays every exact command through the canonical no-shell runner, so caller-authored zero-exit rows are not execution proof. Manual criteria require a repository-external, OS-protected host/provider-verifiable human-decision receipt over candidate, blueprint, Skill lock, preflight, criterion and evidence; a caller-provided current-chat `user:` label is insufficient. Evidence/manual release receipts gain authority only when their exact path/SHA-256/bytes are the selected integrator's marker-bound result evidence; matching an integrator ID alone is insufficient.

## Skill discovery and scoring

Discovery preserves one bounded, normalized, deduplicated query unit per confirmed capability, technology choice, and provider (falling back to confirmed goals only when all three lists are empty), rank-round-robins repository results before global limits, and records the exact unique query set and request count. Generic providers expose only explicit user-confirmed public discovery aliases; their id/kind/configuration and all values remain local. If bounded search results cannot cover every query unit within the repository inspection limit, it fails before content inspection; an insufficient request budget fails before network access rather than omitting a confirmed choice. Every GitHub operation shares a POSIX-enforced total deadline across its bounded retry and byte-limited response read. It resolves the default branch to a full 40-hex commit, reads the pinned Git tree and blobs, and accepts a standalone regular UTF-8 `SKILL.md` plus a root license text. Skills that reference relative links, scripts, references, or assets are rejected because external bundles are never installed; upstream code is never checked out or executed.

Eligibility runs before scoring: allowed host, numeric repository identity, non-archived repository, full commit, safe relative paths, size limits, parsed name/description, allowed SPDX license, no symlink/gitlink/binary/script payload, and no blocking dangerous instruction pattern. An ineligible candidate always scores zero.

Default eligible score (configurable in `.agent/project/skill-policy.json`):

`100 × (0.35 relevance + 0.15 quality + 0.15 maintenance + 0.20 security + 0.10 trust + 0.05 license) × (0.70 + 0.30 evidence confidence)`

- relevance compares only confirmed goals, architecture, choices, capabilities, provider structural identifiers, constraints, and acceptance;
- quality measures parseability, usage/workflow/constraints/verification structure and deterministic steps;
- maintenance uses bounded repository freshness evidence;
- security starts from content-only least privilege and is reduced by prompt/security warnings;
- trust uses organization identity and a tightly capped popularity signal;
- license is one only after the allowlist gate;
- missing evidence lowers confidence; stars can never overcome relevance or security.

The report contains every breakdown and reason code. A score is evidence for ranking, not proof of safety, legality, authorship, or semantic correctness.

## Lock and activation

A non-mutating selection plan binds the chosen candidate, exact bundle, report expiry and prior lock before a policy-valid human receipt may authorize mutation. The lock re-verifies that receipt and binds blueprint/policy/recommendation digests, GitHub host/owner/numeric repository ID, full commit, upstream path, SPDX/license hash, candidate hash, score, an explicit human-reviewed confirmed-capability mapping (similarity is only a suggestion), provenance mode/source, CAS bundle digest, exact file names/sizes/modes/SHA-256, and install time. CAS and active directories must be mode-0700 real directories with only mode-0600, single-link regular `SKILL.md` and `LICENSE.txt` files.

Updates are new candidates and recommendations; force-pushed branches cannot alter an existing full commit lock. Sessions use the verified active bytes and never hot-swap. Retained CAS bundles and lock snapshots support digest-bound rollback. A project should commit the confirmed blueprint, approved candidate/report evidence, lock, referenced CAS, active exact set and knowledge catalog so a fresh clone can verify offline; committed external Markdown remains untrusted below project policy.

## Knowledge, Issue/MR, design-to-CI

`knowledgectl.py` creates a project-private registry. Each active topic has a stable ID, owner, Markdown path, generic kind, tags, and changed-path globs; changed production paths without a knowledge owner fail the plan. Catalog generation hashes but never writes human semantics.

`providerctl.py` emits built-in GitHub/GitLab Issue/change templates, a provider trace manifest, and read-only verification CI only for those confirmed provider environments. Generic confirmed providers remain design authority but require a separately selected and reviewed matching Skill/emitter; they are never silently treated as GitHub. CI verifies the expected blueprint digest, Skill lock, knowledge catalog, and trusted Git changed-path owner plan, then invokes user-selected argv commands. Existing provider output needs a planned, receipt-backed overwrite action. The v2 provider trace commits the predecessor inventory and exact overwrite decision; verification rejects stripped or replayed decisions. Emit/plan shares the project mutation lock and holds stable no-follow directory descriptors. Existing targets use atomic exchange and validate the predecessor actually displaced; absent targets use atomic no-replace. A digest-bound, fsynced journal precedes every multi-file commit, `providerctl.py recover` deterministically handles crashes at every commit boundary, and recovery changes only bytes still owned by the transaction while preserving concurrent third-party content. Emit/verify fail closed until recovery completes. A provider-specific authority artifact preserves only the canonical design digest and Blueprint path; it never duplicates command argv or provider configuration values into generated provider files. Human-readable templates hash argv and expose only configuration key names, while all user YAML scalars remain strings. Generated CI re-verifies the trace, exact generated bytes, full Git history, complete multi-commit initial-push tree, user-selected digest-pinned image/runner/tags, and reviewed Skill capability coverage. GitHub and GitLab selections must declare distinct candidate/protected execution authorities: candidate jobs are ephemeral, protected jobs are both ephemeral and isolated, and self-hosted labels/tags include mutually exclusive pool labels. These Blueprint booleans are configuration requirements, not self-authentication; the provider-owned protected policy/adapter must verify the effective runner-group/tag assignment and one-job ephemerality before its authenticated preflight proof is authoritative. The template never inserts npm, Flutter, Gradle, Cargo, Go, Python application, database, cloud, or framework commands on its own.

## Self-iteration

Outcomes are bounded low-sensitivity counters deduplicated by stable run ID and evidence SHA-256: success, failure, overridden, unused. Skill outcomes use `record`; generic control-plane component outcomes use `record-workflow`. After the policy-configured sample window and success threshold, `evolutionctl.py plan` may propose a trial, replacement, deprecation, retirement, or workflow installer check. It cannot modify deny policy, reduce acceptance, execute a remote installer, merge, deploy, or retire the final active capability owner. Apply selects exactly one digest-addressed action and requires an unchanged blueprint, current Skill lock, unexpired plan/report, policy-valid human-decision receipt, and an already active verified replacement with the exact proposed identity.

Workflow framework updates continue through `install.py --check`, `--update --dry-run`, then reviewed `--update`; project-private blueprint, Skill CAS/lock, knowledge, and outcomes are preserved.

## Remaining limits

Static scans cannot reliably determine malicious intent, all script behavior, legal compatibility, repository-owner compromise, or future maintenance quality. Git commit identity does not prove content is safe. A live GitHub outage or no-token rate limit must be visible; offline catalogs are allowed only as explicit `offline-user-reviewed` assertions; their provenance mode/source remains in the exact approval action and lock, repository metadata receives neutral priors, and verification never relabels it as GitHub-API-observed evidence.
