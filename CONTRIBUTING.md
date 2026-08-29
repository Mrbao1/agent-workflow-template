# Contributing

## Toolchain

The checked-in, candidate-owned GitHub evidence matrix exercises the Cartesian product of both toolchain pairs on both hosts:

- Ubuntu 24.04 with Python 3.9.21 and Node.js 20.19.4
- Ubuntu 24.04 with Python 3.13.5 and Node.js 22.18.0
- macOS 14 with Python 3.9.21 and Node.js 20.19.4
- macOS 14 with Python 3.13.5 and Node.js 22.18.0

Every combination runs both shards across `idle-source`, `polluted-source`, and `installed-project`. Skips fail except the exact audited Docker-not-applicable self-test. This workflow is useful evidence only: a protected immutable external or protected-default-branch verifier must authenticate the candidate bytes and effective matrix before its independently named required check can authorize a release.

Canonical GitLab CI runs both full-suite shards on a Linux/amd64 runner. It pins the
Python 3.9.21 image by platform manifest digest and verifies the Node.js 20.19.4 archive
against its published SHA-256 before extracting only the bounded `node` executable.
The GitLab project must provide an untagged Linux/amd64 runner; runner availability is a
protected project setting, not a stack default copied into adopter projects.

The installer currently requires a POSIX host because it uses advisory file locking.
Use Git, Python, and Node executables available on PATH; no package installation is
required for the repository's standard self-suite.

## Development workflow

1. Start from a clean topic branch.
2. Keep runtime credentials, local state, IDE metadata, and generated reports out of commits.
   Stage intended new source/test files before a full local run: fixture construction
   fails closed rather than silently omitting non-ignored untracked source inputs.
3. Run a targeted check while iterating:

~~~bash
python3 tests/run_all.py --context idle-source --only self_test_name --test-timeout 600
~~~

4. Before review, run the full local isolation matrix:

~~~bash
python3 tests/run_all.py --full --fail-on-skip --allow-skip .agent/skills/manage-local-runtime/scripts/self_test_docker_http.py --test-timeout 600 --require-command python3 --require-command node
~~~

A check that cannot run exits with status 77 and is reported as skip. The sole audited N/A is the exact Docker HTTP self-test above when the project has no tracked `compose.yaml`; every other skip must fail under `--fail-on-skip`.

## Control-plane module boundaries

- `adaptive_common.py`: canonical JSON, Blueprint semantics, shared locks and path rules.
- `schema_validation.py`: bounded dependency-free managed-schema runtime only.
- `humandecision.py`: provider receipt trust boundary; no workflow-specific mutation.
- `agentctl.py`: task/bootstrap/runtime state validation and transactional promotion.
- `workflowctl.py`: node transitions, gate receipts and task completion orchestration.
- `skillctl.py`, `knowledgectl.py`, and `providerctl.py`: isolated domain controllers.
- `install.py`: trusted-source packaging, adoption and migration transaction boundary;
  it must not import or execute target-controlled Python.

Do not add a second implementation of locking, canonical hashing, receipt verification,
schema loading, or no-follow file mutation to a large controller. Extract reusable logic
to the narrow module above and add a direct negative test. Large-file line count alone is
not a reason for a risky release refactor; duplicated trust boundaries are.

## CI and template changes

- Pin every third-party GitHub Action to a full 40-character commit SHA.
- Give workflows explicit least-privilege permissions and bounded job timeouts.
- Never interpolate workflow_dispatch input directly into a run script. Copy it into
  env, validate an exact bounded grammar, and quote every expansion.
- Changes under .agent/ are managed release inputs. Reseal the install and fresh-state
  manifests using the repository's maintenance process before merging.
- Add regression coverage in tests/ for behavior and negative security cases.
- Node-6 fixtures must produce the full `candidate_snapshot` from one descriptor capture; never infer executable intent from checkout mode or recrawl the live tree after hashing.
- Installer updates must revoke provider gate authority regardless of target-reported migration version. Receipt fixtures must cover cross-project/task-generation replay and exact-binding-only revalidation.
- Generic provider discovery sends only explicit public `discovery_aliases`; id/kind/config keys and values plus runner labels remain local. Automatic `provider:<id>` coverage requires a provider-specific id/kind token, and externally referenced Skill assets are rejected rather than silently discarded.

## Releases

Use semantic versioning. A template release must have a clean tree, a passing full matrix over the exact staged index, and fresh independent security and portability reviews of those same bytes. Candidate-owned workflow success and authority-variable shape checks are evidence only and never prove protected branch/check authority. Before publication, query each host's configured protection: when an immutable external GitHub verifier or GitLab Pipeline Execution Policy/compliance authority is configured as a required release check, its authenticated success receipt is mandatory. When such host authority is not configured or cannot be observed, record that fact as unavailable/pending and do not claim protected-CI authorization or relabel candidate CI; do not fabricate a receipt. A release also requires an updated CHANGELOG.md, synchronized version surfaces where applicable, refreshed manifests, an annotated tag, and matching GitHub/GitLab refs. Do not publish from an unreviewed local artifact.

## Review checklist

- New shell boundaries reject metacharacters and newline injection.
- Tests use isolated HOME/XDG/Git configuration and do not ingest untracked files.
- Skips are explicit and required capabilities fail closed.
- Generated reports are uploaded as CI artifacts, not committed.
- Documentation and release notes describe user-visible or security-relevant changes.
