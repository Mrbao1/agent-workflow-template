# Security Policy

## Supported versions

Security fixes are applied to the current `main` branch and the latest actually published supported `4.x` tag. Before the first `4.x` tag is published, only current `main` is supported.
The pre-4.0 trust model accepted caller-controlled local approval text and is unsupported;
older commits and copied template snapshots receive no backported security fixes.

## Human-decision trust boundary

Authoritative Blueprint, workflow, Skill lifecycle, provider overwrite, acceptance, and
evolution decisions require a provider-owned adapter configured at
`agent_control.human_decision_observer.signed_adapter`. The default is `null` and
fails closed. The adapter must be a canonical absolute executable outside the workspace
and temporary directories; it and every parent directory must be OS-owned and not
writable by the Agent process.

The control plane invokes `<adapter> health` before protected mutation and invokes
`<adapter> verify --receipt <absolute-path>` to validate a bounded receipt. Successful
verification must emit exactly
`VERIFIED HUMAN DECISION sha256=<sha256-of-receipt-bytes>`. The adapter must use a
read-only provider credential or equivalent hardware/OS trust boundary, verify the
provider signature and unique event identity, and never create or approve the event it
is checking. A receipt uses `agent-human-decision/v1` and binds the gate, immutable
artifact digest, exact source string, task title/mode, routing profile, decision ID,
provider authority, and timezone-aware observation time. Caller text and repository-
writable JSON are advisory until this adapter verifies their provider provenance.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the canonical GitLab
project's confidential issue form at:

https://git.kuainiujinke.com/user-growth/agent-workflow-template/-/issues/new

Select **Confidential** before entering sensitive details. If that control is unavailable,
contact a project Owner through the GitLab project-members page and request a private
reporting channel before sharing vulnerability details.

Include the affected commit or workflow version, impact, reproduction steps, and any
suggested mitigation. Do not include production credentials, personal data, or active
exploit material beyond what is needed to reproduce safely.

Maintainers should acknowledge a report within five business days, establish severity
and scope, prepare a regression test, and coordinate disclosure after a fix is available.

## Security boundaries

- The installer invocation from an independently verified release checkout is the trust root for the installed Python control plane and built-in Skills. The managed manifest and task activation provide exact-byte drift detection and captured routing, not a signature boundary against an actor that can rewrite both the project control plane and its local verifier as the same OS user. Keep `.agent` owner-only, run only from a trusted checkout, and reinstall from a verified release when same-UID workspace compromise is possible; no local self-hash is authorization.
- External Skills and generated CI inputs are untrusted until validated.
- Caller text and project-writable receipt files are not authorization. A provider adapter
  must be outside the repository, OS-protected, and accompanied by an equally protected
  `agent-provider-adapter/v1` metadata sidecar binding its executable hash and protocol;
  generic shells, interpreters, missing metadata, and unsupported operations fail closed.
- Secrets must not be committed, printed in CI output, or copied into test fixtures.
- GitHub Actions must use full commit SHAs and least-privilege permissions. Candidate-owned GitHub/GitLab
  workflow jobs are evidence only, never protected required-check authority; an immutable external or
  protected-default-branch verifier (and GitLab Pipeline Execution Policy/compliance pipeline) must inspect
  candidate bytes as untrusted data. OIDC publication jobs must execute only pinned external actions and
  exact verified artifacts, never candidate project commands or inline candidate-controlled scripts.
- Private candidate copies isolate the bytes hashed for a receipt, but they are not an OS filesystem,
  network, or hostile-process sandbox. Provider release policy must supply any required OS containment.
- Linux cleanup uses pidfds when available. macOS has no equivalent unprivileged pidfd: cleanup follows exact PID/start identities, descendants, launch sessions, and an unguessable inherited launch token; it signals only individual matching PIDs and re-observes after each step. A newly observed identity is signalable only after two stable identity snapshots and matching launch-session observations; an identity that cannot be attributed this way is non-cleanable, while unrelated same-UID processes are neither evidence nor signal targets. Numeric process-group signaling (including `killpg`) is prohibited; PGID/session inventory is attribution evidence only, and the unreaped leader prevents identifier reuse until all launch identities are clean. Observation plus numeric-PID signaling is not an atomic kernel handle and is not claimed as hostile-process confinement; deployments that require that guarantee must use an OS supervisor/sandbox outside this template.
- Manually dispatched deployment inputs must enter shell steps through environment
  variables, pass strict validation, and remain quoted.
- A skipped required capability is a failure, not a passing security signal.
