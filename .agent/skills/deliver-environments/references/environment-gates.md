# Environment Gates

- Local failure returns to implementation or adapter setup and must still clean processes.
- Test failure never promotes; fix, rebuild once and re-run the affected integration chain.
- Production failure stops rollout, runs the pre-approved rollback, verifies recovery and returns the root cause to solution or implementation.
- Secrets stay in the environment provider; templates contain names, never values.
- Production approval cannot be inferred from a successful test deployment.
- Production readiness cannot be inferred from local branch patterns or generated CI/CD files. The exact provider/repository/default branch/environments/checks/reviewer minimum must first be part of the human-approved requirement contract, not only TASK.
- After test acceptance, production cannot request human release approval until a dedicated OS-protected read-only provider adapter verifies a fresh content-addressed receipt. The receipt proves default-branch reachability and successful provider check runs for the exact artifact source revision, plus effective protection and environment reviewers. Missing access/adapter pauses for a human; missing controls return to provider setup and must be re-read before promotion.
- Human production approval signs the complete deployment-decision packet, not a free-text artifact label. Any provider receipt, artifact, test summary, repository, branch or environment drift invalidates approval and blocks promotion.
- Migration from delivery v2 never reissues old terminal production history. `legacy_promoted`, `legacy_rollback_required` and `legacy_rolled_back` preserve a lossless archive with `assurance=legacy`, cannot call `promote`, and cannot generate a new Node8 release receipt.
