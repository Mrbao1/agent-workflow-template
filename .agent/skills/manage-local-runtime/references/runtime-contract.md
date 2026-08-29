# Runtime Adapter Contract

Each adapter declares start command, readiness condition, public URL, required dependencies, bounded logs, test command, graceful stop, forced stop, cleanup verification and forbidden external effects.

Docker projects must start with `agent_` and record their absolute working directory and Compose files. Process adapters record PID, PGID, start time, command and cwd; a port record must reference its already registered owning PID and use loopback TCP. Identity mismatch fails closed. Registry writes use an exclusive lock and atomic replacement. Never delete volumes unless the requirement contract identifies disposable test data and exact targets.

Foreground review tools are not product adapters and must be launched and attributed by the Agent platform. A local process cannot authenticate a platform Agent with an ID or mutable ledger bytes, so `agentctl.py tool-run` is disabled and never executes caller argv. `.agent/state/tool-leases.json` remains only as a fail-closed migration and cleanup surface for leases left by older releases: malformed, expired, orphaned, or identity-mismatched records block cleanliness, and cleanup may signal only their exact recorded process identities. Platform-supervised review processes are not converted into local product-runtime authority; unrelated project processes remain baseline deltas.
