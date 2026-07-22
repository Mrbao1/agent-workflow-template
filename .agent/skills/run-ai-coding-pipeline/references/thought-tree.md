# Adaptive Thought Tree

```text
request or resume
├─ run workflowctl route-resume; consume exactly one machine route
├─ canonical TASK/context/stage bindings valid? no → repair with evidence; stop
├─ requirement contract approved by a human? no → node 1 clarify-task; stop
├─ unresolved fact/assumption changes scope, acceptance or risk? yes → ask human; stop
├─ budget hard_blocked? → cleanup, split or human decision; stop
├─ budget must_compact? → verified compact handoff + unload stale references; re-read index and continue
├─ repeated same-root-cause failure?
│  ├─ second → return to node 4 solution/re-split
│  └─ third → waiting_human; stop
├─ choose or escalate mode from risk/size/environment
│  ├─ reversible, ≤2 files, one system, local only → fast projection
│  ├─ normal feature/bug/refactor → standard
│  └─ cross-system/data/security/migration/deployment/production → release
└─ route the current node from canonical TASK; stage index is output only
   ├─ 0 init → guards, knowledge, environment, Skills and pending decisions
   ├─ 1 clarify → human requirement gate; no downstream work before approval
   ├─ 2 structure → source-tag facts and expose AI inferences
   ├─ 3 deliverables → scope, batch and per-item acceptance
   ├─ 4 solution/tasks → first-principles design, boundaries and dependencies
   ├─ 5 tests → normal/error/boundary/security/performance/rollback or return 4
   ├─ 6 implementation → smallest closure, integrate, self-check and cleanup
   ├─ 7 acceptance → reuse candidate receipt → targeted adversarial → six-lens cross → one integrator replay; human gate
   └─ 8 delivery → environment-specific promote/rollback/observe/retrospective
```

Before every node, read canonical TASK and choose exactly one transition: `continue`, `return-node`, or `waiting_human`. Use the stage index only to diagnose a generated projection mismatch. A transition must name its input, output, gate, failure destination and reusable evidence. Templates come from the approved contract, mode and capability registry, not from a fixed universal bundle. Escalate on uncertainty, irreversible data, permissions, external users, migrations, production or repeated failure. Failure returns to the nearest node that owns its cause; implementation errors return to 6, missing tests to 5, an unworkable design or second same-root failure to 4, unclear scope to 3, provenance ambiguity to 2, and unclear intent to 1.

Compaction, a child Agent terminal result, a reviewer FAIL and an empty child set are never root-task terminal conditions. After each child terminal event, after every compaction and immediately before every final reply, the host must invoke `python3 .agent/scripts/workflowctl.py route-resume` and follow `TASK.current_node`/`next_action`. The repository can make this decision deterministic and recoverable, but only the host scheduler can start another model turn; a host turn ending is not task completion. The route may report `compact`, `continue`, `waiting_human`, or `complete`; `complete` is legal only for `status=accepted,current_node=idle` with a verified `complete-task` context checkpoint. `terminal=false` forbids a completion claim, and no other state may be presented as finished.
