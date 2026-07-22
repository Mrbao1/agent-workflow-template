# Node Contracts

Read only the active node.

| Node | Input | Output | Gate | Return |
|---|---|---|---|---|
| 0 Bootstrap | project and task | guards, mode, budget, adapters | constraints known | missing material |
| 1 Clarify | raw request | approved requirement contract | `requirements_clarified=true` with user source | stay at 1 |
| 2 Structure | approved contract | roles, flows, data, errors, provenance | no inference used as fact | 1–2 |
| 3 Deliverables | structured requirement | items, exclusions, batches | each item testable | 1–3 |
| 4 Solution | approved scope | architecture, templates, small task graph | interfaces, risk, ownership clear | 3–4 |
| 5 Tests | solution | normal, error, boundary and regression expectations | failure is observable before code | 4–5 |
| 6 Implement | tasks and prewritten tests | mode-specific execution receipt and minimum closed loop | declared checks ran under the supervised runner; no runtime residual or unapproved assumption | 4–6 |
| 7 Accept | integrated artifact | targeted, independent, or live-adapter evidence by mode | success criteria and the exact review policy are bound | root cause node |
| 8 Deliver | accepted artifact | environment promotion, verification, rollback, compacted knowledge | environment gate and human production approval | 4–8 |

## Mode projection

- Fast projects nodes 2–6 into one machine receipt after node 1, then runs targeted node 7 evidence; it never renders unavailable standard templates.
- Standard uses nodes 1–7, keeps one task graph, binds solution/acceptance human decisions and adds independent review only when selected.
- Release uses all nodes and `.agent/skills/run-full-chain-acceptance/SKILL.md`; node 7 requires an implemented adapter's live receipt.

The stage index records `Mode`. Only `release` may require the strict live release gate; `fast` and `standard` must escalate mode first instead of silently running the heaviest path.

Projection never bypasses clarification, observable validation, local cleanup, production approval or root-cause rollback.
