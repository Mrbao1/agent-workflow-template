# Budget Policy

- Fast: one Skill, one reference, no sub-agent, targeted validation.
- Standard: one primary Skill, up to three references, and at most one child Agent only when risk or the user requires independent review.
- Release: up to six references and at most two active child Agents while reserving one root slot; dependent adversarial, cross and integrator review stages remain serial.

Token budgets are routing thresholds, not a reason to skip correctness gates or end the task. When exceeded, compact or split at a stable artifact boundary, publish the exact resume contract and continue from the canonical node. After compaction and before any final reply, `workflowctl route-resume` decides whether the root task is terminal; `terminal=false` forbids a completion claim.

Default routing ceilings are `fast=16000`, `standard=48000`, and `release=96000` tokens. They are capacity limits, not spending targets: work still stops loading optional references at 60%, compacts at 75%, hard-blocks at 90%, uses one automatic test attempt in fast/standard, and keeps mode-specific wall-time limits. Raising a ceiling must never increase test repetition or Agent fan-out. The ceilings were rebalanced after measuring this governance stack: mandatory bootstrap reading costs ≈5,238 tokens and entering clarification ≈6,716 tokens, which was 56% of the former fast ceiling (12,000) before any business file was read.

## Estimated vs measured

Unless a provider-signed usage receipt says otherwise, every number in the ledger is an **estimate**, calibrated per host:

- `context.bootstrap_overhead_tokens` (default `7000`): the one-time startup cost of mandatory bootstrap reading, from user measurement (≈6.7k entering clarification). It is charged **once per task** as a floor on root consumption in the unified account — declared or measured usage above the floor already contains it, so it is never added twice. Calibrate it per host/provider.
- `context.estimated_turn_overhead_tokens` (defaults `fast=2000`, `standard=3000`, `release=4000`): the estimated **per-turn host overhead** — host system-prompt replay plus turn cost. A bootstrap that costs ≈6.7k over the initial reads implies multi-thousand-token system prompts replayed every turn; the old `automatic_transition_token_increment` constants (150/300/500) were fiction. Every recorded root transition raises the active-window floor by this overhead **plus** `agent_control.inherited_turn_estimated_tokens` (default `800`, the inherited host context also charged per fork turn at child dispatch). The deprecated `automatic_transition_token_increment` key remains an accepted alias and keeps its exact legacy arithmetic (bare increment, no inherited surcharge) so existing configs do not break.
- Child margins: `child_system_tool_margin_tokens` (default `4000` — a real host system prompt plus tool definitions is nowhere near the old 1,000), `child_output_margin_tokens` (default `2000`), and per-mode `dispatch_payload_token_limits` (`fast=0`, `standard=16000`, `release=32000`; zero means the mode permits no children).
- **Measured** beats estimated: when TASK carries at least two provider-observed cumulative `usage_receipts`, the delta between the latest two is real per-period growth and replaces the configured transition estimate. `measured` remains a trust claim requiring a content-addressed `agent-usage-receipt/v2` verified by an OS-protected host adapter; caller-authored counters stay `estimated`.

## The arithmetic invariant (fail-closed)

Capsule validation rejects any config where one permitted operation deterministically crosses the hard watermark. For every configured mode:

```
max_child_charge(mode)   = dispatch_payload_limit(mode) + child_system_tool_margin + child_output_margin
baseline_overhead(mode)  = bootstrap_overhead + estimated_turn_overhead(mode) + inherited_turn_estimated_tokens
require: max_child_charge(mode) + baseline_overhead(mode) < hard_budget_ratio × token_budget(mode)
```

With the shipped defaults: fast `0 + 9,800 = 9,800 < 14,400`; standard `22,000 + 10,800 = 32,800 < 43,200`; release `38,000 + 11,800 = 49,800 < 86,400`. A single fully-charged standard child at dispatch (`7,000 bootstrap + 22,000 charge = 29,000 = 60.4%`) reaches only the soft watermark, not must_compact. The check fails closed and names the offending fields; it runs in `contextctl` capsule validation (`workflowlib/budget.py::config_budget_errors`).

## Watermarks and the two accounts

Capsule thresholds are separate from total task usage: soft 60%, compact 75%, hard 90%. Every checkpoint carries an explicit estimate bound to that checkpoint sequence and TASK invariant. Expansion uses the stricter of this fresh estimate and canonical TASK usage, so a stale low TASK counter cannot bypass compact or hard routing. Total usage must state whether it is measured by the host/platform or estimated; never record an unknown value as measured zero.

Canonical transitions advance the active-window estimate monotonically by the per-turn overhead (or the measured receipt delta); they may never reset an active session to a caller default. A lower active estimate is valid only after a deliberate compaction handshake — `contextctl sync --host-compaction` with a verified host receipt — and the checkpoint reason and summary must disclose the reset; lowering an estimate by re-asserting a smaller number is not a compaction. Compaction resets only the **active-window** gate: the cumulative TASK/provider cost account is untouched by it and still blocks at its own budget thresholds. Only a provider receipt whose semantics explicitly measure the current active window may replace that estimate; ordinary cumulative receipts cannot.

TASK hot state is independently bounded at four rollback entries and eight failure signatures by default. Older cumulative history is content-addressed rather than repeated in every prompt. Active evidence targets 4 MiB; after a 24-hour safety window, old unreachable evidence may be archived in verified deterministic chunks of at least 256 KiB. Preview first, preserve all reachable evidence, and retain a bounded restorable index.
