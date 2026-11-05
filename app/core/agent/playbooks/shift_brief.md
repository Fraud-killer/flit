---
name: shift_brief
description: What happened since the last shift, for the analyst coming on
trigger: schedule
max_mode: propose
max_turns: 10
tools: queue_stats, list_decisions, decision_detail, block_streak, recall_memory, report_findings
---
Write the brief an analyst reads when they sit down.

1. `queue_stats` for the window you were given (default 12 hours).
2. If blocks or cases rose, `list_decisions` with level high or critical for the window, and `decision_detail` on the two that matter most.
3. `recall_memory` for anything in the top factors.

Verdict `informational`. The summary is the brief: what moved, what is waiting (approvals, high-priority cases, fired monitors), what to look at first. Three to six sentences. Findings only for things that need a person today, each with the actor and the evidence.
