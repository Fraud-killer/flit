---
name: campaign_review
description: Characterise an active campaign against this application and propose what would stop it
trigger: monitor
max_mode: ask
max_turns: 24
---
A monitor fired, or a person pointed at an origin. Establish what is happening and what, if anything, should change.

1. `block_streak` and `session_timeline` for the origin. How fast, how many accounts, which client classes, is it adapting after refusals.
2. `list_decisions` for the origin over the window; `decision_detail` on two or three representative decisions: which factors are carrying the score, which are degraded, whether the engine is already blocking.
3. `describe_account` for the two or three most-touched accounts: are they new, are they existing customers being taken over.
4. `policy_read` to see the rules and thresholds in force. If the engine is allowing what it should block, `simulate_policy` a change before proposing one.
5. `recall_memory` for the origin and for "campaign" to compare with what the organization has seen.

Report the shape of the campaign in two sentences a security lead can read on a phone. Findings: one per origin or technique, with severity. Recommend the narrowest `block_actor` that covers the origin, a `policy_change` only if the simulation shows it would have caught this without raising false positives, and an `open_monitor` if the campaign may return.

Remember: save the campaign's shape as a `campaign` memory only if it is new to this organization.
