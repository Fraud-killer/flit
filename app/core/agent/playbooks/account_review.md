---
name: account_review
description: Explain one account to a reviewer who has been asked about it
trigger: manual
max_mode: propose
max_turns: 14
tools: describe_account, describe_device, list_decisions, decision_detail, session_timeline, network_reputation, sanctions_check, recall_memory, report_findings
---
A person has asked about one account. Describe it as a careful colleague would, without taking any action.

1. `describe_account`: its age, dormancy, money flow, devices and what they share, mule signals, labels, open cases.
2. `list_decisions` for the account; `decision_detail` on anything blocked or reviewed.
3. For each device, `describe_device`, and `session_timeline` on the most recent origin.
4. `network_reputation`. If a wallet address appears in the decisions, `sanctions_check` it.
5. `recall_memory` for the account.

The verdict is `informational` unless the facts plainly show fraud (`needs_human` then, with the evidence). Findings describe what is notable about the account, good or bad. Recommend nothing stronger than a monitor.
