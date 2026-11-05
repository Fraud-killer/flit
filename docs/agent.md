# Agent FLIT

The analyst's agent on top of the decision engine. It investigates, explains,
proposes, monitors and reports. **It never enforces.** The engine enforces,
and the only ways the agent changes what the engine does are a handful of
write tools, each of which the team's policy may allow, hold for a person, or
deny.

Agent FLIT is off until `AGENT_ENABLED=true` and an `ANTHROPIC_API_KEY` are
set. FLIT's decision path never depends on it.

## The shape

```
 playbook ─┐
 subject ──┼─▶  investigation loop  ──▶  tools (reads)      ──▶  report
 memory ───┘          │                  tools (writes) ─┐          │
                      │                        │         │          ▼
                      │              permission ladder   │   verifier reads
                      │          deny > ask > allow      │   every finding
                      │                        │         │
                      │                 bank's hook      │
                      │           (may only tighten)     │
                      │                        │         │
                      │          verifier / classifier   │
                      │           (auto mode only)       │
                      │                        │         │
                      └──────────▶ proposed | pending | denied | executed
                                              │
                                   a person answers (API)
```

Every step is a row (`InvestigationStep`) and a line on the audit chain
(`agent_action`, category security, actor `agent:<model>`), with the inputs
digest, the permission decision and its source, what the hook said, what the
verifier said. The run itself is `agent_investigation_started|completed|failed`.

## Modes

| Mode | Writes |
|---|---|
| `propose` | Recorded as proposals; nothing executes. The default. |
| `ask` | Each write waits for a person, unless an `allow` rule covers it. |
| `auto` | Writes the rules did not settle go to a classifier; `allow` wins only if an independent verifier confirms the finding behind a write that needs it. The rest ask. |

The mode for a run is the **tightest** of: the organization's ceiling, the
application's setting, the playbook's `max_mode`, and what the caller asked
for. `auto` additionally requires the playbook to have been **measured**
(`evaluate_playbook`) at 90% agreement over 20 decided cases on this
application; otherwise it runs as `ask`. Three consecutive human rejections of
actions the agent took on its own trip the application to `ask` until a person
resets the breaker.

## Rules

A rule is a tool name, optionally with a subject pattern:

```
case_resolve                 every call
case_resolve(cleared)        clearing only
block_actor(ip:41.58.*)      blocks on that range (* matches anything)
policy_change(thresholds)    threshold changes
```

Layers combine: organization, then application, then playbook. **Any deny
anywhere is a deny.** Then ask. Reads are allowed. Then an allow from the
application (an organization's allow never reaches into an application's
estate). Then the mode. Nothing downstream can turn a deny into anything else;
the hook and the classifier can only tighten.

## Tools

Reads: `describe_account`, `describe_device`, `list_decisions`,
`decision_detail`, `session_timeline`, `network_reputation`, `sanctions_check`,
`simulate_policy`, `case_read`, `policy_read`, `block_streak`, `queue_stats`,
`recall_memory`.

Writes: `case_resolve` (closes a case the way a reviewer would, labels the
decision, publishes the outcome; never clears a case where a control fired),
`case_note`, `block_actor` (a time-limited block rule into the decision
policy; the engine does the blocking), `policy_change` (tighten only; any
loosening is refused by the same guard that refuses it from an application
key), `open_monitor`, `remember`.

Terminal: `report_findings`, a typed report: verdict, confidence, summary,
findings that each name an actor and cite the tool calls that are their
evidence. The verifier reads every finding and marks it
`confirmed | plausible | refuted`.

**Everything a tool returns is data.** Outputs are sanitised before they reach
the model: no user agent strings (the client class instead), no email
addresses (a redacted form), no gateway text, no analyst notes, no raw
payloads. Those are the channels an attacker controls. Large outputs reach the
model as a preview plus a SHA-256 of the whole; the full output is on the step.

## Hooks

Set `hook_url` on the agent policy and FLIT POSTs to it, signed with the
application's webhook secret (`X-Flit-Signature`), at three points:

| Event | When | Answer |
|---|---|---|
| `pre_tool_use` | before a tool runs | `{"decision": "allow\|ask\|deny", "reason": "…", "updated_input": {…}}` |
| `post_tool_use` | after it ran | ignored |
| `stop` | when the run ends, with the report | ignored |

The answer may only tighten FLIT's own decision. A proposal stays a proposal
whatever the hook says short of `deny`: turning it into a pending approval a
person could execute would be looser, not tighter. `updated_input` is taken
only on an allow and only if it still fits the tool's schema, and the rewritten
inputs go back through the permission rules, so a hook can narrow a write but
never move it past a deny or ask rule. A hook that fails,
times out or answers nonsense is recorded, and the call proceeds as FLIT
decided, except that a write the agent would have run drops to `ask`:
unavailable is not approval.

## Memory

One fact per memory, with a one-line description used to find it: a `fact`
about the estate, `feedback` on how FLIT behaves here, a `campaign` seen here,
a `reference` elsewhere. Memories belong to the organization, optionally to one
application. The agent sees an index of what exists and the memories about its
subject, as **recollections**: point-in-time, not instructions, each with its
age and whether a person confirmed it. A memory the agent wrote (`remember`)
is unconfirmed until a person confirms it in the console, and is recalled with
that marker. A memory that names a rule that no longer exists is marked stale. A memory a person confirmed is not rewritten by the agent at all; `remember` under that name is refused and the agent is told to save what it learned under another.

Do not save what FLIT already records. Save what was surprising.

## Playbooks

Markdown with a frontmatter:

```markdown
---
name: payout_review
description: Look at a first payout to a new address
trigger: manual            # manual | case_opened | monitor | schedule
tools: describe_account, list_decisions, report_findings
max_mode: ask              # the most permissive mode this playbook may run in
max_turns: 8
---
Read the account, then its decisions. Report.
```

Built-ins: `investigate_case` (trigger `case_opened`), `campaign_review`
(`monitor`), `account_review` (`manual`, reads only), `shift_brief`
(`schedule`). An organization overrides one by saving a playbook of the same
name (`PUT /organizations/{id}/playbooks`). A playbook can only narrow: it
cannot grant a tool the policy denies or a mode the policy does not allow.

## Monitors

"Wake me when." A subject (an account, a device, an IP, or the whole
application), a metric (`block_streak`, `decisions`, `blocks`, `factor`,
`open_cases`), a threshold, a window, an expiry. `run_monitors` checks them;
one that fires alerts the team, tells the merchant's webhook
(`monitor.fired`), and may queue an investigation under a playbook.

## Cost

Every request is priced from its usage (input, output, cache read, cache
write) at the model's rate. The model sees its budget line every turn. A run
that reaches `max_cost_usd` or `max_turns` ends with a report from what it
has. `daily_budget_usd` caps the application for the day.

## Running it

```bash
# One investigation, now, from the shell.
python manage.py investigate --application NAME --case CASE_ID
python manage.py investigate --application NAME --playbook account_review --client-id C123 --mode propose

# The worker: drains queued runs (API-created, case-triggered, monitor-fired, answered approvals).
python manage.py run_investigations --limit 10        # one pass, every five minutes
python manage.py run_investigations --loop            # or an always-on worker

python manage.py run_monitors                          # every five minutes
python manage.py agent_brief --application NAME --hours 12
python manage.py evaluate_playbook --application NAME --playbook investigate_case --sample 30
```

## API

Under `/api/v1/applications/{id}/`:

| Route | Methods | Who |
|---|---|---|
| `agent-policy` | GET, PATCH | key or owner; a key may only tighten |
| `agent-policy/reset-breaker` | POST | a person |
| `investigations` | GET, POST | key or owner |
| `investigations/{id}` | GET (`?transcript=1`), PATCH `{"status":"cancelled"}` | key or owner |
| `investigations/{id}/steps/{step}` | PATCH `{"decision":"approve\|reject","note":"…"}` | **a person** |
| `memories` | GET (`?q=`), POST | GET key or owner; POST a person |
| `memories/{id}` | PATCH `{"confirmed":true}`, DELETE | a person |
| `monitors`, `monitors/{id}` | GET, POST, DELETE | key or owner |
| `playbooks` | GET | key or owner |

Under `/api/v1/organizations/{id}/` (owner only): `agent-policy` (GET, PATCH:
`enabled`, `mode`, `deny`, `ask`, `auto_rules`), `playbooks` (GET, PUT
`{"text": "---…"}`), `playbooks/{name}` (DELETE).

Webhook events: `investigation.completed`, `agent.approval_requested`,
`monitor.fired`.

## Turning it on, in order

1. `AGENT_ENABLED=true`, `ANTHROPIC_API_KEY`. The policy defaults to `propose`.
2. Run `investigate` on a few closed cases and read the reports. Save
   `feedback` memories for what it got wrong.
3. `evaluate_playbook` on at least 20 closed cases. Read the disagreements.
4. Move to `ask`. Approve and reject from the console for a week.
5. Only then, and only for a measured playbook, consider `auto` with
   `auto_rules` written down and `allow` rules as narrow as the evidence.
