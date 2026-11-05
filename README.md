# FLIT — Protecting Money in Motion

> **"Stripe increases the world's GDP. Flit protects the world's money."**

**No merchant or customer should lose money to fraud that could have been prevented.**

FLIT is a real-time fraud decision system — a loss-prevention layer for digital commerce. We don't process payments. We make sure the transactions that *shouldn't* happen... don't.

---

## The Problem We Solve

Fraud today is treated as:
- A **cost of doing business**
- A **post-transaction problem**
- A **chargeback or dispute workflow**

**FLIT flips that model.**

Fraud is not a payments problem. It's a **decision-quality problem at the moment of transaction**. Merchants don't lack tools — they lack **real-time certainty**.

---

## What FLIT Is

| ❌ What FLIT Is *Not* | ✅ What FLIT *Is* |
|----------------------|-------------------|
| Another payments processor | A **loss-prevention layer** for digital commerce |
| A chargeback recovery tool | A **real-time fraud decision system** |
| A rules engine merchants babysit | A **shared protection network** between merchants and customers |

Think: **"Cloudflare, but for fraud."** — **"Seatbelts, not ambulances."**

---

## Why This Matters

- Global fraud losses → **$40B+ annually**
- Fraud grows faster than GDP
- AI has made fraud cheaper, faster, and harder to spot
- Regulators increasingly shift liability to merchants

**FLIT isn't optional. It's inevitable.**

---

## What FLIT Detects, and How Well

FLIT maps its detectors onto the **[MITRE Fight Fraud Framework (F3)](https://github.com/center-for-threat-informed-defense/fight-fraud-framework)** — the fraud taxonomy MITRE's Center for Threat-Informed Defense published in April 2026 with JPMorganChase, Citigroup, Lloyds Banking Group, Standard Chartered and FS-ISAC.

We do not define our own vocabulary. A risk team can ask "which F3 techniques do you cover?" and get an answer in the language they already use.

**[COVERAGE.md](COVERAGE.md)** is that answer. It is generated from the registered rules — never written by hand — and CI fails if it drifts:

```bash
python manage.py coverage_matrix --out ../COVERAGE.md --json ../coverage.json
```

It reports three buckets, not two, because counting techniques FLIT has no telemetry for as "gaps" would be dishonest arithmetic:

| | Meaning |
|---|---|
| **Covered** | At least one detector claims the technique |
| **Addressable** | FLIT receives signals that could detect it, and does not yet — the roadmap |
| **Outside telemetry** | Happens where a server-side decision layer has no eyes, with the reason stated |

Every detector also declares where it sits on an **evidence ladder** — proposed, synthetic-tested, backtested, shadow-validated, production-observed, outcome-calibrated — and the test suite rejects any claim above `proposed` that cannot name the evidence behind it. From `backtested` upward the claim is numerical, so it must point at an entry in the evidence ledger written by the backtest harness, not at an assertion.

`Proposed` is not a criticism. It means a detector is reasoned from how the fraud works and has not yet been measured against labelled history. Publishing that honestly is the point: a fraud tool whose effectiveness numbers cannot be traced to a dataset is asking to be taken on faith.

---

## Features

### Core Security Capabilities

- **Device Fingerprinting** - Integration with Fingerprint.js for reliable device identification
- **Real-time Risk Scoring** - ML-ready weighted scoring engine with configurable thresholds
- **Transaction Monitoring** - AML/CFT compliance with customizable limits
- **Velocity Checks** - Detect rapid-fire requests and unusual activity patterns
- **Impossible Travel Detection** - Flag logins from geographically impossible locations
- **Account Takeover Prevention** - Multi-signal detection for compromised accounts
- **Credential Surface Monitoring** - Reset-to-login timing, scripted credential actions, and one origin working many accounts' resets (the October 2026 takeover pattern)

### Security Infrastructure

- **Rate Limiting** - Per-endpoint, per-user, per-IP throttling with automatic blocking
- **Replay Attack Protection** - Timestamp validation and nonce-based request deduplication
- **Request Validation** - Input sanitization, SQL injection prevention, XSS protection
- **Immutable Audit Logs** - Hash chain over every decision, verified nightly by `verify_audit_chain`
- **Bounded Decisions** - A latency budget per decision; a rule that hangs or raises is reported as unavailable, never a 500
- **Written Policy** - Block, review, challenge and allow rules a fraud team writes in plain terms, inherited from the organization, with an application key able to tighten but never loosen

### Intelligence & Detection

- **IP Intelligence** - VPN/Proxy/Tor detection, datacenter IP identification
- **Bot Detection** - Headless browser detection, automation fingerprinting
- **Behavioral Analysis** - Device trust scoring based on historical patterns

### Real-time Capabilities

- **WebSocket Alerts** - Instant fraud notifications via Django Channels
- **Configurable Alert Levels** - INFO, WARNING, CRITICAL, EMERGENCY
- **Multi-channel Subscriptions** - Per-application and per-organization alert streams

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         API Layer                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ Rate Limit  │  │   Replay    │  │   Request Validation    │  │
│  │ Middleware  │  │ Protection  │  │      & Sanitization     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                      Audit Engine                                │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Rule Processor                        │    │
│  │  • DeviceExpiredRule      • VelocityCheckRule           │    │
│  │  • NewDeviceCountryRule   • ImpossibleTravelRule        │    │
│  │  • UnregisteredDeviceRule • AccountTakeoverRule         │    │
│  │  • AmlCftLimitExceeded    • MaximumDebit/CreditRules    │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                     Risk Scoring Engine                          │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────┐    │
│  │   Weighted    │  │  Historical   │  │   Device Trust    │    │
│  │   Scoring     │  │   Context     │  │     Scoring       │    │
│  └───────────────┘  └───────────────┘  └───────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Real-time Alerts                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              WebSocket Alert Manager                       │  │
│  │         (Django Channels + Redis)                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.12+

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Fraud-killer/flit.git
cd flit

# Start services
docker-compose up -d

# Run migrations
docker-compose exec app python manage.py migrate

# Create superuser
docker-compose exec app python manage.py createsuperuser
```

The API will be available at `http://localhost:18000`

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis URL for channels | `redis://localhost:6379/0` |
| `CACHE_URL` | Redis URL for caching | `redis://localhost:6379/1` |
| `SECRET_KEY` | Django secret key | Required |
| `MCRYPT_KEY` | Encryption key for secrets | Required |
| `FINGERPRINT_SERVER_API_KEY` | Fingerprint server API key (optional second source of device identification) | Optional |
| `ALLOWED_HOSTS` | JSON array of allowed hosts | `["localhost", "127.0.0.1"]` in debug, `[]` otherwise |
| `SECURE_SSL_REDIRECT` | Redirect HTTP to HTTPS when not in debug | `true` |
| `TRUSTED_PROXY_DEPTH` | Proxies that append to `X-Forwarded-For` before FLIT; the client address is the Nth entry from the right | Unset (legacy first-entry reading) |
| `TRIAGE_ENABLED` | Let a model read the case queue (`manage.py triage`); needs `ANTHROPIC_API_KEY` | `false` |
| `TRIAGE_MODEL` | The model that reads cases | `claude-opus-5-5` |
| `AGENT_ENABLED` | Switch on Agent FLIT, the analyst's agent (see `docs/agent.md`); needs `ANTHROPIC_API_KEY` | `false` |
| `AGENT_MODEL` | The investigating model | `claude-opus-5-5` |
| `AGENT_VERIFIER_MODEL` | The independent reader of findings | same as `AGENT_MODEL` |
| `GEOIP_DB_PATH` | Directory containing `GeoLite2-ASN.mmdb` and `GeoLite2-Country.mmdb` | Unset (geolocation disabled) |
| `THREAT_LIST_URL` | Plain-text IP/CIDR blocklist | FireHOL level1 |
| `DEBUG` | Enable debug mode | `false` |

Copy `.env.example` to `.env` for local development; `docker-compose.yml` reads secrets from it.

### IP Intelligence Data

`IPReputationRule` combines three local sources with Fingerprint Smart Signals:

- **GeoIP**: download the free [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) ASN and Country databases and point `GEOIP_DB_PATH` at their directory. Lookups are local, so they add no network latency.
- **Tor exit nodes** and **IP blocklist**: stored in the shared cache (Redis) and refreshed by a management command. Schedule it, for example hourly via cron:

```bash
python manage.py refresh_threat_intel
```

Without these sources the rule still runs, falling back to coarse cloud-provider IP ranges and Fingerprint signals.

## API Usage

### Audit a Transaction

```bash
curl -X POST http://localhost:18000/api/v1/applications/{app_id}/audit-transaction \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}" \
  -H "Content-Type: application/json" \
  -H "X-Timestamp: $(date +%s)" \
  -H "X-Nonce: $(uuidgen)" \
  -d '{
    "id": "txn_123",
    "type": "debit",
    "client_id": "user_123",
    "visit_id": "fingerprint_request_id",
    "amount": 1000.00,
    "currency_code": "USD",
    "ip_address": "81.2.69.160",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
  }'
```

`ip_address` and `user_agent` are the **end user's** values. FLIT receives the request from your server, so it cannot see them itself. When omitted, the IP and user agent Fingerprint recorded for `visit_id` are used.

For mule detection, send `counterparty_id` (who the money came from or went to) and `account_age_days`. Counterparties are what turn "six credits" into "six different senders", which is the difference between a busy account and a collection point.

Payment rules also read optional payment fields when you send them: `status`, `gateway_message`, `provider_responses`, `card_fingerprint`, `card_bin`, `payment_instrument`, `browser_details`, `billing` and `shipping`.

### Response

```json
{
  "ok": true,
  "data": {
    "audit_id": "c27c2f50-04a9-49e5-bebb-893d0a59d8fc",
    "device_id": "cd71cec3-8aae-4425-9339-861ed71ef237",
    "risk_score": 0.35,
    "risk_level": "medium",
    "should_block": false,
    "should_review": false,
    "recommendation": "MONITOR: Moderate risk detected. Continue monitoring.",
    "confidence": 0.75,
    "factors": ["velocity_exceeded_per_hour"],
    "rules": ["VelocityCheckRule", "ImpossibleTravelRule"]
  }
}
```

Every audit is stored, which is what the velocity, account-takeover, historical-score and device-graph checks read. `audit_id` identifies that record, and `device_id` the device FLIT resolved for the event (`null` when no `visit_id` was sent).

Three more fields describe how the decision was reached. `degraded` lists any rule that raised or outlived the decision's latency budget (default 3 s, `Policy.latency_budget_ms`): the decision was made with what arrived, and says so. A control that did not run — sanctions screening, a limit — fails closed and sends the decision to review. `policy_matches` lists the written rules that fired (see *Policy* below). `block_streak` is how many consecutive blocks this origin has now had; the next event from it starts from that.

Two findings sit outside the arithmetic. A sanctions hit is a **hard block**: it does not care about a clean history or a lenient calibration. A control that could not run is a **forced review**: the score is untouched, and a human looks.

### Collect Device Signals (Browser SDK)

FLIT identifies devices itself through [`@flit/browser`](sdk/js/README.md). The page collects signals and exchanges them for a visit token:

```js
import { collect } from "@flit/browser";

const { visitToken } = await collect({ key: "flit_pk_..." });
```

```bash
# What the SDK posts. Public, unauthenticated, rate limited and CORS-open:
# the collection key identifies an application, it authorises nothing.
curl -X POST http://localhost:18000/api/v1/collect \
  -H "Content-Type: application/json" \
  -d '{"key": "flit_pk_...", "signals": { ... }, "device_key": "flit_dk_..."}'
```

Send the token to your server and include it as `visit_token` in the audit. Tokens last 30 minutes.

**Restrict who can use your key.** Set `Application.collect_origins` to the sites allowed to call `/collect` with it:

```json
["https://shop.example.com", "https://*.example.com"]
```

An unlisted origin gets 403 and no CORS headers, so the browser cannot read the refusal either. An empty list accepts any origin, so an integration keeps working until you lock it down. Requests with no `Origin` header (your own server, a native app) are not affected: the allowlist stops another *website* using your key, which is what browsers can enforce.

Identifying material is hashed in the browser and hashed again before storage, so no raw signal is ever written to the database. Devices are **not** linked across applications; each merchant sees only its own view.

A device is recognised by, strongest first: the same signature seen before, the device key the browser returned (only when the signals still broadly agree, so a copied key proves nothing), then a close-enough signal match. One heavy component such as canvas or WebGL may drift — after a browser update, say — and the device is still recognised; two may not.

`visit_token` (FLIT's own SDK) and `visit_id` (Fingerprint) can both be used; send whichever you have.

### Report an Outcome

Tell FLIT what actually happened. Labels are how thresholds get tuned, and they are the training data for scoring models.

```bash
curl -X POST http://localhost:18000/api/v1/applications/{app_id}/outcomes \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}" \
  -H "Content-Type: application/json" \
  -H "X-Timestamp: $(date +%s)" \
  -H "X-Nonce: $(uuidgen)" \
  -d '{"audit_id": "c27c2f50-...", "label": "fraud"}'
```

Labels: `fraud`, `chargeback`, `legit`, `false_positive`. Send `event_id` (your transaction id) instead of `audit_id` to label that event's most recent audit.

**Say what it cost.** Add `amount` and `currency_code` to report the loss as you measured it — after a partial recovery, say. Without them the transaction's own amount stands in. The amount is what the loss ledger and the calibrator add up; a label with no amount from either source is counted but never summed, so the money FLIT reports is a floor, not a guess.

### The Loss Ledger

FLIT exists to prevent money loss, so it keeps the number:

```bash
curl "http://localhost:18000/api/v1/applications/{app_id}/loss?days=30" \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}"
```

Per currency, from the outcomes you reported: `prevented` (fraud FLIT blocked while enforcing), `in_shadow` (fraud it would have blocked while not yet acting), `flagged` (fraud sent to review or challenge), `leaked` (fraud it allowed), `friction` (good customers it blocked), `net` (prevented minus friction) and `leak_rate`. Currencies are never converted or added together, and `counts.unpriced` says how many labelled decisions carried no amount. `python manage.py loss_report --application NAME` prints the same ledger.

The calibrator reads the same money. Beside the rate and recall guardrails, a weight change may not raise the money lost or turned away — one more false positive within the rate tolerance can be a wire, not a coffee — and every calibration run reports `loss` before and after in the application's currency.

### Review Decisions

Every decision is queryable, and anything that comes back for review opens a **case**.

```bash
# The decision feed. Filter by level, label, factor, client_id, device_id,
# days, unlabelled=1.
curl "http://localhost:18000/api/v1/applications/{app_id}/decisions?factor=multi_accounting&days=7" \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}"

# The review queue (status=open by default; `all` for everything).
curl "http://localhost:18000/api/v1/applications/{app_id}/cases" \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}"

# Closing a case labels the decision behind it: confirmed_fraud -> fraud,
# cleared -> legit. This is where most training data comes from.
curl -X PATCH "http://localhost:18000/api/v1/applications/{app_id}/cases/{case_id}" \
  -H "Content-Type: application/json" \
  -d '{"status": "confirmed_fraud", "note": "Card testing"}'
```

One case per campaign, not per decision. Decisions from one origin — a device, or an address when there is none — in a day land on one case, which counts them (`decision_count`, `campaign_key`, `last_decision_at`). A blocked decision, or an origin blocked three times running, opens or raises the case to `priority: high`; the queue sorts high priority first. Three consecutive blocks from one origin also raise a `campaign_detected` alert on the stream.

### Policy

Decisions a person has already made, applied before the score:

```bash
curl -X PATCH "http://localhost:18000/api/v1/applications/{app_id}/policy" \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}" \
  -H "Content-Type: application/json" \
  -d '{
    "thresholds": {"block_at": 0.65},
    "rules": {
      "block":     [{"subject": "cidr", "pattern": "203.0.113.0/24", "reason": "known actor"}],
      "challenge": [{"subject": "asn", "pattern": "AS14061"}],
      "allow":     [{"subject": "client_id", "pattern": "partner-*", "expires_at": "2026-12-31T00:00:00Z"}]
    },
    "disabled_rules": ["DeviceExpiredRule"]
  }'
```

Subjects: `ip`, `cidr`, `country`, `asn`, `email_root`, `email_domain` (`*.example.com` covers subdomains), `device`, `client_id` (glob), `wallet`, `counterparty`, and `factor` — a rule code the decision produced, so `{"subject": "factor", "pattern": "campaign_motif"}` blocks on a finding. Order of precedence: **block > review > challenge > allow**. A block is a hard block. An allow waives only the review and challenge the *score* asked for; it never overrides a block, and it never silences a control that did not run.

`disabled_rules` switches a rule off for this application without a deploy; every decision records which rules sat out.

**Direction matters.** An application key may make FLIT stricter. Only a signed-in owner of the organization may make it looser — raise a threshold, remove a block rule, add an allow, disable a rule, lower a weight. A loosening from an application key is refused with `policy_loosening_forbidden`, and every change, either way, is written to the audit chain (`policy_updated` or `policy_loosened`).

**Organizations.** A bank with many applications sets the estate's policy once:

```bash
curl -X PATCH "http://localhost:18000/api/v1/organizations/{org_id}/policy" \
  -H "Authorization: Bearer {owner_jwt}" \
  -d '{"rules": {"block": [...]}, "max_block_at": 0.7, "required_enforcement": "enforcing", "disabled_rules": []}'
```

Every application inherits the organization's rules and cannot remove them; its thresholds are capped at the organization's ceiling; `required_enforcement` makes every application enforce whatever its own setting says. An application may always be stricter than its organization, never looser.

**Calibration rollback.** `python manage.py calibrate --rollback <run_id>` undoes an applied run, restoring every weight it moved. `GET /calibrations` shows the reversal beside the original.

**The protection network.** `network_fraud_history` fires when at least two other *organizations* (two applications under one owner are one witness) confirmed fraud or a failed challenge on the actor's identity keys in the last 180 days. Failed challenges expire with that window like fraud does. A merchant who reported the actor legit, or a challenge they passed, counts against the history in proportion; enough of them and the network says nothing. The verdict grades itself: two organizations is a challenge, three a review, four on the actor's own keys a block. History that sits only on an IP or an ASN is capped at a review, because one address is many people.

**Rules in shadow.** `shadow_rules` lists rules that run but do not count. Their findings are kept under the decision (`shadow` in the response and in history) and measured by `python manage.py shadow_report --application NAME --days 14`: fires, labelled fraud and legit, precision, lift, and how often the live decision agreed. `--record-evidence` writes the measurement into the evidence ledger, which is how a proposed rule earns the shadow-validated rung against live traffic without acting on anyone. Moving a rule into shadow is a loosening, so an application key cannot do it.

### Webhooks and the Decision Hook

What happens after the response reaches you signed, with retries:

```bash
curl -X PATCH "http://localhost:18000/api/v1/applications/{app_id}/policy" \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}" \
  -d '{
    "webhook": {"url": "https://you.example/flit", "secret": "whsec_…", "events": ["case.opened", "campaign.detected"]},
    "decision_hook": {"url": "https://you.example/decide", "timeout_ms": 150},
    "challenge_method": "otp"
  }'
```

Events: `decision.blocked`, `decision.review`, `case.opened`, `campaign.detected`, `challenge.passed`, `challenge.failed`, `calibration.applied`, `policy.loosened`. Leave `events` out for all of them. Each delivery is a row with backoff (30 s doubling to an hour, eight attempts, then parked as dead), drained by `python manage.py deliver_webhooks`, and carries:

```
X-Flit-Event:      case.opened
X-Flit-Delivery:   <delivery id>
X-Flit-Signature:  t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>
```

Verify by recomputing the HMAC over `"<t>.<raw body>"` with your secret, comparing in constant time, and refusing a `t` more than five minutes old. URLs must be https and may not point at a private, loopback or link-local address; every outbound call FLIT makes goes through the same guard, and a hostname that resolves inside the network is refused at connection time.

**The decision hook** is your own logic, consulted before a decision is final: FLIT posts the decision it is about to return, your endpoint answers `{"decision": "allow|review|challenge|block", "reason": "…"}`. The vote only goes one way. A hook may turn an allow into a review, a review into a challenge, a challenge into a block; it may not loosen anything, because the hook is reachable with the application key and a leaked key that could whitelist its own traffic is the attacker's dream integration. A hook that times out or errors is recorded on the decision (`hook`) and ignored.

**Engine-issued challenges.** With `challenge_method` set (`otp` or `turnstile`), a decision that asks for a step-up issues the challenge itself and returns it under `challenge` (the OTP code appears there once and is never stored). Verify it as usual, then replay the original event with `challenge_id`; the replayed decision carries `challenge_passed`, waives the step-up and discounts the score. A cleared challenge may be presented three times within fifteen minutes, for the same account, and never moves a block, hard or scored: the discount applies only under the block line. A pass also lands on the actor's own identity keys (device, signature, email, wallet; never the IP or ASN), so their next event in the day sees `recent_challenge_passed` without a challenge id. Any confirmed fraud or failed challenge on those keys since voids it: a pass is a receipt for one moment, not a character reference.

**One spelling per identifier.** Account ids, emails and addresses are brought to a canonical form before anything compares them: NFKC with invisible characters removed, `googlemail.com` folded into `gmail.com`, IDNA domains, an IPv4 address written as IPv6 read as the IPv4 address. A local part that mixes alphabets (`pаypal` with a Cyrillic а) is reported as `confusable_email_spelling`.

### A Second Reader for the Queue

With `TRIAGE_ENABLED=true` and an `ANTHROPIC_API_KEY`, a model reads the open cases and proposes a verdict beside the human's:

```bash
python manage.py triage --application "Figo"            # shadow: propose, store, act on nothing
python manage.py triage --application "Figo" --report   # how proposals have agreed with reviewers
python manage.py triage --application "Figo" --apply    # auto-clear, only under the guardrails
```

The leash is short by design. The model sees **structured facts only**: codes and weights, thirty-day money flow, shared devices, the session's shape, labels on record. Nothing a user typed reaches it: no email local part, no user-agent string, no gateway message, no reviewer note, because those are the channels an attacker controls. It answers a fixed schema (`confirmed_fraud`, `cleared`, `needs_human`, a reason, a one-paragraph `summary` the queue shows), and anything else, a refusal, an error, text that is not the schema, is `needs_human` marked unavailable. A `cleared` verdict is read twice, at low effort then high, and the two must agree; a case where a control fired is never cleared.

Auto-clearing is a separate switch that only opens when the measurement has earned it: at least 100 `cleared` proposals closed by a human, blind (the proposal is hidden on open cases), at precision 0.99 or better, a daily cap of 200, and a circuit breaker that trips after three auto-cleared cases later shown to be fraud, whether a reviewer reopened them or a fraud or chargeback outcome arrived through `/outcomes` (`--reset-breaker` to resume). An auto-clear closes the case and nothing else: it writes no label, trains no weight and reaches no other merchant until a person closes the case. Clearing is the only verdict FLIT will ever act on by itself.

### Agent FLIT

The analyst's agent on top of the engine. Point it at a case, an account or an origin and it works the playbook: reads the account, the device, the session, the network, the policy; reaches a verdict; files a typed report whose findings cite the tool calls behind them, each re-read by an independent verifier. It never enforces. Its few writes (close a case, add a time-limited block rule, tighten policy, open a monitor, remember a fact) go through a permission ladder (deny > ask > allow, organization over application over playbook), then your own hook, then, in auto mode, a classifier; anything undecided waits for a person in the console. Every step is on the audit chain.

```bash
POST /api/v1/applications/{id}/investigations      {"case_id": "..."}             # or client_id / ip_address / device_id, playbook
GET  /api/v1/applications/{id}/investigations/{iid}                                # steps, report, pending approvals
PATCH /api/v1/applications/{id}/investigations/{iid}/steps/{sid}  {"decision": "approve"}   # a signed-in person
PATCH /api/v1/applications/{id}/agent-policy       {"mode": "ask", "deny": ["policy_change"], "allow": ["case_note"]}
```

It starts in `propose` mode and earns the rest: `ask` when you are ready to answer it, `auto` only for a playbook measured at 90% agreement with the cases your team closed. Playbooks are markdown your team writes; memories are facts your team confirms. `docs/agent.md` has the whole design.

### Backtest a Portfolio

Replay a merchant's historical payments through the rules and see what FLIT would have caught, before they integrate anything.

```bash
python manage.py backtest history.csv --mapping mapping.json \
  --application "Fintech A" --create --out report.json
```

It reports the threshold curve (what each block threshold would have caught and cost), and ranks rules by lift — how much more often each fires on fraud than on good customers. `backtest_overlap` compares two portfolios and measures how much of one's fraud was already visible in the other.

See [docs/backtesting.md](docs/backtesting.md) for the mapping format, the data to ask for, and how to read the report.

### Simulate a Policy Change

Ask what a change *would have done*, instead of shipping it and waiting for complaints. FLIT re-scores recorded decisions under candidate weights and thresholds and compares them against the labels you have reported.

```bash
curl -X POST "http://localhost:18000/api/v1/applications/{app_id}/simulations" \
  -H "Content-Type: application/json" \
  -d '{"days": 30, "thresholds": {"block_at": 0.5}, "weights": {"bot_detected": 0.9}}'
```

```json
{
  "decisions": 4820, "labelled": 312,
  "baseline":  {"blocked": 41, "caught_fraud": 22, "missed_fraud": 18, "false_positives": 3, "precision": 0.88, "recall": 0.55},
  "candidate": {"blocked": 96, "caught_fraud": 34, "missed_fraud": 6,  "false_positives": 11, "precision": 0.76, "recall": 0.85},
  "changes": {"newly_blocked": 55, "newly_blocked_fraud": 12, "newly_blocked_legit": 8, "newly_allowed": 0}
}
```

Read it as a trade: 12 more frauds caught, 8 more good customers blocked. Baseline and candidate are both recomputed the same way, so the comparison is exact even though a recomputed score can differ slightly from the one recorded at decision time.

Decision thresholds are `block_at` (0.7) and `review_at` (0.5).

### Look Up a Device

```bash
curl http://localhost:18000/api/v1/applications/{app_id}/devices/{device_id} \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}"
```

Returns the device's trust score, integrity flags, the accounts your application has seen on it, its recent events and their labels. Devices are only visible to applications that have seen them.

### Register a Device

```bash
curl -X POST http://localhost:18000/api/v1/applications/{app_id}/register-device \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "user_123",
    "visit_id": "fingerprint_request_id"
  }'
```

### WebSocket Alerts

```javascript
const ws = new WebSocket('ws://localhost:18000/ws/alerts/');

ws.onopen = () => {
  // Subscribe to application alerts
  ws.send(JSON.stringify({
    type: 'subscribe.application',
    application_id: 'your-app-id',
    api_key: 'your-api-key'
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'alert') {
    console.log('Alert received:', data.alert);
  }
};
```

## Security Rules

### Device & Identity Rules

| Rule | Description | Risk Weight |
|------|-------------|-------------|
| `DeviceExpiredRule` | Device registration has expired | 0.3 |
| `NewDeviceCountryRule` | Device accessing from new country | 0.4 |
| `UnregisteredDeviceRule` | Device not registered | 0.5 |
| `ImpossibleTravelRule` | Geographically impossible travel | 0.85 |
| `AccountTakeoverRule` | Multiple takeover signals detected | 0.95 |

### Transaction & Compliance Rules

| Rule | Description | Risk Weight |
|------|-------------|-------------|
| `AmlCftLimitExceededRule` | Transaction exceeds AML/CFT limits | 0.9 |
| `VelocityCheckRule` | Too many transactions in time window | 0.6 |
| `MaximumSingleDebitExceededRule` | Single debit exceeds policy limit | 0.7 |
| `MaximumDailyCumulativeDebitExceededRule` | Daily cumulative limit exceeded | 0.8 |

### Payment Fraud Rules (NEW - Data-Driven)

| Rule | Description | Risk Weight |
|------|-------------|-------------|
| `PaymentFraudRule` | Automated clients, headless browsers, bot detection | 0.95 |
| `GatewayPatternRule` | Issuer fraud flags, decline pattern analysis | 0.85 |
| `CardTestingRule` | Small transactions, high failure rates, BIN enumeration | 0.9 |
| `IPConcentrationRule` | Transaction velocity and multiple cards/customers per IP | 0.8 |
| `ThreeDSTimeoutRule` | 3DS challenge timeouts (bots cannot complete them) | 0.85 |
| `FakeAddressRule` | Known fake/test addresses, duplicate lines, impossible geography | 0.7 |
| `RetryAttackRule` | Rapid card retries and card cycling | 0.9 |
| `IssuerSignalRule` | Issuer fraud, velocity and card-issue decline signals | 0.85 |

Payment rules attach a per-signal score to each finding; it is used as the weight when no explicit weight is configured.

### IP & Bot Intelligence Rules

| Rule | Description | Risk Weight |
|------|-------------|-------------|
| `IPReputationRule` | Tor exit nodes, blocklisted, proxy, VPN, datacenter and high-risk-country IPs | 0.3 – 0.9 |
| `BotSignalRule` | Automated user agents and Fingerprint bad-bot detection (search crawlers allowed) | 0.7 |

### Money Mule Rules

Mule accounts are recognised by the shape of money moving through them, not by any single transaction. These rules read the account's recorded history, so they need `POST /audit-transaction` to be called for both credits and debits.

| Rule | Description | Risk Weight |
|------|-------------|-------------|
| `PassThroughRule` | Account pays out most of what it just received (`pass_through_funds`) | 0.75 |
| `StructuringRule` | Money arriving from many different senders (`many_unique_payers`), or a burst of credits (`credit_structuring`) | 0.55 – 0.7 |
| `DormantAwakeningRule` | A long-quiet account suddenly moving money (`dormant_account_activity`) | 0.5 |
| `AccountFarmingRule` | Several accounts first seen on one device within a day (`account_farming`) | 0.8 |
| `MuleNetworkRule` | Account shares a device with accounts already confirmed fraudulent (`mule_network_device`) | 0.9 |

`MuleNetworkRule` is what the device graph plus your reported outcomes buy together: mules work in sets, and once one is confirmed, the rest of the set becomes visible.

### Session Shape and Agent-Driven Sessions

| Rule | Description | Risk Weight |
|------|-------------|-------------|
| `SessionShapeRule` | `machine_session`: one origin's hour reads as automated — many accounts, rotating clients, machine cadence, credentials on accounts it did not create, the takeover motif repeating, rate-limit breaches. `agent_session`: the rhythm of a model driving a loop — bursts of calls issued together separated by think gaps, and refusals answered within seconds by a *different* attempt. `campaign_motif`: the takeover motif on two or more accounts | 0.85 / 0.85 / 0.95 |
| `BlockStreakRule` | The origin has just been blocked repeatedly; the next variation of a probe does not start from zero | 0.6 |

The agent-shaped signals are what a per-event rule cannot see. A loop driven by a model can rotate its client string and slow its reset-to-login; what it cannot cheaply flatten is that it issues several calls at once and then pauses while the model composes the next step. Known agent client strings (`Claude-User`, `GPTBot`, `ChatGPT-User`, `PerplexityBot`, and so on) are read too, but weighted low: a shell-driven agent sends whatever it types, and the Figo attacker sent `curl` and `python-requests`.

Merchants may forward a small allowlist of the end user's request headers as `headers` (`Accept-Language`, `Accept-Encoding`, `X-Requested-With`, `Sec-CH-UA`, …); the bot detector reads the automation markers among them.

Thresholds default to 80% paid out within an hour, 5 senders a day, 8 credits a day, 60 days of dormancy, and 3 new accounts per device per day. Override them per application on `Policy.mule_thresholds`.

### Look Up an Account

The profile a fraud team opens when a payment is held:

```bash
curl "http://localhost:18000/api/v1/applications/{app_id}/accounts/{client_id}" \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}"
```

Returns 30-day money flow (credits, debits, unique payers and payees, and the pass-through ratio), every device the account has used and how many other accounts share it, which mule signals have fired and how often, reported labels and open cases.

### Device Consistency Rules

Cross-checks on signals collected by the FLIT SDK. A spoofed browser can change any single value; keeping every value consistent with the others is much harder.

| Rule | Description | Risk Weight |
|------|-------------|-------------|
| `DeviceConsistencyRule` | `spoofed_timezone` (zone and UTC offset disagree), `platform_mismatch`, `software_renderer` (VMs and headless browsers), `automation_markers`, `device_class_mismatch` (touch support contradicts the device), `locale_country_mismatch` | 0.15 – 0.8 |

### Device Graph Rules

FLIT keeps a device graph: every `visit_id` resolves to a device, and each device records the accounts that used it.

| Rule | Description | Risk Weight |
|------|-------------|-------------|
| `MultiAccountingRule` | One device used by too many accounts | 0.7 |
| `AccountSharingRule` | One account used from too many devices (`concurrent_devices` within an hour, `account_sharing` within a day) | 0.5 – 0.7 |
| `DeviceTamperingRule` | Tampering, emulators, VMs, rooted/jailbroken devices, hooking frameworks, cloned apps, location spoofing, remote control and MITM proxies | 0.3 – 0.9 |

Thresholds default to 3 accounts per device (30 days), 3 devices per account per day and 2 per hour. Override them per application on `Policy.device_thresholds`:

```json
{"max_accounts_per_device": 5, "accounts_per_device_window_days": 30}
```

## Risk Levels

| Level | Score Range | Action |
|-------|-------------|--------|
| LOW | 0.0 - 0.3 | Allow |
| MEDIUM | 0.3 - 0.5 | Monitor |
| HIGH | 0.5 - 0.7 | Review |
| CRITICAL | 0.7 - 1.0 | Block |

## Target Industries

- **Fintech & Neobanks** - Account security, transaction fraud
- **E-commerce** - Payment fraud, promo abuse
- **Crypto Exchanges** - AML compliance, account takeover
- **Insurance** - Claims fraud, identity verification
- **Gaming** - Account theft, virtual currency fraud

## Production Deployment

### With Redis (Recommended)

```yaml
# docker-compose.prod.yml
services:
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    
  app:
    environment:
      DEBUG: false
      REDIS_URL: redis://redis:6379/0
      CACHE_URL: redis://redis:6379/1
```

### Security Checklist

- [ ] Set strong `SECRET_KEY` and `MCRYPT_KEY`
- [ ] Enable HTTPS/TLS
- [ ] Configure `ALLOWED_HOSTS`
- [ ] Set up Redis with authentication
- [ ] Enable database SSL
- [ ] Configure rate limits for your traffic
- [ ] Set up monitoring and alerting

## The FLIT Advantage

### For Merchants

> *"I can scale without fear."*

- **Pre-transaction protection** — Stop fraud before money moves
- **Zero integration friction** — Works with any payment processor
- **Real-time decisions** — Sub-100ms response times
- **Continuous learning** — Improves from every transaction

### For Customers

> *"I trust this merchant with my money."*

- **Invisible protection** — No friction for legitimate users
- **Account security** — Device fingerprinting prevents takeover
- **Privacy-first** — No PII stored, only behavioral signals

---

## Taglines

- **"Stop fraud before it costs you."**
- **"Preventable fraud ends here."**
- **"Trust every transaction."**
- **"Protection, not reaction."**
- **"Because fraud shouldn't be the cost of growth."**

---

## License

MIT License

## Contributing

Contributions welcome! Please read our contributing guidelines.

---

<p align="center">
  <strong>FLIT — Protecting Money in Motion</strong><br>
  <em>"Flit exists to make preventable fraud impossible."</em>
</p>
