# FLIT: Fraud Defence for AI-Agent Attacks on Financial Infrastructure

**FLIT is an open-source, real-time fraud decision engine for banks, fintechs, payment companies and crypto platforms. It is built for one problem in particular: the attacker is now an AI agent.**

An agent with a browser and a shell reads your API the way an engineer reads a repo. It creates accounts by the hundred, rotates its client strings, slows down when it hits a threshold and tries a different variation when it is refused, all in one session and all for the price of tokens. Rules that score one event at a time lose to that.

FLIT scores the **session**, not only the event. It caps the value that can leave through **one credential**, not only one account. It treats a missing signal as a finding, makes its own AI analyst unable to loosen anything, and refuses to claim more about its detectors than it can show.

```
POST /api/v1/applications/{id}/audit-transaction   →   allow | review | challenge | block
```

FLIT does not process payments. It sits on your login, signup and money-out paths and answers one question before the money moves: should this happen?

> **Status: beta. Licence: MIT.** Most detectors are tested against synthetic attacks but not yet against labelled production traffic. [COVERAGE.md](COVERAGE.md) shows the evidence for each one. Read [Honest limits](#honest-limits) before you put FLIT in front of real money.

---

## Contents

- [Why AI agents change fraud](#why-ai-agents-change-fraud)
- [The threat model](#the-threat-model)
- [How FLIT defends against each attack](#how-flit-defends-against-each-attack)
- [Design principles](#design-principles)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Integrating](#integrating)
- [API reference](#api-reference)
- [Running FLIT on a bank's money-out path](#running-flit-on-a-banks-money-out-path)
- [Agent FLIT: the defender's own agent](#agent-flit-the-defenders-own-agent)
- [Detector catalogue](#detector-catalogue)
- [Measuring what works](#measuring-what-works)
- [Configuration](#configuration)
- [Operations](#operations)
- [Repository layout](#repository-layout)
- [Testing](#testing)
- [Honest limits](#honest-limits)
- [Roadmap](#roadmap)
- [Contributing, security and licence](#contributing-security-and-licence)

---

## Why AI agents change fraud

Fraud defence assumed a human attacker. Humans are slow, get tired, repeat themselves and give up. Fixed thresholds work against them: a human cannot do 3 password resets in a minute, sign up 50 accounts an hour or try 200 small charges without looking automated.

An agent breaks those assumptions in four ways:

| Property of an agent attacker | Why per-event rules fail |
|---|---|
| **It is cheap.** One operator can run hundreds of sessions in parallel for the cost of model calls. | The attacker is cheaper than the defender's review queue. Sending everything to manual review is no longer a defence. |
| **It adapts within a session.** A refusal is feedback, and the next attempt is a different variation. | Every fixed threshold can be learned and stepped over. Slow the reset to 91 seconds, change the user agent for each account, spread the work across IPs. |
| **It reads your API like documentation.** It probes for SSRF, mass assignment, cross-tenant access and missing authorization, and it names each probe after what it tests. | The weak point is often the merchant's own application, not the end user. |
| **It holds credentials, not guesses.** A stolen partner API key or a takeover from a reset flow carries real authority. | Per-account limits never fire when ordinary amounts leave many accounts through one credential. |

### What this looked like in practice

On **20 October 2026**, one operator, almost certainly an agent with a browser and a shell, attacked a live card issuer's platform. In one session it:

- created **226 accounts** and **17 merchant tenants**
- rotated through **six client strings** (`curl`, `python-requests` and others)
- tested **SSRF, mass assignment and cross-tenant access**, naming each probe after what it was testing
- requested password resets for **25 accounts from one address** and took over **18 of them in 52 minutes**, going from reset request to login in **6 to 31 seconds** each time, including accounts with a second factor and accounts that signed in with Google

No per-account rate limit noticed, because per account each action happened only once. The detectors in FLIT's credential-takeover and session-scoring families come from replaying that incident ([`tests/unit/test_credential_takeover.py`](tests/unit/test_credential_takeover.py), [`tests/unit/test_session_scoring.py`](tests/unit/test_session_scoring.py)). The tests include an **evasive replay**: the same attack with the reset slowed to 150 seconds and a different client for each account. That replay gets past every per-event rule, and FLIT blocks it from the third account onwards.

The second scenario FLIT is built for is **the credential drain**. A third party's API credential, legitimately able to move money for a bank's merchants, is stolen. It moves ordinary amounts out of many different accounts over a fast payment rail overnight. Each transfer passes every per-account check, and the loss is the sum. The [outflow controls](#running-flit-on-a-banks-money-out-path) exist for this case.

---

## The threat model

FLIT maps everything to the **[MITRE Fight Fraud Framework (F3)](https://github.com/center-for-threat-informed-defense/fight-fraud-framework)**, published by MITRE's Center for Threat-Informed Defense with JPMorganChase, Citigroup, Lloyds Banking Group, Standard Chartered and FS-ISAC. It does not invent its own vocabulary. The attack chain an agent runs against financial infrastructure, in F3 terms:

| Stage | What the agent does | F3 techniques |
|---|---|---|
| **Resource development** | Mass account and tenant creation, disposable and patterned emails, fresh infrastructure, newly funded wallets | `T1585` Establish Accounts, `T1583` Acquire Infrastructure, `F1020` Create Fake Materials |
| **Reconnaissance and probing** | Walks the public API, scripts every endpoint, retries refused calls with variations, runs into rate limits | `F1002` Abuse of Public-Facing API |
| **Initial access** | Password-reset takeovers, credential stuffing, logins from scripted clients, reactivating dormant accounts | `F1006` Account Takeover, `T1110` Brute Force, `F1042` Reactivate Account |
| **Stealth** | Spoofed device fingerprints, timezone and locale mismatches, VPN and Tor egress, 3DS manipulation, sending fewer signals on purpose | `F1023` Device Fingerprint Spoofing, `F1030` Geolocation Spoofing, `F1001`/`F1039` 3DS |
| **Positioning** | Changing contact details, disabling the second factor, adding new withdrawal addresses, card testing | `F1005` Account Manipulation, `F1012` Card Testing |
| **Monetization** | Draining through a stolen credential, mule networks, pass-through accounts, structuring, crypto cash-out | `F1047` Transfer of Funds, `F1025` EFT, `F1045` Structuring, `F1018` Convert to Crypto |

FLIT also defends **itself** as part of the threat model. An attacker who holds a merchant's API key will try to use it to loosen FLIT: raise thresholds, add allow rules, disable detectors, or point the decision hook at an endpoint that approves everything. An attacker who can type into a form will try to inject instructions into the AI models that read FLIT's case queue. Both are covered below.

---

## How FLIT defends against each attack

### 1. Session scoring: what an agent can't hide

[`SessionShapeRule`](app/core/audit/rules/session_shape_rule.py) reads one origin's last hour and scores how machine-like it is. Every signal is one a loop finds expensive to flatten:

| Signal | What it means | Weight |
|---|---|---|
| `many_accounts` | One origin touching many accounts (measured against **this merchant's** own session baseline) | 0.35 |
| `rotating_clients` | Several client families from one origin | 0.30 |
| `machine_cadence` | Inter-request timing more regular than a person keeps | 0.30 |
| `others_credentials` | Credential actions on accounts the origin did not create | 0.40 |
| `takeover_motif` | The reset → fast login → change sequence repeating | 0.50 |
| `bimodal_cadence` | **The rhythm of an agent:** bursts of parallel calls separated by "think gaps" while the model writes its next step | 0.35 |
| `adaptive_retry` | **The other agent signature:** a refusal answered within seconds by a *different* attempt | 0.40 |
| `agent_client` | Known agent user agents (`Claude-User`, `GPTBot`, `ChatGPT-User`, `PerplexityBot`, ...). Weighted low because a shell-driven agent can send any user agent it likes | 0.20 |
| `rate_limited` | The origin keeps hitting the rate limiter, probing faster than the API allows | 0.30 |

The weights are set so that the one thing a shared office, household or carrier-NAT city produces on its own, many accounts behind one address, never reports by itself. The rule emits `machine_session`, `agent_session` and, when the takeover motif appears on two or more accounts, `campaign_motif`.

### 2. Credential takeover at agent speed

| Rule | What it catches |
|---|---|
| [`ResetToLoginRule`](app/core/audit/rules/reset_to_login_rule.py) | A password reset that turns into a login faster than a person can read an email (graded below 90 s). The attacker isn't guessing, so the time between reset and login is the only place the attack shows. |
| [`CredentialResetStormRule`](app/core/audit/rules/credential_reset_storm_rule.py) | One IP resetting or logging into 3 or more distinct accounts in an hour. It counts distinct accounts, not requests, so an office stays under the threshold. |
| [`AutomatedCredentialActionRule`](app/core/audit/rules/automated_credential_action_rule.py) | A login, reset, 2FA removal or contact change performed by a script. It is strongest when a bare HTTP client comes from a datacenter IP. A person on a VPN with a normal browser doesn't trip it. |
| [`AccountTakeoverRule`](app/core/audit/rules/), `NewDeviceCountryRule`, `ImpossibleTravelRule` | The classic takeover signals: a new device, a new country, travel that isn't physically possible. |

### 3. Adaptation is evidence, not a free retry

- [`BlockStreakRule`](app/core/audit/rules/block_streak_rule.py): an origin blocked several times in a row does not start its next variation from zero. Three consecutive blocks also raise a `campaign_detected` alert and escalate the case.
- [`ChallengeEvasionRule`](app/core/audit/rules/challenge_evasion_rule.py): an actor who walked away from step-up challenges is remembered when they come back.
- **One case per campaign.** Decisions from one origin in a day are grouped into a single case, so a 226-account attack is one item in the queue, not 226.
- **Enforcement costs the attacker time.** FLIT can issue its own challenge (`otp` or `turnstile`), and a passed challenge never moves a block. The principle: *enforcement has to cost the attacker more than detection costs the defender.* A block tells the loop which variation failed. A step-up that costs wall-clock time costs a customer a minute and costs an agent its economics.

### 4. Withholding signals doesn't work

An agent quickly learns that sending nothing scores close to zero. [`ExpectedSignalRule`](app/core/audit/rules/expected_signal_rule.py) treats the absence as the finding: if most of a merchant's users produce a device key and this request doesn't, the omission is scored. The baseline is per application, so a merchant that hasn't deployed device collection is never penalized.

Device-level evasion is cross-checked by [`DeviceConsistencyRule`](app/core/audit/rules/device_consistency_rule.py) (timezone and UTC offset disagree, a software renderer, automation markers, touch support that contradicts the device) and [`DeviceTamperingRule`](app/core/audit/rules/device_tampering_rule.py) (emulators, hooking frameworks, remote control, MITM proxies). A spoofed browser can change any single value. Keeping every value consistent with every other is much harder.

### 5. Mass account creation and identity farming

`AccountFarmingRule`, `MultiAccountingRule`, `DisposableEmailRule`, `EmailPatternRule`, `DomainReputationRule` and `FreshFundingWalletRule` read signups across the **identity ladder**: device, signature, email root, wallet and IP. They count against the keys an attacker can't cheaply rotate. Identifiers are canonicalized first (NFKC, invisible characters removed, `googlemail.com` folded into `gmail.com`, IDNA domains, IPv4-mapped IPv6 addresses), and a local part that mixes alphabets (`pаypal` with a Cyrillic `а`) is reported as `confusable_email_spelling`.

### 6. Stopping one credential from draining many accounts

Every per-account limit is blind to a credential moving normal amounts out of many accounts. FLIT adds controls that look across accounts:

- [`OutflowBreakerRule`](app/core/audit/rules/outflow_breaker_rule.py) caps value **per initiating credential, per channel and per application** over 15-minute, 1-hour and 24-hour windows, with tighter limits off-hours. Amounts are reserved with **atomic increments**, so a burst of concurrent transfers can't all pass together (a burst *is* the attack). A breach **hard-blocks** and **latches** the scope until a signed-in person releases it, sends `outflow.tripped` immediately and opens a case.
- `per_initiator_untrusted` caps what one credential can send to **beneficiaries it has no trusted history with**, at a level far below its overall limit. A drain goes to new accounts and settlement mostly doesn't, so a trip here stops only those debits and legitimate settlement carries on. A trip also revokes beneficiary links still in their cooling period, so a slow drain can't age its mule accounts into trust.
- [`UnknownBeneficiaryRule`](app/core/audit/rules/unknown_beneficiary_rule.py) refuses a credential paying from an account to someone it has never paid from that account. It is opt-in and can run in shadow mode for businesses that genuinely pay new people.
- **A cache outage fails closed.** If the window totals can't be read, the debit is refused (or reviewed, if configured). It is never waved through.

See [Running FLIT on a bank's money-out path](#running-flit-on-a-banks-money-out-path).

### 7. Mule networks and cash-out

`PassThroughRule` (an account paying out most of what it just received), `StructuringRule` (many senders, bursts of credits), `DormantAwakeningRule`, `MuleNetworkRule` (shares a device with accounts already confirmed as fraud), `NewWithdrawalAddressRule`, `CollectionWalletRule`, `CryptoCashOutRule` and `SanctionedAddressRule`. Mules work in sets: once one is confirmed, the device graph exposes the rest.

### 8. A stolen API key can't loosen FLIT

FLIT treats a leaked merchant API key as part of its own threat model:

- **Policy only gets stricter from an application key.** An application key may tighten policy. Loosening it (raising a threshold, removing a block rule, adding an allow, disabling or shadowing a rule, lowering a weight, relaxing outflow limits) needs a **signed-in organization owner**. A loosening attempt with only a key is refused with `policy_loosening_forbidden`, and every change in either direction is written to the hash-chained audit log.
- **Organization ceilings.** An organization sets rules that every application inherits and can't remove, a maximum `block_at`, and can require every application to enforce.
- **The decision hook can only tighten.** Your own endpoint can turn an allow into a review or a review into a block, never the reverse. A hook that times out or errors is recorded and ignored.
- **Outbound calls are SSRF-guarded.** Webhooks and hooks must use https. Private, loopback and link-local destinations are refused, and so is a hostname that *resolves* inside the network at connection time.
- **Requests are HMAC-signed** over method, path, body, timestamp and content type, with nonce-based replay protection and per-application rate limits.

### 9. AI defenders that can't be prompt-injected into approving fraud

FLIT uses models in two places, the [triage reader](#a-second-reader-for-the-queue) and [Agent FLIT](#agent-flit-the-defenders-own-agent). Both are built on the assumption that **anything a user typed is hostile**:

- Models see **structured facts only**: rule codes and weights, money flows, shared devices, session shape, labels. They never see email local parts, user-agent strings, gateway messages, reviewer notes or raw payloads, because those are the channels an attacker controls.
- Output must match a fixed schema. A refusal, an error or free text becomes `needs_human`.
- A model can **never** clear a case where a control fired, never loosen policy and never enforce. Clearing is the only action triage may take on its own, and only after it has earned it: 100 or more human-confirmed proposals at 0.99 precision or better, a daily cap, and a circuit breaker that trips after 3 auto-clears later shown to be fraud.

### 10. A shared protection network

`NetworkReputationRule` flags an actor whose identity keys at least two *other organizations* confirmed as fraud, or who failed challenges there, in the last 180 days. The verdict scales with the evidence: 2 organizations means a challenge, 3 a review, and 4 on the actor's own keys a block. History that sits only on an IP or ASN is capped at review, because one address is many people. Legitimate reports count against the history. Devices are never linked across applications. Each merchant sees only its own view.

---

## Design principles

1. **Score sessions, not only events.** An agent can step over any fixed per-event threshold. It finds it much harder to change the shape of its work.
2. **Cap value across accounts.** One credential, one channel, one application. A per-account limit isn't a limit when the attacker holds a credential that reaches many accounts.
3. **Fail closed on the controls that matter.** A sanctions check, a limit or an outflow window that couldn't be evaluated sends the decision to review or blocks it. Detection rules that time out are reported as `degraded`, never as a 500.
4. **Hard blocks ignore good history.** A sanctions hit or an outflow breach doesn't care about a clean record or a lenient calibration.
5. **Changes made with a key may only tighten.** Policy, hooks, agent writes and webhooks only move toward stricter.
6. **Models read facts, never attacker-controlled text.**
7. **Claims need evidence.** Every detector declares its maturity on an evidence ladder, and CI refuses any claim above `proposed` that can't name the data behind it.
8. **Money is the unit.** Outcomes carry amounts. FLIT reports losses prevented, leaked and turned away per currency, and the calibrator may not raise money lost.

---

## Architecture

```
            your login / signup / payout path
                          │  HMAC-signed, nonce, timestamp
                          ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Security layer      rate limits · replay protection · validation      │
├──────────────────────────────────────────────────────────────────────┤
│ Identity ladder     device · signature · email root · wallet · IP     │
│                     canonicalized; FLIT's own browser SDK or          │
│                     Fingerprint                                       │
├──────────────────────────────────────────────────────────────────────┤
│ Rules (~55)         detections · corroborations · controls            │
│   session shape · credential takeover · outflow breaker ·             │
│   beneficiary · mule · device · payments · crypto · sanctions ·       │
│   network                                                             │
│   each one bounded by a latency budget; failures are reported         │
├──────────────────────────────────────────────────────────────────────┤
│ Decision            written policy (block > review > challenge >      │
│                     allow) → calibrated weighted score → hard blocks  │
│                     → your decision hook (tighten only) → challenge   │
├──────────────────────────────────────────────────────────────────────┤
│ Record              hash-chained audit log · cases (one per campaign) │
│                     · webhooks · WebSocket alerts · outflow trips     │
└──────────────────────────────────────────────────────────────────────┘
          │                         ▲
          ▼                         │ outcomes with amounts
   loss ledger · calibrator · shadow measurement · backtests · triage · Agent FLIT
```

**Stack:** Python 3.11, Django + Django REST Framework, Django Channels (WebSocket alerts), PostgreSQL, Redis (cache, counters, channels), optional MaxMind GeoLite2, optional Fingerprint, and the Anthropic API for the optional triage reader and Agent FLIT. There are browser and Node SDKs in [`sdk/`](sdk/).

---

## Quick start

### Docker

```bash
git clone https://github.com/Fraud-killer/flit.git
cd flit
cp .env.example .env            # set SECRET_KEY and MCRYPT_KEY
docker-compose up -d
docker-compose exec app python manage.py migrate
docker-compose exec app python manage.py createsuperuser
```

The API is at `http://localhost:18000`.

Generate an `MCRYPT_KEY` with:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

### Without Docker

Requires Python 3.11, PostgreSQL 14+ and Redis 6+.

```bash
cd app
pip install pipenv && pipenv install --dev
cp ../.env.example ../.env
python manage.py migrate
python manage.py runserver
```

### Create an application

```bash
python manage.py provision_application --help
```

This creates an organization and application and prints the application id and secret you sign requests with. Onboarding is covered in [docs/deployment.md](docs/deployment.md#onboarding-a-merchant).

---

## Integrating

There are four event types, each with its own endpoint. Send all of them, because session scoring needs the whole story:

| Endpoint | Event | Send it on |
|---|---|---|
| `POST .../audit-authentication` | `AuthenticationEvent` | `login`, `login_failed`, `password_reset_requested`, `password_reset_completed`, `password_change`, `email_change`, `phone_change`, `two_factor_enabled`, `two_factor_disabled`, `new_device_login` |
| `POST .../audit-registration` | `RegistrationEvent` | signups |
| `POST .../audit-transaction` | `TransactionEvent` | every credit **and** debit, including payouts and withdrawals |
| `POST .../audit-client` | `ClientEvent` | other sensitive client actions |

**Send the end user's IP address and user agent.** FLIT receives the request from your server, so it can't see them itself.

**Decide how to fail.** The Node SDK ([`sdk/node/flit.mjs`](sdk/node/flit.mjs)) provides `failOpen` (for signups: if FLIT is unavailable, let the user in) and `failClosed` (for money out: no decision, no transfer).

```js
import { Flit, failClosed } from "./sdk/node/flit.mjs";

const flit = new Flit({ baseUrl, applicationId, secretKey });
const decision = await failClosed(flit.auditPayout({
  id: "txn_123", type: "debit", client_id: "acct_42",
  amount: 250000, currency_code: "NGN",
  initiator_id: "partner_7", channel: "nip",
  counterparty_id: "0123456789", counterparty_bank: "058",
}));
if (decision.should_block || decision.should_review) refuseTransfer();
```

**Collect device signals** in the browser with [`@flit/browser`](sdk/js/README.md):

```js
import { collect } from "@flit/browser";
const { visitToken } = await collect({ key: "flit_pk_..." });
// send visitToken to your server and pass it as visit_token in the audit
```

Restrict which websites may use your collection key with `Application.collect_origins`. Identifying material is hashed in the browser and hashed again before storage. No raw signal is written to the database.

**Report outcomes.** Labels with amounts are what calibration, the loss ledger and the network learn from.

---

## API reference

All endpoints are under `/api/v1/`. Application endpoints are signed with HMAC:

```
Authorization: HMAC-SHA256 {app_id}:{signature}
X-Timestamp:   <unix seconds>
X-Nonce:       <uuid>
```

The signature covers the method, path, canonical JSON body, timestamp and content type. The canonical JSON has sorted keys, no whitespace and escaped non-ASCII, matching Python's `json.dumps(sort_keys=True, separators=(",", ":"))`. [`sdk/node/test/parity.mjs`](sdk/node/test/parity.mjs) checks the Node signer against the Python one.

### Audit a transaction

```bash
curl -X POST http://localhost:18000/api/v1/applications/{app_id}/audit-transaction \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}" \
  -H "Content-Type: application/json" \
  -H "X-Timestamp: $(date +%s)" -H "X-Nonce: $(uuidgen)" \
  -d '{
    "id": "txn_123", "type": "debit", "client_id": "user_123",
    "visit_token": "...", "amount": 1000.00, "currency_code": "USD",
    "ip_address": "81.2.69.160", "user_agent": "Mozilla/5.0 ...",
    "counterparty_id": "acct_987", "account_age_days": 412
  }'
```

Optional fields: `initiator_id`, `channel`, `counterparty_bank` (money-out controls); `counterparty_address`, `chain` (crypto); `status`, `gateway_message`, `provider_responses`, `card_fingerprint`, `card_bin`, `payment_instrument`, `browser_details`, `billing`, `shipping` (payments); `headers` (an allowlist of the end user's request headers, such as `Accept-Language` and `Sec-CH-UA`); `challenge_id` (replaying after a passed step-up).

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
    "rules": ["VelocityCheckRule", "ImpossibleTravelRule"],
    "degraded": [],
    "policy_matches": [],
    "block_streak": 0,
    "shadow": []
  }
}
```

- `degraded`: rules that raised an error or ran past the latency budget (default 3 s). A *control* that didn't run fails closed and forces a review.
- `policy_matches`: the written policy rules that fired.
- `block_streak`: consecutive blocks for this origin.
- `shadow`: findings from rules running in shadow mode. They are measured but don't count.
- In shadow enforcement, `should_block` stays false and `would_block` shows what FLIT would have done.

| Level | Score | Action |
|---|---|---|
| LOW | 0.0 – 0.3 | Allow |
| MEDIUM | 0.3 – 0.5 | Monitor |
| HIGH | 0.5 – 0.7 | Review |
| CRITICAL | 0.7 – 1.0 | Block |

The defaults are `review_at` 0.5 and `block_at` 0.7, and both can be set per policy.

### Endpoint index

| Method and path | Purpose |
|---|---|
| `POST /collect` | Browser SDK signal collection. Public, rate-limited, origin-restricted. |
| `POST /applications/{id}/audit-{transaction,authentication,registration,client}` | Get a decision |
| `POST /applications/{id}/register-device` | Bind a device to an account |
| `POST /applications/{id}/outcomes` | Report `fraud`, `chargeback`, `legit` or `false_positive`, optionally with `amount` |
| `GET  /applications/{id}/loss?days=30` | Loss ledger: prevented, in shadow, flagged, leaked, friction, net, per currency |
| `GET  /applications/{id}/decisions` | Decision feed, filterable by level, label, factor, client, device, days and unlabelled |
| `GET/PATCH /applications/{id}/cases[/{case_id}]` | Review queue. Closing a case labels its decision. |
| `GET/PATCH /applications/{id}/policy` | Written policy, thresholds, disabled and shadow rules, webhooks, hook, challenges, outflow limits |
| `POST /applications/{id}/simulations` | Re-score history under candidate weights and thresholds |
| `GET  /applications/{id}/calibrations` | Calibration runs (the review queue for automatic tuning) |
| `POST/GET /applications/{id}/challenges[/{id}/verify]` | Step-up challenges |
| `GET  /applications/{id}/devices/{device_id}` | Device profile |
| `GET  /applications/{id}/accounts/{client_id}` | Account profile: 30-day money flow, devices, mule signals, labels |
| `GET/PATCH /applications/{id}/outflow-trips[/{trip_id}]` | Open outflow breaker trips; release one (signed-in person) |
| `GET/POST /applications/{id}/trusted-beneficiaries` | Approve known settlement accounts (signed-in person) |
| `POST/GET/PATCH /applications/{id}/investigations[...]` | Agent FLIT investigations and approvals |
| `GET/PATCH /applications/{id}/agent-policy` | Agent mode and allow, ask and deny rules |
| `.../memories`, `.../monitors`, `.../playbooks` | Agent FLIT memory, monitors and playbooks |
| `GET/PATCH /organizations/{id}/policy` | Organization rules, ceilings and required enforcement |
| `ws://.../ws/alerts/` | Real-time alerts per application or organization |

### Written policy

```bash
curl -X PATCH ".../applications/{app_id}/policy" -H "Authorization: HMAC-SHA256 ..." -d '{
  "thresholds": {"block_at": 0.65},
  "rules": {
    "block":     [{"subject": "cidr", "pattern": "203.0.113.0/24", "reason": "known actor"}],
    "challenge": [{"subject": "asn",  "pattern": "AS14061"}],
    "review":    [{"subject": "factor", "pattern": "agent_session"}]
  }
}'
```

The available subjects are `ip`, `cidr`, `country`, `asn`, `email_root`, `email_domain`, `device`, `client_id`, `wallet`, `counterparty`, `initiator` and `factor` (any rule code the decision produced). Precedence is **block > review > challenge > allow**. An allow waives only the review or challenge that the *score* asked for. It never overrides a block or silences a control that didn't run.

### Webhooks

The events are `decision.blocked`, `decision.review`, `case.opened`, `campaign.detected`, `challenge.passed`, `challenge.failed`, `calibration.applied`, `policy.loosened` and `outflow.tripped`. They are signed with `X-Flit-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`. Verify in constant time and reject a `t` older than 5 minutes. Retries back off from 30 s, doubling up to 1 h, for 8 attempts, after which the delivery is parked.

---

## Running FLIT on a bank's money-out path

This is the defence against a stolen partner or operator credential. Both controls are **off until a policy turns them on**.

**FLIT only protects paths that call it.** Every debit path must call `audit-transaction` before the money moves and must refuse the transfer unless FLIT allows it. FLIT does not replace your authorization: a partner credential that can reach other merchants' accounts has to be fixed in your API as well.

Each debit sends:

| Field | Meaning |
|---|---|
| `initiator_id` | The credential, partner or operator behind the transfer (use `customer` for customer-initiated debits) |
| `channel` | The rail, such as `nip` or `intrabank` |
| `counterparty_id` | The beneficiary's account |
| `counterparty_bank` | The beneficiary's bank. An account number alone isn't unique. |

```json
{
  "beneficiary_control": {"enabled": true, "cooling_hours": 72},
  "outflow_limits": {
    "currency": "NGN",
    "per_initiator":           {"15m": 5000000, "1h": 10000000, "24h": 50000000},
    "per_initiator_untrusted": {"1h": 2000000, "24h": 5000000},
    "per_channel":             {"1h": 50000000},
    "per_application":         {"24h": 500000000},
    "off_hours": {"start": "20:00", "end": "07:00", "timezone": "Africa/Lagos", "factor": 0.25},
    "fail": "block"
  }
}
```

These numbers only show the shape. Set yours from your own volumes.

**Go-live order:**

1. Run in shadow mode for longer than the cooling period. Beneficiary links are learned and `would_block` shows what would have stopped.
2. Add known settlement accounts through `POST .../trusted-beneficiaries`.
3. Review the would-be stops against known-good traffic and set the limits.
4. Switch to enforcing.

If the business legitimately pays new beneficiaries, keep `UnknownBeneficiaryRule` in `shadow_rules` and rely on the breaker with a `per_initiator_untrusted` limit. In shadow mode the rule's findings show how much real volume goes to new payees, which is the number to size that limit from.

**Redis matters here.** Window totals live in the cache. Use persistence and a `noeviction` policy. An unreachable cache refuses debits. A cache that silently evicts keys resets the totals to zero. Trips and beneficiary links are stored in Postgres. Point the `outflow.tripped` webhook at something that wakes a person up, because drains happen at night.

The full guide is in [docs/deployment.md](docs/deployment.md#running-flit-on-a-banks-money-out-path).

---

## Agent FLIT: the defender's own agent

If attackers run agents, the analyst needs one too, and it must be harder to subvert than the systems it protects. Agent FLIT investigates a case, account or origin under a playbook your team wrote, using the engine's read services as tools. It files a typed report whose findings cite the tool calls behind them, and an independent verifier re-reads every finding.

**It never enforces.** Its few writes are:

- `case_resolve`, which never clears a case where a control fired
- `case_note`
- `block_actor`, a time-limited block rule
- `policy_change`, which can only tighten
- `open_monitor`
- `remember`

Every write passes through:

```
deny > ask > allow   (organization → application → playbook; any deny wins)
      → your pre_tool_use hook   (may only tighten)
      → classifier + verifier    (auto mode only)
      → proposed | pending a person | denied | executed
```

- **Modes:** `propose` (the default) → `ask` → `auto`. Auto mode needs a playbook measured at 90% agreement over 20 cases your team closed. Three human rejections in a row drop the application back to `ask`.
- **Prompt-injection resistant by construction.** Tool outputs are sanitised before the model sees them: no user agents, no email addresses, no gateway text, no analyst notes, no raw payloads. Large outputs arrive as a preview plus a SHA-256 of the whole.
- **Memory is recollection, not instruction.** Facts the agent saved itself are marked unconfirmed until a person confirms them, and it can't rewrite a fact a person confirmed.
- **Kill switches and budgets.** `AGENT_ENABLED` plus an organization and an application switch, a daily cost budget, and a classifier denial streak breaker.
- **Every step goes on the audit chain.**

The full design is in [docs/agent.md](docs/agent.md). Agent FLIT is off unless `AGENT_ENABLED=true` and `ANTHROPIC_API_KEY` are set. The decision path never depends on it.

### A second reader for the queue

```bash
python manage.py triage --application "Acme"            # shadow: propose and store, act on nothing
python manage.py triage --application "Acme" --report   # agreement with human reviewers
python manage.py triage --application "Acme" --apply    # auto-clear, only under the guardrails
```

---

## Detector catalogue

About 55 rules sit under [`app/core/audit/rules/`](app/core/audit/rules/). Each one declares its F3 techniques, its kind (`detection`, `corroboration` or `control`) and its maturity.

| Family | Rules |
|---|---|
| **Agent and automation** | `SessionShapeRule`, `BlockStreakRule`, `BotSignalRule`, `AutomatedCredentialActionRule`, `ExpectedSignalRule`, `VelocityCheckRule` |
| **Credential takeover** | `ResetToLoginRule`, `CredentialResetStormRule`, `AccountTakeoverRule`, `NewDeviceCountryRule`, `ImpossibleTravelRule`, `UnregisteredDeviceRule`, `DeviceExpiredRule`, `AccountSharingRule` |
| **Money-out controls** | `OutflowBreakerRule`, `UnknownBeneficiaryRule`, `AmlCftLimitExceededRule`, `MaximumSingleDebitExceededRule`, `MaximumDailyCumulativeDebitExceededRule`, `MaximumSingleCreditExceededRule`, `MaximumCumulativeBalanceExceededRule` |
| **Mules and laundering** | `PassThroughRule`, `StructuringRule`, `DormantAwakeningRule`, `MuleNetworkRule`, `AccountFarmingRule` |
| **Synthetic identity and signup** | `MultiAccountingRule`, `DisposableEmailRule`, `EmailPatternRule`, `DomainReputationRule` |
| **Device integrity** | `DeviceConsistencyRule`, `DeviceTamperingRule` |
| **Network and infrastructure** | `IPReputationRule`, `IPConcentrationRule`, `NetworkReputationRule` |
| **Payments** | `PaymentFraudRule`, `CardTestingRule`, `GatewayPatternRule`, `IssuerSignalRule`, `RetryAttackRule`, `ThreeDSTimeoutRule`, `FakeAddressRule` |
| **Crypto** | `NewWithdrawalAddressRule`, `CollectionWalletRule`, `CryptoCashOutRule`, `FreshFundingWalletRule`, `SanctionedAddressRule` |
| **Challenges** | `ChallengeEvasionRule`, `ChallengePassedRule` |

Thresholds can be overridden per application (`Policy.mule_thresholds`, `device_thresholds` and others). Any rule can be disabled (`disabled_rules`) or run in shadow mode (`shadow_rules`) without a deploy. Both count as loosening, so they need a signed-in owner.

---

## Measuring what works

A fraud tool whose numbers can't be traced to a dataset is asking to be taken on faith. FLIT publishes its uncertainty.

**[COVERAGE.md](COVERAGE.md)** is generated from the registered rules, and CI fails if it drifts. Currently FLIT covers **19 of the 44 F3 techniques it has telemetry for**. The other 30 techniques are listed as outside its telemetry, each with the reason.

**The evidence ladder.** Every detector declares one rung, and the test suite rejects any claim above `proposed` that can't name its evidence:

| Rung | Requires |
|---|---|
| Proposed | Reasoned from how the fraud works |
| Synthetic-tested | Fires on a constructed attack and stays quiet on a legitimate lookalike |
| Historically backtested | Measured precision and recall on a merchant's labelled history |
| Shadow-validated | Run on live traffic without acting, then reviewed |
| Production-observed | Acting in production, with decisions labelled |
| Outcome-calibrated | Thresholds set from confirmed outcomes and re-measured on a schedule |

Measurements on a replay whose labels were derived from the same features a rule reads (an "incident replay") are recorded but **earn no rung**.

**Tools for getting from one rung to the next:**

| Tool | What it does |
|---|---|
| `manage.py backtest history.csv --mapping mapping.json` | Replays a portfolio's history and reports a threshold curve and the lift of each rule. See [docs/backtesting.md](docs/backtesting.md). |
| `manage.py shadow_report --record-evidence` | Precision and lift of shadow rules on live traffic |
| `POST /simulations` | What a weight or threshold change *would have done* to recorded decisions |
| `manage.py calibrate --all --apply` | Nightly bounded weight moves from labelled outcomes. Accepted only if false positives stay ≤ 1%, recall doesn't drop and money lost doesn't rise. Can be rolled back with `--rollback <run_id>`. |
| `manage.py loss_report` / `GET /loss` | Money prevented, leaked and turned away, per currency, never converted |

---

## Configuration

Copy [`.env.example`](.env.example) to `.env`.

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | required |
| `REDIS_URL` / `CACHE_URL` | Channels and cache | `redis://localhost:6379/0` and `/1` |
| `SECRET_KEY` | Django secret key | required |
| `MCRYPT_KEY` | Fernet key for secrets at rest | required |
| `ALLOWED_HOSTS` | JSON array | localhost in debug |
| `SECURE_SSL_REDIRECT` | Redirect HTTP to HTTPS outside debug | `true` |
| `TRUSTED_PROXY_DEPTH` | Proxies in front of FLIT that append to `X-Forwarded-For` | unset |
| `FINGERPRINT_SERVER_API_KEY` | Optional second device-identification source | optional |
| `GEOIP_DB_PATH` | Directory containing the GeoLite2 ASN and Country databases | unset |
| `THREAT_LIST_URL` | IP and CIDR blocklist | FireHOL level1 |
| `TRIAGE_ENABLED` / `TRIAGE_MODEL` | Model reader for the case queue | `false` / `claude-opus-5-5` |
| `AGENT_ENABLED` / `AGENT_MODEL` / `AGENT_VERIFIER_MODEL` | Agent FLIT | `false` / `claude-opus-5-5` |
| `ANTHROPIC_API_KEY` | Required only for triage and Agent FLIT | unset |
| `DOMAIN_LOOKUPS_ENABLED` / `CHAIN_LOOKUPS_ENABLED` | Live DNS, RDAP and chain lookups | `true` |
| `DEBUG` | Debug mode | `false` |

---

## Operations

Scheduled jobs (see [docs/deployment.md](docs/deployment.md#scheduled-jobs)):

| Command | Cadence |
|---|---|
| `deliver_webhooks` | every 1–5 min |
| `expire_challenges` | every 5 min |
| `refresh_threat_intel` | hourly |
| `refresh_sanctions` | nightly |
| `calibrate --all` | nightly |
| `verify_audit_chain` | nightly. Checks the hash chain over every decision and policy change. |

**Production checklist**

- [ ] Strong `SECRET_KEY` and `MCRYPT_KEY`, kept out of the repo
- [ ] TLS, `ALLOWED_HOSTS` and `TRUSTED_PROXY_DEPTH` set correctly
- [ ] Redis with auth, persistence and `noeviction` (required for outflow limits)
- [ ] Postgres over SSL, with backups
- [ ] Every money-out path calls FLIT with `failClosed`
- [ ] Shadow mode first. Read `would_block` before enforcing. See [docs/deployment.md](docs/deployment.md#before-enforcing-anything).
- [ ] `outflow.tripped` and `campaign.detected` routed to on-call
- [ ] `verify_audit_chain` scheduled and alerting

---

## Repository layout

```
app/
  api/                 REST views, parsers, serializers
  core/
    audit/             auditor, recorder, identity ladder, rules/
    agent/             Agent FLIT: loop, tools, permissions, hooks, memory, playbooks, evals
    triage/            model reader for the case queue, with guardrails
    calibration/       outcome-driven weight tuning
    backtest/          historical replay harness
    scoring/           weighted risk engine and default weights
    decision/          written policy rules
    intelligence/      IP, bot, email, domain, wallet, sanctions, device signals
    security/          rate limiting, replay protection, request validation
    outbound/          SSRF-guarded client, webhooks, decision hook
    services/          outflow windows, money-out trust, challenges, network reputation ...
    taxonomy/          F3 mapping and the evidence ledger
  kernel/              Django settings
sdk/js/                @flit/browser, device signal collection
sdk/node/              signed server client, failOpen and failClosed
docs/                  agent.md, deployment.md, backtesting.md, integrations/
tests/unit/            ~930 tests, including attack replays
COVERAGE.md            generated F3 coverage matrix
```

---

## Testing

```bash
export DJANGO_SETTINGS_MODULE=kernel.settings DATABASE_URL=sqlite:///test.db SECRET_KEY=dev DEBUG=true \
       DOMAIN_LOOKUPS_ENABLED=false CHAIN_LOOKUPS_ENABLED=false \
       MCRYPT_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
python -m pytest tests -q
cd app && python manage.py makemigrations --check --dry-run
cd app && python manage.py coverage_matrix --out ../COVERAGE.md --check
```

The attack replays worth reading first:

- [`test_credential_takeover.py`](tests/unit/test_credential_takeover.py): the October 2026 takeover, event by event
- [`test_session_scoring.py`](tests/unit/test_session_scoring.py): the evasive replay that gets past every per-event rule
- [`test_outflow_breaker.py`](tests/unit/test_outflow_breaker.py): a credential draining many accounts, concurrent bursts, latching and release
- [`test_policy_api.py`](tests/unit/test_policy_api.py), [`test_ssrf.py`](tests/unit/test_ssrf.py): a stolen key trying to loosen FLIT or reach inside the network
- `test_agent_*.py`, [`test_triage.py`](tests/unit/test_triage.py): permission ladder, hooks, guardrails and injection-safe tool outputs

CI runs all of this on every pull request ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

---

## Honest limits

- **The evidence is mostly synthetic.** One detector is historically backtested. The session-scoring and takeover rules were measured on an incident replay whose labels overlap the features they read, which is recorded and earns no rung. The outflow controls have been tested on synthetic data only. None of this has been shadow-validated on a bank's live traffic yet.
- **FLIT only sees what you send.** A debit path that skips the call is unprotected. FLIT doesn't connect to national payment switches, trace funds across banks or see POS cash-out.
- **A drain that stays under every limit, night after night, gets through.** Size `per_initiator_untrusted` with that in mind, and watch the loss ledger.
- **Session scoring needs volume.** Below 4 events in the window there is no shape to read.
- **30 F3 techniques are outside FLIT's telemetry** (for example SIM swap and social engineering over the phone). COVERAGE.md lists them with reasons.
- The Django admin is unstyled (no static file server), and the Docker image is built by the deploy target, not by CI. See [Known gaps](docs/deployment.md#known-gaps).

---

## Roadmap

From [THESIS.md](THESIS.md#where-flit-goes-next-set-2026-10-22):

| Move | Status |
|---|---|
| **Learns on its own.** Outcomes recalibrate weights nightly, and a human reviews the calibration rather than every case. | First version built |
| **Scores sessions.** Sequence and shape over the last hour, against the merchant's own baseline. | First version built |
| **Probes the merchant.** An agent that walks the merchant's API in staging, mapped to F3, the way an attacker's agent would. | Planned |
| **Shares in real time.** An actor seen at one merchant is challenged on sight at the next within minutes. | Network reputation exists; real-time sharing is planned |
| **Agent FLIT.** The analyst's agent, earning autonomy by agreeing with your team. | First version built |

The **Addressable** list in [COVERAGE.md](COVERAGE.md) is the detection backlog: 25 F3 techniques FLIT already has the signals for, including stolen session cookies, SMS verification abuse and adversary-in-the-browser.

---

## Contributing, security and licence

- **Contributing:** see [CONTRIBUTING.md](CONTRIBUTING.md). New detectors must declare F3 techniques and an honest maturity, ship a synthetic attack *and* a legitimate lookalike, and keep COVERAGE.md current. Fixtures must be synthetic. Never commit real customer or incident data.
- **Security:** please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues.
- **Code of conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Licence:** [MIT](LICENSE).

<p align="center"><strong>FLIT: protecting money in motion, including from machines.</strong></p>
