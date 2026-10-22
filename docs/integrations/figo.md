# Integrating Figo

Figo is a cross-border card issuer: users fund in local currency or USDC, and
spend in USD on a virtual Visa card. It is a useful first integration because
it exercises both halves of FLIT at once — a card rail with issuer declines
and chargebacks, and a crypto rail with on-chain funding and withdrawals.

This guide maps Figo's schema onto FLIT's events. Column names below are the
real ones, taken from the production schema rather than invented.

## What Figo already has

Figo's `transactions` table carries almost everything FLIT needs:

| FLIT field | Figo column | Notes |
|---|---|---|
| `id` | `id` | |
| `type` | `type` | `deposit`/`refund` → credit, `withdrawal`/`internal_transfer`/`bills` → debit |
| `amount` | `amount` | **Minor units.** Scale by 0.01 or every threshold is out by 100× |
| `currency_code` | `currency` | |
| `client_id` | `user_id` | |
| `counterparty_id` | `recipient_id` | |
| `status` | `status` | `success`, `failed`, `pending`, `processing`, `cancelled` |
| `chain` | `chain` | `polygon` dominates; also `base`, `solana`, `stellar`, `bnb` |
| `asset` | `asset` | `usdc`, `usdt` |
| `transaction_hash` | `hash` | |
| `current_cumulative_balance` | `wallet_balance_after` | |

Two fields need a join, and they are the two that drive the crypto rules:

- **`wallet_address`** — the user's own deposit address, from
  `wallet_addresses` by `user_id` and `chain`. This becomes their
  identity-ladder rung, which is what lets FLIT correlate accounts with no
  device fingerprint and no shared IP.
- **`counterparty_address`** — where a withdrawal went. It lives on
  `transaction_recipients.account_number`, but **only when
  `channel = 'CRYPTO'`**: the same column holds a bank account number for
  fiat rails, and keying on that would treat a sort code as a wallet.

`integrations/figo/export.sql` does both joins.

## Backtesting Figo's history

This is the first thing to do, and the only way to move any detector off
`proposed` on the evidence ladder:

```bash
psql "$FIGO_DATABASE_URL" -c "\copy ($(cat integrations/figo/export.sql)) TO 'figo.csv' CSV HEADER"

python manage.py backtest figo.csv \
  --mapping integrations/figo/backtest-mapping.json \
  --application "Figo" --create \
  --out figo-report.json \
  --record-evidence
```

`--record-evidence` writes the measured per-rule results into the evidence
ledger. Without labelled outcomes it records nothing and says so — firing
rates are activity, not evidence, and dressing one up as the other is the
failure this whole ladder exists to prevent.

To get labels, post confirmed outcomes back through
`POST /v1/applications/{id}/outcomes`, or resolve the cases FLIT opens.

## Going live

### Start in shadow. It is the default.

A new application is created in `shadow`: every decision is computed and
recorded exactly as it would be in production, and none of it is acted on.
`should_block` and `should_challenge` come back **false** — not flagged as
unenforced, actually false — so an integration written as
`if (decision.should_block) reject()` cannot turn a customer away during the
shadow period even if someone forgets to check a second flag. What FLIT
decided is reported alongside as `would_block` and `would_challenge`, and it
is the decision that gets **recorded**, so the shadow period is measurable.

Cases still open for review in shadow. A case costs a reviewer's attention,
not a customer's signup, and reviewing is how the labels arrive that make
enforcing defensible later.

Flip when the numbers say so, not on a date:

```python
application.enforcement = "enforcing"
application.save()
```

### The three calls

```ts
import { Flit, failOpen } from "./flit.mjs";

const flit = new Flit({
  baseUrl: process.env.FLIT_URL,
  applicationId: process.env.FLIT_APPLICATION_ID,
  secretKey: process.env.FLIT_SECRET_KEY,
});
```

**1. Registration** — the surface FLIT is strongest on, and the one the
September flood hit.

```ts
const decision = await failOpen(
  flit.auditRegistration({
    id: user.id,
    client_id: user.id,
    email: user.email,
    country: user.country,
    ip_address: req.ip,
    user_agent: req.headers["user-agent"],
    visit_token: body.flit_visit_token,   // from the browser SDK, if present
    action: "registration",
  }),
  (error) => logger.warn({ error }, "flit unavailable"),
);

if (decision.should_block) return reject();
if (decision.should_challenge) return stepUp();
```

**2. Transaction** — every deposit, withdrawal and card spend.

```ts
await failOpen(flit.auditTransaction({
  id: transaction.id,
  client_id: transaction.user_id,
  type: transaction.type === "deposit" ? "credit" : "debit",
  amount: transaction.amount / 100,        // FLIT takes major units
  currency_code: transaction.currency,
  chain: transaction.chain,
  asset: transaction.asset,
  counterparty_address: cryptoDestination,  // recipient.account_number when channel is CRYPTO
  ip_address: req.ip,
  user_agent: req.headers["user-agent"],
}));
```

**3. Outcome** — whenever a dispute, chargeback or confirmed fraud lands.
This is the one that matters most and the one that is easiest to skip: it is
what fills the evidence ledger and what the shared network learns from.

```ts
await failOpen(flit.reportOutcome({ event_id: transaction.id, label: "fraud" }));
```

**4. Authentication** — every credential action, as it happens. This is the
call that did not exist on 20 October 2026, when eighteen accounts were taken
by requesting a reset and logging in seconds later. The reset flow was
already rate-limited and attempt-capped; what it could not see was the
interval, and the interval only exists if both halves are reported.

Hook these handlers in `autospend-core-api`:

| Figo handler | `action` | Notes |
|---|---|---|
| `POST /users/forgot-password` | `password_reset_requested` | Report even for an unknown address? No — only when a user matched, or the storm count fills with noise |
| `POST /users/:email/reset-password` | `password_reset_completed` | After the token check passes |
| `POST /users/login` | `login` / `login_failed` | After 2FA; pass `second_factor: true` when a code was demanded |
| `POST /users/login/google`, `login/apple` | `login` with `auth_method` | |
| `POST /users/disable-2fa` | `two_factor_disabled` | |
| profile email / phone change | `email_change` / `phone_change` | |

```ts
const decision = await failOpen(flit.auditAuthentication({
  id: `${user.id}:login:${Date.now()}`,
  client_id: user.id,
  action: "login",                       // see the table above
  auth_method: "password",               // "google" | "apple" | "token"
  second_factor: requires2FA,            // was a code demanded and passed?
  ip_address: req.ip,
  user_agent: req.headers["user-agent"],
  visit_token: body.flit_visit_token,
}));

if (decision.should_block) return reject();      // in enforcing mode only
if (decision.should_challenge) return stepUp();
```

Report the reset request *before* sending the email, and the login *after*
the second factor. `ResetToLoginRule` measures between them;
`AutomatedCredentialActionRule` reads the client; `CredentialResetStormRule`
counts accounts per IP. In the replay of the October sequence every takeover
blocks on its own, the third account onward also carries the storm, and the
owners who reset slowly from home in the same hour pass untouched
(`tests/unit/test_credential_takeover.py`).

### Fail open, always

`failOpen` returns an inert decision — nothing blocked, nothing challenged —
if FLIT is slow, down or misconfigured. A fraud decision that has not arrived
is not a reason to turn away a real customer. Every call site should go
through it.

Decision latency measured locally over 200 registrations: **p50 7.5ms, p95
8.7ms, p99 11.5ms**, on SQLite with a cold cache. Add network and Postgres
and it stays comfortably inside a 2s timeout, but the timeout is what
protects the signup path, not the average.

### The browser SDK

Add `sdk/js` to the web app and pass the returned `visit_token` on the
registration call. Without it FLIT falls back down the identity ladder to
email root and IP — which works, and is weaker. Once enough of Figo's traffic
carries a device key, `ExpectedSignalRule` will correctly start flagging the
signups that do not.

### Schedule these

```bash
python manage.py refresh_sanctions          # daily, alert on failure
python manage.py expire_challenges          # every few minutes
python manage.py calibrate --all --apply    # nightly: learn from the month's outcomes
```

The last one is the always-on loop. It reads the labels that arrived —
cases closed, chargebacks and false positives reported — proposes bounded
weight changes, re-scores the month under each, and applies only what passes
the guardrails (no more than 1% of good customers blocked, no rise in false
positives beyond tolerance, no drop in recall). Every run, applied or held,
lands in `GET /applications/{id}/calibrations`. Review that, not the cases.

### When to turn enforcement on

Not on a date — on evidence. After a few weeks of shadow, ask the decision
feed:

1. **What would have been blocked, and were any of them good customers?**
   `GET /decisions?days=30` against known-good accounts is the false-positive
   rate FLIT would have imposed. If it is not acceptable, tune thresholds
   before enforcing, not after.
2. **Did the rules that fired have lift?** Run the backtest over the shadow
   period, now with real per-transaction labels from reported outcomes rather
   than the blocked-user proxy.
3. **Start with `challenge`, not `block`.** Raising `block_at` above what the
   data supports while leaving `challenge_at` where it is gets most of the
   protection at a fraction of the customer cost.

## Live integration reference

Three calls, in the order they matter:

1. **Registration** — `POST /v1/applications/{id}/audit-registration` with
   `email`, `country`, `ip_address`, `user_agent`. This is the surface the
   September 2026 signup flood hit, and it is where FLIT is strongest.
2. **Transaction** — `POST /v1/applications/{id}/audit-transaction` on every
   deposit, withdrawal and card spend, with the crypto fields when present.
3. **Outcome** — `POST /v1/applications/{id}/outcomes` when a dispute,
   chargeback or confirmed fraud lands. This is what feeds the evidence
   ledger and the shared protection network.

Add the browser SDK (`/v1/collect`) to the web app for a device key. Without
it FLIT falls back down the ladder to email root and IP, which works but is
weaker — and `ExpectedSignalRule` will correctly start flagging the absence
once enough of Figo's traffic carries one.

## What FLIT will not do for Figo

FLIT does not read chains. No balances, no clustering, no provenance, no
indirect exposure. Figo already has custody and chain analytics providers for
that, and duplicating them badly would help nobody.

FLIT's half is what happens before anything is signed: the device, the
session, the signup, the takeover, and the shape of money moving between
accounts.

Two on-chain exceptions, both deliberately narrow because both are free and
neither needs a graph:

- **Has this wallet ever transacted?** One RPC call. A brand-new wallet
  funding a brand-new account is a farm signature, the same way a
  domain registered yesterday is.
- **Is this address on the OFAC SDN list?** One string comparison against a
  list Treasury publishes publicly. This is the exact-match half of an
  obligation and nothing more — an address one hop from a sanctioned one is
  invisible to it. That is what a screening vendor is for, and a fintech with
  real obligations should still have one.

Both need scheduling:

```bash
python manage.py refresh_sanctions   # daily; alert on failure
python manage.py expire_challenges   # every few minutes
```

A sanctions list that quietly stopped refreshing is worse than no list, so
FLIT reports an unloaded or stale list on the decision itself rather than
letting the check pass silently.

## First backtest: what actually happened

Run 2026-09-19 over **11,868 transactions** (2026-02-01 to 2026-09-19), all
replayed, none skipped.

**Labels are the weak part, and they decide how much any of this means.**
Figo has no chargeback data — `card_disputes` is empty — so the only ground
truth available is which users were blocked. That gives 235 fraud
transactions from 24 blocked users against 11,408 from 457 verified,
never-blocked users. Both sides are approximations: a user blocked in May has
their February transactions labelled fraud, and undetected fraud is labelled
legit.

### The headline

At the shipped threshold of 0.7, FLIT blocked **nothing** and caught **none**
of the 235. The best point anywhere on the curve is `block_at` 0.3–0.4, which
catches 20 of 235 — **8.5% recall at an 8.8% false-positive rate**, precision
0.02. That is not a deployable setting; it is a measurement that the
transaction rules, as they stand, do not separate fraud from good customers
on this portfolio.

### Rule by rule

| Rule code | Fired | On fraud | On legit | Lift |
|---|---|---|---|---|
| `credit_structuring` | 56 | 12 | 44 | **13.1** |
| `pass_through_funds` | 769 | 10 | 751 | 0.65 |
| `crypto_cash_out` | 38 | 0 | 21 | — |
| `high_failure_rate` | 154 | 0 | 154 | — |
| `new_withdrawal_address` | 22 | 0 | 21 | — |
| `dormant_account_activity` | 36 | 0 | 36 | — |

Only **`credit_structuring`** carries signal: 13× more likely on a blocked
user than a good one, precision 0.21. It is the one detector in FLIT now
sitting at `backtested` on the evidence ladder, and this run is why.

`pass_through_funds` has lift **below 1** — it fires slightly *more* on good
customers than on fraud here. That is worth knowing and worth not shipping a
claim about.

### Two defects the run exposed

- **`crypto_cash_out` gated on the chain alone**, and Figo settles internally
  in stablecoin, so 11,859 of 11,868 rows carry a chain. The rule fired 1,352
  times on wallet-to-card movements that never left the platform. It now
  requires an external destination address; firings dropped to **38**.
- **The policy currency defaulted to NGN** while Figo is 100% USD, so
  `policy_currency_mismatch` fired on every row and the AML limit could not be
  evaluated at all. Set `aml_cft_limit` in the currency the portfolio actually
  uses before reading anything into a run.

### Why this is measuring the wrong half

A transactions export does not exercise the part of FLIT that works best on
Figo. The September 2026 signup flood was caught 11 out of 11 by the
registration rules — and none of those rules appear in this backtest, because
a transaction export contains no signups. Figo's documented fraud history is
largely signup-stage: temp-email farming, ring registrations, accounts
blocked before they ever transacted. Of the 69 blocked users, only 24 ever
made a transaction.

So the honest reading is not "FLIT does not work on Figo". It is: **the
transaction rules do not separate this portfolio, the labels are too weak to
conclude much, and the half of FLIT that does work here has not been measured
yet.**

### What would make the next run mean more

1. **Per-transaction labels.** Blocked-user proxy labels put a whole history
   on the wrong side of the line. Even a few dozen confirmed fraudulent
   transactions would be worth more than 235 inferred ones.
2. **Replay registrations, not just transactions.** That is where FLIT is
   strong and where Figo's fraud actually lives.
3. **Report outcomes going forward** through `POST /outcomes`, so labels
   accumulate as ground truth instead of being reconstructed afterwards.

## Observations from Figo's production data

Checked on 2026-09-19, and worth knowing before the first backtest:

- **No collection wallets.** Across every successful crypto withdrawal since
  launch, exactly one destination address has been paid by more than one
  Figo user — two users, six transfers, $94, over nine months.
  `CollectionWalletRule` produces no false positives on this portfolio, and
  Figo does not currently have a mule fan-in problem.
- **Withdrawal failures dominate.** In the last 90 days there were 3,134
  failed withdrawals against 1,699 successful ones. That is an operational
  number rather than a fraud one, but it matters here for two reasons: a
  backtest that counts failed attempts as transactions will overstate
  volume, and a genuine fraud signal hiding in that rate would currently be
  invisible.
