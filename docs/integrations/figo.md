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

## Live integration

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

FLIT does not read chains. It has no balances, no clustering, no sanctions
screening, no provenance. Figo already has custody and chain analytics
providers for that, and duplicating them badly would help nobody.

FLIT's half is what happens before anything is signed: the device, the
session, the signup, the takeover, and the shape of money moving between
accounts.

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
