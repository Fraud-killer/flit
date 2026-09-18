# Backtesting

Replay a portfolio's historical payments through FLIT's rules and see what it would have caught.

Use it to calibrate thresholds against real outcomes instead of guessing, and to show a prospective merchant what FLIT would have found in their own history.

```bash
python manage.py backtest history.csv \
  --mapping mapping.json \
  --application "Fintech A" --create \
  --out report.json
```

## What you need

| Field | Why it matters |
|---|---|
| **Outcomes** (chargeback, confirmed fraud, confirmed good) | Without labels you get firing rates, but no precision, recall or threshold curve. This is the difference between calibration and exploration. |
| **Credits as well as debits** | The mule rules read money flowing both ways. Debits only, and they are inert. |
| **Counterparty identifiers** | Turns "six credits" into "six different senders". Pseudonymous is fine. |
| **Device identifier** | Any stable per-device value, hashed is fine, as long as the same device hashes the same way. Drives the device graph rules. |
| IP address, user agent, timestamps | Feeds the IP, bot and velocity rules. |
| Account age | Feeds dormancy and new-account signals. |

**Send no raw card numbers or personal details.** Nothing here needs them. Hashed identifiers are enough for every rule FLIT has, and they keep the exercise out of scope for most data-protection headaches.

## The mapping file

Every export names its columns differently, so a small mapping file describes yours rather than reshaping the export by hand:

```json
{
  "fields": {
    "id": "txn_ref",
    "type": "direction",
    "amount": "amount_minor",
    "client_id": "customer_uuid",
    "counterparty_id": "peer_uuid",
    "device_id": "device_hash",
    "ip_address": "ip",
    "user_agent": "user_agent",
    "account_age_days": "customer_age_days"
  },
  "constants": { "currency_code": "NGN" },
  "values": { "type": { "IN": "credit", "OUT": "debit" } },
  "label_field": "outcome",
  "labels": { "chargeback": "chargeback", "confirmed_fraud": "fraud", "settled": "legit" },
  "amount_scale": 0.01,
  "timestamp_field": "created_at"
}
```

- `fields` maps **FLIT's field name** to your column. `values` and `labels` are keyed the same way.
- `amount_scale` converts minor units (`0.01` for kobo or cents).
- Labels must map onto `fraud`, `chargeback`, `legit` or `false_positive`. Anything unmapped stays unlabelled and is excluded from precision and recall.

CSV, JSON and newline-delimited JSON are all accepted.

## How the replay stays honest

- **The clock moves with the data.** Every rule asks what time it is — velocity windows, dormancy, first-seen. Replaying old payments against today's clock would silently disable most of them, so the replay freezes time at each transaction's own timestamp and processes them in order.
- **Labels arrive late.** A chargeback lands weeks after a payment. Applying labels instantly would let `MuleNetworkRule` see fraud nobody had reported yet, and flatter the results. Labels are applied once the simulated clock passes `--label-delay-days` (default 7).
- **It runs the real rules.** Not a copy of the logic, so the numbers reflect what production would do.

A replay **writes** decisions, devices and labels to the database, so point it at an application created for the purpose (`--create`), never a live one.

## Reading the report

```
Current policy (block at 0.7)
  blocked 70 (6.5%), caught 17, missed 9, false positives 53 (5.0%)
  precision 0.2429, recall 0.6538

Threshold curve
   block_at  blocked  caught  missed  false+   prec  recall
       0.85       40      13      13      27  0.325     0.5
       0.95       12      10      16       2 0.8333  0.3846

Rules (by lift)
  rule                              fired  fraud  legit       lift
  pass_through_funds                   12     12      0 fraud only
  many_unique_payers                   16      9      7      51.67
```

- **The curve is the decision.** Each row is a trade: blocking lower catches more fraud and turns away more good customers. Pick the point that matches the portfolio's appetite, then set `block_at` in the policy.
- **Lift ranks the rules.** How much more often a rule fires on fraud than on good customers. Above 1 carries signal; at or below 1 is noise however often it fires. `fraud only` means it never fired on a good customer — the most useful kind.
- **`false_positive_rate`** is the share of *known good* customers that would be blocked. It is the number a merchant will ask about first.

## Comparing two portfolios

```bash
python manage.py backtest_overlap "Fintech A" "Fintech B"
```

Reports shared devices, counterparties and IPs, and then the number that matters: **how much of each portfolio's confirmed fraud came from a device the other portfolio had already seen**. That is the consortium argument, measured rather than asserted.

## Caveats worth stating to a merchant

- **Survivorship bias.** The export only contains transactions their current system allowed. Fraud it already blocked is invisible, so measured recall flatters FLIT.
- **Label quality decides everything.** "Chargeback" is not "fraud" — friendly fraud and service disputes live there too. Mislabelled data produces confidently wrong thresholds.
- **Class imbalance.** A thousand transactions with four frauds cannot calibrate anything. Volume matters more than breadth.

## Trying it without real data

```bash
python manage.py backtest_sample --out wallet.csv --mapping mapping.json --prefix wallet --shared-ring
python manage.py backtest_sample --out lender.csv --prefix lender --seed 11 --shared-ring
```

Generates two synthetic portfolios with mule rings and card-testing planted among ordinary traffic; `--shared-ring` makes one ring work both, so the overlap analysis has something real to find. The patterns are planted, so this proves the harness runs end to end — **not** that the rules are accurate. Only real portfolios can show that.
