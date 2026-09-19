-- Figo -> FLIT backtest export.
--
-- One row per transaction, with the two fields FLIT cannot get from the
-- transactions table alone:
--
--   counterparty_address  the external address on the other side, which is
--                         what CollectionWalletRule counts accounts against
--                         and what FreshFundingWalletRule asks about
--
-- Figo's own wallet_addresses rows are deliberately not exported. They are
-- deposit addresses Figo generates per user, so each correlates only the
-- account it already belongs to, and its age says when Figo created it. The
-- address worth having is the external one on the other side of the transfer,
-- which for deposits currently sits in provider_data rather than a column.
--
-- A crypto destination lives on the recipient row as `account_number` when
-- the channel is CRYPTO — the same column holds a bank account number for
-- fiat rails, so the channel check is what keeps the two apart.

SELECT
    t.id,
    t.type::text                AS type,
    t.status::text              AS status,
    t.amount,                   -- minor units; mapping applies amount_scale
    t.currency::text            AS currency,
    t.user_id,
    t.recipient_id,
    t.chain::text               AS chain,
    t.asset::text               AS asset,
    t.hash,
    t.wallet_balance_after,
    t.created_at,

    CASE
        WHEN r.channel::text = 'CRYPTO' THEN r.account_number
    END                         AS counterparty_address

FROM transactions t
LEFT JOIN transaction_recipients r ON r.id = t.recipient_id
WHERE t.deleted_at IS NULL
  -- Figo launched in February 2026; earlier rows are beta and distort
  -- baselines. See the launch-date note in the Figo CNS memory.
  AND t.created_at >= '2026-02-01'
ORDER BY t.created_at;
