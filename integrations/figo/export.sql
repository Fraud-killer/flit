-- Figo -> FLIT backtest export.
--
-- One row per transaction, with the two fields FLIT cannot get from the
-- transactions table alone:
--
--   wallet_address        the address the user funds from, which becomes
--                         their identity-ladder rung
--   counterparty_address  where a crypto withdrawal went, which is what
--                         CollectionWalletRule counts accounts against
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

    -- The user's own deposit address for this chain, when they have one.
    (
        SELECT w.address
        FROM wallet_addresses w
        WHERE w.user_id = t.user_id
          AND w.chain = t.chain
        ORDER BY w.created_at
        LIMIT 1
    )                           AS wallet_address,

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
