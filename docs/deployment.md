# Deploying FLIT

Written for whoever is putting FLIT in front of real traffic for the first
time. It assumes Railway, because that is where it is going; nothing here is
Railway-specific except the commands.

## What FLIT needs

| | Why |
|---|---|
| **Postgres** | Decisions, the identity graph, cases, the audit log |
| **Redis** | Not optional. The identity baselines, sanctions list, threat lists, domain and wallet caches all live in the shared cache, and WebSocket alerts use it as a channel layer. Without it, workers disagree with each other. |
| **Outbound HTTPS** | Domain, chain and sanctions lookups. All degrade to "unknown" rather than failing a decision, so this is optional in the sense that FLIT still works — with less signal. |

## First deploy

The whole project — the API, Postgres, Redis and the five scheduled jobs — is
declared in `.railway/railway.ts` and applied with Railway's Infrastructure as
Code. Nothing is clicked together in the dashboard, so what runs is what the
repository says runs. (`railway.toml` is gone: Railway stops reading it on
2026-12-01.)

```bash
brew upgrade railway      # needs 5.42 or newer for `railway config`
npm install               # the `railway` SDK the authoring file imports
railway login
railway init --name flit  # or: railway link, for an existing project

export FLIT_SECRET_KEY="$(python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')"
export FLIT_MCRYPT_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

railway config plan       # read-only preview of everything it will create
railway config apply
```

The two secrets are read from the shell only while the file is applied; in
every later apply they are left as Railway holds them (`preserve()`). Nothing
secret is in the file or in git.

`MCRYPT_KEY` encrypts every merchant's API secret. **Rotating or losing it
invalidates all of them** — back it up somewhere you would back up a signing
key, not somewhere you would back up a config file.

The first apply builds `Dockerfile.app`, runs `migrate` as a pre-deploy step
(once per deploy, not once per replica) and health-checks `/health/`, which is
exempt from the HTTPS redirect so the check sees the app rather than a 301.
`healthcheck.railway.app`, the host the check arrives as, is already in
`ALLOWED_HOSTS`; without it Django answers 400 and Railway calls the deploy
unhealthy.

Then give the API a hostname and tell Django about it:

```bash
railway domain --service flit
```

Put the generated (or custom) host in `PUBLIC_HOSTS` in `.railway/railway.ts`
and apply again. That fills `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`.

Railway's GitHub app must be able to see the repository for the `github(...)`
source to deploy. If the first apply reports that it cannot, authorise the
organisation once in the Railway dashboard and apply again, or deploy the
working tree directly with `railway up --service flit` (and once per job
service) while that is sorted out.

## Scheduled jobs

Eight matter. Each is its own cron service in `.railway/railway.ts`, built from
the same image as the API:

```bash
python manage.py deliver_webhooks --limit 200   # every 5 minutes — drains the webhook queue
python manage.py expire_challenges              # every 5 minutes
python manage.py refresh_sanctions              # daily 03:30 UTC — alert on failure
python manage.py refresh_threat_intel           # hourly at :15 — Tor exits and IP blocklist into the cache
python manage.py calibrate --all --apply        # nightly 02:00 UTC — learn from outcomes
python manage.py verify_audit_chain             # nightly 04:00 UTC — exits non-zero on a break
python manage.py run_monitors                   # every 5 minutes — Agent FLIT monitors (no-op while the agent is off)
python manage.py run_investigations --limit 10  # every 5 minutes — drains queued investigations (no-op while the agent is off)
```

The last two cost nothing while `AGENT_ENABLED` is off. With it on, a queued
investigation (from the API, a case, a monitor, or an answered approval) waits
up to five minutes for the next pass; when that is too slow for your
reviewers, run `run_investigations --loop` as an always-on service instead
and drop the cron. Both take the job lock, so two workers never run the same
investigation.

Five minutes is Railway's floor between cron runs, so a webhook is delivered
within five minutes of the decision plus the row's own backoff, not within one.
Railway has no alert of its own for a cron that exits non-zero; watch
`refresh_sanctions` and `verify_audit_chain` from whatever already watches
your logs.

Every scheduled command holds a cache lock while it runs (`core.services.job_lock`), so
a cron that fires twice skips the second run instead of calibrating the same
application twice or delivering the same webhook twice; a lock older than an hour
is reclaimed. With `TRIAGE_ENABLED` set, add `python manage.py triage --application NAME`
hourly per application; it proposes in shadow until `--apply` is added and the
measurement allows it.

`deliver_webhooks` is idempotent and safe to overlap: a delivery is claimed
by being saved with its next attempt time, and a merchant endpoint that is
down costs nothing but a row waiting for its backoff.

When a rule is running in shadow for a merchant, `shadow_report` is the
measurement; run it when the labels have had time to arrive:

```bash
python manage.py shadow_report --application "Figo" --days 14 --record-evidence
```

`loss_report --application NAME --days 30` is the number a merchant's fraud
head wants: what FLIT prevented, leaked and turned away, per currency, from
the outcomes they reported. It is also `GET /applications/{id}/loss`. Run it
when you review the shadow period; it is only as complete as the labels and
amounts the merchant sends.

`verify_audit_chain` walks every application's hash chain and fails when a
row has been edited or the chain has been broken. The chain only proves
anything if somebody runs this; wire the exit status to an alert.

`calibrate` is the loop that moves weights from the labels that arrived. It
is safe to schedule with `--apply` because of its guardrails: a bounded step
per weight, a minimum labelled sample, and a re-score of the month under
every proposal that rejects anything blocking more good customers or
catching less fraud. It never changes a detector's evidence claim; it says
which rules have earned one. Every run is a `CalibrationRun` row, so the
review is `GET /applications/{id}/calibrations`, and a held run with its
reason is as much the point as an applied one.

A sanctions list that quietly stopped refreshing is worse than no list, so
FLIT reports an unloaded or stale list on the decision itself. Alert on the
job anyway — the report tells the merchant, not you.

If a calibration run turns out to have been wrong, undo it by id:

```bash
python manage.py calibrate --rollback <run_id>
```

Every weight the run moved goes back to where it moved it from, and the
reversal is its own `CalibrationRun` row next to the original.

## Agent FLIT

Off by default. To turn it on: set `AGENT_ENABLED=true` and `ANTHROPIC_API_KEY`
on the API service and on the `run-investigations` and `run-monitors`
services. Every application's agent policy starts in `propose` mode; the
order to loosen it, and why, is in `docs/agent.md` ("Turning it on, in
order"). Watch the `agent_action` and `agent_investigation_*` rows on the audit
chain the way you watch policy changes; `agent_policy_loosened` is the one
that matters.

## Behind a load balancer

`TRUSTED_PROXY_DEPTH` is the number of proxies that append to
`X-Forwarded-For` before a request reaches FLIT. `.railway/railway.ts` sets it
to 1 — one balancer. Rate limits and the recorded client address then use the
entry your balancer wrote, not the one the client typed. Unset, FLIT reads the
first entry, which a client can forge. Change it if you put another proxy in
front.

## Onboarding a merchant

```bash
railway run python manage.py provision_application "Figo" \
  --owner ops@spendfigo.com --currency USD
```

It prints the application id, the secret key and the collect key. **The secret
is shown once** — only its encrypted form is stored and nothing can print it
back.

Set the currency. A policy limit denominated in a currency the merchant does
not use cannot be evaluated at all, and every decision reports a mismatch
instead. The first Figo backtest ran with an NGN limit against a USD
portfolio and the AML rule never evaluated once.

Applications are created in **shadow**. See `docs/integrations/figo.md` for
what that means and when to leave it:

```bash
railway run python manage.py set_enforcement Figo enforcing
```

That command prints what the shadow period actually saw — how many decisions,
how many would have blocked — and warns if there is no history behind the
decision.

## Optional integrations, and what you lose without them

Everything here is optional. FLIT degrades rather than fails.

| Not configured | Effect |
|---|---|
| `GEOIP_DB_PATH` | No ASN, country or datacenter detection. `IPReputationRule` falls back to Tor and blocklist matching only. |
| `FINGERPRINT_*` | Device identity comes from FLIT's own `/v1/collect` collector instead. Nothing else changes, and onboarding works without a Fingerprint account. |
| `TURNSTILE_SECRET_KEY` | Turnstile challenges error rather than pass — deliberately, since a verifier that cannot be reached must not wave an actor through. OTP challenges are unaffected. |
| `CHAIN_RPC_URLS` | Public nodes are used. They are rate limited; set your own before any real volume. |

## Before enforcing anything

Deploying FLIT is not the same as letting it act. A new application is in
shadow, and it should stay there until its own traffic says otherwise — see
"When to turn enforcement on" in `docs/integrations/figo.md`.

The one number worth knowing before you start: decision latency measured over
200 registrations was **p50 7.5ms, p95 8.7ms, p99 11.5ms** on SQLite with a
cold cache. Postgres and a network hop will add to that, and the client-side
timeout is what actually protects a signup path — not the average.

## Health

| Path | For |
|---|---|
| `/health/` | Liveness, used by the Railway health check |
| `/health/ready/` | Readiness — checks the database |
| `/health/status/` | Detailed status |

## Running FLIT on a bank's money-out path

These controls stop one credential from draining accounts. Both are off until
a policy turns them on, so nothing changes for other integrations.

**FLIT only protects paths that call it.** Every debit path has to call
`audit-transaction` before the money moves, and has to refuse the transfer
unless the answer says otherwise. A route that skips the call is unprotected,
and so is a flaw that lets an attacker skip the bank's own middleware. FLIT also
does not replace the bank's authorization: a partner credential that can reach
other merchants' accounts has to be fixed in the bank's API.

**What each debit must send**, besides the amount, currency and `client_id`:

| Field | Meaning |
|---|---|
| `initiator_id` | The credential, partner or operator behind the transfer |
| `channel` | The rail, such as `nip` or `intrabank` |
| `counterparty_id` | The beneficiary's account |
| `counterparty_bank` | The beneficiary's bank; an account number alone is not unique |

Send an `initiator_id` for customer-initiated debits too, such as `customer`.

**Fail closed.** Wrap these calls in `failClosed(flit.auditPayout(event))` from
`sdk/node/flit.mjs`, or do the equivalent in your own client: no decision, no
transfer. `failOpen` is for signups. Check the volume on this path against the
default of 1,000 audit calls a minute per origin, and set
`provision_application --audit-rate-limit` if it could pass that, because a
refused call is now a refused payment.

**Configure the policy** with `PATCH /api/v1/applications/:id/policy`:

```json
{
  "beneficiary_control": {"enabled": true, "cooling_hours": 72},
  "outflow_limits": {
    "currency": "NGN",
    "per_initiator": {"15m": 5000000, "1h": 10000000, "24h": 50000000},
    "per_initiator_untrusted": {"1h": 2000000, "24h": 5000000},
    "per_channel": {"1h": 50000000},
    "per_application": {"24h": 500000000},
    "off_hours": {"start": "20:00", "end": "07:00", "timezone": "Africa/Lagos", "factor": 0.25},
    "fail": "block"
  }
}
```

The numbers above show the shape only. Set them from the bank's own volumes. An
application key can tighten these; only a signed-in owner can raise, remove or
relax them.

**Go-live order:**

1. Run in shadow for longer than the cooling period. `should_block` stays false,
   `would_block` shows what would have stopped, and beneficiaries are learned.
2. Add known settlement accounts with `POST .../trusted-beneficiaries`, which
   needs a signed-in person.
3. Review the would-be stops against known-good traffic, and set the limits.
4. Move to enforcing with `set_enforcement`.

If a business legitimately pays new beneficiaries, leave `UnknownBeneficiaryRule`
in `shadow_rules` and rely on the breaker, with a `per_initiator_untrusted` limit.
In shadow, the rule's findings show how much of the real volume goes to new
beneficiaries, which is the number to set that limit from.

**Unknown beneficiary.** A debit is refused unless this credential has a trusted
history of paying this beneficiary from this account. Trust comes from a link
aging through the cooling period or from a person's approval. A fraud or
chargeback label ends it. Once enforcing, a refused transfer teaches FLIT
nothing, so a genuinely new beneficiary needs a person to approve it first.

**Outflow breaker.** A debit that would take a scope over a limit is refused, and
the scope stays stopped until a signed-in person releases it with
`PATCH .../outflow-trips/:id`, which also clears its window. Open trips are at
`GET .../outflow-trips`. A `per_application` or `per_channel` trip stops all
outflow in that scope, so set those limits with that in mind. Each trip sends an
`outflow.tripped` webhook straight away and opens a case.

`per_initiator_untrusted` counts only debits to a beneficiary this credential
has no trusted history of paying from this account, or debits that don't say
where they go. It can sit far below `per_initiator`, because a drain goes to new
accounts and settlement mostly doesn't. Its trip stops only such debits, so
payments to trusted beneficiaries carry on. Links are learned whenever this
limit or `beneficiary_control` is set. When a credential trips, its links still
in the cooling period are revoked, so payees found during a drain kept under the
limit never become trusted by age; a person can approve any that are genuine.
It doesn't stop a drain that stays under this limit night after night; size it
with that in mind. Point that webhook at
something that wakes a person up, because trips happen at night.

**Redis.** Window totals live in the cache. If Redis cannot be reached, debits
are refused (or reviewed, with `"fail": "review"`). If Redis restarts or evicts
these keys, the totals restart from zero without any error. Use persistence and a
`noeviction` policy, and confirm both on the deployed instance. Open trips and
beneficiary links are in Postgres and are not affected.

**What this does not do:** it doesn't connect to NIBSS, trace funds across banks,
or detect POS cash-out. It has been tested only against synthetic data, so the
coverage matrix lists both rules as synthetic-tested.

## Known gaps

- **No static file server.** `django.contrib.admin` is installed but its CSS
  will not load, because nothing serves `STATIC_ROOT`. The admin is usable but
  unstyled. Every operational task has a management command precisely so that
  admin is never on the critical path; add whitenoise if you want the admin to
  look right.
- **The image is built only by Railway.** `Dockerfile.app` is exercised by
  `docker-compose` locally and by every Railway deploy, but CI does not build
  it. Two things the first Railway build taught: the build context is
  `.dockerignore` (Railway falls back to `.gitignore` without one, which hid
  `app/Pipfile.lock`), and the base image must be Python 3.11 because that is
  what the lockfile was resolved for and `pipenv --deploy` refuses anything
  else.
