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

Five matter. Each is its own cron service in `.railway/railway.ts`, built from
the same image as the API:

```bash
python manage.py deliver_webhooks --limit 200   # every 5 minutes — drains the webhook queue
python manage.py expire_challenges              # every 5 minutes
python manage.py refresh_sanctions              # daily 03:30 UTC — alert on failure
python manage.py calibrate --all --apply        # nightly 02:00 UTC — learn from outcomes
python manage.py verify_audit_chain             # nightly 04:00 UTC — exits non-zero on a break
```

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

`refresh_threat_intel` (Tor exit nodes, IP blocklist) is worth an hourly job
if IP reputation matters to you.

If a calibration run turns out to have been wrong, undo it by id:

```bash
python manage.py calibrate --rollback <run_id>
```

Every weight the run moved goes back to where it moved it from, and the
reversal is its own `CalibrationRun` row next to the original.

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
