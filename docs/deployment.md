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

```bash
railway login
railway init            # or: railway link, for an existing project
railway add --database postgres
railway add --database redis
```

Railway injects `DATABASE_URL` and `REDIS_URL`. Set the rest:

```bash
railway variables set \
  SECRET_KEY="$(python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')" \
  MCRYPT_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  DEBUG=False \
  ALLOWED_HOSTS='["flit.up.railway.app"]' \
  CSRF_TRUSTED_ORIGINS='["https://flit.up.railway.app"]' \
  CACHE_URL="$REDIS_URL"

railway up
```

`MCRYPT_KEY` encrypts every merchant's API secret. **Rotating or losing it
invalidates all of them** — back it up somewhere you would back up a signing
key, not somewhere you would back up a config file.

`railway.toml` runs `migrate` as a pre-deploy step and health-checks
`/health/`, which is exempt from the HTTPS redirect so the check sees the app
rather than a 301.

## Scheduled jobs

Two matter, as separate Railway cron services:

```bash
python manage.py refresh_sanctions    # daily — alert on failure
python manage.py expire_challenges    # every few minutes
```

A sanctions list that quietly stopped refreshing is worse than no list, so
FLIT reports an unloaded or stale list on the decision itself. Alert on the
job anyway — the report tells the merchant, not you.

`refresh_threat_intel` (Tor exit nodes, IP blocklist) is worth an hourly job
if IP reputation matters to you.

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
- **The image has not been built in CI.** `Dockerfile.app` is exercised by
  `docker-compose` locally but no pipeline builds it, so the first Railway
  build is the first real test of it.
