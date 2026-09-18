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

## Features

### Core Security Capabilities

- **Device Fingerprinting** - Integration with Fingerprint.js for reliable device identification
- **Real-time Risk Scoring** - ML-ready weighted scoring engine with configurable thresholds
- **Transaction Monitoring** - AML/CFT compliance with customizable limits
- **Velocity Checks** - Detect rapid-fire requests and unusual activity patterns
- **Impossible Travel Detection** - Flag logins from geographically impossible locations
- **Account Takeover Prevention** - Multi-signal detection for compromised accounts

### Security Infrastructure

- **Rate Limiting** - Per-endpoint, per-user, per-IP throttling with automatic blocking
- **Replay Attack Protection** - Timestamp validation and nonce-based request deduplication
- **Request Validation** - Input sanitization, SQL injection prevention, XSS protection
- **Immutable Audit Logs** - Blockchain-style hash chain for tamper detection

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
