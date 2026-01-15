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
| `FINGERPRINT_SERVER_API_KEY` | Fingerprint.js API key | Required |
| `DEBUG` | Enable debug mode | `false` |

## API Usage

### Audit a Transaction

```bash
curl -X POST http://localhost:18000/api/v1/applications/{app_id}/audit-transaction \
  -H "Authorization: HMAC-SHA256 {app_id}:{signature}" \
  -H "Content-Type: application/json" \
  -H "X-Timestamp: $(date +%s)" \
  -H "X-Nonce: $(uuidgen)" \
  -d '{
    "client_id": "user_123",
    "device_fingerprint": "fp_abc123",
    "amount": "1000.00",
    "currency_code": "USD",
    "latitude": 40.7128,
    "longitude": -74.0060
  }'
```

### Response

```json
{
  "ok": true,
  "data": {
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
| `IPConcentrationRule` | Datacenter IPs, multiple cards/customers per IP | 0.8 |

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
