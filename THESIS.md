# FLIT — Protecting Money in Motion

> **"Stripe increases the world's GDP. Flit protects the world's money."**

---

## The Core Belief

**No merchant or customer should lose money to fraud that could have been prevented.**

Most fraud today isn't sophisticated.
It's **predictable, repeatable, and ignored until it's expensive.**

Flit is built to stop that.

---

## What Problem Flit Is Actually Solving

Fraud today is treated as:

* A **cost of doing business**
* A **post-transaction problem**
* A **chargeback or dispute workflow**

Flit flips that model.

### Flit's Thesis

Fraud is not a payments problem.
It's a **decision-quality problem at the moment of transaction**.

Merchants don't lack tools.
They lack **real-time certainty**.

---

## Flit's Positioning (Crisp & Defensible)

### ❌ What Flit Is *Not*

* Not another payments processor
* Not a chargeback recovery tool
* Not a rules engine merchants babysit

### ✅ What Flit *Is*

* A **loss-prevention layer** for digital commerce
* A **real-time fraud decision system**
* A **shared protection network** between merchants and customers

Think:

> **"Cloudflare, but for fraud."**
> **"Seatbelts, not ambulances."**

---

## Mission Statements

1. **"Flit exists to make preventable fraud impossible."**
2. **"Protecting merchants and customers from losing money they shouldn't lose."**
3. **"Fraud prevention, before the money moves."**
4. **"Flit protects money in motion."**

---

## The Emotional Hook

Stripe sells **growth**.
Flit sells **peace of mind**.

### For Merchants

> *"I can scale without fear."*

### For Customers

> *"I trust this merchant with my money."*

That trust compound is enormous.

---

## Why This Is a Big Market

* Global fraud losses → **$40B+ annually**
* Fraud grows faster than GDP
* AI has made fraud cheaper, faster, and harder to spot
* Regulators increasingly shift liability to merchants

**Flit isn't optional. It's inevitable.**

---

## Taglines

* **"Stop fraud before it costs you."**
* **"Preventable fraud ends here."**
* **"Trust every transaction."**
* **"Protection, not reaction."**
* **"Because fraud shouldn't be the cost of growth."**

---

## Strategic Position

Flit's framing is excellent because:

* We're not competing with Stripe
* We're **orthogonal** to them
* We can integrate with *every* processor

If Flit becomes:

> *"The default loss-prevention layer merchants plug in before they scale"*

...we're building **infrastructure, not a feature**.

---

## Technical Manifestation

This thesis is implemented through:

### Pre-Transaction Decision Engine

```
Request → Security Layer → Audit Engine → Risk Score → Decision
                ↓                ↓              ↓
           Rate Limit      15+ Rules      ALLOW/REVIEW/BLOCK
           Replay Check    ML Scoring     Real-time Alert
           Bot Detection   Historical     Merchant Dashboard
```

### Core Capabilities

| Capability | Purpose | Thesis Alignment |
|------------|---------|------------------|
| **Real-time Risk Scoring** | Sub-100ms decisions | "Before the money moves" |
| **Device Fingerprinting** | Identity certainty | "Real-time certainty" |
| **Velocity Detection** | Pattern recognition | "Predictable fraud" |
| **Bot Detection** | Automation blocking | "Seatbelts, not ambulances" |
| **IP Intelligence** | Network-level protection | "Shared protection network" |
| **Gateway Pattern Analysis** | Learn from declines | "Continuous improvement" |

### Rule Categories

1. **Identity Rules** — Who is making this transaction?
2. **Behavior Rules** — Does this match expected patterns?
3. **Compliance Rules** — Does this meet regulatory requirements?
4. **Fraud Rules** — Does this match known attack patterns?

---

## The FLIT Promise

Every transaction that passes through FLIT receives:

1. **A risk score** — Quantified certainty
2. **A recommendation** — ALLOW, REVIEW, or BLOCK
3. **Explainable factors** — Why this decision was made
4. **Real-time alerts** — For high-risk events
5. **Audit trail** — Immutable, tamper-proof logs

---

## Success Metrics

| Metric | Target | Why It Matters |
|--------|--------|----------------|
| **Fraud Prevention Rate** | >95% | Core value proposition |
| **False Positive Rate** | <1% | Don't block good customers |
| **Decision Latency** | <100ms | Real-time requirement |
| **Integration Time** | <1 day | Zero friction adoption |
| **Uptime** | 99.99% | Infrastructure reliability |

---

## Competitive Moat

1. **Data Network Effects** — More merchants = better fraud detection
2. **Real-time Architecture** — Built for speed, not retrofitted
3. **Processor Agnostic** — Works with everyone
4. **Developer Experience** — Simple API, powerful results
5. **Continuous Learning** — Every transaction improves the system

---

## Where FLIT Goes Next (set 2026-10-22)

On 20 October 2026 one operator — almost certainly an agent with a browser
and a shell — created 226 accounts and 17 merchant tenants against a live
card issuer, rotated six client strings, tested SSRF, mass assignment and
cross-tenant access, named each probe after what it was testing, and took 18
accounts in 52 minutes. The attacker is now cheaper than the defender's
review queue, adapts inside a single session, and reads the merchant's API
the way an engineer reads a repo.

A rules engine that scores events loses to that on arithmetic. FLIT evolves
into:

**A system that learns from outcomes on its own, scores sessions instead of
events, probes the merchant before the attacker does, and shares what it
sees across merchants in real time.**

The four moves, each built on something already here:

| Move | From | To | Foundation already in place |
|---|---|---|---|
| **Learns on its own** — *first cut built 2026-10-22* | Cases a reviewer labels, thresholds a person sets | Outcomes recalibrate thresholds nightly; a human reviews the calibration, not the cases. `Calibrator` reads the month's labelled decisions, proposes bounded weight moves per code from measured precision, re-scores the month under each and together, accepts only what passes the guardrails (false positives ≤ 1%, no rise beyond tolerance, no drop in recall), and writes every run to a `CalibrationRun`. Decisions now use the calibrated engine (`engine_for`), so the policy a simulation predicted is the policy that decides. `manage.py calibrate --all --apply` nightly; `GET /calibrations` is the review queue | Evidence ledger, backtest harness, `simulate_policy`; `tests/unit/test_self_calibration.py` |
| **Scores sessions** — *first cut built 2026-10-22* | A fixed threshold per event (90 s, 3 accounts, a UA list) | The sequence of actions from one origin over an hour, scored against what a human session looks like. `SessionShapeRule` reads one origin's hour — accounts touched, client families, cadence, accounts it did not create, the takeover motif repeating — against `SessionBaseline`, percentiles of the merchant's own recent sessions. The October replay with the reset slowed to 150 s and a different client per account steps over every event rule and is blocked from the third account | Identity ladder, `AccountActivity`, `AuthenticationEvent`; `tests/unit/test_session_scoring.py` |
| **Probes the merchant** | Assumes the application is sound and the user is the problem | A FLIT agent that walks the merchant's API in staging, continuously, mapped to F3 — a fourth coverage column: *is the merchant exposed* | F3 taxonomy, coverage matrix, the Gh0stAnts and October findings as the first test set |
| **Shares in real time** | Nightly sync, k-anonymity floor | An actor seen at one merchant is challenged on sight at the next, in minutes | `NetworkReputationRule`, shared identity keys |

And one principle that follows from all four: **enforcement has to be cheaper
than detection.** Blocking tells the loop which variation failed. Step-ups
that cost wall-clock time — a delayed reset email, a liveness check on a
new-device withdrawal, a hold on a first payout to a new address — cost a
customer a minute and cost an agent its economics.

None of this relaxes the standard that already exists. Every move still has
to answer: what is the evidence, and can it be traced to a dataset.

---

<p align="center">
  <strong>FLIT — Protecting Money in Motion</strong><br>
  <em>"Flit exists to make preventable fraud impossible."</em>
</p>
