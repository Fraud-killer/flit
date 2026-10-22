"""
The loop that learns from outcomes on its own.

A fraud tool tuned by a person waiting for complaints is tuned at the speed
of complaints. An attacker that is a loop is tuned at the speed of its own
feedback, which is seconds. The only way to close that gap is for the
defender's thresholds to move on their own, from the ground truth that
already arrives — reviewers closing cases, merchants reporting chargebacks
and false positives — and for the person to review what moved rather than
each case that moved it.

So this runs on a schedule, and it is deliberately cautious:

- It moves a weight only when the labelled sample behind the move is large
  enough to mean something, and only by a bounded step.
- Every proposal is re-scored against the same labelled history before it
  is accepted, and rejected if it would block more good customers than the
  guardrail allows, or catch less fraud than the weights in force.
- The accepted set is re-scored together, because proposals that pass alone
  can fail in combination.
- Everything it saw, proposed, accepted, rejected and why is written to a
  CalibrationRun before anything is applied.

What it does not do is promote a detector up the evidence ladder. A measured
precision over enough labels makes a rule *eligible* for a measured rung, and
the run says so; a person changes the claim.
"""

from collections import defaultdict
from datetime import timedelta

from django.utils import timezone

from core.models import AuditLog, CalibrationRun, CalibrationMode
from core.scoring import DEFAULT_WEIGHTS, DEFAULT_THRESHOLDS
from core.services.simulate_policy import SimulatePolicy

from .engine import engine_for


# Codes that are reported, never scored. Moving their weight is meaningless.
UNSCORED = {"req_event_attrs", "sanctions_screening_unavailable", "sanctions_list_stale"}


class Calibrator:
    WINDOW_DAYS = 30
    MAX_DECISIONS = 20000

    # Sample gates. Below these the run is held: a weight moved on a handful
    # of labels is a guess with a number on it.
    MIN_LABELLED = 50
    MIN_FRAUD = 10
    MIN_FIRED = 20
    MIN_FRAUD_FOR_UP = 5
    MIN_LEGIT_FOR_DOWN = 10

    # A weight that fires this precisely on fraud earns more say; one that
    # fires no more often on fraud than chance earns less.
    UP_AT_PRECISION = 0.8

    # Bounded steps. The loop runs nightly, so a weight that deserves to
    # double gets there in a week, and one that was wrong to move is a small
    # mistake that the next run reverses.
    MAX_STEP = 0.15
    FLOOR = 0.05
    CEILING = 1.0

    # Guardrails, measured on the labelled rows: the share of good customers
    # a candidate would block, and how much that may rise over the weights
    # in force. Recall may never fall.
    MAX_FALSE_POSITIVE_RATE = 0.01
    FALSE_POSITIVE_TOLERANCE = 0.002

    THRESHOLD_SWEEP = (0.6, 0.65, 0.7, 0.75, 0.8)

    @classmethod
    def run(cls, *, application, days=None, apply=False):
        days = days or cls.WINDOW_DAYS
        policy = application.policy
        rows = cls.load(application, days)
        labelled = [row for row in rows if row["decision"].label]
        fraud = [row for row in labelled if SimulatePolicy.is_fraud(row["decision"])]
        legit = [row for row in labelled if SimulatePolicy.is_legit(row["decision"])]

        run = CalibrationRun(
            application=application, window_days=days,
            decisions=len(rows), labelled=len(labelled), fraud=len(fraud), legit=len(legit),
        )

        current_weights = dict((policy.calibration or {}).get("weights") or {})
        current_engine = engine_for(policy)
        run.before = cls.measure(current_engine, labelled)
        run.threshold_sweep = cls.sweep(current_engine, labelled)

        if len(labelled) < cls.MIN_LABELLED or len(fraud) < cls.MIN_FRAUD:
            run.mode = CalibrationMode.HELD
            run.reason = (
                f"Too few labels to calibrate on: {len(labelled)} labelled "
                f"({len(fraud)} fraud) in {days} days; needs {cls.MIN_LABELLED} "
                f"and {cls.MIN_FRAUD}."
            )
            run.after = run.before
            run.save()
            return run

        stats = cls.rule_stats(labelled, fraud, legit)
        run.measured = cls.measured(stats)

        proposals = cls.propose(stats, current_weights, current_engine, base_rate=len(fraud) / len(labelled))
        proposals = cls.screen(proposals, current_weights, policy, labelled, run.before)
        run.proposals = proposals

        accepted = [proposal for proposal in proposals if proposal["accepted"]]
        candidate_weights = dict(current_weights)
        for proposal in accepted:
            candidate_weights[proposal["code"]] = proposal["to"]

        candidate_engine = cls.engine(policy, candidate_weights)
        run.after = cls.measure(candidate_engine, labelled)

        if not accepted:
            run.mode = CalibrationMode.HELD if proposals else CalibrationMode.DRY_RUN
            run.reason = (
                "Every proposal failed a guardrail." if proposals
                else "No weight had enough evidence behind it to move."
            )
            run.after = run.before
            run.save()
            return run

        together = cls.guardrail(run.before, run.after)
        if together:
            # Proposals that pass alone can fail in combination. Hold the
            # whole set rather than guess at which to drop.
            for proposal in accepted:
                proposal["accepted"] = False
                proposal["rejected"] = f"in combination: {together}"
            run.mode = CalibrationMode.HELD
            run.reason = f"The accepted proposals together failed a guardrail: {together}"
            run.after = run.before
            run.save()
            return run

        if apply:
            policy.calibration = dict(
                policy.calibration or {},
                weights=candidate_weights,
                thresholds=(policy.calibration or {}).get("thresholds") or {},
                calibrated_at=timezone.now().isoformat(),
                run_id=str(run.id),
            )
            policy.save(update_fields=["calibration", "updated_at"])
            run.mode = CalibrationMode.APPLIED
            run.applied = True
            run.applied_at = timezone.now()
            run.reason = f"Applied {len(accepted)} weight change(s)."
        else:
            run.mode = CalibrationMode.DRY_RUN
            run.reason = f"{len(accepted)} proposal(s) pass the guardrails; not applied (dry run)."

        run.save()
        return run

    # -- loading and measuring -------------------------------------------

    @classmethod
    def load(cls, application, days):
        since = timezone.now() - timedelta(days=days)
        decisions = (
            AuditLog.objects
            .filter(application_id=application.id, timestamp__gte=since)
            .order_by("-timestamp")[:cls.MAX_DECISIONS]
        )

        rows = []
        for decision in decisions:
            factors, _ = SimulatePolicy.factors_for(decision)
            rows.append(dict(decision=decision, factors=factors))
        return rows

    @classmethod
    def engine(cls, policy, weights):
        from core.scoring import RiskEngine

        thresholds = (policy.calibration or {}).get("thresholds") or None
        return RiskEngine(
            SimulatePolicy.merge_weights(weights) if weights else DEFAULT_WEIGHTS,
            SimulatePolicy.merge_thresholds(thresholds),
        )

    @classmethod
    def measure(cls, engine, labelled, block_at=None):
        blocked = caught = false_positives = 0
        fraud_total = legit_total = 0
        threshold = engine.thresholds.block_at if block_at is None else block_at

        for row in labelled:
            decision = row["decision"]
            scored = SimulatePolicy.score(engine, decision, row["factors"])
            is_blocked = scored["score"] >= threshold
            is_fraud = SimulatePolicy.is_fraud(decision)
            is_legit = SimulatePolicy.is_legit(decision)

            fraud_total += is_fraud
            legit_total += is_legit
            if is_blocked:
                blocked += 1
                caught += is_fraud
                false_positives += is_legit

        return dict(
            block_at=threshold,
            blocked=blocked,
            caught_fraud=caught,
            missed_fraud=fraud_total - caught,
            false_positives=false_positives,
            precision=SimulatePolicy.ratio(caught, caught + false_positives),
            recall=SimulatePolicy.ratio(caught, fraud_total),
            false_positive_rate=SimulatePolicy.ratio(false_positives, legit_total),
        )

    @classmethod
    def sweep(cls, engine, labelled):
        return [cls.measure(engine, labelled, block_at=point) for point in cls.THRESHOLD_SWEEP]

    @classmethod
    def rule_stats(cls, labelled, fraud, legit):
        on_fraud = defaultdict(int)
        on_legit = defaultdict(int)
        # The weight each decision actually gave the code. A code a rule
        # reports at zero weight — a data-completeness marker — is recorded
        # at zero, and that is how the calibrator knows not to touch it.
        recorded_weight = {}

        for rows, counter in ((fraud, on_fraud), (legit, on_legit)):
            for row in rows:
                seen = set()
                for factor in row["factors"]:
                    code = factor["code"]
                    if code in seen:
                        continue
                    seen.add(code)
                    counter[code] += 1
                    if "weight" in factor and code not in recorded_weight:
                        recorded_weight[code] = factor["weight"]

        stats = {}
        for code in set(on_fraud) | set(on_legit):
            if code in UNSCORED:
                continue
            fired = on_fraud[code] + on_legit[code]
            stats[code] = dict(
                code=code,
                fired=fired,
                on_fraud=on_fraud[code],
                on_legit=on_legit[code],
                precision=SimulatePolicy.ratio(on_fraud[code], fired),
                fraud_rate=SimulatePolicy.ratio(on_fraud[code], len(fraud)),
                legit_rate=SimulatePolicy.ratio(on_legit[code], len(legit)),
                recorded_weight=recorded_weight.get(code),
            )
        return stats

    @classmethod
    def measured(cls, stats):
        """Codes with enough labels behind them for the number to mean something."""
        rows = [
            dict(stat, eligible_for="production_observed")
            for stat in stats.values()
            if stat["fired"] >= cls.MIN_FIRED and stat["on_fraud"] >= cls.MIN_FRAUD_FOR_UP
        ]
        return sorted(rows, key=lambda row: (-(row["precision"] or 0), -row["fired"]))

    # -- proposing and screening -----------------------------------------

    @classmethod
    def current_weight(cls, engine, code):
        return engine.weights.get_weight(code, default=None)

    @classmethod
    def propose(cls, stats, current_weights, engine, *, base_rate):
        proposals = []

        for code, stat in sorted(stats.items()):
            if stat["fired"] < cls.MIN_FIRED:
                continue

            # The weight in force: an override the calibrator wrote, else
            # what decisions recorded for the code, else the engine's view.
            if code in current_weights:
                weight = float(current_weights[code])
            elif stat.get("recorded_weight") is not None:
                weight = float(stat["recorded_weight"])
            else:
                weight = cls.current_weight(engine, code)

            if not weight or weight <= 0:
                # Reported, never scored. Nothing to calibrate.
                continue

            precision = stat["precision"] or 0.0

            if precision >= cls.UP_AT_PRECISION and stat["on_fraud"] >= cls.MIN_FRAUD_FOR_UP:
                target = min(cls.CEILING, round(weight * (1 + cls.MAX_STEP), 4))
                direction = "up"
                reason = (
                    f"fires on fraud {precision:.0%} of the time "
                    f"({stat['on_fraud']} fraud, {stat['on_legit']} legit)"
                )
            elif precision <= base_rate and stat["on_legit"] >= cls.MIN_LEGIT_FOR_DOWN:
                target = max(cls.FLOOR, round(weight * (1 - cls.MAX_STEP), 4))
                direction = "down"
                reason = (
                    f"fires on fraud {precision:.0%} of the time, no better than "
                    f"the {base_rate:.0%} base rate ({stat['on_fraud']} fraud, {stat['on_legit']} legit)"
                )
            else:
                continue

            if target == weight:
                continue

            proposals.append(dict(
                code=code, direction=direction,
                **{"from": round(weight, 4), "to": target},
                fired=stat["fired"], on_fraud=stat["on_fraud"], on_legit=stat["on_legit"],
                precision=stat["precision"], reason=reason,
                accepted=False, rejected=None,
            ))

        return proposals

    @classmethod
    def screen(cls, proposals, current_weights, policy, labelled, before):
        """Re-score each proposal on its own against the weights in force."""
        for proposal in proposals:
            candidate = dict(current_weights, **{proposal["code"]: proposal["to"]})
            after = cls.measure(cls.engine(policy, candidate), labelled)
            failure = cls.guardrail(before, after)

            proposal["effect"] = dict(
                caught_fraud=after["caught_fraud"],
                false_positives=after["false_positives"],
                recall=after["recall"],
                false_positive_rate=after["false_positive_rate"],
            )
            proposal["accepted"] = failure is None
            proposal["rejected"] = failure

        return proposals

    @classmethod
    def guardrail(cls, before, after):
        """
        Why a candidate is not acceptable, or None.

        The ceiling binds on what a proposal *does*, not on what it inherits.
        A month whose recomputed baseline already blocks more good customers
        than the ceiling allows is a month that needs calibrating, and a
        proposal that leaves that rate where it is — or lowers it — must not
        be refused for a problem it did not cause. So: a proposal may never
        raise the false-positive rate beyond tolerance, may never push it
        above the ceiling from below, and may never cost recall.
        """
        fp_after = after["false_positive_rate"] or 0.0
        fp_before = before["false_positive_rate"] or 0.0
        recall_after = after["recall"] or 0.0
        recall_before = before["recall"] or 0.0

        if fp_after > fp_before + cls.FALSE_POSITIVE_TOLERANCE:
            return (
                f"would raise the share of good customers blocked from "
                f"{fp_before:.2%} to {fp_after:.2%}"
            )
        if fp_after > cls.MAX_FALSE_POSITIVE_RATE and fp_after > fp_before:
            return (
                f"would block {fp_after:.1%} of good customers, above the "
                f"{cls.MAX_FALSE_POSITIVE_RATE:.1%} ceiling"
            )
        if recall_after < recall_before:
            return f"would drop recall from {recall_before:.1%} to {recall_after:.1%}"
        return None


def serialize_run(run):
    return dict(
        id=str(run.id),
        application_id=str(run.application_id),
        started_at=run.started_at.isoformat() if run.started_at else None,
        window_days=run.window_days,
        mode=run.mode,
        reason=run.reason,
        applied=run.applied,
        applied_at=run.applied_at.isoformat() if run.applied_at else None,
        sample=dict(decisions=run.decisions, labelled=run.labelled, fraud=run.fraud, legit=run.legit),
        before=run.before,
        after=run.after,
        proposals=run.proposals,
        threshold_sweep=run.threshold_sweep,
        measured=run.measured,
    )


def format_run(run):
    lines = [
        f"{run.application.name}: {run.mode} — {run.reason}",
        f"  sample  {run.decisions} decisions, {run.labelled} labelled "
        f"({run.fraud} fraud, {run.legit} legit) over {run.window_days} days",
    ]

    before, after = run.before or {}, run.after or {}
    if before:
        lines.append(
            f"  before  recall {_pct(before.get('recall'))}  "
            f"precision {_pct(before.get('precision'))}  "
            f"false positives {_pct(before.get('false_positive_rate'))}"
        )
    if after and after is not before:
        lines.append(
            f"  after   recall {_pct(after.get('recall'))}  "
            f"precision {_pct(after.get('precision'))}  "
            f"false positives {_pct(after.get('false_positive_rate'))}"
        )

    if run.proposals:
        lines.append("")
        lines.append(f"  {'code':<34} {'from':>6} {'to':>6}  outcome")
        for proposal in run.proposals:
            outcome = "accepted" if proposal["accepted"] else f"rejected: {proposal['rejected']}"
            lines.append(
                f"  {proposal['code']:<34} {proposal['from']:>6} {proposal['to']:>6}  {outcome}"
            )
            lines.append(f"  {'':<34} {'':>6} {'':>6}  {proposal['reason']}")

    if run.measured:
        lines.append("")
        lines.append("  measured (eligible for a production-observed claim once a reviewer confirms)")
        for row in run.measured[:10]:
            lines.append(
                f"    {row['code']:<32} fired {row['fired']:>5}  "
                f"fraud {row['on_fraud']:>5}  legit {row['on_legit']:>5}  "
                f"precision {_pct(row['precision'])}"
            )

    return "\n".join(lines)


def _pct(value):
    return "—" if value is None else f"{value:.1%}"
