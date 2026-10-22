"""
The risk engine an application actually decides with.

Until now every decision used the shipped defaults, and a merchant's tuning
lived only in simulations. The calibrator writes what it has learned onto the
policy; this is the one place that reads it back, so that what a simulation
predicted and what a decision does are the same arithmetic.
"""

from core.scoring import RiskEngine


def engine_for(policy):
    calibration = getattr(policy, "calibration", None) or {}
    weights = calibration.get("weights") or None
    thresholds = calibration.get("thresholds") or None

    if not weights and not thresholds:
        return RiskEngine()

    # Imported here: the simulator imports models, and models are not ready
    # when the scoring package is.
    from core.services.simulate_policy import SimulatePolicy

    return RiskEngine(
        SimulatePolicy.merge_weights(weights),
        SimulatePolicy.merge_thresholds(thresholds),
    )
