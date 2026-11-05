"""
The risk engine an application actually decides with.

Until now every decision used the shipped defaults, and a merchant's tuning
lived only in simulations. The calibrator writes what it has learned onto the
policy; this is the one place that reads it back, so that what a simulation
predicted and what a decision does are the same arithmetic.
"""

from core.scoring import RiskEngine, RiskThresholds


def engine_for(policy, organization_policy=None):
    """
    The engine for one application: its calibration, capped by its
    organization. An application may decide earlier than its organization
    allows, never later.
    """
    calibration = getattr(policy, "calibration", None) or {}
    weights = calibration.get("weights") or None
    thresholds = calibration.get("thresholds") or None

    if not weights and not thresholds and organization_policy is None:
        return RiskEngine()

    # Imported here: the simulator imports models, and models are not ready
    # when the scoring package is.
    from core.services.simulate_policy import SimulatePolicy

    return RiskEngine(
        SimulatePolicy.merge_weights(weights),
        apply_ceiling(SimulatePolicy.merge_thresholds(thresholds), organization_policy),
    )


def apply_ceiling(thresholds, organization_policy):
    """Thresholds no later than the organization permits."""
    if organization_policy is None:
        return thresholds

    max_block = getattr(organization_policy, "max_block_at", None)
    max_review = getattr(organization_policy, "max_review_at", None)

    block_at = thresholds.block_at if max_block is None else min(thresholds.block_at, float(max_block))
    review_at = thresholds.review_at if max_review is None else min(thresholds.review_at, float(max_review))

    return RiskThresholds(
        block_at=block_at,
        review_at=min(review_at, block_at),
        challenge_at=min(thresholds.challenge_at, review_at, block_at),
    )
