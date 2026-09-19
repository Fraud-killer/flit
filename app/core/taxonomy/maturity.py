"""
How much a detector has actually been shown to work.

FLIT ships 60-odd tuned numbers. Almost none of them have a written reason,
and a threshold nobody can account for is indistinguishable from a guess —
right up until a customer asks why they were blocked, or an auditor asks how
the number was chosen.

The ladder makes that gap visible instead of leaving it implied. A detector
declares where it actually sits, and nothing about it may be described as
proven above that rung. Most rules start at PROPOSED, and that is the honest
answer until a backtest says otherwise.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Rung:
    key: str
    rank: int
    label: str
    requires: str


class Maturity:
    """The evidence ladder, weakest first."""

    PROPOSED = "proposed"
    SYNTHETIC_TESTED = "synthetic_tested"
    BACKTESTED = "backtested"
    SHADOW_VALIDATED = "shadow_validated"
    PRODUCTION_OBSERVED = "production_observed"
    OUTCOME_CALIBRATED = "outcome_calibrated"

    LADDER = (
        Rung(PROPOSED, 0, "Proposed",
             "Reasoned from how the fraud works. No evidence yet."),
        Rung(SYNTHETIC_TESTED, 1, "Synthetic-tested",
             "Fires on a constructed example of the technique and stays quiet "
             "on a constructed legitimate lookalike."),
        Rung(BACKTESTED, 2, "Historically backtested",
             "Run against a merchant's labelled history, with measured "
             "precision and recall at the shipped threshold."),
        Rung(SHADOW_VALIDATED, 3, "Shadow-validated",
             "Run against live traffic without acting on it, and reviewed."),
        Rung(PRODUCTION_OBSERVED, 4, "Production-observed",
             "Acting in production, with its decisions labelled by reviewers."),
        Rung(OUTCOME_CALIBRATED, 5, "Outcome-calibrated",
             "Thresholds set from confirmed outcomes rather than judgement, "
             "and re-measured on a schedule."),
    )

    BY_KEY = {rung.key: rung for rung in LADDER}
    VALUES = tuple(rung.key for rung in LADDER)

    # Above this, a claim needs more than an argument behind it, so a
    # detector must say where its evidence came from.
    NEEDS_PROVENANCE = SYNTHETIC_TESTED

    @classmethod
    def rank(cls, key):
        rung = cls.BY_KEY.get(key)
        return rung.rank if rung else -1

    @classmethod
    def label(cls, key):
        rung = cls.BY_KEY.get(key)
        return rung.label if rung else "Unknown"

    @classmethod
    def requires(cls, key):
        rung = cls.BY_KEY.get(key)
        return rung.requires if rung else ""

    @classmethod
    def is_measured(cls, key):
        """Whether the rung implies numbers rather than an argument."""
        return cls.rank(key) >= cls.rank(cls.BACKTESTED)
