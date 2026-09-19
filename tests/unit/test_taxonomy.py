"""
Tests for the detection taxonomy and the coverage matrix.

The matrix is a claim FLIT makes to customers about what it detects and how
well. These tests are what stop that claim drifting away from the software:
every declaration must be valid, every measured claim must name evidence that
exists, and the published document must match what the registered rules
actually say.
"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def detectors():
    from core.taxonomy import registry

    return registry.detectors()


class TestFrameworkCatalogue:
    def test_the_pinned_framework_is_f3_v1_1(self):
        from core.taxonomy import F3

        assert F3.version() == "1.1"
        assert "fight-fraud-framework" in F3.source()

    def test_the_catalogue_holds_the_full_technique_set(self):
        from core.taxonomy import F3

        # F3 v1.1: 123 techniques across 8 tactics.
        assert len(F3.techniques()) == 123
        assert len(F3.tactics()) == 8

    def test_known_identifiers_resolve(self):
        from core.taxonomy import F3

        assert F3.name("F1012") == "Card Testing"
        assert F3.name("T1585") == "Establish Accounts"
        assert "Positioning" in [
            F3.tactic_name(t) for t in F3.tactics_for("F1012")
        ]

    def test_an_unknown_identifier_raises(self):
        from core.taxonomy import F3, UnknownTechnique

        try:
            F3.name("F9999")
            raise AssertionError("should have rejected an unknown technique")
        except UnknownTechnique:
            pass


class TestDetectorDeclarations:
    def test_every_registered_rule_declares_a_valid_kind(self):
        from core.audit.rules.base_rule import RuleKind

        for row in detectors():
            assert row["kind"] in RuleKind.VALUES, row["rule"]

    def test_every_registered_rule_declares_a_valid_maturity(self):
        from core.taxonomy import Maturity

        for row in detectors():
            assert row["maturity"] in Maturity.VALUES, row["rule"]

    def test_no_detector_claims_a_technique_the_framework_does_not_define(self):
        from core.taxonomy import registry

        assert registry.unknown_techniques() == []

    def test_a_claim_above_proposed_must_name_its_evidence(self):
        """
        The core discipline. A rule may sit anywhere on the ladder, but it may
        not claim to have been shown to work without saying where.
        """
        from core.taxonomy import registry

        assert registry.unproven() == []

    def test_a_measured_claim_must_rest_on_the_evidence_ledger(self):
        """
        Vacuous today — nothing claims a measured rung yet, which is the
        honest state of the product. It is the gate for when something does.
        """
        from core.taxonomy import evidence

        assert evidence.unsupported_claims(detectors()) == []

    def test_only_detections_claim_techniques(self):
        """
        A policy limit fires because a merchant set it, and a reputation
        lookup is evidence about the actor. Counting either as technique
        coverage would inflate the matrix.
        """
        from core.audit.rules.base_rule import RuleKind

        for row in detectors():
            if row["kind"] != RuleKind.DETECTION:
                assert row["techniques"] == [], row["rule"]

    def test_every_detection_rule_claims_at_least_one_technique(self):
        from core.audit.rules.base_rule import RuleKind

        for row in detectors():
            if row["kind"] == RuleKind.DETECTION:
                assert row["techniques"], row["rule"]


class TestCoverage:
    def test_the_three_buckets_account_for_every_technique(self):
        from core.taxonomy import F3, registry

        data = registry.coverage()
        parents = [t for t in F3.techniques() if "." not in t]

        assert data["totals"]["techniques"] == len(parents)
        assert (
            len(data["covered"]) + len(data["addressable"])
            + len(data["out_of_telemetry"]) == len(parents)
        )

    def test_the_buckets_do_not_overlap(self):
        from core.taxonomy import registry

        data = registry.coverage()
        buckets = [
            {entry["id"] for entry in data[name]}
            for name in ("covered", "addressable", "out_of_telemetry")
        ]

        assert not buckets[0] & buckets[1]
        assert not buckets[0] & buckets[2]
        assert not buckets[1] & buckets[2]

    def test_out_of_telemetry_techniques_say_why(self):
        from core.taxonomy import registry

        for entry in registry.coverage()["out_of_telemetry"]:
            assert entry["reason"], entry["id"]

    def test_the_september_attack_maps_to_a_covered_technique(self):
        """
        The bulk signup flood is F3's Establish Accounts, and FLIT now covers
        it. This is the taxonomy earning its keep: the incident has a name
        that a bank's risk team already uses.
        """
        from core.taxonomy import registry

        covered = {entry["id"]: entry for entry in registry.coverage()["covered"]}

        assert "T1585" in covered
        assert "AccountFarmingRule" in covered["T1585"]["rules"]

    def test_a_techniques_maturity_is_that_of_its_best_detector(self):
        from core.taxonomy import Maturity, registry

        rows = {row["rule"]: row for row in detectors()}

        for entry in registry.coverage()["covered"]:
            best = max(
                Maturity.rank(rows[rule]["maturity"]) for rule in entry["rules"]
            )
            assert Maturity.rank(entry["maturity"]) == best, entry["id"]


class TestPublishedMatrix:
    def test_the_published_matrix_matches_the_registered_rules(self):
        """
        The anti-drift test, and the reason the matrix is generated at all.
        A coverage document that is written rather than derived keeps reading
        well long after it stopped being true.
        """
        from core.taxonomy.render import render

        published = (REPO_ROOT / "COVERAGE.md").read_text()

        assert published == render(), (
            "COVERAGE.md is stale. Regenerate it:\n"
            "    python manage.py coverage_matrix --out ../COVERAGE.md "
            "--json ../coverage.json"
        )

    def test_the_matrix_states_how_much_is_actually_measured(self):
        from core.taxonomy import registry

        totals = registry.coverage()["totals"]

        # Not an aspiration: whatever this number is, the document says it.
        assert "measured" in totals
        assert totals["measured"] <= totals["covered"]
