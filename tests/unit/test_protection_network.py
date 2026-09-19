"""
Tests for the shared protection network.

An attack on one merchant should protect the next one before it reaches them.
That is the claim, and it is only worth making if the mechanism that shares
protection cannot also leak one merchant's customers to another — so the
privacy boundary is tested at least as hard as the detection is.
"""

from datetime import timedelta

from django.utils import timezone

from tests.unit.test_signup_defence import BROWSER, CURL, codes, register


SHARED_IP = "203.0.113.77"


def make_application(name, *, contributes=True, consumes=True):
    from core.models import User, Organization, Application

    user = User.objects.create_user(email=f"{name}@flit.io", password="x" * 12)
    organization = Organization.objects.create(name=f"{name} Org", owner=user)

    return Application.objects.create(
        name=name,
        organization=organization,
        contributes_to_network=contributes,
        consumes_network=consumes,
    )


def key_for(key_type, value):
    """The global key node for a value, as the resolver would create it."""
    from core.models.identity import IdentityKey

    key, _ = IdentityKey.objects.get_or_create(
        key_type=key_type, value_hash=IdentityKey.hash_value(key_type, value),
    )
    return key


def report_fraud(application, key, *, count=1, when=None):
    from core.services.network_reputation import NetworkReputation

    NetworkReputation.record(
        identity_key_ids=[key.id], application=application, outcome="fraud",
        count=count,
    )

    if when:
        from core.models.identity import IdentityObservation

        IdentityObservation.objects.filter(
            identity_key=key, application=application,
        ).update(last_fraud_at=when)


def lookup(application, key):
    from core.services.network_reputation import NetworkReputation

    return NetworkReputation.lookup(
        identity_key_ids=[key.id], application=application,
    )


class TestPrivacyBoundary:
    def test_a_merchant_never_reads_their_own_observations_back(self, db):
        """
        Otherwise a merchant's own suspicion would come back as though it
        were corroboration from somewhere else.
        """
        alpha = make_application("alpha")
        key = key_for("ip", SHARED_IP)

        report_fraud(alpha, key, count=5)

        assert lookup(alpha, key).applications == 0

    def test_says_nothing_when_only_one_other_merchant_saw_it(self, db):
        """
        k-anonymity. With a single contributor, a merchant probing a key
        learns something about one identifiable merchant.
        """
        alpha = make_application("alpha")
        beta = make_application("beta")
        key = key_for("ip", SHARED_IP)

        report_fraud(beta, key)

        verdict = lookup(alpha, key)

        assert verdict.applications == 0
        assert not verdict.is_reportable

    def test_reports_once_two_other_merchants_have_seen_it(self, db):
        alpha = make_application("alpha")
        key = key_for("ip", SHARED_IP)

        report_fraud(make_application("beta"), key)
        report_fraud(make_application("gamma"), key)

        verdict = lookup(alpha, key)

        assert verdict.applications == 2
        assert verdict.is_reportable

    def test_the_answer_carries_counts_but_never_identities(self, db):
        alpha = make_application("alpha")
        key = key_for("ip", SHARED_IP)

        report_fraud(make_application("beta"), key)
        report_fraud(make_application("gamma"), key)

        context = lookup(alpha, key).as_context()
        serialized = str(context)

        assert context["applications"] == 2
        for leak in ("beta", "gamma", "application_id", "client_id"):
            assert leak not in serialized

    def test_a_merchant_who_contributes_nothing_reads_nothing(self, db):
        """Reciprocal by design: a one-way reader is a free rider."""
        taker = make_application("taker", contributes=False)
        key = key_for("ip", SHARED_IP)

        report_fraud(make_application("beta"), key)
        report_fraud(make_application("gamma"), key)

        assert lookup(taker, key).applications == 0

    def test_a_merchant_who_opted_out_publishes_nothing(self, db):
        private = make_application("private", contributes=False)
        key = key_for("ip", SHARED_IP)

        report_fraud(private, key)

        from core.models.identity import IdentityObservation

        assert IdentityObservation.objects.count() == 0

    def test_stale_confirmations_stop_counting(self, db):
        from core.services.network_reputation import NETWORK_WINDOW_DAYS

        alpha = make_application("alpha")
        key = key_for("ip", SHARED_IP)
        long_ago = timezone.now() - timedelta(days=NETWORK_WINDOW_DAYS + 30)

        report_fraud(make_application("beta"), key, when=long_ago)
        report_fraud(make_application("gamma"), key, when=long_ago)

        assert lookup(alpha, key).applications == 0


class TestNetworkSeverity:
    def test_more_independent_merchants_means_a_stronger_signal(self, db):
        alpha = make_application("alpha")
        key = key_for("ip", SHARED_IP)

        report_fraud(make_application("beta"), key)
        report_fraud(make_application("gamma"), key)
        two = lookup(alpha, key).severity

        report_fraud(make_application("delta"), key)
        report_fraud(make_application("epsilon"), key)
        four = lookup(alpha, key).severity

        assert four > two

    def test_repeat_reports_from_one_merchant_do_not_inflate_it(self, db):
        """
        Ten confirmations from two merchants is weaker than one each from
        six, and the score has to reflect that or a single noisy merchant
        could drive the network.
        """
        alpha = make_application("alpha")
        quiet_key = key_for("ip", "203.0.113.1")
        loud_key = key_for("ip", "203.0.113.2")

        report_fraud(make_application("beta"), quiet_key)
        report_fraud(make_application("gamma"), quiet_key)

        report_fraud(make_application("delta"), loud_key, count=50)
        report_fraud(make_application("epsilon"), loud_key, count=50)

        assert lookup(alpha, loud_key).severity == lookup(alpha, quiet_key).severity


class TestGroundTruthPublishing:
    def test_closing_a_case_as_fraud_publishes_to_the_network(
        self, application, no_geoip,
    ):
        from core.models import Case, CaseStatus

        register(
            application,
            email="ringleader@uberip.com",
            ip_address=SHARED_IP,
            user_agent=CURL,
            client_id="ring_1",
        )

        case = Case.objects.filter(application=application).first()
        assert case is not None, "a reviewable decision should open a case"

        case.resolve(status=CaseStatus.CONFIRMED_FRAUD)

        from core.models.identity import IdentityObservation

        assert IdentityObservation.objects.filter(
            application=application, fraud_count__gt=0,
        ).exists()

    def test_a_decision_records_the_keys_it_rested_on(
        self, application, no_geoip,
    ):
        """Without this, a label an hour later has nothing to attribute to."""
        from core.models import AuditLog

        register(
            application,
            email="traceable@uberip.com",
            ip_address=SHARED_IP,
            user_agent=CURL,
            client_id="traceable_1",
        )

        audit_log = AuditLog.objects.filter(actor_id="traceable_1").first()

        assert (audit_log.context or {}).get("identity_key_ids")


class TestNetworkProtectsTheNextMerchant:
    def test_an_actor_two_merchants_caught_is_flagged_at_the_third(
        self, application, no_geoip,
    ):
        """
        The whole point, end to end: a ring that burns one merchant and moves
        on arrives at the next one already known.
        """
        key = key_for("ip", SHARED_IP)
        report_fraud(make_application("beta"), key)
        report_fraud(make_application("gamma"), key)

        result = register(
            application,
            email="ordinary.looking@gmail.com",
            ip_address=SHARED_IP,
            user_agent=BROWSER,
            client_id="newcomer_1",
        )

        assert "network_fraud_history" in codes(result)

    def test_the_minimum_network_says_verify_and_more_says_no(
        self, application, no_geoip,
    ):
        """
        Two contributors is the k-anonymity floor — the least the network can
        legally say. Turning a customer away on the bare minimum is the wrong
        trade; asking them to verify is not. Corroboration past the floor is
        what escalates to a block.
        """
        from tests.unit.test_signup_defence import make_visit

        verdicts = {}

        for contributors in (2, 4):
            ip = f"203.0.113.{150 + contributors}"
            key = key_for("ip", ip)

            for index in range(contributors):
                report_fraud(make_application(f"m{contributors}_{index}"), key)

            result = register(
                application,
                email=f"clean{contributors}@gmail.com",
                ip_address=ip,
                user_agent=BROWSER,
                visit=make_visit(f"v{contributors}", ip=ip),
                visit_id=f"v{contributors}",
                client_id=f"client_{contributors}",
            )

            verdicts[contributors] = result

        assert verdicts[2].should_challenge and not verdicts[2].should_block
        assert verdicts[4].should_block

    def test_a_clean_actor_is_unaffected_by_the_network(
        self, application, no_geoip,
    ):
        key = key_for("ip", SHARED_IP)
        report_fraud(make_application("beta"), key)
        report_fraud(make_application("gamma"), key)

        result = register(
            application,
            email="unrelated@gmail.com",
            ip_address="198.51.100.200",
            user_agent=BROWSER,
            client_id="unrelated_1",
        )

        assert "network_fraud_history" not in codes(result)

    def test_the_merchant_sees_why_without_seeing_who(
        self, application, no_geoip,
    ):
        key = key_for("ip", SHARED_IP)
        report_fraud(make_application("beta"), key)
        report_fraud(make_application("gamma"), key)

        result = register(
            application,
            email="ordinary.looking@gmail.com",
            ip_address=SHARED_IP,
            user_agent=BROWSER,
            client_id="newcomer_2",
        )

        message = next(
            m for m in result.reasons if m.code == "network_fraud_history"
        )

        assert message.context["applications"] == 2
        assert "beta" not in str(message.context)
        assert "gamma" not in str(message.context)
