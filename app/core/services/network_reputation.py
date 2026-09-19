"""
The shared protection network.

An attack on one merchant should protect the next one, before it reaches
them. That is the whole claim behind "Cloudflare, but for fraud", and it is
the one thing a single-tenant rules engine cannot copy: it compounds with
every merchant who joins.

It also has to be done carefully, because the same mechanism that shares
protection could leak one merchant's customers to another. Four rules keep
that from happening, and every one of them is enforced here rather than left
to the caller:

1. **Your own rows never come back.** A query excludes the asking
   application, so the answer is strictly what *others* saw. A merchant
   cannot read their own data back as corroboration of itself.
2. **k-anonymity.** Nothing is reported unless at least two distinct other
   applications saw it. With a single contributor, a merchant probing a key
   would learn something about one identifiable merchant.
3. **Counts, never identities.** The answer says how many applications and
   how recently. It never says which, and there is no call that would.
4. **Reciprocity.** Only an application that contributes may read (see
   Application.reads_network).

What crosses the boundary is a verdict about a key the asking merchant is
already looking at. Nothing can be enumerated: there is no call that lists
keys, and a key is only ever answered for when the merchant already holds it.
"""

import logging
from datetime import timedelta

from asgiref.sync import sync_to_async
from django.db.models import F, Q, Sum, Count
from django.utils import timezone

from core.models.identity import IdentityObservation


logger = logging.getLogger(__name__)


# Confirmations older than this stop counting. Fraud two years ago says
# little about the actor holding the key today.
NETWORK_WINDOW_DAYS = 180

# The k in k-anonymity: how many distinct other applications must have seen
# something before the network will say so.
MIN_CONTRIBUTORS = 2


class NetworkVerdict:
    """What the network is willing to say about one key."""

    def __init__(self, *, applications=0, fraud_count=0,
                 challenge_failed_count=0, last_fraud_at=None):
        self.applications = applications
        self.fraud_count = fraud_count
        self.challenge_failed_count = challenge_failed_count
        self.last_fraud_at = last_fraud_at

    @property
    def is_reportable(self):
        return self.applications >= MIN_CONTRIBUTORS

    @property
    def severity(self):
        """
        How much a corroborated history is worth, 0.0–1.0.

        Driven by how many independent merchants confirmed it rather than by
        how many times: ten confirmations from two merchants is a weaker
        signal than one each from six.
        """
        base = 0.55 + 0.15 * (self.applications - MIN_CONTRIBUTORS)

        if self.challenge_failed_count:
            base += 0.05

        return round(min(base, 0.95), 4)

    def as_context(self):
        """Safe to hand a merchant: counts and recency, never identities."""
        return dict(
            applications=self.applications,
            fraud_count=self.fraud_count,
            challenge_failed_count=self.challenge_failed_count,
            last_fraud_at=self.last_fraud_at.isoformat() if self.last_fraud_at else None,
            window_days=NETWORK_WINDOW_DAYS,
        )


def _lookup(identity_key_ids, application):
    since = timezone.now() - timedelta(days=NETWORK_WINDOW_DAYS)

    aggregate = (
        IdentityObservation.objects
        .filter(identity_key_id__in=identity_key_ids)
        # Rule 1: never the asking application's own observations.
        .exclude(application=application)
        .filter(
            Q(last_fraud_at__gte=since) | Q(challenge_failed_count__gt=0),
        )
        .aggregate(
            applications=Count("application", distinct=True),
            fraud_count=Sum("fraud_count"),
            challenge_failed_count=Sum("challenge_failed_count"),
        )
    )

    applications = aggregate["applications"] or 0

    if applications < MIN_CONTRIBUTORS:
        # Rule 2: below k, the network says nothing at all — not even that
        # there was something to say.
        return NetworkVerdict()

    last_fraud_at = (
        IdentityObservation.objects
        .filter(identity_key_id__in=identity_key_ids)
        .exclude(application=application)
        .filter(last_fraud_at__gte=since)
        .order_by("-last_fraud_at")
        .values_list("last_fraud_at", flat=True)
        .first()
    )

    return NetworkVerdict(
        applications=applications,
        fraud_count=aggregate["fraud_count"] or 0,
        challenge_failed_count=aggregate["challenge_failed_count"] or 0,
        last_fraud_at=last_fraud_at,
    )


class NetworkReputation:
    @classmethod
    def lookup(cls, *, identity_key_ids, application):
        """What other applications have confirmed about these keys."""
        if not identity_key_ids:
            return NetworkVerdict()

        # Rule 4: contributing is what buys the right to read.
        if not getattr(application, "reads_network", False):
            return NetworkVerdict()

        try:
            return _lookup(identity_key_ids, application)
        except Exception:
            logger.warning("Could not read network reputation", exc_info=True)
            return NetworkVerdict()

    @classmethod
    async def lookup_async(cls, *, identity_key_ids, application):
        return await sync_to_async(cls.lookup)(
            identity_key_ids=identity_key_ids, application=application,
        )

    @classmethod
    def record(cls, *, identity_key_ids, application, outcome, count=1):
        """
        Publish one application's experience of a key to the network.

        `outcome` is one of fraud, legit, challenge_failed, challenge_passed.
        An application that does not contribute records nothing — not even
        locally, because a local-only half of this table would quietly become
        a second, divergent source of truth.
        """
        if not identity_key_ids or not getattr(
            application, "contributes_to_network", False,
        ):
            return 0

        fields = {
            "fraud": ("fraud_count", "last_fraud_at"),
            "legit": ("legit_count", "last_legit_at"),
            "challenge_failed": ("challenge_failed_count", None),
            "challenge_passed": ("challenge_passed_count", None),
        }

        if outcome not in fields:
            raise ValueError(f"Unknown network outcome: {outcome}")

        counter, stamp = fields[outcome]
        now = timezone.now()
        written = 0

        for identity_key_id in identity_key_ids:
            try:
                observation, _ = IdentityObservation.objects.get_or_create(
                    identity_key_id=identity_key_id, application=application,
                )

                update = {counter: F(counter) + count, "last_seen_at": now}
                if stamp:
                    update[stamp] = now

                IdentityObservation.objects.filter(pk=observation.pk).update(**update)
                written += 1
            except Exception:
                logger.warning(
                    "Could not record network observation", exc_info=True,
                )

        return written

    @classmethod
    async def record_async(cls, *, identity_key_ids, application, outcome, count=1):
        return await sync_to_async(cls.record)(
            identity_key_ids=identity_key_ids,
            application=application,
            outcome=outcome,
            count=count,
        )
