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

from core.identity_keys import IdentityKeyType
from core.models.identity import IdentityObservation


logger = logging.getLogger(__name__)


# Confirmations older than this stop counting. Fraud two years ago says
# little about the actor holding the key today.
NETWORK_WINDOW_DAYS = 180

# The k in k-anonymity: how many distinct other applications must have seen
# something before the network will say so.
MIN_CONTRIBUTORS = 2


# Keys that name a network rather than an actor. Corroboration found only on
# these can ask a customer to verify; it cannot, on its own, turn them away.
SHARED_KEY_TYPES = frozenset({IdentityKeyType.IP, IdentityKeyType.ASN})

# The most a verdict resting on shared keys alone may be worth. With the
# default weight this lands in the challenge band and under the block line.
SHARED_ONLY_CAP = 0.6


class NetworkVerdict:
    """What the network is willing to say about one key."""

    def __init__(self, *, organizations=0, fraud_count=0, challenge_failed_count=0,
                 legit_count=0, challenge_passed_count=0, key_types=(), last_fraud_at=None):
        self.organizations = organizations
        self.fraud_count = fraud_count
        self.challenge_failed_count = challenge_failed_count
        self.legit_count = legit_count
        self.challenge_passed_count = challenge_passed_count
        self.key_types = sorted(set(key_types))
        self.last_fraud_at = last_fraud_at

    # The old name, kept for callers that counted applications.
    @property
    def applications(self):
        return self.organizations

    @property
    def adverse(self):
        return self.fraud_count + self.challenge_failed_count

    @property
    def favourable(self):
        return self.legit_count + self.challenge_passed_count

    @property
    def net(self):
        return self.adverse - self.favourable

    @property
    def shared_only(self):
        """Every key the adverse history sits on names a network, not an actor."""
        return bool(self.key_types) and set(self.key_types) <= SHARED_KEY_TYPES

    @property
    def is_reportable(self):
        return self.organizations >= MIN_CONTRIBUTORS and self.net > 0

    @property
    def severity(self):
        """
        How much a corroborated history is worth, 0.0–1.0.

        Driven by how many independent organizations confirmed it rather than
        by how many times: ten confirmations from two merchants is a weaker
        signal than one each from six. Favourable reports on the same keys —
        a merchant who said the actor was fine, a challenge they passed —
        pull it down in proportion. History that sits only on an IP or an ASN
        is capped under the block line: one address is many people.
        """
        base = 0.55 + 0.15 * (self.organizations - MIN_CONTRIBUTORS)

        if self.challenge_failed_count:
            base += 0.05

        if self.favourable:
            base *= self.adverse / (self.adverse + self.favourable)

        if self.shared_only:
            base = min(base, SHARED_ONLY_CAP)

        return round(max(0.0, min(base, 0.95)), 4)

    def as_context(self):
        """Safe to hand a merchant: counts and recency, never identities."""
        return dict(
            organizations=self.organizations,
            applications=self.organizations,
            fraud_count=self.fraud_count,
            challenge_failed_count=self.challenge_failed_count,
            legit_count=self.legit_count,
            challenge_passed_count=self.challenge_passed_count,
            key_types=self.key_types,
            shared_only=self.shared_only,
            last_fraud_at=self.last_fraud_at.isoformat() if self.last_fraud_at else None,
            window_days=NETWORK_WINDOW_DAYS,
        )


def _lookup(identity_key_ids, application):
    """
    What other organizations have seen on these keys inside the window.

    Rule 1: never the asking application's own rows, nor its sibling
    applications': two applications under one organization are one witness.
    Rule 2: below k distinct organizations the network says nothing. A failed
    challenge expires with the window like a confirmed fraud does; a legit
    report or a passed challenge on the same key counts against the history
    rather than being ignored.
    """
    since = timezone.now() - timedelta(days=NETWORK_WINDOW_DAYS)

    rows = (
        IdentityObservation.objects
        .filter(identity_key_id__in=identity_key_ids, last_seen_at__gte=since)
        .exclude(application=application)
        .exclude(application__organization_id=getattr(application, "organization_id", None))
        .select_related("identity_key", "application")
    )

    adverse_organizations = set()
    key_types = set()
    fraud = failed = legit = passed = 0
    last_fraud_at = None

    for row in rows:
        recent_fraud = row.fraud_count if (row.last_fraud_at and row.last_fraud_at >= since) else 0
        recent_failed = row.challenge_failed_count
        recent_legit = row.legit_count if (row.last_legit_at and row.last_legit_at >= since) else 0
        recent_passed = row.challenge_passed_count

        if recent_fraud or recent_failed:
            adverse_organizations.add(row.application.organization_id)
            key_types.add(row.identity_key.key_type)
        if recent_fraud and (last_fraud_at is None or row.last_fraud_at > last_fraud_at):
            last_fraud_at = row.last_fraud_at

        fraud += recent_fraud
        failed += recent_failed
        legit += recent_legit
        passed += recent_passed

    if len(adverse_organizations) < MIN_CONTRIBUTORS:
        # Rule 2: below k, the network says nothing at all — not even that
        # there was something to say.
        return NetworkVerdict()

    return NetworkVerdict(
        organizations=len(adverse_organizations),
        fraud_count=fraud,
        challenge_failed_count=failed,
        legit_count=legit,
        challenge_passed_count=passed,
        key_types=key_types,
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
