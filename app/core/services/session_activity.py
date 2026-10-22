"""
What one origin has been doing lately, read back as a session.

Every rule before this one scored an event. A session is the sequence of
events from one origin — a device when there is one, an IP when there is
not — over a window, across every account it touched. It is the unit an
automated attacker works in, and the one it cannot easily disguise: a loop
can slow its reset-to-login past any fixed threshold and rotate its client
string per account, but it is still one origin, working many accounts, with
the same motif, at a cadence no person keeps.

"What a human session looks like" is not a constant. It is measured from the
merchant's own recent sessions and expressed as percentiles, the same way
`ExpectedSignalRule` learns what signal a merchant's traffic normally
carries. A merchant whose users sit behind carrier-grade NAT will have many
accounts per IP as its normal, and the baseline absorbs that. Until a merchant
has enough history, cautious defaults apply, and the scorer leans on the
shape signals an office does not produce.
"""

import logging
import statistics
from collections import defaultdict
from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone

from core.models import AuditLog


logger = logging.getLogger(__name__)


RESET_ACTIONS = ("password_reset_requested", "password_reset_completed")
LOGIN_ACTIONS = ("login", "new_device_login")
MANIPULATION_ACTIONS = ("password_change", "email_change", "phone_change", "two_factor_disabled")
CREDENTIAL_ACTIONS = RESET_ACTIONS + LOGIN_ACTIONS + MANIPULATION_ACTIONS
DEBIT_ACTION = "transaction_debit"
REGISTRATION_ACTION = "registration"


def client_family(user_agent):
    """
    The client behind a user agent, coarsely.

    Chrome upgrading between two logins is one client. `curl`, then
    `python-requests`, then `okhttp` is three, and that count is the signal,
    so versions and platform strings are deliberately thrown away: the first
    token before a slash or a space is enough to tell families apart.
    """
    if not user_agent:
        return None

    token = user_agent.strip().split()[0] if user_agent.strip() else ""
    family = token.split("/")[0].lower()

    return family or None


class SessionProfile:
    """One origin's events over a window, and the shape they make."""

    def __init__(self, *, origin, events, now=None):
        self.origin = origin
        self.events = sorted(events, key=lambda event: event["timestamp"])
        self.now = now or timezone.now()

    def __len__(self):
        return len(self.events)

    @staticmethod
    def summarize(log):
        return dict(
            timestamp=log.timestamp,
            action=log.action,
            actor_id=log.actor_id,
            user_agent=log.user_agent,
            category=log.category,
            risk_score=log.risk_score,
        )

    def gaps(self):
        """Seconds between consecutive events."""
        return [
            (later["timestamp"] - earlier["timestamp"]).total_seconds()
            for earlier, later in zip(self.events, self.events[1:])
        ]

    def by_account(self):
        grouped = defaultdict(list)
        for event in self.events:
            if event["actor_id"]:
                grouped[event["actor_id"]].append(event)
        return grouped

    def motifs(self):
        """
        Per account, whether the session shows the takeover motif.

        `credential`: a reset request followed later by a login.
        `takeover`: that, then a manipulation or a debit — the attacker got
        in and did something with it.
        """
        credential = set()
        takeover = set()

        for actor_id, events in self.by_account().items():
            seen_reset = False
            seen_login = False
            for event in events:
                action = event["action"]
                if action in RESET_ACTIONS:
                    seen_reset = True
                elif action in LOGIN_ACTIONS and seen_reset:
                    seen_login = True
                    credential.add(actor_id)
                elif seen_login and (action in MANIPULATION_ACTIONS or action == DEBIT_ACTION):
                    takeover.add(actor_id)

        return credential, takeover

    def features(self):
        gaps = self.gaps()
        accounts = {event["actor_id"] for event in self.events if event["actor_id"]}
        families = {client_family(event["user_agent"]) for event in self.events}
        families.discard(None)

        registered_here = {
            event["actor_id"] for event in self.events
            if event["action"] == REGISTRATION_ACTION and event["actor_id"]
        }
        credential_accounts = {
            event["actor_id"] for event in self.events
            if event["action"] in CREDENTIAL_ACTIONS and event["actor_id"]
        }
        credential_motifs, takeover_motifs = self.motifs()

        median_gap = statistics.median(gaps) if gaps else None
        regularity = None
        if len(gaps) >= 3 and statistics.mean(gaps) > 0:
            spread = statistics.pstdev(gaps) / statistics.mean(gaps)
            regularity = round(max(0.0, 1.0 - spread), 3)

        return dict(
            events=len(self.events),
            accounts=len(accounts),
            client_families=len(families),
            action_kinds=len({event["action"] for event in self.events}),
            registrations=len(registered_here),
            # Credentials touched on accounts this origin did not create in
            # the window: somebody else's accounts.
            credential_accounts_not_registered=len(credential_accounts - registered_here),
            credential_motifs=len(credential_motifs),
            takeover_motifs=len(takeover_motifs),
            median_gap_seconds=round(median_gap, 1) if median_gap is not None else None,
            gap_regularity=regularity,
            span_seconds=(
                round((self.events[-1]["timestamp"] - self.events[0]["timestamp"]).total_seconds())
                if len(self.events) > 1 else 0
            ),
        )


class SessionActivity:
    WINDOW_MINUTES = 60
    MAX_EVENTS = 500

    @classmethod
    def load(cls, *, application, device_fingerprint=None, ip_address=None,
             window_minutes=None, now=None):
        """
        The session for an origin: the device when one is known, otherwise
        the IP. A device is the stronger key, so when both are present the
        session follows the device and the IP is not used to widen it.
        """
        now = now or timezone.now()
        window = window_minutes or cls.WINDOW_MINUTES

        queryset = AuditLog.objects.filter(
            application_id=application.id,
            timestamp__gte=now - timedelta(minutes=window),
        )

        if device_fingerprint:
            origin = dict(key="device", value=device_fingerprint)
            queryset = queryset.filter(device_fingerprint=device_fingerprint)
        elif ip_address:
            origin = dict(key="ip", value=ip_address)
            queryset = queryset.filter(ip_address=ip_address)
        else:
            return None

        events = [
            SessionProfile.summarize(log)
            for log in queryset.order_by("-timestamp")[:cls.MAX_EVENTS]
        ]

        return SessionProfile(origin=origin, events=events, now=now)


class SessionBaseline:
    """
    What this merchant's sessions normally look like, as percentiles.

    Built from the last week of recorded decisions, grouped into one-hour
    sessions per origin. Read by `SessionShapeRule` so that "many accounts
    from one IP" means many *for this merchant* — a carrier-NAT city and a
    campus network are not the same normal.
    """

    WINDOW_DAYS = 7
    SAMPLE_CAP = 5000
    CACHE_SECONDS = 300
    # Fewer sessions than this and the percentiles are noise.
    MIN_SESSIONS = 30

    # Used until a merchant has a baseline. Deliberately permissive on
    # accounts, because shared addresses are ordinary; the shape signals
    # carry the decision until history can tighten this.
    DEFAULTS = dict(
        accounts_p95=3,
        client_families_p95=1,
        events_p95=20,
        median_gap_p05=20.0,
        sessions=0,
    )

    @classmethod
    def cache_key(cls, application_id):
        return f"flit:session_baseline:{application_id}"

    @classmethod
    def load(cls, *, application):
        key = cls.cache_key(application.id)

        try:
            cached = cache.get(key)
            if cached is not None:
                return cached

            result = cls.compute(application=application) or dict(cls.DEFAULTS)
            cache.set(key, result, cls.CACHE_SECONDS)
            return result
        except Exception:
            logger.warning("Could not read session baseline", exc_info=True)
            return dict(cls.DEFAULTS)

    @classmethod
    def compute(cls, *, application):
        rows = list(
            AuditLog.objects.filter(
                application_id=application.id,
                timestamp__gte=timezone.now() - timedelta(days=cls.WINDOW_DAYS),
            )
            .order_by("-timestamp")
            .values("timestamp", "action", "actor_id", "user_agent", "device_fingerprint", "ip_address")
            [:cls.SAMPLE_CAP]
        )

        sessions = defaultdict(list)
        for row in rows:
            origin = row["device_fingerprint"] or row["ip_address"]
            if not origin:
                continue
            bucket = row["timestamp"].replace(minute=0, second=0, microsecond=0)
            sessions[(origin, bucket)].append(dict(
                timestamp=row["timestamp"],
                action=row["action"],
                actor_id=row["actor_id"],
                user_agent=row["user_agent"],
                category=None,
                risk_score=None,
            ))

        if len(sessions) < cls.MIN_SESSIONS:
            return None

        profiles = [
            SessionProfile(origin=None, events=events).features()
            for events in sessions.values()
        ]

        gaps = [p["median_gap_seconds"] for p in profiles if p["median_gap_seconds"] is not None]

        return dict(
            accounts_p95=cls.percentile([p["accounts"] for p in profiles], 95),
            client_families_p95=cls.percentile([p["client_families"] for p in profiles], 95),
            events_p95=cls.percentile([p["events"] for p in profiles], 95),
            median_gap_p05=cls.percentile(gaps, 5) if gaps else cls.DEFAULTS["median_gap_p05"],
            sessions=len(profiles),
        )

    @staticmethod
    def percentile(values, pct):
        if not values:
            return None
        ordered = sorted(values)
        index = max(0, min(len(ordered) - 1, round((pct / 100) * (len(ordered) - 1))))
        return ordered[index]
