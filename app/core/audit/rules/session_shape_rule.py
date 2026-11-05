"""
Score the session, not the event.

Every fixed threshold in FLIT can be learned and stepped over: slow the
reset-to-login past ninety seconds, change the client string per account,
spread the resets across addresses. What a loop cannot cheaply change is
that it is one origin, working accounts it did not create, with the same
motif, at a cadence no person keeps. Those are properties of the session,
and this rule reads them.

Judged against the merchant's own baseline where one exists, so that "many
accounts from one address" means many *for this merchant*. Without a
baseline the defaults are permissive on accounts — shared addresses are
ordinary — and the decision rests on the shape signals an office, a
household or a carrier-NAT city does not produce: rotating client families,
machine cadence, credentials touched on accounts the origin did not create,
and the takeover motif repeating.
"""

from asgiref.sync import sync_to_async
from devkit.message import Message

from core.audit.events import SIGNAL_EVENTS
from core.audit.lock_cache import lockcache, LockCache
from core.audit.recorder import AuditRecorder
from core.services.session_activity import SessionActivity, SessionBaseline, SessionProfile

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import event_value


class SessionShapeRule(BaseRule, LockCache):

    techniques = ("F1002", "F1006", "T1585")
    kind = RuleKind.DETECTION
    # Backtested on the Figo export (2026-09-15 to 2026-10-22, 952 labelled
    # fraud events): machine_session fired 300 times and agent_session 307,
    # every one on labelled fraud. The numbers are in the evidence ledger.
    maturity = Maturity.BACKTESTED
    provenance = "tests/unit/test_session_scoring.py::TestEvasiveReplay"
    evidence_codes = ("machine_session", "agent_session")

    # Below this many events in the window there is no shape to read.
    MIN_EVENTS = 4
    # Machine-likeness at or above this is reported.
    REPORT_AT = 0.5

    # How much each shape signal contributes to machine-likeness. They are
    # set so that the one signal a shared address produces on its own —
    # many accounts — never reports alone.
    CONTRIBUTIONS = dict(
        many_accounts=0.35,
        rotating_clients=0.3,
        machine_cadence=0.3,
        others_credentials=0.4,
        takeover_motif=0.5,
        # The agent-shaped signals. Bursts separated by think gaps, and
        # refusals answered with a different attempt, are the rhythm of a
        # model driving a loop. The client string is the weakest of the
        # three, because a shell-driven agent sends whatever it types.
        bimodal_cadence=0.35,
        adaptive_retry=0.4,
        agent_client=0.2,
        # The origin has been hitting the rate limiter: it is probing faster
        # than the API allows, which no customer does.
        rate_limited=0.3,
    )

    # Signals that, when present, mark the session as agent-driven rather
    # than merely scripted.
    AGENT_SIGNALS = ("bimodal_cadence", "adaptive_retry")

    @property
    def applies(self):
        return isinstance(self.event, SIGNAL_EVENTS) and (
            event_value(self.event, "ip_address") is not None
            or self.scope.device_identity is not None
        )

    def current_event(self):
        """This event, as the session would record it, since it is not yet recorded."""
        from django.utils import timezone

        return dict(
            timestamp=timezone.now(),
            action=AuditRecorder.action(self.event),
            actor_id=self.event.account_id,
            user_agent=event_value(self.event, "user_agent"),
            category=AuditRecorder.category(self.event),
            risk_score=None,
            blocked=None,
            outcome=AuditRecorder.outcome(self.event),
        )

    @lockcache(key="session")
    async def session(self):
        identity = self.scope.device_identity
        window = getattr(self.policy, "session_window_minutes", SessionActivity.WINDOW_MINUTES)

        profile = await sync_to_async(SessionActivity.load)(
            application=self.application,
            device_fingerprint=identity.external_id if identity else None,
            ip_address=event_value(self.event, "ip_address"),
            window_minutes=window,
        )

        if profile is None:
            return None

        return SessionProfile(
            origin=profile.origin,
            events=profile.events + [self.current_event()],
            now=profile.now,
        )

    @lockcache(key="baseline")
    async def baseline(self):
        return await sync_to_async(SessionBaseline.load)(application=self.application)

    @classmethod
    def signals(cls, features, baseline):
        """Which shape signals the session shows, each graded 0 to 1."""
        found = {}

        accounts_p95 = baseline.get("accounts_p95") or SessionBaseline.DEFAULTS["accounts_p95"]
        if features["accounts"] > accounts_p95:
            excess = (features["accounts"] - accounts_p95) / max(accounts_p95, 1)
            found["many_accounts"] = min(1.0, 0.5 + 0.25 * excess)

        families_p95 = baseline.get("client_families_p95") or SessionBaseline.DEFAULTS["client_families_p95"]
        if features["client_families"] >= max(3, families_p95 + 2):
            found["rotating_clients"] = min(1.0, 0.6 + 0.2 * (features["client_families"] - 3))

        gap_p05 = baseline.get("median_gap_p05") or SessionBaseline.DEFAULTS["median_gap_p05"]
        gap = features["median_gap_seconds"]
        if gap is not None and features["events"] >= 5 and gap < gap_p05:
            strength = 0.6
            if (features["gap_regularity"] or 0) >= 0.7:
                strength = 1.0
            found["machine_cadence"] = strength

        if features["registrations"] >= 3 and features["credential_accounts_not_registered"] >= 1:
            found["others_credentials"] = min(
                1.0, 0.6 + 0.1 * features["credential_accounts_not_registered"],
            )

        if features["takeover_motifs"] >= 2:
            found["takeover_motif"] = 1.0
        elif features["takeover_motifs"] == 1 and features["credential_motifs"] >= 2:
            found["takeover_motif"] = 0.7

        # Bursts, then silence, then bursts. Judged against how much
        # batching this merchant's own traffic shows.
        burst_p95 = baseline.get("burst_ratio_p95")
        if burst_p95 is None:
            burst_p95 = SessionBaseline.DEFAULTS["burst_ratio_p95"]
        if (
            features["events"] >= 6
            and features["burst_ratio"] >= max(0.3, burst_p95 + 0.1)
            and features["think_gaps"] >= 2
        ):
            found["bimodal_cadence"] = min(1.0, 0.7 + 0.1 * (features["think_gaps"] - 2))

        if features["adaptive_retries"] >= 2:
            found["adaptive_retry"] = min(1.0, 0.6 + 0.2 * (features["adaptive_retries"] - 2))

        if features["agent_clients"] >= 1:
            found["agent_client"] = 1.0

        if features["rate_limited"] >= 1:
            found["rate_limited"] = min(1.0, 0.6 + 0.2 * (features["rate_limited"] - 1))

        return found

    @classmethod
    def machine_likeness(cls, signals):
        return round(min(1.0, sum(
            cls.CONTRIBUTIONS[name] * strength for name, strength in signals.items()
        )), 3)

    async def perform(self):
        session = await self.session()
        if session is None or len(session) < self.MIN_EVENTS:
            return None

        features = session.features()
        baseline = await self.baseline()
        signals = self.signals(features, baseline)

        if not signals:
            return None

        likeness = self.machine_likeness(signals)
        messages = []

        if likeness >= self.REPORT_AT:
            messages.append(Message(
                code="machine_session",
                path=session.origin["key"] if session.origin else "ip_address",
                text=(
                    f"Session from this {session.origin['key']} looks automated: "
                    + ", ".join(sorted(signals))
                ),
                context=dict(
                    severity=likeness,
                    origin=session.origin,
                    signals={name: round(strength, 2) for name, strength in signals.items()},
                    features=features,
                    baseline={
                        key: baseline.get(key)
                        for key in ("accounts_p95", "client_families_p95", "median_gap_p05", "burst_ratio_p95", "sessions")
                    },
                ),
            ))

        # Reported separately from `machine_session` so the two can be
        # measured apart: a script and an agent are both machines, but only
        # one of them is reading the refusals.
        agent_signals = {name: signals[name] for name in self.AGENT_SIGNALS if name in signals}
        if agent_signals:
            messages.append(Message(
                code="agent_session",
                path=session.origin["key"] if session.origin else "ip_address",
                text=(
                    f"Session from this {session.origin['key']} looks agent-driven: "
                    + ", ".join(sorted(agent_signals))
                ),
                context=dict(
                    severity=min(1.0, max(agent_signals.values())),
                    origin=session.origin,
                    signals={name: round(strength, 2) for name, strength in agent_signals.items()},
                    burst_ratio=features["burst_ratio"],
                    think_gaps=features["think_gaps"],
                    adaptive_retries=features["adaptive_retries"],
                    agent_clients=features["agent_clients"],
                ),
            ))

        # The motif repeating is reported in its own right: it is the
        # takeover, not a property of the client that did it.
        if features["takeover_motifs"] >= 2:
            messages.append(Message(
                code="campaign_motif",
                path="action",
                text=(
                    f"Reset, login, then money or manipulation on "
                    f"{features['takeover_motifs']} accounts from one origin"
                ),
                context=dict(
                    severity=min(1.0, 0.8 + 0.1 * (features["takeover_motifs"] - 2)),
                    origin=session.origin,
                    accounts_taken=features["takeover_motifs"],
                    accounts_with_credential_motif=features["credential_motifs"],
                ),
            ))

        return messages or None
