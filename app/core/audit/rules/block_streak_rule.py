"""
The attacker's own failed attempts, read as evidence.

Each event is scored on what it carries. A loop that has just been blocked
three times from one address carries that too, and this rule is where it
counts. It reads the streak recorded by the previous decisions for the same
origin — device when there is one, address when there is not — and raises
the next event accordingly. One block is a customer having a bad day. Three
in a row is a probe adapting.
"""

from asgiref.sync import sync_to_async
from devkit.message import Message

from core.audit.events import SIGNAL_EVENTS
from core.services.block_streak import BlockStreak

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import event_value


class BlockStreakRule(BaseRule):

    techniques = ("F1002",)
    kind = RuleKind.DETECTION
    # Backtested on the Figo export: 271 fires, all on labelled fraud.
    # Measured on the Figo replay, whose labels were derived from the blocks
    # this rule counts; that is an incident replay, not evidence. Shadow
    # traffic is what earns the next rung.
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_block_streak.py::TestBlockStreakRule"
    evidence_codes = ("block_streak",)

    # Below this many consecutive blocks there is nothing to say.
    REPORT_AT = 2

    @property
    def origin(self):
        identity = self.scope.device_identity
        return BlockStreak.origin_for(
            device_fingerprint=identity.external_id if identity else None,
            ip_address=event_value(self.event, "ip_address"),
        )

    @property
    def applies(self):
        return isinstance(self.event, SIGNAL_EVENTS) and self.origin is not None

    async def perform(self):
        streak = await sync_to_async(BlockStreak.read)(self.application.id, self.origin)
        consecutive = streak["consecutive"]

        if consecutive < self.REPORT_AT:
            return None

        return Message(
            code="block_streak",
            path="ip_address" if self.origin.startswith("ip:") else "device",
            text=f"This origin has been blocked {consecutive} times in a row",
            context=dict(
                severity=min(1.0, 0.4 + 0.2 * consecutive),
                consecutive=consecutive,
                total_24h=streak["total_24h"],
                origin=self.origin,
            ),
        )
