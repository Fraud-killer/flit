from devkit.message import Message
from core.audit.events import ClientEvent, TransactionEvent

from .base_rule import BaseRule
from .visit_signals import fetch_visit_signals, event_value


class DeviceConsistencyRule(BaseRule):
    """
    Flags browsers whose own signals contradict each other.

    A spoofed browser can change any single value; keeping every value
    consistent with the others is much harder, so these cross-checks catch
    what a plain fingerprint comparison misses.
    """

    # consistency flag -> (message code, text)
    FLAGS = {
        "spoofed_timezone": ("spoofed_timezone", "Reported timezone and UTC offset disagree"),
        "platform_mismatch": ("platform_mismatch", "Operating system reported inconsistently"),
        "software_renderer": ("software_renderer", "Graphics are software-rendered, typical of VMs and headless browsers"),
        "automation_markers": ("automation_markers", "Browser shows automation markers"),
        "device_class_mismatch": ("device_class_mismatch", "Touch support contradicts the reported device class"),
        "locale_country_mismatch": ("locale_country_mismatch", "Browser locale does not match the country of the IP address"),
    }

    @property
    def applies(self):
        return (
            isinstance(self.event, (ClientEvent, TransactionEvent))
            and event_value(self.event, "visit_token") is not None
        )

    async def perform(self):
        visit = await fetch_visit_signals(self)
        flags = getattr(visit, "consistency_flags", None) or []

        return [
            Message(
                code=code,
                path="visit_token",
                text=text,
                context=dict(signal=flag, matched_by=getattr(visit, "matched_by", None)),
            )
            for flag, (code, text) in self.FLAGS.items()
            if flag in flags
        ]
