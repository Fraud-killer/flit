from devkit.message import Message
from core.audit.events import ClientEvent, TransactionEvent

from .base_rule import BaseRule
from .visit_signals import fetch_visit_signals, event_value


class DeviceTamperingRule(BaseRule):
    """
    Flags devices whose integrity Fingerprint could not trust: tampered
    browsers, emulators and VMs, rooted/jailbroken phones, hooking frameworks,
    cloned apps, remote control, location spoofing and MITM proxies.
    """

    # visit.device_signals flag -> (message code, text)
    SIGNALS = {
        "tampering": ("device_tampering", "Browser or device has been tampered with"),
        "virtual_machine": ("virtual_machine", "Device is a virtual machine"),
        "emulator": ("emulator", "Device is an emulator"),
        "jailbroken": ("jailbroken_device", "Device is rooted or jailbroken"),
        "hooking_framework": ("hooking_framework", "A hooking framework (e.g. Frida) is running"),
        "cloned_app": ("cloned_app", "App is running in a cloned or dual-app environment"),
        "developer_tools": ("developer_tools", "Browser developer tools are open"),
        "location_spoofing": ("location_spoofing", "Device location is being spoofed"),
        "remote_control": ("remote_control", "Device is being remotely controlled"),
        "mitm_attack": ("mitm_attack", "Traffic is passing through a man-in-the-middle proxy"),
    }

    @property
    def applies(self):
        return (
            isinstance(self.event, (ClientEvent, TransactionEvent))
            and event_value(self.event, "visit_id") is not None
        )

    async def perform(self):
        visit = await fetch_visit_signals(self)
        signals = getattr(visit, "device_signals", None) or {}

        return [
            Message(
                code=code,
                path="visit_id",
                text=text,
                context=dict(
                    signal=flag,
                    suspect_score=getattr(visit, "suspect_score", None),
                ),
            )
            for flag, (code, text) in self.SIGNALS.items()
            if signals.get(flag)
        ]
