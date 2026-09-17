from devkit.message import Message
from core.audit.events import ClientEvent, TransactionEvent
from core.intelligence.ip_intelligence import IPIntelligence

from .base_rule import BaseRule
from .visit_signals import fetch_visit_signals, event_value


class IPReputationRule(BaseRule):
    """
    Flags Tor, VPN, proxy, datacenter, blocklisted and high-risk-country IPs.

    Combines local intelligence (GeoIP, Tor and threat lists) for the event's
    `ip_address` with Fingerprint Smart Signals for its `visit_id`. When the
    event has no `ip_address`, the IP Fingerprint saw for the visit is used.
    """

    @property
    def applies(self):
        return isinstance(self.event, (ClientEvent, TransactionEvent)) and (
            event_value(self.event, "ip_address") is not None
            or event_value(self.event, "visit_id") is not None
        )

    async def perform(self):
        visit = await fetch_visit_signals(self)

        ip_address = event_value(self.event, "ip_address") or getattr(visit, "ip", None)
        if not ip_address:
            return []

        info = await IPIntelligence.analyze(ip_address)
        visit_flag = lambda name: bool(getattr(visit, name, None))

        base_context = dict(
            ip_address=ip_address,
            asn=info.asn or getattr(visit, "asn", None),
            asn_org=info.asn_org or getattr(visit, "asn_org", None),
            country_code=info.country_code,
        )

        checks = [
            (
                "tor_exit_node",
                info.is_tor, visit_flag("tor"),
                "IP address is a Tor exit node",
            ),
            (
                "known_attacker",
                info.is_known_attacker, visit_flag("ip_blocklisted"),
                "IP address is on a threat blocklist",
            ),
            (
                "proxy_detected",
                info.is_proxy, visit_flag("proxy"),
                "IP address belongs to a proxy",
            ),
            (
                "vpn_detected",
                info.is_vpn, visit_flag("vpn"),
                "IP address belongs to a VPN provider",
            ),
            (
                "datacenter_ip",
                info.is_datacenter, visit_flag("is_datacenter"),
                "IP address belongs to a hosting or cloud provider",
            ),
        ]

        messages = []

        for code, local_hit, visit_hit, text in checks:
            if not (local_hit or visit_hit):
                continue

            sources = [
                source for source, hit in (("local", local_hit), ("fingerprint", visit_hit))
                if hit
            ]

            messages.append(
                Message(
                    code=code,
                    path="ip_address",
                    text=text,
                    context=dict(base_context, sources=sources),
                )
            )

        if info.country_code in IPIntelligence.HIGH_RISK_COUNTRIES:
            messages.append(
                Message(
                    code="high_risk_country",
                    path="ip_address",
                    text="IP address is located in a high-risk country",
                    context=dict(base_context, sources=["local"]),
                )
            )

        return messages
