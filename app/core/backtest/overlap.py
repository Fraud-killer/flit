"""
Measures how much two portfolios share.

This is the consortium thesis, testable: if a device or counterparty that
defrauded one fintech also appears at another, a shared network would have
warned the second one. The number that matters is the last line — the share
of a portfolio's fraud that was already known elsewhere.
"""

from core.models import AuditLog, DeviceAccountLink
from core.audit.models import AuditLogLabel


FRAUD_LABELS = [AuditLogLabel.FRAUD, AuditLogLabel.CHARGEBACK]


def compare(first, second):
    return dict(
        applications=[first.name, second.name],
        devices=overlap_devices(first, second),
        counterparties=overlap_counterparties(first, second),
        ip_addresses=overlap_ips(first, second),
        fraud_known_elsewhere=fraud_known_elsewhere(first, second),
    )


def devices_of(application, fraud_only=False):
    links = DeviceAccountLink.objects.filter(application=application)

    if fraud_only:
        fraudulent = set(
            AuditLog.objects
            .filter(application_id=application.id, label__in=FRAUD_LABELS)
            .values_list("actor_id", flat=True)
        )
        links = links.filter(client_id__in=fraudulent)

    return set(links.values_list("device__external_id", flat=True))


def overlap_devices(first, second):
    left = devices_of(first)
    right = devices_of(second)

    return summarize(left, right)


def overlap_ips(first, second):
    left = values(first, "ip_address")
    right = values(second, "ip_address")

    return summarize(left, right)


def overlap_counterparties(first, second):
    left = context_values(first, "counterparty_id")
    right = context_values(second, "counterparty_id")

    return summarize(left, right)


def fraud_known_elsewhere(first, second):
    """
    For each portfolio: of the devices behind its confirmed fraud, how many
    were already seen at the other one. This is what a consortium would have
    caught.
    """
    return {
        first.name: shared_share(devices_of(first, fraud_only=True), devices_of(second)),
        second.name: shared_share(devices_of(second, fraud_only=True), devices_of(first)),
    }


def shared_share(fraud_devices, other_devices):
    shared = fraud_devices & other_devices

    return dict(
        fraud_devices=len(fraud_devices),
        also_seen_elsewhere=len(shared),
        share=round(len(shared) / len(fraud_devices), 4) if fraud_devices else None,
    )


def values(application, field):
    return {
        value for value in
        AuditLog.objects.filter(application_id=application.id).values_list(field, flat=True)
        if value
    }


def context_values(application, key):
    return {
        (context or {}).get(key)
        for context in AuditLog.objects.filter(application_id=application.id).values_list("context", flat=True)
        if (context or {}).get(key)
    }


def summarize(left, right):
    shared = left & right

    return dict(
        first=len(left),
        second=len(right),
        shared=len(shared),
        share_of_first=round(len(shared) / len(left), 4) if left else None,
        share_of_second=round(len(shared) / len(right), 4) if right else None,
    )


def format_overlap(result):
    lines = []
    add = lines.append

    first, second = result["applications"]
    add(f"Overlap: {first} vs {second}")

    for name in ("devices", "counterparties", "ip_addresses"):
        entry = result[name]
        add(f"  {name:<15} {entry['first']:>7} / {entry['second']:>7} shared {entry['shared']:>7} "
            f"({percent(entry['share_of_first'])} of the first)")

    add("")
    add("Fraud already known to the other portfolio")
    for name, entry in result["fraud_known_elsewhere"].items():
        add(f"  {name:<30} {entry['also_seen_elsewhere']}/{entry['fraud_devices']} devices "
            f"({percent(entry['share'])})")

    return "\n".join(lines)


def percent(value):
    return f"{value:.1%}" if value is not None else "n/a"
