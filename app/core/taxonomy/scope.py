"""
Which F3 techniques FLIT could ever detect.

Reporting "FLIT covers 21 of 123 techniques" would be dishonest arithmetic.
A large part of F3 describes things that happen where FLIT has no eyes at
all — a stolen envelope, a PIN read over someone's shoulder, a phone call to
a call centre. Counting those as gaps would understate coverage and, worse,
imply they are on a roadmap.

So a technique sits in one of three buckets:

  covered      — at least one detector claims it
  addressable  — FLIT receives signals that could detect it, and does not yet
  no telemetry — it happens outside anything FLIT is sent

Only the middle bucket is a roadmap. The third is a statement about where the
product's boundary is, which is a more useful thing to tell a customer than a
percentage.

Each exclusion carries its reason so the judgement can be argued with.
"""


# Technique -> why no signal FLIT receives could show it.
NO_TELEMETRY = {
    "F1008": "ATM hardware; FLIT sees no device-level ATM telemetry",
    "F1009": "Physical and branch deposit channels",
    "F1010": "Purchased at a physical counter",
    "F1011": "Card data captured offline, before any transaction",
    "F1013": "Happens in a payroll system, not the payment platform",
    "F1014": "Paper instruments",
    "F1017": "Cash and physical instruments",
    "F1019": "Card manufactured offline",
    "F1022": "Requires mailbox access",
    "F1026": "Occurs on a third-party gambling platform",
    "F1027": "Document review sits with the KYB provider",
    "F1029": "Reconnaissance carried out off-platform",
    "F1032": "Social engineering outside the product surface",
    "F1033": "Needs the operator's internal admin logs, not customer traffic",
    "F1034": "Voice channel",
    "F1035": "Physical mail",
    "F1037": "Card-present NFC; FLIT is a card-not-present decision layer",
    "F1040": "Telephony infrastructure",
    "F1041": "Physical observation",
    "T1113": "Endpoint capture, invisible to a server-side decision",
    "T1189": "Endpoint compromise",
    "T1195": "Vendor supply chain",
    "T1555": "Endpoint credential stores",
    "T1593": "Open-source reconnaissance",
    "T1598": "Phishing carried out off-platform",
    "T1608": "Attacker-side infrastructure",
    "T1650": "Access bought in criminal markets",
    "T1660": "Phishing carried out off-platform",
    "T1667": "Requires mailbox visibility",
    "T1672": "Mail infrastructure",
}


def is_addressable(technique_id):
    """Whether FLIT could, in principle, detect this from what it is sent."""
    return technique_id.split(".")[0] not in NO_TELEMETRY


def exclusion_reason(technique_id):
    return NO_TELEMETRY.get(technique_id.split(".")[0])
