"""
The correlation keys FLIT can identify an actor by, and what each is worth.

Deliberately free of Django imports: both the ORM models and the scoring
weights need these constants, and neither should have to import the other.
"""


class IdentityKeyType:
    """
    The kinds of key FLIT can correlate accounts on, strongest first.

    A device fingerprint is the best key there is, but it only exists if the
    client ran our JavaScript — which an attacker hitting an endpoint with
    curl has, by definition, declined to do. The weaker keys below survive
    that, so correlation degrades instead of disappearing.
    """

    DEVICE = "device"
    SIGNATURE = "signature"
    EMAIL_ROOT = "email_root"
    IP = "ip"
    ASN = "asn"

    CHOICES = [
        (DEVICE, "Device identity"),
        (SIGNATURE, "Device signature"),
        (EMAIL_ROOT, "Normalised email"),
        (IP, "IP address"),
        (ASN, "Autonomous system"),
    ]

    # How much a correlation found on this key is worth. A device match is
    # near-certain; an IP match is a shared office as often as it is a farm.
    # These scale the weight of any rule code suffixed with the key type,
    # e.g. `account_farming:ip` (see core.scoring.weights.RiskWeights).
    CONFIDENCE = {
        DEVICE: 1.0,
        SIGNATURE: 0.8,
        EMAIL_ROOT: 0.6,
        IP: 0.5,
        ASN: 0.35,
    }

    @classmethod
    def confidence(cls, key_type, default=0.3):
        return cls.CONFIDENCE.get(key_type, default)
