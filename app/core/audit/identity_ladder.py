"""
The identity ladder.

FLIT used to correlate accounts on exactly one key: the device fingerprint.
That key only exists when the client runs our JavaScript, so the rules that
depend on it — account farming, multi-accounting, mule networks — switched
themselves off against precisely the adversary who was most deliberate.

The ladder replaces that single nullable key with an ordered set. Rules ask
for the strongest key available and score their finding by that key's
confidence, so correlation degrades instead of disappearing.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from core.identity_keys import IdentityKeyType


# What a well-behaved browser session is expected to produce. Coverage is
# measured against this, and a shortfall is itself evidence (see
# ExpectedSignalRule).
# Weighted so that no combination of the weaker keys can reach the score a
# device alone gives: coverage below 0.5 means the device key is missing, and
# above it means the device key is present. That keeps the number readable.
# Distinguishes "no network node" from "not specified" when adding a rung.
SAME_AS_KEY = object()


EXPECTED_KEY_WEIGHTS = {
    IdentityKeyType.DEVICE: 0.6,
    IdentityKeyType.EMAIL_ROOT: 0.15,
    IdentityKeyType.IP: 0.15,
    IdentityKeyType.ASN: 0.10,
}


@dataclass
class IdentityRung:
    """
    One correlation key resolved for an event.

    Two handles, because the two jobs have different owners. `key` is what
    accounts are counted on — a DeviceIdentity for the device rung, whose
    links live in DeviceAccountLink, and an IdentityKey for every other rung.
    `network_key` is always the global IdentityKey, which is the node the
    shared protection network keeps reputation against.
    """

    key_type: str
    value: str
    confidence: float
    key: object = None
    network_key: object = None

    @property
    def persisted(self) -> bool:
        return self.key is not None

    def __str__(self):
        return f"{self.key_type}({self.confidence})"


@dataclass
class IdentityLadder:
    """Every key FLIT could resolve for one event, strongest first."""

    rungs: List[IdentityRung] = field(default_factory=list)

    def add(self, key_type: str, value: str, key=None, network_key=SAME_AS_KEY):
        if not value:
            return None

        confidence = IdentityKeyType.CONFIDENCE.get(key_type, 0.3)
        rung = IdentityRung(
            key_type=key_type,
            value=str(value),
            confidence=confidence,
            key=key,
            # Every rung but the device one counts on its own IdentityKey, so
            # that is also its network node unless told otherwise. The
            # sentinel matters: passing an explicit None means "there is no
            # network node", which is not the same as "use the counting key".
            network_key=key if network_key is SAME_AS_KEY else network_key,
        )
        self.rungs.append(rung)
        self.rungs.sort(key=lambda item: item.confidence, reverse=True)
        return rung

    def get(self, key_type: str) -> Optional[IdentityRung]:
        for rung in self.rungs:
            if rung.key_type == key_type:
                return rung
        return None

    def has(self, key_type: str) -> bool:
        return self.get(key_type) is not None

    def correlation_rungs(self) -> List[IdentityRung]:
        """The rungs a rule can actually count accounts on, strongest first."""
        return [rung for rung in self.rungs if rung.persisted]

    def strongest(self) -> Optional[IdentityRung]:
        rungs = self.correlation_rungs()
        return rungs[0] if rungs else None

    def network_key_ids(self) -> List[str]:
        """The global keys this event touched, for the shared network."""
        return [
            str(rung.network_key.id) for rung in self.rungs
            if rung.network_key is not None
        ]

    @property
    def coverage(self) -> float:
        """
        How much of the expected signal set this event produced, 0.0–1.0.

        A browser that ran our JavaScript and reached us directly scores near
        1.0. A bare HTTP client with a throwaway address scores near 0.2 —
        and that shortfall is the thing worth alerting on, because the rules
        that would otherwise speak have nothing to speak about.
        """
        present = sum(
            weight for key_type, weight in EXPECTED_KEY_WEIGHTS.items()
            if self.has(key_type)
        )
        total = sum(EXPECTED_KEY_WEIGHTS.values())
        return round(present / total, 3) if total else 0.0

    @property
    def missing_expected(self) -> List[str]:
        return [
            key_type for key_type in EXPECTED_KEY_WEIGHTS
            if not self.has(key_type)
        ]

    def describe(self) -> dict:
        return dict(
            rungs=[rung.key_type for rung in self.rungs],
            coverage=self.coverage,
            missing=self.missing_expected,
            strongest=self.strongest().key_type if self.strongest() else None,
        )
