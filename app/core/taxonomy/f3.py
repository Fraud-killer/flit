"""
FLIT's mapping onto the MITRE Fight Fraud Framework (F3).

FLIT does not define its own fraud taxonomy. One already exists: MITRE's
Center for Threat-Informed Defense published F3 in April 2026, built with
JPMorganChase, Citigroup, Lloyds Banking Group, Standard Chartered and
FS-ISAC. It has 8 tactics and 123 techniques, it is free, and the banks a
fintech wants to be trusted by already speak it.

Inventing a parallel vocabulary would mean asking the industry to learn ours.
Mapping onto theirs means a risk team can ask "which F3 techniques do you
cover?" and get an answer in the language they already use — and it makes
FLIT's blind spots legible instead of invisible, which is the more useful
half.

The catalogue beside this file is a pinned index of F3 v1.1 (identifiers,
names and tactics only). F3 is Apache-2.0; see NOTICE. MITRE does not endorse
FLIT, and nothing here should be read as implying that it does.
"""

import json
from functools import lru_cache
from pathlib import Path


CATALOGUE_PATH = Path(__file__).with_name("f3_catalogue.json")


class UnknownTechnique(Exception):
    """A detector referenced an identifier that is not in the framework."""


@lru_cache(maxsize=1)
def _catalogue():
    return json.loads(CATALOGUE_PATH.read_text())


class F3:
    @classmethod
    def version(cls):
        return _catalogue()["version"]

    @classmethod
    def source(cls):
        return _catalogue()["source"]

    @classmethod
    def techniques(cls):
        return _catalogue()["techniques"]

    @classmethod
    def tactics(cls):
        return _catalogue()["tactics"]

    @classmethod
    def exists(cls, technique_id):
        return technique_id in cls.techniques()

    @classmethod
    def name(cls, technique_id):
        entry = cls.techniques().get(technique_id)
        if entry is None:
            raise UnknownTechnique(technique_id)
        return entry["name"]

    @classmethod
    def tactics_for(cls, technique_id):
        entry = cls.techniques().get(technique_id)
        if entry is None:
            raise UnknownTechnique(technique_id)
        return entry["tactics"]

    @classmethod
    def tactic_name(cls, tactic_id):
        return cls.tactics().get(tactic_id, tactic_id)

    @classmethod
    def describe(cls, technique_id):
        return dict(
            id=technique_id,
            name=cls.name(technique_id),
            tactics=[
                dict(id=tactic, name=cls.tactic_name(tactic))
                for tactic in cls.tactics_for(technique_id)
            ],
        )

    @classmethod
    def validate(cls, technique_ids):
        """Raise on any identifier the framework does not define."""
        unknown = [
            technique_id for technique_id in technique_ids
            if not cls.exists(technique_id)
        ]

        if unknown:
            raise UnknownTechnique(", ".join(sorted(unknown)))

        return True
