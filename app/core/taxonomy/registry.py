"""
What FLIT detects, read from the detectors themselves.

The coverage matrix is generated here rather than written by hand, and that
is the whole point. Hand-maintained coverage documents drift the moment a
rule is added, renamed or retired, and they drift silently — the document
still reads well while describing software that no longer exists. Deriving it
from the registered rules means the map cannot disagree with the territory:
if it is wrong, the code is wrong.
"""

from collections import defaultdict

from .f3 import F3
from .maturity import Maturity
from .scope import exclusion_reason, is_addressable


def rule_classes():
    from core.audit.auditor import Auditor

    return Auditor.rule_classes


def detectors():
    """Every registered rule and what it declares about itself."""
    from core.audit.rules.base_rule import RuleKind

    rows = []

    for rule_class in rule_classes():
        techniques = tuple(getattr(rule_class, "techniques", ()) or ())
        rows.append(dict(
            rule=rule_class.__name__,
            kind=getattr(rule_class, "kind", RuleKind.DETECTION),
            techniques=list(techniques),
            maturity=getattr(rule_class, "maturity", Maturity.PROPOSED),
            provenance=getattr(rule_class, "provenance", "") or "",
            evidence_codes=list(getattr(rule_class, "evidence_codes", ()) or ()),
        ))

    return sorted(rows, key=lambda row: row["rule"])


def coverage():
    """
    F3 techniques grouped into covered, addressable and out of telemetry.

    A technique's maturity is that of its strongest detector: one measured
    detector is enough to say the technique is measured, while several
    unmeasured ones are not.
    """
    from core.audit.rules.base_rule import RuleKind

    by_technique = defaultdict(list)

    for row in detectors():
        if row["kind"] != RuleKind.DETECTION:
            continue
        for technique in row["techniques"]:
            by_technique[technique].append(row)

    covered, addressable, out_of_telemetry = [], [], []

    for technique_id in sorted(F3.techniques()):
        # Sub-techniques inherit their parent's treatment; FLIT maps at
        # technique level, which is the granularity its signals support.
        if "." in technique_id:
            continue

        entry = dict(
            id=technique_id,
            name=F3.name(technique_id),
            tactics=[
                F3.tactic_name(tactic) for tactic in F3.tactics_for(technique_id)
            ],
        )

        rows = by_technique.get(technique_id)

        if rows:
            best = max(rows, key=lambda row: Maturity.rank(row["maturity"]))
            entry.update(
                rules=[row["rule"] for row in rows],
                maturity=best["maturity"],
                measured=Maturity.is_measured(best["maturity"]),
            )
            covered.append(entry)
        elif is_addressable(technique_id):
            addressable.append(entry)
        else:
            entry["reason"] = exclusion_reason(technique_id)
            out_of_telemetry.append(entry)

    return dict(
        framework=dict(
            name="MITRE Fight Fraud Framework (F3)",
            version=F3.version(),
            source=F3.source(),
        ),
        covered=covered,
        addressable=addressable,
        out_of_telemetry=out_of_telemetry,
        totals=summarise(covered, addressable, out_of_telemetry),
    )


def summarise(covered, addressable, out_of_telemetry):
    in_scope = len(covered) + len(addressable)

    return dict(
        techniques=len(covered) + len(addressable) + len(out_of_telemetry),
        in_scope=in_scope,
        covered=len(covered),
        addressable=len(addressable),
        out_of_telemetry=len(out_of_telemetry),
        measured=sum(1 for entry in covered if entry["measured"]),
        coverage_of_addressable=(
            round(len(covered) / in_scope, 3) if in_scope else 0.0
        ),
    )


def maturity_summary():
    """How many detectors sit on each rung."""
    counts = {key: 0 for key in Maturity.VALUES}

    for row in detectors():
        counts[row["maturity"]] = counts.get(row["maturity"], 0) + 1

    return counts


def unproven():
    """
    Detectors claiming a rung above PROPOSED with nothing to point at.

    Enforced by the test suite: a rule may sit anywhere on the ladder, but it
    may not claim evidence it cannot name.
    """
    return [
        row["rule"] for row in detectors()
        if Maturity.rank(row["maturity"]) >= Maturity.rank(Maturity.NEEDS_PROVENANCE)
        and not row["provenance"]
    ]


def unknown_techniques():
    """Identifiers a detector claims that F3 does not define."""
    unknown = set()

    for row in detectors():
        for technique in row["techniques"]:
            if not F3.exists(technique):
                unknown.add(f"{row['rule']}:{technique}")

    return sorted(unknown)
