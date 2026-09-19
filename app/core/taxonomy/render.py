"""Render the coverage matrix as Markdown."""

from .maturity import Maturity
from . import registry


def render(data=None, detector_rows=None):
    data = data or registry.coverage()
    detector_rows = detector_rows or registry.detectors()
    totals = data["totals"]
    framework = data["framework"]
    out = []

    def add(line=""):
        out.append(line)

    add("# FLIT detection coverage")
    add()
    add(
        "Generated from the registered rules by "
        "`python manage.py coverage_matrix`. Do not edit by hand — a coverage "
        "document that is written rather than derived starts lying the first "
        "time a rule changes."
    )
    add()
    add(
        f"Mapped against **{framework['name']} v{framework['version']}**. "
        f"FLIT does not define its own fraud taxonomy; it maps onto the one "
        f"the industry already uses ([source]({framework['source']}))."
    )
    add()

    add("## Where FLIT stands")
    add()
    add("| | Techniques |")
    add("|---|---|")
    add(f"| Covered by at least one detector | **{totals['covered']}** |")
    add(f"| Addressable, not yet covered | {totals['addressable']} |")
    add(f"| Outside FLIT's telemetry | {totals['out_of_telemetry']} |")
    add(f"| **In scope** (covered + addressable) | **{totals['in_scope']}** |")
    add(f"| F3 techniques in total | {totals['techniques']} |")
    add()
    add(
        f"Coverage of what FLIT can see: "
        f"**{round(totals['coverage_of_addressable'] * 100)}%** "
        f"({totals['covered']}/{totals['in_scope']})."
    )
    add()
    add(
        f"Of the {totals['covered']} covered techniques, **{totals['measured']}** "
        "rest on a detector with measured precision and recall. The rest are "
        "reasoned but not yet measured — see the ladder below."
    )
    add()

    add("## Evidence ladder")
    add()
    counts = registry.maturity_summary()
    add("| Rung | Detectors | What it requires |")
    add("|---|---|---|")
    for rung in Maturity.LADDER:
        add(f"| {rung.label} | {counts.get(rung.key, 0)} | {rung.requires} |")
    add()
    add(
        "`Proposed` is not a criticism. It means the detector is reasoned "
        "from how the fraud works and has not been measured against labelled "
        "history yet. Nothing above that rung may be claimed without naming "
        "the evidence, and the test suite enforces it."
    )
    add()

    add("## Covered techniques")
    add()
    add("| F3 | Technique | Tactic | Evidence | Detectors |")
    add("|---|---|---|---|---|")
    for entry in sorted(data["covered"], key=lambda e: e["id"]):
        add(
            f"| `{entry['id']}` | {entry['name']} | {', '.join(entry['tactics'])} "
            f"| {Maturity.label(entry['maturity'])} | {', '.join(entry['rules'])} |"
        )
    add()

    add("## Addressable, not yet covered")
    add()
    add(
        "FLIT already receives signals that could detect these. This is the "
        "roadmap, in priority order set by whoever is reading it."
    )
    add()
    add("| F3 | Technique | Tactic |")
    add("|---|---|---|")
    for entry in sorted(data["addressable"], key=lambda e: e["id"]):
        add(f"| `{entry['id']}` | {entry['name']} | {', '.join(entry['tactics'])} |")
    add()

    add("## Outside FLIT's telemetry")
    add()
    add(
        "These happen where a server-side decision layer has no eyes. They "
        "are listed so the boundary is explicit rather than implied, and each "
        "reason can be argued with."
    )
    add()
    add("| F3 | Technique | Why |")
    add("|---|---|---|")
    for entry in sorted(data["out_of_telemetry"], key=lambda e: e["id"]):
        add(f"| `{entry['id']}` | {entry['name']} | {entry['reason']} |")
    add()

    add("## Detectors")
    add()
    add("| Rule | Kind | F3 | Evidence | Shown by |")
    add("|---|---|---|---|---|")
    for row in detector_rows:
        techniques = ", ".join(f"`{t}`" for t in row["techniques"]) or "—"
        add(
            f"| {row['rule']} | {row['kind']} | {techniques} "
            f"| {Maturity.label(row['maturity'])} | {row['provenance'] or '—'} |"
        )
    add()

    return "\n".join(out) + "\n"
