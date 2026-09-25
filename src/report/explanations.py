"""Reader-facing report views: severity order, explanations and related areas.

This module adds presentation data only. It never changes which findings
exist or what they say. Guidance text comes from
``src.analyze.common.guidance``. Related areas (PT-007) list other findings in
the same report that belong to an area a reader should also review. If there
are none, the report says so explicitly, because a missing finding is not
proof that a control is in place.
"""

from collections import defaultdict
from typing import Dict, List, Optional

from src.analyze.common.guidance import AREAS, Guidance, guidance_for
from src.analyze.common.issue import Finding, FindingBasis


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN")
_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

NO_RELATED_FINDING = (
    "No finding in this area was reported. That is not proof the control is in place: "
    "check the assessment coverage and verify it on the device."
)


# PT-009: what the finding is based on. Rules declare the basis; it is never
# inferred from the finding text.
BASIS_TEXT = {
    FindingBasis.EXPLICIT_VALUE: (
        "Configured value",
        "The configuration explicitly sets the value described in the evidence.",
    ),
    FindingBasis.DOCUMENTED_DEFAULT: (
        "Vendor default",
        "Nothing is set explicitly, and the vendor documents the reported value as the "
        "default for this platform or release.",
    ),
    FindingBasis.MISSING_EXPLICIT_SETTING: (
        "Setting not explicitly configured",
        "The recommended hardening setting is not in the configuration. The default was "
        "not assessed, so on some software releases the effective value may already be "
        "safe. Setting it explicitly, as the fix describes, removes the doubt and keeps "
        "the device safe across upgrades.",
    ),
    FindingBasis.REQUIRED_SETTING_MISSING: (
        "Required setting not configured",
        "A control this baseline requires is not configured, and the device does not "
        "provide it by default, so the protection is absent until it is added.",
    ),
}


def ordered_findings(issues: Dict[str, Finding]) -> List[tuple]:
    """Return ``(key, finding)`` pairs sorted by severity, keeping report order within one."""

    indexed = list(enumerate(issues.items()))
    indexed.sort(key=lambda item: (_RANK.get(item[1][1].severity.name, 99), item[0]))
    return [pair for _, pair in indexed]


def _anchor(position: int) -> str:
    return f"finding-{position}"


def build_finding_views(issues: Dict[str, Finding]) -> List[dict]:
    """Presentation records for every finding, in severity order."""

    ordered = ordered_findings(issues)
    anchors = {key: _anchor(position) for position, (key, _) in enumerate(ordered, start=1)}
    guidance: Dict[str, Optional[Guidance]] = {
        key: guidance_for(finding.rule_id) for key, finding in ordered
    }
    by_area: Dict[str, List[str]] = defaultdict(list)
    for key, _ in ordered:
        if guidance[key] is not None:
            by_area[guidance[key].area].append(key)

    views = []
    for position, (key, finding) in enumerate(ordered, start=1):
        entry = guidance[key]
        related = []
        if entry is not None:
            for area_key in AREAS[entry.area].related:
                others = [other for other in by_area.get(area_key, ()) if other != key]
                related.append({
                    "area": area_key,
                    "title": AREAS[area_key].title,
                    "findings": [
                        {
                            "key": other,
                            "anchor": anchors[other],
                            "title": issues[other].title,
                            "rule-id": issues[other].rule_id,
                            "severity": issues[other].severity.value,
                            "severity-class": issues[other].severity.name.lower(),
                        }
                        for other in others
                    ],
                    "note": None if others else NO_RELATED_FINDING,
                })
        views.append({
            "key": key,
            "anchor": anchors[key],
            "number": position,
            "finding": finding,
            "severity": finding.severity.value,
            "severity-class": finding.severity.name.lower(),
            "guidance": entry,
            "area-title": AREAS[entry.area].title if entry is not None else "General",
            "related": related,
            "basis": finding.basis.value if finding.basis else None,
            "basis-label": BASIS_TEXT[finding.basis][0] if finding.basis else None,
            "basis-note": BASIS_TEXT[finding.basis][1] if finding.basis else None,
        })
    return views


def json_security_audit(issues: Dict[str, Finding]) -> Dict[str, dict]:
    """Finding dictionaries with additive ``guidance`` and ``related-areas`` keys."""

    views = {view["key"]: view for view in build_finding_views(issues)}
    result = {}
    for key, finding in issues.items():
        view = views[key]
        record = finding.to_dict()
        record["guidance"] = view["guidance"].to_dict() if view["guidance"] else None
        record["basis-note"] = view["basis-note"]
        record["related-areas"] = [
            {
                "area": item["area"],
                "title": item["title"],
                "findings": [
                    {"key": other["key"], "rule-id": other["rule-id"]}
                    for other in item["findings"]
                ],
                "note": item["note"],
            }
            for item in view["related"]
        ]
        result[key] = record
    return result


def severity_tiles(issues: Dict[str, Finding]) -> List[dict]:
    """Counts for every severity level, including zero, in display order."""

    counts = defaultdict(int)
    labels = {}
    for finding in issues.values():
        counts[finding.severity.name] += 1
        labels[finding.severity.name] = finding.severity.value
    tiles = []
    for name in SEVERITY_ORDER:
        if name == "UNKNOWN" and not counts[name]:
            continue
        tiles.append({
            "name": name.lower(),
            "label": labels.get(name, name.capitalize()),
            "count": counts[name],
        })
    return tiles


def coverage_counts(coverage: dict) -> Dict[str, int]:
    """Number of normalized fields per knowledge state."""

    counts: Dict[str, int] = defaultdict(int)
    for field in coverage.get("fields", ()):
        counts[str(field.get("knowledge-state", "unknown"))] += 1
    return dict(counts)


__all__ = [
    "BASIS_TEXT",
    "NO_RELATED_FINDING",
    "SEVERITY_ORDER",
    "build_finding_views",
    "coverage_counts",
    "json_security_audit",
    "ordered_findings",
    "severity_tiles",
]
