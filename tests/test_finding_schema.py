import json
from pathlib import Path

import pytest

from src.analyze.common.issue import Finding, Issue, Severity
from src.analyze.cisco.ios.issue.cisco_ios_issue import CiscoIOSIssue


def make_finding(**overrides):
    values = {
        "rule_id": "vendor.os.control",
        "device": "VENDOR_OS",
        "title": "Example finding",
        "observation": "An insecure setting is effective.",
        "impact": "The management plane is exposed.",
        "recommendation": "Disable the insecure setting.",
        "severity": Severity.HIGH,
        "exploitability": "Reachable from an untrusted network.",
        "evidence": ("line 10: insecure setting",),
    }
    values.update(overrides)
    return Finding(**values)


def test_finding_requires_keyword_arguments():
    with pytest.raises(TypeError):
        Finding(
            "vendor.os.control",
            "VENDOR_OS",
            "Title",
            "Observation",
            "Impact",
            "Recommendation",
        )


@pytest.mark.parametrize("severity", ["critical", "High", Severity.MEDIUM, "LOW"])
def test_finding_normalizes_valid_severity(severity):
    finding = make_finding(severity=severity)
    assert isinstance(finding.severity, Severity)


def test_finding_rejects_invalid_severity():
    with pytest.raises(ValueError, match="Invalid severity"):
        make_finding(severity="urgent")


@pytest.mark.parametrize(
    "field",
    ["rule_id", "device", "title", "observation", "impact", "recommendation"],
)
def test_finding_rejects_empty_required_fields(field):
    with pytest.raises(ValueError, match=field):
        make_finding(**{field: " "})


def test_finding_serializes_severity_and_exploitability_separately():
    serialized = make_finding().to_dict()

    assert serialized["severity"] == "High"
    assert serialized["exploitability"] == "Reachable from an untrusted network."
    assert serialized["ease"] == serialized["exploitability"]
    assert serialized["evidence"] == ["line 10: insecure setting"]
    json.dumps(serialized)


def test_legacy_issue_imports_resolve_to_neutral_finding_type():
    assert Issue is Finding
    assert CiscoIOSIssue is Finding


def test_plugins_do_not_construct_vendor_specific_issue_types():
    plugin_root = Path(__file__).parents[1] / "src" / "analyze"
    plugin_sources = [
        path.read_text(encoding="utf-8")
        for path in plugin_root.rglob("*_plugin.py")
        if "cisco_ios_issue.py" not in str(path)
    ]

    assert all("CiscoIOSIssue" not in source for source in plugin_sources)
