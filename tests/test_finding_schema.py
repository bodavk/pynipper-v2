import json
from pathlib import Path

import pytest

from src.analyze.common.issue import Finding, Issue, Severity
from src.report.report import _generate_html_report


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
        "references": ("https://example.test/hardening",),
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
    assert serialized["references"] == ["https://example.test/hardening"]
    json.dumps(serialized)


def test_finding_rejects_empty_references():
    with pytest.raises(ValueError, match="reference"):
        make_finding(references=("",))


def test_html_report_includes_finding_evidence_and_references(tmp_path):
    output = tmp_path / "report.html"
    finding = make_finding()
    _generate_html_report(
        str(output),
        {"1. Example": finding},
        [],
        {"device-type": "VENDOR_OS", "hostname": "test-device"},
    )
    report = output.read_text(encoding="utf-8")
    assert "pynipper-v2" in report
    assert "line 10: insecure setting" in report
    assert "https://example.test/hardening" in report
    assert "ajax.googleapis.com" not in report


def test_issue_name_resolves_to_neutral_finding_type():
    assert Issue is Finding


def test_plugins_do_not_construct_vendor_specific_issue_types():
    plugin_root = Path(__file__).parents[1] / "src" / "analyze"
    plugin_sources = [
        path.read_text(encoding="utf-8")
        for path in plugin_root.rglob("*_plugin.py")
    ]

    assert all("CiscoIOSIssue" not in source for source in plugin_sources)
