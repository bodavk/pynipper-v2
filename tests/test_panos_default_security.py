"""Explicit PAN-OS interzone default-rule overrides (SC-007)."""

import json
import subprocess
import sys

import pytest

from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.analyze.common.issue import Severity
from src.devices.paloalto.panos import PaloAltoPANOSParser


def _config(local="", shared="", panorama=""):
    return (
        "<config version='11.1'><shared>"
        f"{shared}</shared><devices><entry name='localhost.localdomain'>"
        "<vsys><entry name='vsys1'><rulebase>"
        f"{local}</rulebase></entry></vsys></entry></devices>{panorama}</config>"
    )


def _override(name="interzone-default", action="allow"):
    return (
        "<default-security-rules><rules>"
        f"<entry name='{name}'><action>{action}</action></entry>"
        "</rules></default-security-rules>"
    )


@pytest.mark.parametrize("local,shared,panorama,expected", [
    (_override(), "", "", True),
    (_override(action="deny"), "", "", False),
    (_override(action="deny"), _override(), "", False),
    ("", _override(), "", True),
    ("", _override(), "<device-group><entry name='dg1'/></device-group>", False),
    (_override(), _override(action="deny"), "<device-group><entry name='dg1'/></device-group>", True),
    (_override(name="intrazone-default"), "", "", False),
    (_override(action="not-a-valid-action"), "", "", False),
    ("", "", "", False),
])
def test_explicit_interzone_override(tmp_path, local, shared, panorama, expected):
    path = tmp_path / "panos.xml"
    path.write_text(_config(local, shared, panorama), encoding="utf-8")
    parser = PaloAltoPANOSParser(str(path))
    findings = [
        issue for issue in process_panos_conf(parser).values()
        if issue.rule_id == "paloalto.panos.policy.interzone_default_allow"
    ]
    assert bool(findings) is expected
    if expected:
        assert len(findings) == 1
        assert "interzone-default" in findings[0].evidence[0]
        assert findings[0].references
        assert findings[0].severity == Severity.HIGH


def test_duplicate_or_missing_action_is_unknown(tmp_path):
    duplicate = _override() + _override(action="deny")
    path = tmp_path / "panos.xml"
    path.write_text(_config(local=duplicate), encoding="utf-8")
    parser = PaloAltoPANOSParser(str(path))
    assert parser.get_default_security_rules()[0].resolution_state == "unknown"
    assert all(
        issue.rule_id != "paloalto.panos.policy.interzone_default_allow"
        for issue in process_panos_conf(parser).values()
    )


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_includes_explicit_default_override(tmp_path, output_type):
    path = tmp_path / "panos.xml"
    path.write_text(_config(local=_override()), encoding="utf-8")
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "PAN_OS", "-i", str(path),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "Interzone default security rule permits unmatched traffic" in rendered
    if output_type == "JSON":
        data = json.loads(rendered)
        assert sum(
            item["rule_id"] == "paloalto.panos.policy.interzone_default_allow"
            for item in data["security-audit"].values()
        ) == 1
