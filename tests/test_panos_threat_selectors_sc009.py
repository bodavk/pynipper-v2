"""SC-009: explicit, attached PAN-OS high-severity signature actions."""

import json
import subprocess
import sys

import pytest

from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.devices.paloalto.panos import PaloAltoPANOSParser


RULE_ID = "paloalto.panos.policy.threat_selector_nonblocking"


def _selector(name, severity, action, extra=""):
    return (
        f"<entry name='{name}'><severity><member>{severity}</member></severity>"
        f"<action><{action}/></action>{extra}</entry>"
    )


def _config(selectors, *, attached=True, enabled=True, profile_type="vulnerability"):
    profile = (
        f"<profiles><{profile_type}><entry name='MIXED'>"
        f"<rules>{selectors}</rules></entry></{profile_type}></profiles>"
    )
    attachment = (
        f"<profile-setting><profiles><{profile_type}><member>MIXED</member>"
        f"</{profile_type}></profiles></profile-setting>" if attached else ""
    )
    disabled = "<disabled>yes</disabled>" if not enabled else ""
    return (
        "<config version='11.2'><devices><entry name='localhost.localdomain'>"
        "<vsys><entry name='vsys1'>" + profile +
        "<rulebase><security><rules><entry name='ALLOW-WEB'>"
        "<from><member>trust</member></from><to><member>untrust</member></to>"
        "<source><member>any</member></source><destination><member>any</member></destination>"
        "<application><member>web-browsing</member></application>"
        "<service><member>application-default</member></service><action>allow</action>"
        + disabled + attachment +
        "</entry></rules></security></rulebase></entry></vsys></entry></devices></config>"
    )


def _scan(tmp_path, xml):
    path = tmp_path / "panos.xml"
    path.write_text(xml, encoding="utf-8")
    parser = PaloAltoPANOSParser(str(path))
    return parser, [item for item in process_panos_conf(parser).values() if item.rule_id == RULE_ID]


@pytest.mark.parametrize("selectors,expected", [
    (_selector("high-alert", "high", "alert") + _selector("medium-block", "medium", "reset-both"), True),
    (_selector("critical-allow", "critical", "allow") + _selector("high-block", "high", "drop"), True),
    (_selector("high-block", "high", "reset-both") + _selector("high-alert", "high", "alert"), False),
    (_selector("high-alert", "high", "alert") + _selector("high-block", "high", "reset-both"), True),
    (_selector("low-alert", "low", "alert") + _selector("high-block", "high", "reset-both"), False),
    (_selector("high-default", "high", "default") + _selector("medium-block", "medium", "drop"), False),
    (_selector("narrow", "high", "alert", "<threat-name>specific</threat-name>")
     + _selector("high-block", "high", "drop"), False),
    (_selector("cve-narrow", "high", "alert", "<cve>CVE-2026-0001</cve>")
     + _selector("high-block", "high", "drop"), False),
    ("<entry name='unknown-coverage'><action><drop/></action></entry>"
     + _selector("high-alert", "high", "alert"), False),
])
def test_first_broad_high_severity_action(tmp_path, selectors, expected):
    parser, findings = _scan(tmp_path, _config(selectors))
    assert bool(findings) is expected
    assert parser.get_security_inspection()[0].profiles[0].threat_selectors
    if expected:
        assert len(findings) == 1
        assert "selector" in " ".join(findings[0].evidence)


def test_attachment_and_disabled_rule_scope(tmp_path):
    mixed = _selector("critical-alert", "critical", "alert") + _selector("low-block", "low", "drop")
    assert not _scan(tmp_path, _config(mixed, attached=False))[1]
    assert not _scan(tmp_path, _config(mixed, enabled=False))[1]


def test_local_profile_precedes_same_named_shared_profile(tmp_path):
    local = _config(_selector("high-block", "high", "drop"))
    shared_weak = (
        "<shared><profiles><vulnerability><entry name='MIXED'><rules>"
        + _selector("high-alert", "high", "alert")
        + _selector("low-block", "low", "drop")
        + "</rules></entry></vulnerability></profiles></shared>"
    )
    _, findings = _scan(tmp_path, local.replace("<devices>", shared_weak + "<devices>"))
    assert not findings


def test_antispyware_member_severity_and_wholly_nonblocking_dedup(tmp_path):
    mixed = (
        "<entry name='high-alert'><severity><member>critical</member><member>high</member>"
        "</severity><action>alert</action></entry>"
        + _selector("low-block", "low", "drop")
    )
    _, findings = _scan(tmp_path, _config(mixed, profile_type="spyware"))
    assert len(findings) == 1
    assert "critical, high" in findings[0].observation
    only_alert = _selector("high-alert", "high", "alert")
    parser, findings = _scan(tmp_path, _config(only_alert))
    assert not findings
    assert any(
        item.rule_id == "paloalto.panos.policy.security_profile_ineffective"
        for item in process_panos_conf(parser).values()
    )


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_threat_selector_without_secret(tmp_path, output_type):
    path = tmp_path / "panos.xml"
    path.write_text(
        _config(_selector("high-alert", "high", "alert") + _selector("low-block", "low", "drop"))
        .replace("<config version='11.2'>", "<config version='11.2'><secret>syntheticprivate</secret>"),
        encoding="utf-8",
    )
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "PAN_OS", "-i", str(path),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "Attached PAN-OS threat profile does not block" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == RULE_ID for item in data["security-audit"].values())
