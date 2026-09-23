"""SC-003: explicit IOS/XE access-edge admission bypasses."""

import json
import subprocess
import sys

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser


BASE = "version 17.9\naaa new-model\naaa authentication dot1x default group radius\n"
PORT = "interface GigabitEthernet1/0/1\n switchport mode access\n"
FORCE_ID = "cisco.ios.layer2.access_edge.dot1x_force_authorized"
GLOBAL_ID = "cisco.ios.layer2.access_edge.dot1x_global_disabled"
OPEN_ID = "cisco.ios.layer2.access_edge.dot1x_open_access"
ADMISSION_IDS = {FORCE_ID, GLOBAL_ID, OPEN_ID}


def _scan(tmp_path, commands, role="access-edge"):
    path = tmp_path / "switch.conf"
    path.write_text(BASE + commands, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    if role:
        parser.set_assessment_context(AssessmentContext.from_mapping({
            "interface_roles": {"GigabitEthernet1/0/1": role},
        }))
    findings = {item.rule_id: item for item in process_cisco_ios_conf(parser).values()}
    return parser, findings


@pytest.mark.parametrize("command", [
    "authentication port-control force-authorized",
    "dot1x port-control force-authorized",
    "access-session port-control force-authorized",
])
def test_explicit_force_authorized_access_edge(tmp_path, command):
    parser, findings = _scan(
        tmp_path, "dot1x system-auth-control\n" + PORT + f" {command}\n",
    )
    record = parser.get_access_admission_interfaces()[0]
    assert record.global_dot1x is True
    assert record.aaa_state == "configured-external"
    assert record.port_control == "force-authorized"
    assert FORCE_ID in findings
    assert "assessment policy" in " ".join(findings[FORCE_ID].evidence)


def test_port_override_and_secure_auto(tmp_path):
    _, restored = _scan(
        tmp_path,
        "dot1x system-auth-control\n" + PORT
        + " authentication port-control force-authorized\n"
        + " authentication port-control auto\n",
    )
    assert not ADMISSION_IDS.intersection(restored)
    parser, removed = _scan(
        tmp_path,
        "dot1x system-auth-control\n" + PORT
        + " authentication port-control force-authorized\n"
        + " no authentication port-control\n",
    )
    assert parser.get_access_admission_interfaces()[0].port_control is None
    assert not ADMISSION_IDS.intersection(removed)


def test_global_disable_overrides_auto(tmp_path):
    _, findings = _scan(
        tmp_path,
        "dot1x system-auth-control\nno dot1x system-auth-control\n"
        + PORT + " authentication port-control auto\n",
    )
    assert GLOBAL_ID in findings
    assert FORCE_ID not in findings
    _, restored = _scan(
        tmp_path,
        "no dot1x system-auth-control\ndot1x system-auth-control\n"
        + PORT + " authentication port-control auto\n",
    )
    assert not ADMISSION_IDS.intersection(restored)


def test_open_authentication_and_removal(tmp_path):
    _, findings = _scan(
        tmp_path,
        "dot1x system-auth-control\n" + PORT
        + " access-session port-control auto\n authentication open\n",
    )
    assert OPEN_ID in findings
    _, removed = _scan(
        tmp_path,
        "dot1x system-auth-control\n" + PORT
        + " access-session port-control auto\n authentication open\n"
        + " no authentication open\n",
    )
    assert not ADMISSION_IDS.intersection(removed)


@pytest.mark.parametrize("suffix,role", [
    (" shutdown\n authentication port-control force-authorized\n", "access-edge"),
    (" switchport mode trunk\n authentication port-control force-authorized\n", "access-edge"),
    (" no switchport\n authentication port-control force-authorized\n", "access-edge"),
    (" authentication port-control force-authorized\n", "uplink"),
    (" authentication port-control force-authorized\n", None),
])
def test_inactive_or_unassessed_port_is_not_flagged(tmp_path, suffix, role):
    _, findings = _scan(tmp_path, "dot1x system-auth-control\n" + PORT + suffix, role)
    assert not ADMISSION_IDS.intersection(findings)


def test_unknown_aaa_or_global_state_is_not_called_secure(tmp_path):
    parser, findings = _scan(tmp_path, PORT + " authentication port-control auto\n")
    record = parser.get_access_admission_interfaces()[0]
    assert record.global_dot1x is None
    assert record.aaa_state == "configured-external"
    assert not ADMISSION_IDS.intersection(findings)
    _, findings = _scan(
        tmp_path, "no aaa authentication dot1x default\n"
        + PORT + " authentication port-control auto\n",
    )
    assert not ADMISSION_IDS.intersection(findings)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_cli_and_redaction(tmp_path, output_type):
    config = tmp_path / "switch.conf"
    config.write_text(
        BASE + "username rescue secret 0 syntheticprivate\n"
        "dot1x system-auth-control\n" + PORT
        + " authentication port-control force-authorized\n",
        encoding="utf-8",
    )
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "policy_version": "edge-test-v1",
        "interface_roles": {"GigabitEthernet1/0/1": "access-edge"},
    }), encoding="utf-8")
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "IOS_XE", "-i", str(config),
         "-o", output_type, "-f", str(report), "-x", "--assessment-policy", str(policy)],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "Access-edge port bypasses 802.1X authentication" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == FORCE_ID for item in data["security-audit"].values())
