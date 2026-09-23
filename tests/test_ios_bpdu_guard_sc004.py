"""SC-004: effective IOS/XE access-edge BPDU guard."""

import json
import subprocess
import sys

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.common.assessment import AssessmentContext
from src.devices.cisco.ios import CiscoIOSParser


BASE = "version 17.9\nhostname edge-switch\n"
PORT = "interface GigabitEthernet1/0/1\n switchport mode access\n"
GUARD_ID = "cisco.ios.layer2.access_edge.bpdu_guard_ineffective"
FILTER_ID = "cisco.ios.layer2.access_edge.bpdu_filter_bypass"


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


def test_global_guard_with_local_disable_and_reset(tmp_path):
    commands = (
        "spanning-tree portfast edge default\n"
        "spanning-tree portfast edge bpduguard default\n" + PORT
        + " spanning-tree bpduguard disable\n"
    )
    parser, findings = _scan(tmp_path, commands)
    policy = parser.get_bpdu_guard_policies()[0]
    assert policy.portfast is True
    assert policy.guard_state == "local-disabled"
    assert GUARD_ID in findings
    assert "spanning-tree bpduguard disable" in findings[GUARD_ID].evidence
    _, reset = _scan(tmp_path, commands + " no spanning-tree bpduguard\n")
    assert GUARD_ID not in reset


@pytest.mark.parametrize("commands,state", [
    ("spanning-tree portfast bpduguard default\n" + PORT
     + " spanning-tree portfast\n", "inherited-enabled"),
    ("spanning-tree portfast edge bpduguard default\n" + PORT
     + " spanning-tree portfast edge\n", "inherited-enabled"),
    (PORT + " spanning-tree bpduguard enable\n", "local-enabled"),
])
def test_effective_guard_is_not_reported(tmp_path, commands, state):
    parser, findings = _scan(tmp_path, commands)
    assert parser.get_bpdu_guard_policies()[0].guard_state == state
    assert GUARD_ID not in findings


def test_global_disable_and_local_enable_override(tmp_path):
    commands = (
        "spanning-tree portfast default\n"
        "no spanning-tree portfast bpduguard default\n" + PORT
    )
    parser, findings = _scan(tmp_path, commands)
    assert parser.get_bpdu_guard_policies()[0].guard_state == "global-disabled"
    assert GUARD_ID in findings
    _, locally_enabled = _scan(
        tmp_path, commands + " spanning-tree bpduguard enable\n"
    )
    assert GUARD_ID not in locally_enabled


def test_global_guard_without_portfast_is_not_mistaken_for_protection(tmp_path):
    parser, findings = _scan(
        tmp_path,
        "spanning-tree portfast bpduguard default\n" + PORT
        + " spanning-tree portfast disable\n",
    )
    assert parser.get_bpdu_guard_policies()[0].guard_state == "portfast-disabled"
    assert GUARD_ID in findings
    _, unknown = _scan(
        tmp_path, "spanning-tree portfast bpduguard default\n" + PORT,
    )
    assert GUARD_ID not in unknown


def test_local_bpdu_filter_is_not_treated_as_guard(tmp_path):
    _, findings = _scan(
        tmp_path, PORT
        + " spanning-tree bpduguard enable\n"
        + " spanning-tree bpdufilter enable\n",
    )
    assert FILTER_ID in findings
    assert GUARD_ID not in findings
    _, restored = _scan(
        tmp_path, PORT
        + " spanning-tree bpduguard enable\n"
        + " spanning-tree bpdufilter enable\n"
        + " no spanning-tree bpdufilter\n",
    )
    assert FILTER_ID not in restored


@pytest.mark.parametrize("suffix,role", [
    (" shutdown\n spanning-tree bpduguard disable\n", "access-edge"),
    (" switchport mode trunk\n spanning-tree bpduguard disable\n", "access-edge"),
    (" channel-group 1 mode active\n spanning-tree bpduguard disable\n", "access-edge"),
    (" spanning-tree bpduguard disable\n", "uplink"),
    (" spanning-tree bpduguard disable\n", None),
])
def test_ineligible_ports_are_not_flagged(tmp_path, suffix, role):
    _, findings = _scan(tmp_path, PORT + suffix, role)
    assert GUARD_ID not in findings
    assert FILTER_ID not in findings


def test_lag_removal_and_malformed_setting(tmp_path):
    parser, findings = _scan(
        tmp_path,
        PORT + " channel-group 1 mode active\n no channel-group 1\n"
        + " spanning-tree bpduguard disable\n",
    )
    assert not parser.get_bpdu_guard_policies()[0].lag_member
    assert GUARD_ID in findings
    _, malformed = _scan(tmp_path, PORT + " spanning-tree bpduguard maybe\n")
    assert GUARD_ID not in malformed


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_cli_and_redaction(tmp_path, output_type):
    config = tmp_path / "switch.conf"
    config.write_text(
        BASE + "username rescue secret 0 syntheticprivate\n"
        + PORT + " spanning-tree bpduguard disable\n",
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
    assert "Access-edge port has ineffective BPDU guard" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == GUARD_ID for item in data["security-audit"].values())
