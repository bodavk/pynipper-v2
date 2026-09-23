"""SC-009: explicit FortiOS IPS severity/action on active accept policies."""

import json
import subprocess
import sys

import pytest

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


RULE_ID = "fortinet.fortios.policy.ips_selector_nonblocking"


def _entry(number, severity, action, status="enable", extra=""):
    return (
        f"edit {number}\nset severity {severity}\nset status {status}\n"
        f"set action {action}\n{extra}next\n"
    )


def _config(entries, *, attached=True, enabled=True):
    sensor = "config ips sensor\nedit MIXED\nconfig entries\n" + entries + "end\nnext\nend\n"
    policy = (
        "config firewall policy\nedit 1\nset srcintf lan\nset dstintf internal\n"
        "set action accept\nset utm-status enable\n"
        + ("set ips-sensor MIXED\n" if attached else "")
        + ("set status disable\n" if not enabled else "")
        + "next\nend\n"
    )
    return sensor + policy


def _scan(tmp_path, config):
    path = tmp_path / "fortios.conf"
    path.write_text(config, encoding="utf-8")
    parser = FortiOSParser(str(path))
    return parser, [item for item in process_fortios_conf(parser).values() if item.rule_id == RULE_ID]


@pytest.mark.parametrize("entries,expected", [
    (_entry(1, "high", "pass") + _entry(2, "low", "block"), True),
    (_entry(1, "critical high", "pass") + _entry(2, "low", "block"), True),
    (_entry(1, "high", "block") + _entry(2, "high", "pass"), False),
    (_entry(1, "high", "pass") + _entry(2, "high", "block"), True),
    (_entry(1, "low", "pass") + _entry(2, "high", "block"), False),
    (_entry(1, "high", "default", status="default") + _entry(2, "high", "pass"), False),
    (_entry(1, "high", "pass", status="disable") + _entry(2, "high", "block"), False),
    (_entry(1, "high", "pass", extra="set cve CVE-2026-0001\n")
     + _entry(2, "high", "block"), False),
])
def test_ordered_explicit_ips_actions(tmp_path, entries, expected):
    parser, findings = _scan(tmp_path, _config(entries))
    assert bool(findings) is expected
    assert parser.get_security_inspection()[0].profiles[0].ips_selectors
    if expected:
        assert len(findings) == 1
        assert "set action pass" in " ".join(findings[0].evidence)


def test_unbound_or_disabled_policy_does_not_report(tmp_path):
    mixed = _entry(1, "critical", "pass") + _entry(2, "low", "block")
    assert not _scan(tmp_path, _config(mixed, attached=False))[1]
    assert not _scan(tmp_path, _config(mixed, enabled=False))[1]


def test_profile_group_binding_preserves_selector_action(tmp_path):
    mixed = _entry(1, "high", "pass") + _entry(2, "low", "block")
    config = _config(mixed).replace(
        "set ips-sensor MIXED\n",
        "set profile-type group\nset profile-group INSPECT\n",
    )
    config = (
        "config firewall profile-group\nedit INSPECT\nset ips-sensor MIXED\nnext\nend\n"
        + config
    )
    parser, findings = _scan(tmp_path, config)
    assert len(findings) == 1
    assert parser.get_security_inspection()[0].attachment_mode == "group"


def test_wholly_nonblocking_sensor_avoids_duplicate_selector_finding(tmp_path):
    parser, findings = _scan(tmp_path, _config(_entry(1, "high", "pass")))
    assert parser.get_security_inspection()[0].profiles[0].content_state == "nonblocking"
    assert not findings


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_output_redacts_unrelated_secret(tmp_path, output_type):
    path = tmp_path / "fortios.conf"
    path.write_text(
        "config system admin\nedit rescue\nset password syntheticprivate\nnext\nend\n"
        + _config(_entry(1, "high", "pass") + _entry(2, "low", "block")),
        encoding="utf-8",
    )
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "FORTIOS", "-i", str(path),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "Attached FortiOS IPS sensor passes" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == RULE_ID for item in data["security-audit"].values())
