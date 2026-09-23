"""Bound ASA local-admin and active management idle policy (SC-002 subset)."""

import json
import subprocess
import sys

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.devices.cisco.asa import CiscoASAParser


BASE = """ASA Version 9.18(4)
hostname asa-admin
username rescue password SyntheticPrivateValue privilege 15
ssh 192.0.2.0 255.255.255.0 management
aaa authentication ssh console LOCAL
http server enable
http 192.0.2.0 255.255.255.0 management
aaa authentication http console LOCAL
"""


def _scan(tmp_path, config):
    path = tmp_path / "asa.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoASAParser(str(path))
    findings = list(process_asa_conf(parser).values())
    return parser, findings


def _ids(findings):
    return {item.rule_id for item in findings}


def test_explicit_unsafe_local_password_and_lockout(tmp_path):
    parser, findings = _scan(
        tmp_path, BASE + "no aaa local authentication attempts max-fail\n"
        "password-policy minimum-length 4\n",
    )
    assert parser.get_local_lockout_limit().value is None
    assert parser.get_local_password_minimum().value == 4
    assert {
        "cisco.asa.admin.local_lockout_disabled",
        "cisco.asa.admin.local_password_minimum",
    } <= _ids(findings)
    assert "SyntheticPrivateValue" not in str(findings)


def test_secure_override_and_inactive_management(tmp_path):
    _, findings = _scan(
        tmp_path, BASE + "no aaa local authentication attempts max-fail\n"
        "aaa local authentication attempts max-fail 3\n"
        "password-policy minimum-length 4\npassword-policy minimum-length 12\n",
    )
    assert "cisco.asa.admin.local_lockout_disabled" not in _ids(findings)
    assert "cisco.asa.admin.local_password_minimum" not in _ids(findings)

    _, findings = _scan(
        tmp_path, BASE + "no ssh 192.0.2.0 255.255.255.0 management\n"
        "no http server enable\nno aaa local authentication attempts max-fail\n"
        "password-policy minimum-length 3\n",
    )
    assert "cisco.asa.admin.local_lockout_disabled" not in _ids(findings)
    assert "cisco.asa.admin.local_password_minimum" not in _ids(findings)


def test_remote_only_and_pre_917_emergency_account_are_not_graded(tmp_path):
    remote = BASE.replace("console LOCAL", "console TAC") + "aaa-server TAC protocol tacacs+\n"
    _, findings = _scan(
        tmp_path, remote + "no aaa local authentication attempts max-fail\n"
        "password-policy minimum-length 3\n",
    )
    assert "cisco.asa.admin.local_lockout_disabled" not in _ids(findings)
    assert "cisco.asa.admin.local_password_minimum" not in _ids(findings)

    older = BASE.replace("9.18(4)", "9.16(2)")
    _, findings = _scan(tmp_path, older + "no aaa local authentication attempts max-fail\n")
    assert "cisco.asa.admin.local_lockout_disabled" not in _ids(findings)


def test_active_ssh_and_asdm_idle_with_precedence_and_reset(tmp_path):
    config = BASE + "ssh timeout 30\nhttp server idle-timeout 45\n"
    _, findings = _scan(tmp_path, config)
    assert "cisco.asa.ssh.idle_timeout_excessive" in _ids(findings)
    assert "cisco.asa.asdm.idle_timeout_excessive" in _ids(findings)

    parser, findings = _scan(
        tmp_path, config + "http connection idle-timeout 300\n"
        "ssh timeout 5\n",
    )
    assert parser.get_asdm_idle_policy().minutes == 5
    assert "cisco.asa.ssh.idle_timeout_excessive" not in _ids(findings)
    assert "cisco.asa.asdm.idle_timeout_excessive" not in _ids(findings)

    parser, findings = _scan(tmp_path, config + "no http server idle-timeout\n")
    assert parser.get_asdm_idle_policy().resolution_state == "unknown"
    assert "cisco.asa.asdm.idle_timeout_excessive" not in _ids(findings)


def test_malformed_timeout_and_minimum_stay_unknown(tmp_path):
    parser, findings = _scan(
        tmp_path, BASE + "ssh timeout nope\nhttp server idle-timeout nope\n"
        "password-policy minimum-length nope\n",
    )
    assert parser.get_asdm_idle_policy().resolution_state == "invalid"
    assert "cisco.asa.asdm.idle_timeout_excessive" not in _ids(findings)
    assert "cisco.asa.ssh.idle_timeout_excessive" not in _ids(findings)
    assert "cisco.asa.admin.local_password_minimum" not in _ids(findings)


def test_asdm_idle_unsupported_in_multiple_context_and_old_release(tmp_path):
    parser, findings = _scan(
        tmp_path, BASE + "mode multiple\nhttp server idle-timeout 60\n",
    )
    assert parser.get_asdm_idle_policy().resolution_state == "unsupported-release"
    assert "cisco.asa.asdm.idle_timeout_excessive" not in _ids(findings)
    parser, findings = _scan(
        tmp_path, BASE.replace("9.18(4)", "9.12(1)")
        + "http connection idle-timeout 3600\n",
    )
    assert parser.get_asdm_idle_policy().resolution_state == "unsupported-release"
    assert "cisco.asa.asdm.idle_timeout_excessive" not in _ids(findings)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_explicit_asa_admin_policy(tmp_path, output_type):
    path = tmp_path / "asa.conf"
    path.write_text(
        BASE + "no aaa local authentication attempts max-fail\n"
        "password-policy minimum-length 3\nssh timeout 30\n",
        encoding="utf-8",
    )
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "ASA", "-i", str(path),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "ASA local administrative login lockout is explicitly disabled" in rendered
    assert "SyntheticPrivateValue" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert "cisco.asa.admin.local_password_minimum" in {
            item["rule_id"] for item in data["security-audit"].values()
        }
