"""Bound explicit EOS local-password minimum assessment (SC-002 subset)."""

import json
import subprocess
import sys

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.devices.arista.eos import AristaEOSParser


BASE = """! device: leaf (DCS-7050, EOS-4.36.2F)
hostname leaf
username rescue secret sha512 $6$salt$syntheticprivate
aaa authentication login default local
management ssh
   no shutdown
   idle-timeout 5
"""


def _scan(tmp_path, config):
    path = tmp_path / "eos.conf"
    path.write_text(config, encoding="utf-8")
    parser = AristaEOSParser(str(path))
    return parser, list(process_arista_conf(parser).values())


def _ids(findings):
    return {item.rule_id for item in findings}


@pytest.mark.parametrize("policy,expected_state,expected", [
    ("management security password minimum length 1\n", "explicit", True),
    ("management security password minimum length 15\n", "explicit", False),
    ("management security password minimum length 1\n"
     "management security password minimum length 15\n", "explicit", False),
    ("management security password minimum length 1\n"
     "no management security password\n", "explicit-disabled", True),
    ("management security password minimum length nope\n", "invalid", False),
    ("", "unknown", False),
])
def test_eos_explicit_global_minimum(tmp_path, policy, expected_state, expected):
    parser, findings = _scan(tmp_path, BASE + policy)
    assert parser.get_password_minimum_policy().resolution_state == expected_state
    assert ("arista.eos.admin.local_password_minimum_ineffective" in _ids(findings)) is expected


def test_nested_form_and_named_profile_leave_effective_minimum_unknown(tmp_path):
    parser, findings = _scan(
        tmp_path,
        BASE + "management security\n   password\n"
        "      minimum length 1\n      policy external\n"
        "         minimum length 15\n",
    )
    assert parser.get_password_minimum_policy().minimum_length == 1
    assert parser.get_password_minimum_policy().resolution_state == "unknown-profile"
    assert "arista.eos.admin.local_password_minimum_ineffective" not in _ids(findings)


def test_remote_only_and_unknown_release_suppress_local_claim(tmp_path):
    policy = "management security password minimum length 1\n"
    _, remote_findings = _scan(
        tmp_path, BASE.replace("login default local", "login default group tacacs+") + policy,
    )
    assert "arista.eos.admin.local_password_minimum_ineffective" not in _ids(remote_findings)
    parser, older_findings = _scan(
        tmp_path, BASE.replace("4.36.2F", "4.32.1F") + policy,
    )
    assert parser.get_password_minimum_policy().resolution_state == "unsupported-release"
    assert "arista.eos.admin.local_password_minimum_ineffective" not in _ids(older_findings)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_eos_password_minimum_and_redaction(tmp_path, output_type):
    path = tmp_path / "eos.conf"
    path.write_text(
        BASE + "management security password minimum length 1\n",
        encoding="utf-8",
    )
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "ARISTA_EOS", "-i", str(path),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "EOS local administrative password minimum is ineffective" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(
            item["rule_id"] == "arista.eos.admin.local_password_minimum_ineffective"
            for item in data["security-audit"].values()
        )
