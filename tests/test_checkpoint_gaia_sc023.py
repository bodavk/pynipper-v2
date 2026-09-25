"""SC-023: Check Point Gaia OS (Clish `show configuration`) parser, checks and secrets."""

import pytest

from src.analyze.checkpoint.core.process_checkpoint_gaia_conf import process_checkpoint_gaia_conf
from src.analyze.common.issue import FindingBasis
from src.devices import get_parser
from src.devices.checkpoint.gaia import CheckPointGaiaParser
from src.devices.detection import detect_device_type
from src.report.secret_evidence import collect_secret_evidence

HEADER = "#\n# Configuration of gw1\n# Language version: 15.0v1\n#\nset hostname gw1\n"
SAFE_LOCKOUT = "set password-controls deny-on-fail enable on\n"


def _parser(tmp_path, body):
    path = tmp_path / "gaia.conf"
    path.write_text(HEADER + body, encoding="utf-8")
    return CheckPointGaiaParser(str(path))


def _rules(tmp_path, body):
    return {f.rule_id: f for f in process_checkpoint_gaia_conf(_parser(tmp_path, body)).values()}


def test_detection_and_factory(tmp_path):
    path = tmp_path / "gaia.conf"
    path.write_text(HEADER, encoding="utf-8")
    assert detect_device_type(str(path)) == "CHECKPOINT_GAIA"
    assert isinstance(get_parser("checkpoint-gaia", str(path)), CheckPointGaiaParser)
    assert get_parser("CHECKPOINT_GAIA", str(path)).get_hostname() == "gw1"


def test_language_version_is_not_reported_as_software_version(tmp_path):
    parser = _parser(tmp_path, "")
    assert parser.language_version == "15.0v1"
    assert parser.get_version() == "?"


def test_telnet_last_command_wins(tmp_path):
    assert "checkpoint.gaia.management.telnet" in _rules(tmp_path, SAFE_LOCKOUT + "set net-access telnet on\n")
    assert "checkpoint.gaia.management.telnet" not in _rules(
        tmp_path, SAFE_LOCKOUT + "set net-access telnet on\nset net-access telnet off\n")


def test_absent_telnet_is_not_a_finding(tmp_path):
    assert _rules(tmp_path, SAFE_LOCKOUT) == {}


def test_lockout_default_is_documented(tmp_path):
    finding = _rules(tmp_path, "")["checkpoint.gaia.password_policy.lockout_disabled"]
    assert finding.basis is FindingBasis.DOCUMENTED_DEFAULT
    explicit = _rules(tmp_path, "set password-controls deny-on-fail enable off\n")
    assert explicit["checkpoint.gaia.password_policy.lockout_disabled"].basis is FindingBasis.EXPLICIT_VALUE


def test_snmp_checks_need_the_agent(tmp_path):
    body = SAFE_LOCKOUT + "set snmp agent-version any\nadd snmp community public read-write\n"
    assert not any(rule.startswith("checkpoint.gaia.snmp") for rule in _rules(tmp_path, body))
    rules = _rules(tmp_path, body + "set snmp agent on\n")
    assert {"checkpoint.gaia.snmp.default_community", "checkpoint.gaia.snmp.write_community",
            "checkpoint.gaia.snmp.legacy_version"} <= set(rules)


def test_deleted_community_is_not_effective(tmp_path):
    body = (SAFE_LOCKOUT + "set snmp agent on\nset snmp agent-version any\n"
            "add snmp community public read-only\ndelete snmp community public\n")
    assert not any(rule.startswith("checkpoint.gaia.snmp") for rule in _rules(tmp_path, body))


@pytest.mark.parametrize("level,expected", [("authNoPriv", True), ("authPriv", False)])
def test_snmpv3_security_level(tmp_path, level, expected):
    body = (SAFE_LOCKOUT + "set snmp agent on\n"
            f"add snmp usm user mon security-level {level} auth-pass-phrase Example1\n")
    assert ("checkpoint.gaia.snmp.v3_security" in _rules(tmp_path, body)) is expected


@pytest.mark.parametrize("line,rule", [
    ("set password-controls history-checking off", "checkpoint.gaia.password_policy.history_disabled"),
    ("set password-controls complexity 1", "checkpoint.gaia.password_policy.complexity"),
    ("set password-controls min-password-length 6", "checkpoint.gaia.password_policy.minimum_length"),
    ("set inactivity-timeout 30", "checkpoint.gaia.cli.idle_timeout_excessive"),
    ("set message banner off", "checkpoint.gaia.banner.login_disabled"),
])
def test_explicit_weak_values(tmp_path, line, rule):
    assert rule in _rules(tmp_path, SAFE_LOCKOUT + line + "\n")


@pytest.mark.parametrize("line", [
    "set password-controls complexity 2",
    "set password-controls min-password-length 8",
    "set inactivity-timeout 10",
    'set message banner on msgvalue "Authorized use only"',
])
def test_acceptable_values_are_silent(tmp_path, line):
    assert _rules(tmp_path, SAFE_LOCKOUT + line + "\n") == {}


def test_evidence_redacts_secrets(tmp_path):
    body = (SAFE_LOCKOUT + "set snmp agent on\nadd snmp community public read-only\n"
            "add snmp usm user mon security-level authNoPriv auth-pass-phrase TopSecret1\n")
    evidence = " ".join(" ".join(f.evidence) for f in _rules(tmp_path, body).values())
    assert "TopSecret1" not in evidence
    assert "community <redacted>" in evidence


def test_show_secrets_returns_only_credential_lines(tmp_path):
    body = (SAFE_LOCKOUT + "set snmp agent on\nadd snmp community lab read-only\n"
            "add user admin2 uid 0 homedir /home/admin2\nset user admin2 password-hash $6$abc$def\n"
            "add user gone uid 0 homedir /home/gone\nset user gone password-hash $6$old$old\ndelete user gone\n")
    result = collect_secret_evidence(_parser(tmp_path, body))
    lines = [entry["source-line"] for entry in result["entries"]]
    assert lines == ["add snmp community lab read-only", "set user admin2 password-hash $6$abc$def"]
    assert result["status"] == "unmasked-credential-lines"
