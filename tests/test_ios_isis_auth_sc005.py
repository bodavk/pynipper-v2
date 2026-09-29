"""SC-005: bounded IOS/XE IS-IS hello and database authentication."""

import json
import subprocess
import sys

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.devices.cisco.ios import CiscoIOSParser


BASE = "version 17.9\nhostname isis-router\n"
PROCESS = ("router isis CORE\n net 49.0001.1921.6800.1001.00\n"
           " is-type level-2-only\n")
PORT = "interface GigabitEthernet0/0\n ip router isis CORE\n"
PREFIX = "cisco.ios.routing.isis."


def _scan(tmp_path, config):
    source = tmp_path / "isis.conf"
    source.write_text(BASE + config, encoding="utf-8")
    parser = CiscoIOSParser(str(source))
    findings = [finding for finding in process_cisco_ios_conf(parser).values()
                if finding.rule_id.startswith(PREFIX)]
    return parser, findings


def test_valid_md5_hello_and_database_are_separate(tmp_path):
    parser, findings = _scan(
        tmp_path, PROCESS + " authentication mode md5 level-2\n"
        " authentication key-chain KC level-2\n"
        "key chain KC\n key 1\n  key-string 7 syntheticprivate\n"
        + PORT + " isis authentication mode md5 level-2\n"
        " isis authentication key-chain KC level-2\n",
    )
    assert findings == []
    records = parser.get_isis_authentication()
    assert {(record.level, record.scope, record.state) for record in records} == {
        ("level-2", "hello", "configured-md5"),
        ("level-2", "database", "configured-md5"),
    }
    assert "syntheticprivate" not in " ".join(
        item.text for record in records for item in record.evidence)


@pytest.mark.parametrize("scope,command", [
    ("hello", " isis authentication mode md5 level-2\n"
              " isis authentication key-chain KC level-2\n"
              " isis authentication send-only level-2\n"),
    ("database", " authentication mode md5 level-2\n"
                 " authentication key-chain KC level-2\n"
                 " authentication send-only level-2\n"),
])
def test_send_only_is_scoped_and_removable(tmp_path, scope, command):
    config = PROCESS + (command if scope == "database" else "") + PORT
    if scope == "hello":
        config += command
    parser, findings = _scan(tmp_path, config)
    affected = [record for record in parser.get_isis_authentication()
                if record.state == "send-only"]
    assert [record.scope for record in affected] == [scope]
    assert [item.rule_id for item in findings] == [PREFIX + "send_only"]
    removed = " no isis authentication send-only level-2\n" if scope == "hello" else " no authentication send-only level-2\n"
    if scope == "hello":
        config += removed
    else:
        config = config.replace(PORT, removed + PORT)
    _, restored = _scan(tmp_path, config)
    assert PREFIX + "send_only" not in {item.rule_id for item in restored}


def test_text_and_legacy_passwords_are_redacted(tmp_path):
    parser, findings = _scan(
        tmp_path, PROCESS + " domain-password secret-db\n" + PORT
        + " isis password secret-hello level-2\n",
    )
    assert len(findings) == 2
    assert all(item.rule_id == PREFIX + "cleartext_authentication" for item in findings)
    all_evidence = " ".join(item.text for record in parser.get_isis_authentication()
                            for item in record.evidence)
    assert "secret-db" not in all_evidence
    assert "secret-hello" not in all_evidence
    assert "<redacted>" in all_evidence


def test_legacy_type7_password_is_fully_redacted(tmp_path):
    parser, _ = _scan(tmp_path, PROCESS + PORT + " isis password 7 syntheticprivate level-2\n")
    assert "syntheticprivate" not in " ".join(
        item.text for record in parser.get_isis_authentication() for item in record.evidence)


def test_ordered_removal_of_interface_authentication(tmp_path):
    parser, findings = _scan(
        tmp_path, PROCESS + PORT + " isis authentication mode md5 level-2\n"
        " isis authentication key-chain MISSING level-2\n"
        " no isis authentication mode level-2\n"
        " no isis authentication key-chain level-2\n",
    )
    assert next(record for record in parser.get_isis_authentication()
                if record.scope == "hello").state == "unknown"
    assert findings == []


def test_unresolved_key_chain_does_not_count_as_md5(tmp_path):
    parser, findings = _scan(
        tmp_path, PROCESS + " authentication mode md5 level-2\n"
        " authentication key-chain MISSING level-2\n" + PORT,
    )
    assert {(record.scope, record.state) for record in parser.get_isis_authentication()} == {
        ("hello", "unknown"), ("database", "unresolved")}
    assert [item.rule_id for item in findings] == [PREFIX + "key_resolution"]


def test_level_and_active_binding_filtering(tmp_path):
    parser, findings = _scan(
        tmp_path, "router isis CORE\n net 49.0001.1921.6800.1001.00\n"
        " is-type level-1-2\n authentication mode text level-1\n"
        + PORT + " isis circuit-type level-2-only\n",
    )
    assert {record.level for record in parser.get_isis_authentication()} == {"level-2"}
    assert findings == []


@pytest.mark.parametrize("config", [
    PROCESS + " authentication mode text level-2\n" + PORT + " shutdown\n",
    PROCESS + " authentication mode text level-2\n" + PORT + " no ip router isis CORE\n",
    PROCESS + " authentication mode text level-2\n passive-interface GigabitEthernet0/0\n" + PORT,
    PROCESS + " authentication mode text level-2\n" + "no router isis CORE\n" + PORT,
    "router isis CORE\n is-type level-2-only\n authentication mode text level-2\n" + PORT,
    "router isis CORE\n net 49.0001.1921.6800.1001.00\n"
    " authentication mode text level-2\n" + PORT,  # no explicit process level
])
def test_unbound_or_inactive_process_is_ungraded(tmp_path, config):
    parser, findings = _scan(tmp_path, config)
    assert parser.get_isis_authentication() == []
    assert findings == []


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_and_secret_redaction(tmp_path, output_type):
    source = tmp_path / "isis-public.conf"
    source.write_text(
        BASE + PROCESS + " domain-password secret-db\n" + PORT
        + " isis password secret-hello level-2\n",
        encoding="utf-8",
    )
    report = tmp_path / f"isis.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "IOS_XE", "-i", str(source),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "IS-IS selects cleartext authentication" in rendered
    assert "secret-db" not in rendered + completed.stdout + completed.stderr
    assert "secret-hello" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        payload = json.loads(rendered)
        assert any(item["rule_id"] == PREFIX + "cleartext_authentication"
                   for item in payload["security-audit"].values())
