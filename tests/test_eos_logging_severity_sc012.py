"""SC-012: explicit EOS trap/buffer thresholds that exclude syslog errors."""

import json
import subprocess
import sys

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.devices.arista.eos import AristaEOSParser


REMOTE_ID = "arista.eos.logging.remote_severity_excludes_errors"
BUFFER_ID = "arista.eos.logging.buffer_severity_excludes_errors"
BASE = "! device: leaf (DCS-7050, EOS-4.36.2F)\nhostname leaf\n"


def _scan(tmp_path, commands):
    path = tmp_path / "eos.conf"
    path.write_text(BASE + commands, encoding="utf-8")
    parser = AristaEOSParser(str(path))
    return parser, {item.rule_id: item for item in process_arista_conf(parser).values()}


@pytest.mark.parametrize("trap,expected", [
    ("logging trap emergencies", True),
    ("logging trap alerts", True),
    ("logging trap critical", True),
    ("logging trap 2", True),
    ("logging trap system severity 1", True),
    ("logging trap errors", False),
    ("logging trap warnings", False),
    ("logging trap informational", False),
    ("logging trap no-such-level", False),
])
def test_remote_error_severity_gate(tmp_path, trap, expected):
    parser, findings = _scan(tmp_path, "logging host 192.0.2.10\n" + trap + "\n")
    assert (REMOTE_ID in findings) is expected
    assert parser.get_logging_severity_policy().trap_state == (
        "invalid" if "no-such" in trap else "explicit"
    )


def test_vrf_destination_and_ordered_resets(tmp_path):
    parser, findings = _scan(
        tmp_path,
        "logging vrf mgmt host 192.0.2.10 protocol tls\n"
        "logging trap alerts\n",
    )
    assert REMOTE_ID in findings
    assert parser.get_logging_destinations()[0].scope == "mgmt"
    _, removed = _scan(
        tmp_path,
        "logging vrf mgmt host 192.0.2.10\n"
        "no logging vrf mgmt host 192.0.2.10\nlogging trap alerts\n",
    )
    assert REMOTE_ID not in removed
    _, reset = _scan(
        tmp_path,
        "logging host 192.0.2.10\nlogging trap alerts\nno logging trap\n",
    )
    assert REMOTE_ID not in reset
    _, ordered = _scan(
        tmp_path,
        "logging host 192.0.2.10\nlogging trap alerts\nlogging trap errors\n",
    )
    assert REMOTE_ID not in ordered


@pytest.mark.parametrize("buffer,expected", [
    ("logging buffered alerts 1000", True),
    ("logging buffered 2 1000", True),
    ("logging buffered errors 1000", False),
    ("logging buffered warnings 1000", False),
    ("logging buffered 5000", False),
    ("logging buffered alerts 1000\nno logging buffered", False),
])
def test_local_buffer_is_independent(tmp_path, buffer, expected):
    _, findings = _scan(tmp_path, buffer + "\n")
    assert (BUFFER_ID in findings) is expected
    assert REMOTE_ID not in findings


def test_disabled_logging_and_conflicting_trap_scopes_are_ungraded(tmp_path):
    disabled_parser, disabled = _scan(
        tmp_path, "logging host 192.0.2.10\nlogging trap alerts\n"
        "logging buffered alerts 1000\nno logging on\n"
    )
    assert REMOTE_ID not in disabled
    assert BUFFER_ID not in disabled
    assert not disabled_parser.get_logging_destinations()
    assert "arista.eos.logging.remote_destination" in disabled
    parser, conflict = _scan(
        tmp_path,
        "logging host 192.0.2.10\nlogging trap alerts\n"
        "logging trap system severity informational\n",
    )
    assert parser.get_logging_severity_policy().trap_state == "unknown-conflict"
    assert REMOTE_ID not in conflict


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_and_redaction(tmp_path, output_type):
    path = tmp_path / "eos.conf"
    path.write_text(
        BASE + "username rescue secret sha512 $6$salt$syntheticprivate\n"
        "logging host 192.0.2.10\nlogging trap alerts\n",
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
    assert "EOS remote logging excludes error-severity events" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == REMOTE_ID for item in data["security-audit"].values())
