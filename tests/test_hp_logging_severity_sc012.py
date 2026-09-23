"""SC-012: bounded AOS-S Event Log forwarding and severity checks."""

import json
import subprocess
import sys

import pytest

from src.analyze.hp.core.process_hp_conf import process_hp_conf
from src.devices.hp.procurve import HPProCurveParser


SEVERITY_ID = "hp.procurve.logging.remote_severity_excludes_errors"
EVENT_ID = "hp.procurve.logging.remote_event_disabled"
DESTINATION_ID = "hp.procurve.logging.remote_destination"
BASE = "; J9772A Configuration Editor; Created on release #YA.16.10.0023\nhostname edge\n"


def _scan(tmp_path, commands, base=BASE):
    path = tmp_path / "switch.conf"
    path.write_text(base + commands, encoding="utf-8")
    parser = HPProCurveParser(str(path))
    return parser, {item.rule_id: item for item in process_hp_conf(parser).values()}


@pytest.mark.parametrize("severity,expected", [
    ("logging severity major", True),
    ("logging severity error", False),
    ("logging severity warning", False),
    ("logging severity info", False),
    ("logging severity debug", False),
    ("logging severity unknown", False),
    ("logging severity major\nno logging severity major", False),
    ("logging severity major\nlogging severity error", False),
])
def test_remote_error_threshold(tmp_path, severity, expected):
    parser, findings = _scan(tmp_path, "logging 192.0.2.10\n" + severity + "\n")
    assert (SEVERITY_ID in findings) is expected
    assert len(parser.get_logging_destinations()) == 1


def test_disabled_remote_destination_and_ordered_reenable(tmp_path):
    parser, findings = _scan(
        tmp_path,
        "logging 192.0.2.10\nlogging severity major\n"
        "no debug destination logging\nlogging 192.0.2.20\n",
    )
    assert not parser.get_logging_destinations()
    assert DESTINATION_ID in findings
    assert SEVERITY_ID not in findings
    assert "no debug destination logging" in findings[DESTINATION_ID].evidence
    _, restored = _scan(
        tmp_path,
        "logging 192.0.2.10\nno debug destination logging\n"
        "debug destination logging\nlogging severity major\n",
    )
    assert SEVERITY_ID in restored
    assert DESTINATION_ID not in restored


def test_event_forwarding_disabled_and_restored(tmp_path):
    _, disabled = _scan(
        tmp_path, "logging 192.0.2.10\nlogging severity major\nno debug event\n"
    )
    assert EVENT_ID in disabled
    assert SEVERITY_ID not in disabled
    assert DESTINATION_ID not in disabled
    assert "no debug event" in disabled[EVENT_ID].evidence
    _, restored = _scan(
        tmp_path,
        "logging 192.0.2.10\nno debug event\ndebug event\nlogging severity major\n",
    )
    assert EVENT_ID not in restored
    assert SEVERITY_ID in restored


def test_removed_unbound_and_unknown_release(tmp_path):
    parser, findings = _scan(
        tmp_path, "logging 192.0.2.10\nno logging 192.0.2.10\nlogging severity major\n"
    )
    assert not parser.get_logging_destinations()
    assert SEVERITY_ID not in findings
    parser, findings = _scan(tmp_path, "logging filter security\nlogging severity major\n")
    assert not parser.get_logging_destinations()
    assert SEVERITY_ID not in findings
    unknown_base = "; J9772A Configuration Editor; Created on release #YA.16.09.0023\n"
    _, findings = _scan(tmp_path, "logging 192.0.2.10\nlogging severity major\n", unknown_base)
    assert SEVERITY_ID not in findings


def test_host_reset_and_hostname_destination(tmp_path):
    parser, findings = _scan(
        tmp_path,
        "logging 192.0.2.10\nno logging\nlogging domain-name logs.example.test\n"
        "logging severity major\n",
    )
    assert [item.address for item in parser.get_logging_destinations()] == ["logs.example.test"]
    assert SEVERITY_ID in findings


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_and_redaction(tmp_path, output_type):
    path = tmp_path / "switch.conf"
    path.write_text(
        BASE + "password manager user-name admin plaintext syntheticprivate\n"
        "logging 192.0.2.10\nlogging severity major\n",
        encoding="utf-8",
    )
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "HP_PROCURVE", "-i", str(path),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "AOS-S remote logging excludes error events" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == SEVERITY_ID for item in data["security-audit"].values())
