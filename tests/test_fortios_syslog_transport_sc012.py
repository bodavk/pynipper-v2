"""SC-012: explicit FortiOS remote-syslog TLS state, not TCP reliability."""

import json
import subprocess
import sys

import pytest

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


RULE_ID = "fortinet.fortios.logging.remote_cleartext"


def _sink(number="", *, status="enable", mode="reliable", encryption="disable",
          server="192.0.2.10", tls_minimum=None):
    lines = [f"config log syslogd{number} setting", f"set status {status}", f"set server {server}"]
    if mode is not None:
        lines.append(f"set mode {mode}")
    if encryption is not None:
        lines.append(f"set enc-algorithm {encryption}")
    if tls_minimum is not None:
        lines.append(f"set ssl-min-proto-version {tls_minimum}")
    lines.append("end")
    return "\n".join(lines) + "\n"


def _scan(tmp_path, config):
    path = tmp_path / "fortios.conf"
    path.write_text(config, encoding="utf-8")
    parser = FortiOSParser(str(path))
    return parser, [item for item in process_fortios_conf(parser).values() if item.rule_id == RULE_ID]


@pytest.mark.parametrize("mode,encryption,status,expected", [
    ("reliable", "disable", "enable", True),
    ("legacy-reliable", "disable", "enable", True),
    ("udp", "disable", "enable", True),
    ("reliable", "high", "enable", False),
    ("reliable", "high-medium", "enable", False),
    ("reliable", None, "enable", False),
    ("reliable", "disable", "disable", False),
])
def test_explicit_syslog_encryption_independent_of_delivery(
    tmp_path, mode, encryption, status, expected
):
    parser, findings = _scan(tmp_path, _sink(mode=mode, encryption=encryption, status=status))
    assert bool(findings) is expected
    sinks = parser.get_syslog_sinks()
    if status == "enable":
        assert len(sinks) == 1
        assert sinks[0].transport_state == (
            "explicit-cleartext" if encryption == "disable"
            else "explicit-tls" if encryption in {"high", "high-medium"}
            else "unknown"
        )
    else:
        assert not sinks


def test_multiple_destinations_are_independent(tmp_path):
    parser, findings = _scan(
        tmp_path,
        _sink("", encryption="high") + _sink("2", encryption="disable", server="192.0.2.11"),
    )
    assert len(parser.get_syslog_sinks()) == 2
    assert len(findings) == 1
    assert "192.0.2.11" in findings[0].observation


@pytest.mark.parametrize("encryption,tls_minimum,expected", [
    ("low", "TLSv1-2", True),
    ("high", "SSLv3", True),
    ("high", "TLSv1", True),
    ("high-medium", "TLSv1-1", True),
    ("high", "TLSv1-2", False),
    ("high", "TLSv1-3", False),
])
def test_explicit_weak_tls_settings(tmp_path, encryption, tls_minimum, expected):
    parser, _ = _scan(
        tmp_path, _sink(encryption=encryption, tls_minimum=tls_minimum)
    )
    weak = [
        item for item in process_fortios_conf(parser).values()
        if item.rule_id == "fortinet.fortios.logging.remote_weak_tls"
    ]
    assert bool(weak) is expected
    if expected:
        assert parser.get_syslog_sinks()[0].transport_state == "explicit-weak-tls"
        assert "ssl-min-proto-version" in " ".join(weak[0].evidence)


def test_vdom_override_must_be_enabled(tmp_path):
    override = (
        "config log syslogd override-setting\nset status enable\n"
        "set server 192.0.2.20\nset mode reliable\n"
        "set enc-algorithm disable\nend\n"
    )
    prefix = "config vdom\nedit blue\n"
    suffix = "next\nend\n"
    _, inactive = _scan(tmp_path, prefix + override + suffix)
    assert not inactive
    active_config = (
        prefix + "config log setting\nset syslog-override enable\nend\n"
        + override + suffix
    )
    parser, active = _scan(tmp_path, active_config)
    assert len(active) == 1
    assert parser.get_syslog_sinks()[0].scope == "blue"


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_and_secret_redaction(tmp_path, output_type):
    path = tmp_path / "fortios.conf"
    path.write_text(
        "config system admin\nedit rescue\nset password syntheticprivate\nnext\nend\n"
        + _sink(),
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
    assert "Enabled FortiOS remote syslog explicitly disables TLS" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == RULE_ID for item in data["security-audit"].values())
