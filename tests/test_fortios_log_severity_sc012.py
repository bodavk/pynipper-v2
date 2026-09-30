"""SC-012: explicit error-severity exclusion on active FortiOS remote sinks."""

import json
import subprocess
import sys

import pytest

from src.analyze.common.issue import FindingBasis
from src.analyze.common.guidance import guidance_for
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


RULE_ID = "fortinet.fortios.logging.error_severity_filtered"


def test_rule_has_logging_guidance():
    guidance = guidance_for(RULE_ID)
    assert guidance is not None
    assert guidance.area == "logging-audit"


def _scan(tmp_path, config):
    path = tmp_path / "fortios.conf"
    path.write_text(config, encoding="utf-8")
    parser = FortiOSParser(str(path))
    findings = [item for item in process_fortios_conf(parser).values() if item.rule_id == RULE_ID]
    return parser, findings


def _sink(number="", *, status="enable", server="192.0.2.10", override=False):
    section = f"log syslogd{number} {'override-setting' if override else 'setting'}"
    return f"config {section}\nset status {status}\nset server {server}\nend\n"


def _filter(threshold, number="", *, override=False):
    section = f"log syslogd{number} {'override-filter' if override else 'filter'}"
    return f"config {section}\nset severity {threshold}\nend\n"


@pytest.mark.parametrize("threshold,expected", [
    ("emergency", True), ("alert", True), ("critical", True),
    ("error", False), ("warning", False), ("notification", False),
    ("information", False), ("debug", False),
])
def test_only_explicit_stricter_than_error_is_reported(tmp_path, threshold, expected):
    parser, findings = _scan(tmp_path, _sink() + _filter(threshold))
    assert bool(findings) is expected
    assert bool(parser.get_syslog_severity_gaps()) is expected
    if expected:
        assert findings[0].basis == FindingBasis.EXPLICIT_VALUE
        assert "error-level" in findings[0].observation
        assert "set severity" in " ".join(findings[0].evidence)


@pytest.mark.parametrize("config", [
    _sink(status="disable") + _filter("critical"),
    "config log syslogd setting\nset status enable\nend\n" + _filter("critical"),
    _sink(),
    _filter("critical"),
    _sink("2") + _filter("critical"),
])
def test_inactive_missing_and_nonmatching_sinks_do_not_infer_gap(tmp_path, config):
    _, findings = _scan(tmp_path, config)
    assert not findings


def test_each_remote_destination_is_assessed_independently(tmp_path):
    _, findings = _scan(
        tmp_path,
        _sink() + _filter("error")
        + _sink("2", server="192.0.2.11") + _filter("critical", "2"),
    )
    assert len(findings) == 1
    assert "192.0.2.11" in findings[0].observation


@pytest.mark.parametrize("filter_body", [
    "set severity critical\nunset severity",
    "set severity unsupported",
])
def test_removed_or_unknown_threshold_is_not_reported(tmp_path, filter_body):
    config = _sink() + f"config log syslogd filter\n{filter_body}\nend\n"
    _, findings = _scan(tmp_path, config)
    assert not findings


def test_vdom_override_filter_requires_active_matching_override(tmp_path):
    prefix = "config vdom\nedit blue\n"
    suffix = "next\nend\n"
    override = _sink(override=True) + _filter("critical", override=True)
    _, inactive = _scan(tmp_path, prefix + override + suffix)
    assert not inactive
    config = prefix + "config log setting\nset syslog-override enable\nend\n" + override + suffix
    parser, active = _scan(tmp_path, config)
    assert len(active) == 1
    assert parser.get_syslog_severity_gaps()[0].scope == "blue"


def test_global_filter_is_not_misapplied_to_vdom_override(tmp_path):
    config = (
        _filter("critical")
        + "config vdom\nedit blue\nconfig log setting\nset syslog-override enable\nend\n"
        + _sink(override=True) + "next\nend\n"
    )
    _, findings = _scan(tmp_path, config)
    assert not findings


def _faz(number="", *, status="enable", server="192.0.2.60", override=False):
    section = f"log fortianalyzer{number} {'override-setting' if override else 'setting'}"
    return f"config {section}\nset status {status}\nset server {server}\nend\n"


def _faz_filter(threshold, number="", *, override=False):
    section = f"log fortianalyzer{number} {'override-filter' if override else 'filter'}"
    return f"config {section}\nset severity {threshold}\nend\n"


def test_fortianalyzer_primary_and_secondary_are_independent(tmp_path):
    parser, findings = _scan(
        tmp_path,
        _faz() + _faz_filter("error")
        + _faz("2", server="192.0.2.61") + _faz_filter("critical", "2"),
    )
    assert len(parser.get_fortianalyzer_severity_gaps()) == 1
    assert len(findings) == 1
    assert "192.0.2.61" in findings[0].observation


def test_fortianalyzer_disabled_or_unbound_does_not_report(tmp_path):
    _, findings = _scan(
        tmp_path,
        _faz(status="disable") + _faz_filter("critical")
        + _faz("2") + _faz_filter("error", "2")
        + _faz("3", status="disable") + _faz_filter("critical", "3"),
    )
    assert not findings


def test_fortianalyzer_vdom_override_replaces_base_filter(tmp_path):
    config = (
        _faz() + _faz_filter("critical")
        + "config vdom\nedit blue\nconfig log setting\nset faz-override enable\nend\n"
        + _faz(override=True) + _faz_filter("error", override=True)
        + "next\nend\n"
    )
    _, findings = _scan(tmp_path, config)
    assert len(findings) == 1  # Root's base destination remains active.
    assert "scope 'root'" in findings[0].observation


def test_fortianalyzer_active_vdom_override_uses_own_filter(tmp_path):
    config = (
        "config vdom\nedit blue\nconfig log setting\nset faz-override enable\nend\n"
        + _faz(override=True) + _faz_filter("alert", override=True)
        + "next\nend\n"
    )
    parser, findings = _scan(tmp_path, config)
    assert len(parser.get_fortianalyzer_severity_gaps()) == 1
    assert len(findings) == 1
    assert "scope 'blue'" in findings[0].observation


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_contains_scoped_finding_without_secret(tmp_path, output_type):
    path = tmp_path / "fortios.conf"
    path.write_text(
        "config system admin\nedit rescue\nset password syntheticprivate\nnext\nend\n"
        + _sink() + _filter("critical"),
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
    assert "FortiOS remote log filter excludes error-level events" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == RULE_ID for item in data["security-audit"].values())
