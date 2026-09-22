import json
import subprocess
import sys

import pytest

from src.analyze.cisco.ios.plugins.baseline_plugin import PluginIOSBaseline
from src.devices import get_parser


def _analyze(tmp_path, config, device="IOS_ROUTER"):
    path = tmp_path / "ios.conf"
    path.write_text(config, encoding="utf-8")
    parser = get_parser(device, str(path))
    plugin = PluginIOSBaseline()
    plugin.check_management_lines(parser)
    return parser, plugin.get_issues()


def _timeout_findings(issues):
    return [issue for issue in issues if "session_timeout" in issue.rule_id]


@pytest.mark.parametrize("minutes", [90, 720])
def test_excessive_vty_timeout_is_reported(minutes, tmp_path):
    config = f"""version 17.9
line vty 0 4
 exec-timeout {minutes} 0
 transport input ssh
"""
    parser, issues = _analyze(tmp_path, config)
    policies = parser.get_effective_line_timeouts()
    assert [(item.line, item.timeout_minutes, item.active) for item in policies] == [
        ("line vty 0 4", minutes, True),
    ]
    findings = _timeout_findings(issues)
    assert [item.rule_id for item in findings] == ["cisco.ios.line.session_timeout_excessive"]
    assert f"{minutes} minutes" in findings[0].observation


@pytest.mark.parametrize("minutes,seconds", [(5, 0), (10, 0), (9, 59)])
def test_ten_minutes_or_less_is_not_excessive(minutes, seconds, tmp_path):
    _, issues = _analyze(
        tmp_path,
        f"version 17.9\nline vty 0 4\n exec-timeout {minutes} {seconds}\n transport input ssh\n",
    )
    assert _timeout_findings(issues) == []


def test_line_range_override_reports_only_remaining_excessive_range(tmp_path):
    parser, issues = _analyze(
        tmp_path,
        """version 17.9
line vty 0 15
 exec-timeout 90 0
 transport input ssh
line vty 0 4
 exec-timeout 5 0
""",
    )
    policies = parser.get_effective_line_timeouts()
    assert [(item.line, item.timeout_minutes) for item in policies] == [
        ("line vty 0 4", 5),
        ("line vty 5 15", 90),
    ]
    findings = _timeout_findings(issues)
    assert len(findings) == 1
    assert findings[0].observation.startswith("line vty 5 15 ")


def test_zero_timeout_is_distinguished_by_line_class(tmp_path):
    _, issues = _analyze(
        tmp_path,
        """version 17.9
line con 0
 exec-timeout 0 0
line aux 0
 exec-timeout 0 0
 transport input ssh
line vty 0 4
 exec-timeout 0 0
 transport input ssh
""",
    )
    assert {item.rule_id for item in _timeout_findings(issues)} == {
        "cisco.ios.console.session_timeout",
        "cisco.ios.auxiliary.session_timeout",
        "cisco.ios.vty.session_timeout",
    }


def test_disabled_malformed_reset_and_partial_lines_do_not_create_timeout_risks(tmp_path):
    _, issues = _analyze(
        tmp_path,
        """version 17.9
line vty 0 4
 exec-timeout 90 0
 no exec
 transport input none
line vty 5 9
 exec-timeout many
 transport input ssh
line vty 10 14
 exec-timeout 90 0
 default exec-timeout
 transport input ssh
line vty 15 15
 exec-timeout 90 0
""",
    )
    assert _timeout_findings(issues) == []


@pytest.mark.parametrize("device", ["IOS_ROUTER", "IOS_XE"])
def test_public_cli_reports_excessive_timeout(device, tmp_path):
    config = tmp_path / "ios.conf"
    config.write_text(
        "version 17.9\nline vty 0 4\n exec-timeout 90 0\n transport input ssh\n",
        encoding="utf-8",
    )
    output = tmp_path / f"{device}.json"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", device, "-i", str(config),
         "-o", "JSON", "-f", str(output), "-x"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert "cisco.ios.line.session_timeout_excessive" in {
        item["rule_id"] for item in report["security-audit"].values()
    }
