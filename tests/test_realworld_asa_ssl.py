import json
import subprocess
import sys

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.cisco.asa.plugins.asa_checks_plugin import PluginASAChecks
from src.devices.cisco.asa import CiscoASAParser


INTERFACE = """interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 192.0.2.1 255.255.255.0
"""


def _analyze(tmp_path, config, public=False):
    path = tmp_path / "asa.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoASAParser(str(path))
    if public:
        issues = list(process_asa_conf(parser).values())
    else:
        plugin = PluginASAChecks()
        plugin.analyze(parser)
        issues = plugin.get_issues()
    return parser, issues


def test_active_webvpn_legacy_protocol_and_ciphers_are_separate_findings(tmp_path):
    config = f"""ASA Version 9.3(2)
{INTERFACE}ssl server-version tlsv1-only
ssl encryption des-sha1 3des-sha1 aes128-sha1 aes256-sha1
webvpn
 enable outside
!
"""
    parser, issues = _analyze(tmp_path, config, public=True)
    policy = parser.get_ssl_service_policy()
    assert policy.active_interfaces == ("outside",)
    assert policy.server_minimum == "tlsv1-only"
    assert policy.weak_cipher_commands == (
        "ssl encryption des-sha1 3des-sha1 aes128-sha1 aes256-sha1",
    )
    assert {issue.rule_id for issue in issues} >= {
        "cisco.asa.tls.minimum_version",
        "cisco.asa.tls.weak_cipher",
    }
    assert all("SelfsignedSecret" not in " ".join(issue.evidence) for issue in issues)


def test_webvpn_disable_and_missing_interface_prevent_active_assertion(tmp_path):
    disabled = f"""ASA Version 9.18(4)
{INTERFACE}ssl server-version tlsv1
ssl cipher tlsv1 low
webvpn
 enable outside
 no enable
!
"""
    parser, issues = _analyze(tmp_path, disabled)
    assert parser.get_ssl_service_policy().active_interfaces == ()
    assert not {"cisco.asa.tls.minimum_version", "cisco.asa.tls.weak_cipher"} & {
        issue.rule_id for issue in issues
    }

    _, partial = _analyze(
        tmp_path,
        "ASA Version 9.18(4)\nssl server-version tlsv1\nwebvpn\n enable outside\n!\n",
    )
    assert "cisco.asa.tls.minimum_version" not in {issue.rule_id for issue in partial}


def test_ssl_policy_honors_ordered_no_and_secure_replacement(tmp_path):
    config = f"""ASA Version 9.18(4)
{INTERFACE}ssl server-version tlsv1
no ssl server-version
ssl server-version tlsv1.2 dtlsv1.2
ssl encryption 3des-sha1
no ssl encryption
ssl cipher tlsv1.2 low
no ssl cipher tlsv1.2
ssl cipher tlsv1.2 fips
webvpn
 enable outside
!
"""
    parser, issues = _analyze(tmp_path, config)
    policy = parser.get_ssl_service_policy()
    assert policy.server_minimum == "tlsv1.2"
    assert policy.weak_cipher_commands == ()
    assert not {"cisco.asa.tls.minimum_version", "cisco.asa.tls.weak_cipher"} & {
        issue.rule_id for issue in issues
    }


def test_modern_cipher_levels_and_custom_suites_are_evaluated(tmp_path):
    base = f"ASA Version 9.12(4)\n{INTERFACE}ssl server-version tlsv1.2\nwebvpn\n enable outside\n!\n"
    for command in (
        "ssl cipher tlsv1.2 all",
        "ssl cipher tlsv1.2 low",
        "ssl cipher tlsv1.2 medium",
        'ssl cipher tlsv1.2 custom "AES256-SHA:DES-CBC3-SHA"',
    ):
        _, issues = _analyze(tmp_path, base.replace("ssl server-version", command + "\nssl server-version"))
        assert "cisco.asa.tls.weak_cipher" in {issue.rule_id for issue in issues}


def test_unknown_release_or_malformed_policy_is_not_reported_as_active_risk(tmp_path):
    config = f"""{INTERFACE}ssl server-version futuretls
ssl cipher tlsv1.2 vendor-defined
ssl client-version tlsv1
webvpn
 enable outside
!
"""
    parser, issues = _analyze(tmp_path, config)
    policy = parser.get_ssl_service_policy()
    assert not policy.server_minimum_valid
    assert policy.client_minimum == "tlsv1"
    assert policy.unknown_cipher_commands == ("ssl cipher tlsv1.2 vendor-defined",)
    assert not {"cisco.asa.tls.minimum_version", "cisco.asa.tls.weak_cipher"} & {
        issue.rule_id for issue in issues
    }


def test_old_client_only_setting_does_not_describe_inbound_webvpn(tmp_path):
    config = f"""ASA Version 9.18(4)
{INTERFACE}ssl server-version tlsv1.2
ssl client-version tlsv1
ssl cipher default low
webvpn
 enable outside
!
"""
    _, issues = _analyze(tmp_path, config)
    assert not {"cisco.asa.tls.minimum_version", "cisco.asa.tls.weak_cipher"} & {
        issue.rule_id for issue in issues
    }


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_cli_reports_active_webvpn_protocol_and_cipher_risks(tmp_path, output_type):
    config = tmp_path / "asa.conf"
    config.write_text(
        f"""ASA Version 9.3(2)
{INTERFACE}ssl server-version tlsv1-only
ssl encryption des-sha1 3des-sha1 aes256-sha1
webvpn
 enable outside
!
""",
        encoding="utf-8",
    )
    output = tmp_path / f"report.{output_type.casefold()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "ASA", "-i", str(config),
         "-o", output_type, "-f", str(output), "-x"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = output.read_text(encoding="utf-8")
    assert "Active ASA WebVPN permits an obsolete TLS version" in report
    assert "Active ASA WebVPN offers weak TLS cipher suites" in report
    if output_type == "JSON":
        data = json.loads(report)
        assert {item["rule_id"] for item in data["security-audit"].values()} >= {
            "cisco.asa.tls.minimum_version",
            "cisco.asa.tls.weak_cipher",
        }
