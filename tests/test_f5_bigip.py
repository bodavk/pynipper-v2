"""BIG-IP parser, effective controls, and public report boundary."""

import json
import subprocess
import sys

import pytest

from src.analyze.f5.core.process_bigip_conf import BIGIP_PLUGINS, process_bigip_conf
from src.analyze.f5.plugins.bigip_checks_plugin import PluginF5BIGIPChecks
from src.devices import get_parser
from src.devices.f5.bigip import F5BIGIPParser, F5ParseError


def _parse(tmp_path, content):
    path = tmp_path / "device.scf"
    path.write_text(content, encoding="utf-8")
    return F5BIGIPParser(str(path))


def _ids(parser):
    return [finding.rule_id for finding in process_bigip_conf(parser).values()]


def test_registry_parser_and_explicit_plugin(tmp_path):
    parser = _parse(tmp_path, "#TMSH-VERSION: 16.1.5\nsys sshd { login disabled }\n")
    assert isinstance(get_parser("BIGIP", parser.config_filepath), F5BIGIPParser)
    assert BIGIP_PLUGINS == (PluginF5BIGIPChecks,)
    assert parser.get_version() == "16.1.5"
    assert _ids(parser) == []


def test_effective_last_setting_and_service_gate(tmp_path):
    parser = _parse(tmp_path, """sys sshd { login enabled allow none inactivity-timeout 0 }
sys sshd { login disabled allow { 192.0.2.0/24 } inactivity-timeout 300 }
sys httpd { allow none redirect-http-to-https enabled }
cli global-settings { audit enabled idle-timeout 15 }
auth password-policy { policy-enforcement enabled }
sys syslog { remote-servers { log1 { host 192.0.2.2 } } }
""")
    assert _ids(parser) == []
    assert parser.get_services() == {"ssh": False}
    assert parser.get_setting("sys httpd", "allow").value == "none"


def test_http_redirect_is_not_exposed_when_allow_none_blocks_clients(tmp_path):
    parser = _parse(tmp_path, "sys httpd { allow none redirect-http-to-https disabled }\n")
    assert _ids(parser) == []


def test_source_values_are_discarded_and_unknown_stays_ungraded(tmp_path):
    secret = "SensitiveF5Secret"
    parser = _parse(tmp_path, f"""sys sshd {{ login enabled allow {{ 192.0.2.0/24 }} inactivity-timeout bogus }}
auth user /Common/admin {{ password {secret} }}
sys httpd {{ ssl-certkeyfile {secret} redirect-http-to-https enabled }}
""")
    assert _ids(parser) == []
    assert parser.get_setting("sys sshd", "inactivity-timeout").resolution_state == "unknown"
    assert secret not in str(parser.get_native_config())
    assert secret not in str(parser.get_normalized_config())


def test_client_ssl_cleartext_requires_active_attachment_and_profile(tmp_path):
    parser = _parse(tmp_path, """ltm profile client-ssl /Common/unsafe {
  mode enabled allow-non-ssl enabled
}
ltm virtual /Common/live {
  enabled profiles { /Common/unsafe { context clientside } }
}
ltm virtual /Common/stopped {
  disabled profiles { /Common/unsafe { context clientside } }
}
ltm virtual /Other/unresolved {
  enabled profiles { /Other/unsafe { context clientside } }
}
""")
    assert _ids(parser) == ["f5.bigip.ltm.clientssl_cleartext_enabled"]
    finding = next(iter(process_bigip_conf(parser).values()))
    assert "/Common/live" in finding.observation
    assert "/Common/stopped" not in finding.observation


def test_unbound_or_inactive_client_ssl_is_not_reported(tmp_path):
    parser = _parse(tmp_path, """ltm profile client-ssl /Common/unused {
  mode enabled allow-non-ssl enabled
}
ltm profile client-ssl /Common/off {
  mode disabled allow-non-ssl enabled
}
ltm virtual /Common/live {
  enabled profiles { /Common/off { context clientside } }
}
""")
    assert _ids(parser) == []


@pytest.mark.parametrize("content", [
    "sys sshd { login enabled\n",
    "not-a-bigip-configuration\n",
    "sys sshd { login enabled } }\n",
])
def test_malformed_or_unrelated_input_fails_closed(tmp_path, content):
    with pytest.raises(F5ParseError) as error:
        _parse(tmp_path, content)
    assert "login enabled" not in str(error.value)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_cli_reports_findings_without_source_secret(tmp_path, output_type):
    source = tmp_path / "device.scf"
    source.write_text("""#TMSH-VERSION: 16.1.5
sys sshd { login enabled allow none inactivity-timeout 0 }
auth user /Common/admin { password SensitiveF5Secret }
""", encoding="utf-8")
    output = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "F5_BIGIP", "-i", str(source),
         "-o", output_type, "-f", str(output), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = output.read_text(encoding="utf-8")
    assert "SSH permits unrestricted management sources" in report
    assert "SensitiveF5Secret" not in report + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(report)
        assert {item["rule_id"] for item in data["security-audit"].values()} == {
            "f5.bigip.ssh.unrestricted_sources", "f5.bigip.ssh.idle_timeout_disabled",
        }


def test_public_parse_error_report_contains_no_source_values(tmp_path):
    source = tmp_path / "device.scf"
    source.write_text("sys sshd { password SensitiveF5Secret\n", encoding="utf-8")
    output = tmp_path / "report.json"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "F5_BIGIP", "-i", str(source),
         "-o", "JSON", "-f", str(output), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 2
    report = output.read_text(encoding="utf-8")
    assert "parse_error" in report
    assert "SensitiveF5Secret" not in report + completed.stdout + completed.stderr
