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
    assert _ids(parser) == ["f5.bigip.credentials.local_plaintext"]
    assert parser.get_setting("sys sshd", "inactivity-timeout").resolution_state == "unknown"
    assert secret not in str(parser.get_native_config())
    assert secret not in str(parser.get_normalized_config())
    assert secret not in str(process_bigip_conf(parser))


def test_local_user_credential_storage_is_last_explicit_and_secret_free(tmp_path):
    parser = _parse(tmp_path, """#TMSH-VERSION: 16.1.5
auth user /Common/first { password FirstSecret }
auth user /Common/first { encrypted-password $6$protected }
auth user /Common/second { password ******* }
auth user /Common/third { password ThirdSecret }
""")
    assert _ids(parser) == ["f5.bigip.credentials.local_plaintext"]
    finding = next(iter(process_bigip_conf(parser).values()))
    assert "/Common/third" in finding.observation
    assert "ThirdSecret" not in str(finding)
    assert {item.name: item.storage for item in parser.get_local_user_credentials()} == {
        "/Common/first": "encrypted",
        "/Common/second": "unknown",
        "/Common/third": "plaintext",
    }


def test_explicit_local_lockout_and_minimum_length_settings(tmp_path):
    parser = _parse(tmp_path, """#TMSH-VERSION: 16.1.5
auth password-policy { policy-enforcement enabled max-login-failures 0 minimum-length 0 }
""")
    assert set(_ids(parser)) == {
        "f5.bigip.password_policy.login_lockout_disabled",
        "f5.bigip.password_policy.minimum_length_disabled",
    }
    assert parser.get_setting("auth password-policy", "max-login-failures").value == 0
    assert parser.get_setting("auth password-policy", "minimum-length").value == 0

    safe = _parse(tmp_path, """#TMSH-VERSION: 16.1.5
auth password-policy { policy-enforcement enabled max-login-failures 5 minimum-length 14 }
""")
    assert _ids(safe) == []


def test_password_policy_overrides_and_unknown_values_are_conservative(tmp_path):
    parser = _parse(tmp_path, """auth password-policy { policy-enforcement enabled max-login-failures 0 minimum-length 0 }
auth password-policy { max-login-failures 6 minimum-length bogus }
""")
    assert "f5.bigip.password_policy.login_lockout_disabled" not in _ids(parser)
    assert "f5.bigip.password_policy.minimum_length_disabled" not in _ids(parser)
    assert parser.get_setting("auth password-policy", "minimum-length").resolution_state == "unknown"


def test_active_remote_auth_with_explicitly_empty_provider_servers(tmp_path):
    parser = _parse(tmp_path, """#TMSH-VERSION: 16.1.5
auth source { type radius fallback false }
auth radius /Common/system-auth { servers none }
""")
    assert _ids(parser) == ["f5.bigip.auth.active_remote_servers_none"]
    assert parser.get_remote_auth_profiles("radius")[0].servers_state == "none"


@pytest.mark.parametrize("content", [
    "auth source { type local }\nauth radius /Common/unused { servers none }\n",
    "auth source { type radius }\n",
    "auth source { type radius }\nauth radius /Common/unknown { }\n",
    "auth source { type radius }\nauth radius /Common/live { servers { /Common/one } }\n",
    "auth source { type radius }\nauth radius /Common/empty { servers none }\n"
    "auth radius /Common/live { servers { /Common/one } }\n",
])
def test_remote_auth_missing_or_usable_server_state_is_not_inferred(tmp_path, content):
    parser = _parse(tmp_path, content)
    assert "f5.bigip.auth.active_remote_servers_none" not in _ids(parser)


def test_active_remote_auth_last_server_setting_wins(tmp_path):
    parser = _parse(tmp_path, """auth source { type ldap }
auth ldap /Common/system-auth { servers none }
auth ldap /Common/system-auth { servers { 192.0.2.10 } }
""")
    assert "f5.bigip.auth.active_remote_servers_none" not in _ids(parser)
    parser = _parse(tmp_path, """auth source { type tacacs }
auth tacacs /Common/system-auth { servers { 192.0.2.10 } }
auth tacacs /Common/system-auth { servers none }
""")
    assert "f5.bigip.auth.active_remote_servers_none" in _ids(parser)


def test_remote_auth_provider_secret_is_not_retained_in_evidence(tmp_path):
    parser = _parse(tmp_path, """auth source { type tacacs }
auth tacacs /Common/system-auth { secret PrivateSyntheticKey servers none }
""")
    assert _ids(parser) == ["f5.bigip.auth.active_remote_servers_none"]
    assert "PrivateSyntheticKey" not in str(parser.get_native_config())
    assert "PrivateSyntheticKey" not in str(process_bigip_conf(parser))


@pytest.mark.parametrize("provider", ["ldap", "cert-ldap"])
def test_active_ldap_provider_with_explicit_ssl_disablement(tmp_path, provider):
    parser = _parse(tmp_path, f"""auth source {{ type {provider} }}
auth {provider} /Common/system-auth {{ servers {{ ldap.example.test }} ssl disabled bind-pw SyntheticBindPassword }}
""")
    assert _ids(parser) == ["f5.bigip.auth.ldap_ssl_disabled"]
    assert "SyntheticBindPassword" not in str(parser.get_native_config())
    assert "SyntheticBindPassword" not in str(process_bigip_conf(parser))


@pytest.mark.parametrize("content", [
    "auth source { type local }\nauth ldap /Common/unused { servers { ldap.example.test } ssl disabled }",
    "auth source { type ldap }\nauth ldap /Common/unknown { servers { ldap.example.test } }",
    "auth source { type ldap }\nauth ldap /Common/secure { servers { ldap.example.test } ssl enabled }",
    "auth source { type ldap }\nauth ldap /Common/secure { servers { ldap.example.test } ssl start-tls }",
    "auth source { type ldap }\nauth ldap /Common/empty { servers none ssl disabled }",
    "auth source { type ldap }\nauth ldap /Common/weak { servers { ldap.example.test } ssl disabled }\n"
    "auth ldap /Common/secure { servers { ldap2.example.test } ssl enabled }",
])
def test_ldap_transport_qualification_avoids_unknown_or_alternative_profiles(tmp_path, content):
    parser = _parse(tmp_path, content)
    assert "f5.bigip.auth.ldap_ssl_disabled" not in _ids(parser)


@pytest.mark.parametrize("transport", ["enabled", "start-tls"])
def test_active_ldap_tls_peer_check_explicitly_disabled(tmp_path, transport):
    parser = _parse(tmp_path, f"""auth source {{ type ldap }}
auth ldap /Common/system-auth {{ servers {{ ldap.example.test }} ssl {transport} ssl-check-peer disabled }}
""")
    assert _ids(parser) == ["f5.bigip.auth.ldap_peer_check_disabled"]


@pytest.mark.parametrize("content", [
    "auth source { type local }\nauth ldap /Common/unused { servers { ldap.example.test } ssl enabled ssl-check-peer disabled }",
    "auth source { type ldap }\nauth ldap /Common/unknown { servers { ldap.example.test } ssl enabled }",
    "auth source { type ldap }\nauth ldap /Common/verified { servers { ldap.example.test } ssl enabled ssl-check-peer enabled }",
    "auth source { type ldap }\nauth ldap /Common/no-tls { servers { ldap.example.test } ssl disabled ssl-check-peer disabled }",
    "auth source { type ldap }\nauth ldap /Common/weak { servers { ldap.example.test } ssl enabled ssl-check-peer disabled }\n"
    "auth ldap /Common/verified { servers { ldap2.example.test } ssl enabled ssl-check-peer enabled }",
])
def test_ldap_peer_check_requires_only_active_verifiably_unchecked_providers(tmp_path, content):
    parser = _parse(tmp_path, content)
    assert "f5.bigip.auth.ldap_peer_check_disabled" not in _ids(parser)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_password_policy_report_is_secret_free(tmp_path, output_type):
    source = tmp_path / "device.scf"
    source.write_text("""#TMSH-VERSION: 16.1.5
auth password-policy { policy-enforcement enabled max-login-failures 0 minimum-length 0 }
auth user /Common/admin { password SensitiveF5Secret }
""", encoding="utf-8")
    output = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "f5-bigip", "-i", str(source),
         "-o", output_type, "-f", str(output), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = output.read_text(encoding="utf-8")
    assert "Local login lockout is disabled" in report
    assert "SensitiveF5Secret" not in report + completed.stdout + completed.stderr


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
            "f5.bigip.credentials.local_plaintext",
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
