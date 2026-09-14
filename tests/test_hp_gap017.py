from src.analyze.hp.plugins.hp_checks_plugin import PluginHPChecks
from src.devices.common.models import ConfigurationState
from src.devices.hp.procurve import HPProCurveParser


HEADER = "; J9772A Configuration Editor; Created on release #YA.16.10.0023\n"


def _parse(tmp_path, content):
    path = tmp_path / "switch.conf"
    path.write_text(HEADER + content, encoding="utf-8")
    return HPProCurveParser(str(path))


def _administrative_findings(parser):
    plugin = PluginHPChecks()
    plugin.check_administrative_policy(parser)
    return plugin.get_issues()


def test_local_manager_operator_roles_and_removals_are_ordered(tmp_path):
    parser = _parse(
        tmp_path,
        "include-credentials\n"
        "password all user-name breakglass sha256 hidden\n"
        "no password manager\n",
    )
    credentials = {item.role: item for item in parser.get_local_administrator_credentials()}
    assert credentials["manager"].state == ConfigurationState.DISABLED
    assert credentials["operator"].state == ConfigurationState.ENABLED
    assert credentials["operator"].credential_format == "sha256"
    findings = _administrative_findings(parser)
    assert [item.rule_id for item in findings] == [
        "hp.procurve.admin.manager_credential_missing",
        "hp.procurve.admin.login_banner",
        "hp.procurve.admin.remote_cli_idle_timeout",
        "hp.procurve.admin.serial_idle_timeout",
    ]
    assert "hidden" not in " ".join(value for item in findings for value in item.evidence)


def test_unexported_credentials_remain_unknown(tmp_path):
    parser = _parse(tmp_path, "ip ssh\n")
    credentials = {item.role: item for item in parser.get_local_administrator_credentials()}
    assert credentials["manager"].state == ConfigurationState.UNKNOWN
    assert "hp.procurve.admin.manager_credential_missing" not in {
        item.rule_id for item in _administrative_findings(parser)
    }


def test_channel_authentication_defaults_override_and_reset(tmp_path):
    parser = _parse(
        tmp_path,
        "no telnet-server\n"
        "ip ssh\n"
        "aaa authentication ssh login radius local\n"
        "aaa authentication ssh enable tacacs none\n"
        "no aaa authentication ssh enable tacacs none\n",
    )
    policies = {
        (item.channel, item.access_level): item
        for item in parser.get_administrative_authentication_policies()
    }
    assert (policies[("ssh", "login")].primary, policies[("ssh", "login")].secondary) == (
        "radius", "local",
    )
    assert policies[("ssh", "enable")].resolution_state == "documented-default"
    assert policies[("telnet", "login")].applicable is False


def test_authorized_method_is_graded_only_on_applicable_channel(tmp_path):
    parser = _parse(
        tmp_path,
        "no telnet-server\n"
        "no ip ssh\n"
        "aaa authentication ssh login radius authorized\n"
        "aaa authentication console enable radius authorized\n"
        "banner motd \"Notice\"\n"
        "console idle-timeout 600\n"
        "console idle-timeout serial-usb 600\n",
    )
    findings = _administrative_findings(parser)
    bypasses = [item for item in findings if item.rule_id == "hp.procurve.admin.unauthenticated_method"]
    assert len(bypasses) == 1
    assert "console enable" in bypasses[0].observation


def test_session_channels_inherit_override_and_keep_web_separate(tmp_path):
    parser = _parse(
        tmp_path,
        "ip ssh\n"
        "web-management ssl\n"
        "console idle-timeout 900\n"
        "console idle-timeout serial-usb 300\n"
        "web-management idle-timeout 1200\n",
    )
    sessions = {item.channel: item for item in parser.get_administrative_session_policies()}
    assert sessions["remote-cli"].timeout_seconds == 900
    assert sessions["serial-usb"].timeout_seconds == 300
    assert sessions["web"].timeout_seconds == 1200
    assert {
        item.rule_id for item in _administrative_findings(parser)
    } >= {
        "hp.procurve.admin.remote_cli_idle_timeout",
        "hp.procurve.admin.web_idle_timeout",
    }


def test_malformed_timeout_is_unknown_and_not_promoted_to_finding(tmp_path):
    parser = _parse(
        tmp_path,
        "ip ssh\n"
        "banner motd \"Notice\"\n"
        "console idle-timeout malformed\n"
        "console idle-timeout serial-usb 600\n",
    )
    sessions = {item.channel: item for item in parser.get_administrative_session_policies()}
    assert sessions["remote-cli"].resolution_state == "invalid"
    assert sessions["remote-cli"].timeout_seconds is None
    assert "hp.procurve.admin.remote_cli_idle_timeout" not in {
        item.rule_id for item in _administrative_findings(parser)
    }


def test_banner_and_webagent_plaintext_tls_are_independent_and_ordered(tmp_path):
    parser = _parse(
        tmp_path,
        "web-management plaintext\n"
        "web-management ssl\n"
        "no web-management plaintext\n"
        "banner motd \"Authorized access only\"\n"
        "no banner motd\n",
    )
    states = parser.get_service_states()
    assert states["http"].state == ConfigurationState.DISABLED
    assert states["https"].state == ConfigurationState.ENABLED
    assert parser.get_login_banner_policy().state == ConfigurationState.DISABLED


def test_unknown_release_does_not_invent_administrative_defaults(tmp_path):
    path = tmp_path / "unknown.conf"
    path.write_text("hostname unknown\n", encoding="utf-8")
    parser = HPProCurveParser(str(path))
    assert all(
        item.resolution_state == "unknown-release"
        for item in parser.get_administrative_authentication_policies()
    )
    assert all(
        item.resolution_state == "unknown-release"
        for item in parser.get_administrative_session_policies()
    )
    assert _administrative_findings(parser) == []
