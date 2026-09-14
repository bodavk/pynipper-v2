from src.analyze.arista.plugins.arista_checks_plugin import PluginAristaChecks
from src.devices.arista.eos import AristaEOSParser


def _parse(tmp_path, content):
    path = tmp_path / "eos-gap017.conf"
    path.write_text(content, encoding="utf-8")
    return AristaEOSParser(str(path))


def _admin_issues(parser):
    plugin = PluginAristaChecks()
    plugin.check_administrative_policy(parser)
    return plugin.get_issues()


def test_administrators_resolve_custom_default_and_removed_roles(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
role audit-admin
username alice secret sha512 $6$salt$hash
username alice role audit-admin
username bob secret sha512 $6$salt$hash
aaa authorization policy local default-role temporary-role
role temporary-role
no role temporary-role
""",
    )
    administrators = {item.name: item for item in parser.get_administrators()}
    assert administrators["alice"].role == "audit-admin"
    assert administrators["alice"].role_class == "custom"
    assert administrators["alice"].role_resolved
    assert administrators["alice"].credential_state == "approved_hash"
    assert administrators["bob"].role == "temporary-role"
    assert not administrators["bob"].role_resolved
    assert [item.rule_id for item in _admin_issues(parser)] == [
        "arista.eos.admin.role_reference"
    ]


def test_aaa_order_local_fallback_and_explicit_authorization_reset(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management ssh
   no shutdown
   idle-timeout 5
aaa authentication login default group tacacs+ local
default aaa authentication login default
aaa authorization commands all default group tacacs+ local
no aaa authorization commands all default
aaa authentication policy lockout failure 5 duration 300
banner login
""",
    )
    policies = {
        (item.policy_type, item.service, item.connection): item
        for item in parser.get_aaa_policies()
    }
    login = policies[("authentication", "login", "default")]
    assert login.methods == ("local",)
    assert login.local_fallback is True
    commands = policies[("authorization", "commands-all", "default")]
    assert commands.methods == ("none",)
    assert commands.unauthenticated is True
    assert [item.rule_id for item in _admin_issues(parser)] == [
        "arista.eos.authentication.unauthenticated_method"
    ]


def test_cli_only_management_still_requires_centralized_authentication(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management ssh
   no shutdown
""",
    )
    plugin = PluginAristaChecks()
    plugin.check_authentication(parser)
    assert [item.rule_id for item in plugin.get_issues()] == [
        "arista.eos.authentication.centralized"
    ]


def test_remote_aaa_requires_command_authorization_and_complete_accounting(tmp_path):
    base = """! device: leaf (DCS-7050, EOS-4.36.2F)
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa authentication policy lockout failure 5 duration 300
banner login
management ssh
   idle-timeout 5
"""
    incomplete = _admin_issues(_parse(tmp_path, base))
    assert [item.rule_id for item in incomplete] == [
        "arista.eos.authorization.commands",
        "arista.eos.authentication.accounting",
    ]

    complete = base + """aaa authorization commands all default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
aaa accounting commands all default stop-only logging
"""
    assert _admin_issues(_parse(tmp_path, complete)) == []


def test_session_blocks_fold_order_and_suppress_inapplicable_or_invalid_values(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management ssh
   idle-timeout 30
   timeout 60 warning 5
management ssh
   idle-timeout 5
management console
   shutdown
   idle-timeout 0
management telnet
   no shutdown
   idle-timeout invalid
""",
    )
    sessions = {item.channel: item for item in parser.get_management_sessions()}
    assert sessions["ssh"].idle_timeout_minutes == 5
    assert sessions["ssh"].absolute_timeout_minutes == 60
    assert sessions["console"].applicable is False
    assert sessions["telnet"].applicable is True
    assert sessions["telnet"].resolution_state == "invalid"
    assert not [
        item for item in _admin_issues(parser)
        if item.rule_id == "arista.eos.admin.idle_timeout"
    ]


def test_absolute_session_timeout_is_release_gated(tmp_path):
    old = _parse(
        tmp_path,
        "! device: leaf (DCS-7050, EOS-4.35.2F)\nmanagement ssh\n   timeout 30 warning 5\n",
    ).get_management_sessions()[0]
    assert old.absolute_timeout_minutes is None
    assert old.resolution_state == "unsupported-release"

    current = _parse(
        tmp_path,
        "! device: leaf (DCS-7050, EOS-4.36.0F)\nmanagement ssh\n   timeout 30 warning 5\n",
    ).get_management_sessions()[0]
    assert current.absolute_timeout_minutes == 30
    assert current.resolution_state == "explicit"


def test_motd_does_not_replace_login_banner_and_order_is_effective(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
banner login
no banner login
banner motd
management console
   idle-timeout 5
""",
    )
    banner = parser.get_banner_policy()
    assert banner.login_enabled is False
    assert banner.motd_enabled is True
    assert [item.rule_id for item in _admin_issues(parser)] == [
        "arista.eos.admin.login_banner",
    ]


def test_eapi_tls_profile_reference_certificate_and_versions_are_independent(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management api http-commands
   protocol https ssl profile LEGACY
   no shutdown
management security
   ssl profile LEGACY
      tls versions 1.0 1.2
""",
    )
    endpoint = parser.get_eapi_endpoints()[0]
    assert endpoint.ssl_profile == "LEGACY"
    profile = parser.get_ssl_profiles()["legacy"]
    assert profile.certificate == ""
    assert profile.tls_versions == ("1.0", "1.2")
    rule_ids = [item.rule_id for item in _admin_issues(parser)]
    assert "arista.eos.eapi.tls_certificate" in rule_ids
    assert "arista.eos.eapi.legacy_tls" in rule_ids


def test_removed_or_undefined_tls_profiles_do_not_survive_effective_state(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management api http-commands
   protocol https ssl profile REMOVED
   no shutdown
management security
   ssl profile REMOVED
      certificate old.pem
no ssl profile REMOVED
""",
    )
    assert parser.get_ssl_profiles() == {}
    assert "arista.eos.eapi.tls_profile_reference" in {
        item.rule_id for item in _admin_issues(parser)
    }

    repeated = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management security
   ssl profile CURRENT
      certificate current.pem
   ssl profile CURRENT
      tls versions 1.2 1.3
management api http-commands
   protocol https ssl profile OLD
   protocol https ssl profile CURRENT
   no shutdown
""",
    )
    profile = repeated.get_ssl_profiles()["current"]
    assert profile.certificate == "current.pem"
    assert profile.tls_versions == ("1.2", "1.3")
    assert repeated.get_eapi_endpoints()[0].ssl_profile == "CURRENT"

    reset = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management api http-commands
   protocol https ssl profile OLD
   protocol https
   no shutdown
""",
    )
    assert reset.get_eapi_endpoints()[0].ssl_profile == ""


def test_disabled_management_surfaces_suppress_applicability_findings(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management api http-commands
   protocol https ssl profile MISSING
   shutdown
management ssh
   shutdown
   idle-timeout 0
no banner login
""",
    )
    plugin = PluginAristaChecks()
    plugin.check_authentication(parser)
    plugin.check_administrative_policy(parser)
    assert plugin.get_issues() == []


def test_lockout_thresholds_and_malformed_values_are_conservative(tmp_path):
    weak = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management ssh
   idle-timeout 5
aaa authentication policy lockout failure 10 window 60 duration 30
banner login
""",
    )
    assert "arista.eos.authentication.lockout_policy" in {
        item.rule_id for item in _admin_issues(weak)
    }

    malformed = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.36.2F)
management ssh
   idle-timeout 5
aaa authentication policy lockout failure invalid duration nope
banner login
""",
    )
    lockout = malformed.get_lockout_policy()
    assert lockout.resolution_state == "invalid"
    assert "arista.eos.authentication.lockout_policy" not in {
        item.rule_id for item in _admin_issues(malformed)
    }
