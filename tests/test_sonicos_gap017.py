from src.analyze.sonicwall.plugins.sonicos_checks_plugin import PluginSonicOSChecks
from src.devices.common.models import KnowledgeState
from src.devices.sonicwall.sonicos import SonicOSParser


def _parse(tmp_path, content):
    path = tmp_path / "sonicos-gap017.txt"
    path.write_text(content, encoding="utf-8")
    return SonicOSParser(str(path))


def _administrative_findings(parser):
    plugin = PluginSonicOSChecks()
    plugin.check_administration(parser)
    return plugin.get_issues()


def test_legacy_defaults_are_typed_but_73_omissions_remain_unknown(tmp_path):
    legacy = _parse(tmp_path, 'firmware-version "SonicOS 7.2.1"\n')
    password = legacy.get_password_policy()
    session = legacy.get_admin_session_policy()
    assert (password.minimum_length, password.complexity) == (8, "none")
    assert (session.idle_logout_minutes, session.lockout_enabled, session.max_cli_attempts) == (5, False, 5)
    assert legacy.get_banner_policy().connection_enabled is False
    assert legacy.get_management_tls_policy().certificate_type == "self-signed"

    current = _parse(tmp_path, 'firmware-version "SonicOS 7.3.0"\n')
    assert current.get_password_policy().minimum_length is None
    assert current.get_admin_session_policy().lockout_enabled is None
    assert current.get_banner_policy().connection_enabled is None
    assert current.get_management_tls_policy().certificate_type is None
    assert current.get_normalized_config().users.state == KnowledgeState.UNKNOWN


def test_explicit_administrative_controls_override_custom_export_defaults(tmp_path):
    parser = _parse(
        tmp_path,
        '''firmware-version "SonicOS 7.1.2"
interface X0
  zone LAN
  management https ssh
administration
  admin one-time-password totp
  password minimum-length 14
  password complexity alpha-and-numeric-and-symbols
  idle-logout-time 4
  user-lockout
    failures-per-minute 3
    lockout-duration 15
  max-login-attempts-cli 4
  no log-without-lockout
  tls-and-above
  web-management certificate corp-management
cli banner connection "Authorized use only"
''',
    )
    assert parser.get_administrators()[0].otp_enabled is True
    assert parser.get_password_policy().minimum_length == 14
    assert parser.get_admin_session_policy().failures_per_minute == 3
    assert parser.get_banner_policy().connection_enabled is True
    assert parser.get_management_tls_policy().minimum_version == "tls1.1"
    assert parser.get_management_tls_policy().certificate_type == "imported"
    assert _administrative_findings(parser) == []


def test_local_admin_roles_deletions_and_local_aaa_fallback_are_resolved(tmp_path):
    parser = _parse(
        tmp_path,
        '''firmware-version "SonicOS 7.1.2"
user authentication
  method radius+local
user local-users
  user auditor password TOPSECRET member-of "SonicWall Administrators"
    member-of "SonicWall Read-Only Admins"
    no member-of "SonicWall Administrators"
    one-time-pwd-required
  user deleted-admin
    password encrypted REMOVESECRET
  no user deleted-admin
''',
    )
    administrators = parser.get_administrators()
    assert [(item.name, item.effective_role) for item in administrators[1:]] == [
        ("auditor", "read-only-admin")
    ]
    assert administrators[1].credential_present is True
    assert administrators[1].otp_enabled is True
    authentication = parser.get_authentication_policy()
    assert authentication.method == "radius+local"
    assert authentication.permits_local_fallback is True
    evidence = " ".join(item.text for admin in administrators for item in admin.evidence)
    assert "TOPSECRET" not in evidence
    assert "REMOVESECRET" not in evidence


def test_password_constraint_scope_uses_native_plural_aliases(tmp_path):
    parser = _parse(
        tmp_path,
        '''firmware-version "SonicOS 7.3.0"
administration
  admin one-time-password totp
  password minimum-length 14
  password complexity alpha-and-numeric-and-symbols
  password constraints-apply-to builtin-admin full-admins
''',
    )
    assert parser.get_password_policy().scopes == ("admin", "full-admin")
    findings = _administrative_findings(parser)
    assert [item.rule_id for item in findings] == [
        "sonicwall.sonicos.password.admin_scope"
    ]
    assert "limited-admin" in findings[0].observation


def test_higher_precedence_admin_membership_is_reported(tmp_path):
    parser = _parse(
        tmp_path,
        '''firmware-version "SonicOS 7.3.0"
user local-users
  user overprivileged
    password encrypted SECRET
  group "SonicWall Read-Only Admins"
    member overprivileged
  group "SonicWall Administrators"
    member overprivileged
''',
    )
    administrator = parser.get_administrators()[1]
    assert administrator.effective_role == "full-admin"
    assert set(administrator.roles) == {"full-admin", "read-only-admin"}
    findings = _administrative_findings(parser)
    assert [item.rule_id for item in findings] == [
        "sonicwall.sonicos.admin.conflicting_roles"
    ]
    assert "SECRET" not in " ".join(value for item in findings for value in item.evidence)


def test_nested_custom_admin_group_is_resolved_without_looping_on_cycle(tmp_path):
    parser = _parse(
        tmp_path,
        '''firmware-version "SonicOS 7.3.0"
user local-users
  user nested-admin member-of "Audit Team"
    password encrypted SECRET
  group "Audit Team"
    member "Nested Group"
  group "Nested Group"
    member "Audit Team"
  group "Limited Administrators"
    member "Audit Team"
''',
    )
    administrators = parser.get_administrators()
    assert [(item.name, item.effective_role) for item in administrators[1:]] == [
        ("nested-admin", "limited-admin")
    ]


def test_weak_explicit_session_and_tls_controls_are_independent(tmp_path):
    parser = _parse(
        tmp_path,
        '''firmware-version "SonicOS 7.3.0"
interface X0
  zone LAN
  management https ssh
administration
  admin one-time-password totp
  password minimum-length 14
  password complexity alpha-and-numeric-and-symbols
  idle-logout-time 30
  user-lockout failures-per-minute 10 lockout-duration 1
  max-login-attempts-cli 9
  log-without-lockout
  no tls-and-above
  web-management certificate self-signed
cli banner connection "Authorized use only"
''',
    )
    assert [item.rule_id for item in _administrative_findings(parser)] == [
        "sonicwall.sonicos.admin.lockout_policy",
        "sonicwall.sonicos.admin.idle_timeout",
        "sonicwall.sonicos.admin.cli_login_attempts",
        "sonicwall.sonicos.admin.log_without_lockout",
        "sonicwall.sonicos.management.legacy_tls",
        "sonicwall.sonicos.management.self_signed_certificate",
    ]


def test_disabled_management_services_are_not_graded(tmp_path):
    parser = _parse(
        tmp_path,
        '''firmware-version "SonicOS 7.1.2"
interface X0
  zone LAN
  shutdown
  management https ssh
administration
  no user-lockout
  idle-logout-time 99
  max-login-attempts-cli 15
  no tls-and-above
''',
    )
    assert parser.get_services() == {"http": False, "https": False, "ssh": False, "snmp": False}
    assert [item.rule_id for item in _administrative_findings(parser)] == [
        "sonicwall.sonicos.admin.mfa_missing",
        "sonicwall.sonicos.password.minimum_length",
        "sonicwall.sonicos.password.complexity",
    ]


def test_malformed_explicit_numbers_remain_unknown_and_are_not_findings(tmp_path):
    parser = _parse(
        tmp_path,
        '''firmware-version "SonicOS 7.3.0"
interface X0
  zone LAN
  management ssh
administration
  admin one-time-password totp
  password minimum-length malformed
  idle-logout-time malformed
  user-lockout
    failures-per-minute malformed
    lockout-duration malformed
  max-login-attempts-cli malformed
cli banner connection "Authorized use only"
''',
    )
    assert parser.get_password_policy().minimum_length is None
    session = parser.get_admin_session_policy()
    assert session.idle_logout_minutes is None
    assert session.failures_per_minute is None
    assert session.lockout_duration_minutes is None
    assert session.max_cli_attempts is None
    assert _administrative_findings(parser) == []
