from src.analyze.juniper.core.process_screenos_conf import process_screenos_conf
from src.analyze.juniper.plugins.screenos_baseline_plugin import PluginScreenOSBaseline
from src.devices.juniper.screenos import JuniperScreenOSParser


def _parser(tmp_path, config: str) -> JuniperScreenOSParser:
    path = tmp_path / "screenos-gap016.conf"
    path.write_text(config, encoding="utf-8")
    return JuniperScreenOSParser(str(path))


def _issues(parser: JuniperScreenOSParser):
    plugin = PluginScreenOSBaseline()
    plugin.analyze(parser)
    return plugin.get_issues()


def test_screenos_63_default_deny_and_explicit_default_permit(tmp_path):
    parser = _parser(tmp_path, 'set version "6.3.0r27.0"\n')
    state = parser.get_firewall_policy_state()
    assert state.default_action == "deny-all"
    assert state.resolution_state == "documented-default"
    assert not [issue for issue in _issues(parser) if issue.rule_id.endswith("default_permit")]

    parser = _parser(
        tmp_path,
        '''set version "6.3.0r27.0"
set policy default-permit-all
''',
    )
    state = parser.get_firewall_policy_state()
    assert state.default_action == "permit-all"
    findings = [
        issue for issue in _issues(parser)
        if issue.rule_id == "juniper.screenos.policy.default_permit"
    ]
    assert len(findings) == 1
    assert "default-permit-all" in findings[0].evidence[0]


def test_screenos_default_policy_honors_unset_and_override(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version "6.3.0r27.0"
set policy default-permit-all
unset policy default-permit-all
''',
    )
    assert parser.get_firewall_policy_state().default_action == "deny-all"

    parser = _parser(
        tmp_path,
        '''set version "6.3.0r27.0"
set policy default-permit-all
unset policy default-permit-all
set policy default-permit-all
''',
    )
    assert parser.get_firewall_policy_state().default_action == "permit-all"


def test_screenos_timeout_domains_are_independent_and_bound(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version "6.3.0r27.0"
set console timeout 0
set interface "ethernet0/0" zone "Trust"
set interface "ethernet0/0" manage ssl
set ssl enable
set admin auth web timeout 30
set auth-server "admins" type tacacs
set auth-server "admins" account-type admin
set auth-server "admins" timeout 20
set admin auth server "admins"
set auth-server "users" type radius
set auth-server "users" account-type auth
set auth-server "users" timeout 60
set policy id 10 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit auth server "users"
set auth-server "unused" type radius
set auth-server "unused" timeout 0
''',
    )
    controls = parser.get_session_controls()
    assert {(item.scope, item.name, item.timeout_minutes) for item in controls if item.active} == {
        ("console-telnet", "console/Telnet", 0),
        ("web-management", "Web administration", 30),
        ("authentication-server", "admins", 20),
        ("authentication-server", "users", 60),
    }
    rule_ids = {issue.rule_id for issue in _issues(parser)}
    assert "juniper.screenos.administration.session_timeout" in rule_ids
    assert "juniper.screenos.administration.web_session_timeout" in rule_ids
    assert "juniper.screenos.administration.remote_session_timeout" in rule_ids
    assert "juniper.screenos.authentication.session_timeout" in rule_ids
    assert not any("unused" in issue.observation for issue in _issues(parser))


def test_screenos_policy_context_auth_server_binding_is_resolved(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version "6.3.0r27.0"
set auth-server "users" type radius
set auth-server "users" timeout 30
set policy id 12 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit
set auth server "users"
exit
''',
    )
    policy = parser.policies["12"]
    assert policy.auth_server == "users"
    control = next(item for item in parser.get_session_controls() if item.name == "users")
    assert control.active
    assert control.uses == ("policy:12",)
    assert "juniper.screenos.authentication.session_timeout" in {
        issue.rule_id for issue in _issues(parser)
    }


def test_screenos_disabled_policy_does_not_activate_auth_server(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version "6.3.0r27.0"
set auth-server "users" type radius
set auth-server "users" timeout 30
set policy id 12 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit
set auth server "users"
set log session-init
set policy id 12 disable
exit
''',
    )
    control = next(item for item in parser.get_session_controls() if item.name == "users")
    assert not control.active
    assert control.uses == ()
    assert "juniper.screenos.authentication.session_timeout" not in {
        issue.rule_id for issue in _issues(parser)
    }


def test_screenos_full_policy_auth_server_unset_is_effective(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version "6.3.0r27.0"
set auth-server "users" type radius
set auth-server "users" timeout 30
set policy id 12 from "Trust" to "Untrust" "Any" "Any" "HTTP" permit
set policy id 12 auth server "users"
unset policy id 12 auth server
''',
    )
    assert parser.policies["12"].auth_server == ""
    control = next(item for item in parser.get_session_controls() if item.name == "users")
    assert not control.active


def test_screenos_timeout_defaults_alias_unset_and_unresolved_binding(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version "6.3.0r27.0"
set interface "ethernet0/0" zone "Trust"
set interface "ethernet0/0" manage web
set admin auth timeout 0
set admin auth web timeout 30
unset admin auth web timeout
set auth-server "users" type radius
set auth-server "users" timeout 40
unset auth-server "users" timeout
set auth default auth server "users"
set admin auth server "missing"
''',
    )
    controls = parser.get_session_controls()
    web = next(item for item in controls if item.scope == "web-management")
    users = next(item for item in controls if item.name == "users")
    missing = next(item for item in controls if item.name == "missing")
    assert (web.timeout_minutes, web.value_source) == (0, "explicit-legacy-alias")
    assert (users.timeout_minutes, users.value_source) == (10, "documented-default")
    assert missing.resolution_state == "unresolved"
    rule_ids = {issue.rule_id for issue in _issues(parser)}
    assert "juniper.screenos.administration.web_session_timeout" in rule_ids
    assert "juniper.screenos.authentication.session_timeout" not in rule_ids
    assert "juniper.screenos.authentication.server_reference" in rule_ids


def test_screenos_unknown_release_does_not_infer_gap016_defaults(tmp_path):
    parser = _parser(
        tmp_path,
        '''set policy default-permit-all
set console timeout 0
set admin auth web timeout 0
''',
    )
    assert parser.get_firewall_policy_state().resolution_state == "unsupported-release"
    assert parser.get_session_controls() == ()
    rule_ids = {issue.rule_id for issue in _issues(parser)}
    assert "juniper.screenos.policy.default_permit" not in rule_ids
    assert "juniper.screenos.administration.session_timeout" not in rule_ids
    assert "juniper.screenos.administration.web_session_timeout" not in rule_ids


def test_screenos_gap016_findings_reach_public_processor_and_redact_secrets(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version "6.3.0r27.0"
set policy default-permit-all
set auth-server "users" type radius
set auth-server "users" radius secret "DoNotLeak"
set auth-server "users" timeout 60
set auth default auth server "users"
''',
    )
    findings = list(process_screenos_conf(parser).values())
    rule_ids = {finding.rule_id for finding in findings}
    assert "juniper.screenos.policy.default_permit" in rule_ids
    assert "juniper.screenos.authentication.session_timeout" in rule_ids
    assert all(finding.references for finding in findings)
    assert all(
        "donotleak" not in evidence.casefold()
        for finding in findings
        for evidence in finding.evidence
    )
