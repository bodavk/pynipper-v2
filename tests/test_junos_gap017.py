from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.devices.juniper.junos import JunOSParser


def _parser(tmp_path, config: str, name: str = "junos-gap017.conf") -> JunOSParser:
    path = tmp_path / name
    path.write_text(config, encoding="utf-8")
    return JunOSParser(str(path))


def _issues(parser: JunOSParser):
    plugin = PluginJunOSBaseline()
    plugin.analyze(parser)
    return plugin.get_issues()


def _gap017_rule_ids(parser: JunOSParser) -> set[str]:
    return {
        issue.rule_id
        for issue in _issues(parser)
        if issue.rule_id.startswith("juniper.junos.authentication.accounting_")
        or issue.rule_id
        in {
            "juniper.junos.authentication.login_banner",
            "juniper.junos.authentication.login_class_binding",
            "juniper.junos.authentication.idle_timeout",
            "juniper.junos.administration.web_session_timeout",
            "juniper.junos.administration.web_session_limit",
        }
    }


def test_junos_login_class_timeout_precedence_and_bindings(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version 22.4R1.10
set system login idle-timeout 20
set system login class auditors permissions view
set system login class auditors idle-timeout 10
set system login user audit class auditors
set system login user ops class super-user
''',
    )
    policies = {item.name: item for item in parser.get_login_class_policies()}
    assert policies["auditors"].permissions == ("view",)
    assert policies["auditors"].users == ("audit",)
    assert policies["auditors"].idle_timeout_minutes == 10
    assert policies["auditors"].timeout_source == "class-explicit"
    assert policies["super-user"].predefined
    assert policies["super-user"].defined
    assert policies["super-user"].idle_timeout_minutes == 20
    assert policies["super-user"].timeout_source == "global-explicit"


def test_junos_missing_disabled_and_unresolved_login_class_controls(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version 22.4R1.10
set system login message "Authorized use only"
set system login class admins permissions all
set system login class admins idle-timeout 0
set system login user ops class admins
set system login user audit class missing-class
set system login user orphan authentication ssh-ed25519 "ssh-ed25519 AAAAredacted"
''',
    )
    issues = _issues(parser)
    rule_ids = [issue.rule_id for issue in issues]
    assert rule_ids.count("juniper.junos.authentication.idle_timeout") == 1
    assert rule_ids.count("juniper.junos.authentication.login_class_binding") == 2
    assert all(issue.references for issue in issues)


def test_junos_remote_accounting_and_pre_auth_message_are_independent(tmp_path):
    vulnerable = _parser(
        tmp_path,
        '''set version 22.4R1.10
set system authentication-order [ tacplus password ]
set system tacplus-server 192.0.2.5 secret "$9$hidden"
set system login announcement "Maintenance tonight"
''',
        "vulnerable.conf",
    )
    assert _gap017_rule_ids(vulnerable) == {
        "juniper.junos.authentication.login_banner",
        "juniper.junos.authentication.accounting_events",
        "juniper.junos.authentication.accounting_destination",
    }

    secure = _parser(
        tmp_path,
        '''set version 22.4R1.10
set system authentication-order [ tacplus password ]
set system tacplus-server 192.0.2.5 secret "$9$hidden"
set system accounting events [ login change-log interactive-commands ]
set system accounting destination tacplus
set system login message "Authorized use only"
''',
        "secure.conf",
    )
    accounting = secure.get_accounting_policy()
    assert set(accounting.events) == {"login", "change-log", "interactive-commands"}
    assert accounting.destination_methods == ("tacplus",)
    assert accounting.resolved_methods == ("tacplus",)
    assert _gap017_rule_ids(secure) == set()


def test_junos_jweb_explicit_session_controls_and_invalid_values(tmp_path):
    vulnerable = _parser(
        tmp_path,
        '''set version 22.4R1.10
set system login message "Authorized use only"
set system services web-management https system-generated-certificate
set system services web-management session idle-timeout 60
''',
        "jweb-vulnerable.conf",
    )
    web = vulnerable.get_web_management_policy()
    assert web.enabled
    assert web.protocols == ("https",)
    assert web.idle_timeout_minutes == 60
    assert web.session_limit is None
    assert _gap017_rule_ids(vulnerable) == {
        "juniper.junos.administration.web_session_timeout",
        "juniper.junos.administration.web_session_limit",
    }

    invalid = _parser(
        tmp_path,
        '''set version 22.4R1.10
set system login message "Authorized use only"
set system services web-management https system-generated-certificate
set system services web-management session idle-timeout invalid
set system services web-management session session-limit 0
''',
        "jweb-invalid.conf",
    )
    web = invalid.get_web_management_policy()
    assert web.idle_timeout_resolution == "invalid"
    assert web.session_limit_resolution == "invalid"
    assert _gap017_rule_ids(invalid) == set()


def test_junos_hierarchical_administrative_policy_matches_display_set(tmp_path):
    hierarchical = _parser(
        tmp_path,
        '''version 22.4R1.10;
system {
    authentication-order [ tacplus password ];
    tacplus-server 192.0.2.5 { secret "$9$hidden"; }
    accounting {
        events [ login change-log interactive-commands ];
        destination { tacplus; }
    }
    login {
        message "Authorized use only";
        idle-timeout 10;
        user ops { class super-user; }
    }
    services {
        web-management {
            https { system-generated-certificate; }
            session { idle-timeout 30; session-limit 4; }
        }
    }
}
''',
        "hierarchical.conf",
    )
    assert _gap017_rule_ids(hierarchical) == set()
    assert hierarchical.get_login_class_policies()[0].idle_timeout_minutes == 10
    assert hierarchical.get_web_management_policy().session_limit == 4


def test_junos_unexpanded_groups_suppress_new_absence_findings(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version 22.4R1.10
set groups ADMIN system login message "Authorized use only"
set groups ADMIN system accounting events [ login change-log interactive-commands ]
set apply-groups ADMIN
set system authentication-order [ tacplus password ]
set system tacplus-server 192.0.2.5 secret "$9$hidden"
set system login user ops class super-user
set system services web-management https system-generated-certificate
''',
    )
    assert _gap017_rule_ids(parser) == set()


def test_junos_gap017_findings_reach_public_processor_without_secrets(tmp_path):
    parser = _parser(
        tmp_path,
        '''set version 22.4R1.10
set system authentication-order [ tacplus password ]
set system tacplus-server 192.0.2.5 secret "DoNotLeak"
set system login user ops class super-user
set system services web-management https system-generated-certificate
set system services web-management session idle-timeout 60
''',
    )
    findings = list(process_junos_conf(parser).values())
    rule_ids = {item.rule_id for item in findings}
    assert "juniper.junos.authentication.login_banner" in rule_ids
    assert "juniper.junos.authentication.idle_timeout" in rule_ids
    assert "juniper.junos.authentication.accounting_events" in rule_ids
    assert "juniper.junos.authentication.accounting_destination" in rule_ids
    assert "juniper.junos.administration.web_session_timeout" in rule_ids
    assert "juniper.junos.administration.web_session_limit" in rule_ids
    assert all(item.references for item in findings)
    assert all(
        "donotleak" not in evidence.casefold()
        for item in findings
        for evidence in item.evidence
    )
