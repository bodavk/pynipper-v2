from src.analyze.juniper.plugins.screenos_checks_plugin import PluginScreenOSChecks
from src.devices.juniper.screenos import JuniperScreenOSParser


def _analyze(tmp_path, config):
    path = tmp_path / "screenos.conf"
    path.write_text(config, encoding="utf-8")
    parser = JuniperScreenOSParser(str(path))
    plugin = PluginScreenOSChecks()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


def test_management_findings_identify_interface_zone_and_manager_scope(tmp_path):
    config = '''set admin manager-ip 192.0.2.10 255.255.255.255
set interface "ethernet0/0" zone "Untrust"
set interface "ethernet0/0" manage telnet web ssh
set interface "ethernet0/1" zone "Trust"
set interface "ethernet0/1" manage web
set interface "ethernet0/1" manage-ip 10.0.0.10 255.255.255.255
set interface "ethernet0/2" zone "Untrust"
set interface "ethernet0/2" manage telnet
set interface "ethernet0/2" disable
'''
    _, issues = _analyze(tmp_path, config)
    management = [issue for issue in issues if ".management." in issue.rule_id]
    assert len(management) == 3
    assert any("ethernet0/0" in issue.observation and "Untrust" in issue.observation for issue in management)
    assert any("ethernet0/1" in issue.observation and "10.0.0.10" in issue.observation for issue in management)
    assert all("ethernet0/2" not in issue.observation for issue in management)


def test_unset_management_method_is_not_reported(tmp_path):
    _, issues = _analyze(
        tmp_path,
        '''set interface "ethernet0/0" zone "Untrust"
set interface "ethernet0/0" manage telnet web
unset interface "ethernet0/0" manage telnet web
''',
    )
    assert not [issue for issue in issues if ".management." in issue.rule_id]


def test_policy_requires_source_destination_service_and_permit_in_same_rule(tmp_path):
    config = '''set policy id 1 from "Trust" to "Untrust" "Any" "Server" "ANY" permit
set policy id 2 from "Trust" to "Untrust" "Client" "Any" "ANY" permit
set policy id 3 from "Trust" to "Untrust" "Any" "Any" "HTTPS" permit
set policy id 4 from "Trust" to "Untrust" "Any" "Any" "ANY" deny
set policy id 5 from "Trust" to "Untrust" "Any" "Any" "ANY" permit log
set policy id 6 from "Trust" to "Untrust" "Any" "Any" "ANY" permit
set policy id 6 disable
'''
    _, issues = _analyze(tmp_path, config)
    broad = [issue for issue in issues if issue.rule_id == "juniper.screenos.policy.broad_permit"]
    assert len(broad) == 1
    assert "policy ID 5" in broad[0].observation
    assert "log" in broad[0].observation


def test_policy_continuation_and_later_remove_change_effective_result(tmp_path):
    config = '''set policy id 10 from "Trust" to "Untrust" "Any" "Any" "ANY" permit
set policy id 10
set dst-address "RestrictedServer"
unset dst-address "Any"
exit
set policy id 20 from "Trust" to "Untrust" "Any" "Any" "ANY" permit
unset policy id 20
'''
    parser, issues = _analyze(tmp_path, config)
    assert list(parser.policies) == ["10"]
    assert parser.policies["10"].destinations == ["RestrictedServer"]
    assert "juniper.screenos.policy.broad_permit" not in {issue.rule_id for issue in issues}
