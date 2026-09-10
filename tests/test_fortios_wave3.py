from src.analyze.fortinet.plugins.fortios_checks_plugin import PluginFortiOSChecks
from src.devices.fortinet.fortios import FortiOSParser


def _analyze(tmp_path, config):
    path = tmp_path / "fortigate.conf"
    path.write_text(config, encoding="utf-8")
    parser = FortiOSParser(str(path))
    plugin = PluginFortiOSChecks()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


def test_management_findings_are_per_interface_protocol_and_scope(tmp_path):
    config = '''config system interface
edit "wan1"
set role wan
set ip 198.51.100.1 255.255.255.0
set allowaccess ping http telnet
next
edit "lan"
set role lan
set allowaccess https ssh
next
edit "down-wan"
set role wan
set status down
set allowaccess http
next
end
config system admin
edit "restricted"
set trusthost1 192.0.2.0 255.255.255.0
next
edit "unrestricted"
next
end
'''
    parser, issues = _analyze(tmp_path, config)
    management = [
        issue for issue in issues
        if issue.rule_id == "fortinet.fortios.management.insecure_protocol"
    ]
    assert len(management) == 2
    assert {issue.observation.split()[0] for issue in management} == {"TELNET", "HTTP"}
    assert all("wan1" in issue.observation for issue in management)
    assert all("no effective trusted-host restriction" in issue.observation for issue in management)
    assert parser.get_services()["http"] is True
    assert all("down-wan" not in issue.observation for issue in management)


def test_management_exposure_preserves_vdom_scope(tmp_path):
    config = '''config vdom
edit "blue"
config system interface
edit "wan1"
set role wan
set allowaccess http
next
end
next
edit "green"
config system interface
edit "mgmt"
set role lan
set allowaccess telnet
next
end
next
end
'''
    _, issues = _analyze(tmp_path, config)
    management = [
        issue for issue in issues
        if issue.rule_id == "fortinet.fortios.management.insecure_protocol"
    ]
    assert len(management) == 2
    assert any("'blue'" in issue.observation and "wan1" in issue.observation for issue in management)
    assert any("'green'" in issue.observation and "mgmt" in issue.observation for issue in management)


def test_interface_any_is_not_confused_with_address_and_service_any(tmp_path):
    config = '''config firewall policy
edit 1
set srcintf "any"
set dstintf "any"
set srcaddr "AdminSubnet"
set dstaddr "Web01"
set service "HTTPS"
set schedule "always"
set action accept
next
edit 2
set srcintf "lan"
set dstintf "wan1"
set srcaddr "all"
set dstaddr "all"
set service "ALL"
set schedule "always"
set action accept
set logtraffic all
next
edit 3
set srcintf "any"
set dstintf "any"
set srcaddr "all"
set dstaddr "all"
set service "ALL"
set action accept
set status disable
next
end
'''
    _, issues = _analyze(tmp_path, config)
    broad = [issue for issue in issues if issue.rule_id == "fortinet.fortios.policy.broad_accept"]
    assert len(broad) == 1
    assert "policy '2'" in broad[0].observation
    assert "lan" in broad[0].observation
    assert "logtraffic is all" in broad[0].observation


def test_fortios_tls_enums_match_vendor_spelling(tmp_path):
    config = '''config system global
set ssl-min-proto-version TLSv1-1
set admin-https-ssl-versions tlsv1-1 tlsv1-2
end
'''
    _, issues = _analyze(tmp_path, config)
    tls = [issue for issue in issues if issue.rule_id == "fortinet.fortios.tls.minimum_version"]
    assert len(tls) == 1
    assert "tlsv1-1" in tls[0].observation


def test_enabled_logging_targets_and_disabled_sections(tmp_path):
    disabled = '''config log syslogd setting
set status disable
set server 192.0.2.50
end
'''
    _, issues = _analyze(tmp_path, disabled)
    assert "fortinet.fortios.logging.missing" in {issue.rule_id for issue in issues}

    for section, settings in (
        ("log syslogd setting", "set status enable\nset server 192.0.2.50"),
        ("log fortianalyzer setting", "set status enable\nset server 192.0.2.60"),
        ("log fortiguard setting", "set status enable"),
        ("system central-management", "set type fortimanager\nset fmg 192.0.2.70"),
    ):
        _, target_issues = _analyze(
            tmp_path,
            f"config {section}\n{settings}\nend\n",
        )
        assert "fortinet.fortios.logging.missing" not in {
            issue.rule_id for issue in target_issues
        }
