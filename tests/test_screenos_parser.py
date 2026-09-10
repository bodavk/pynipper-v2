from src.devices.common.models import ConfigurationState
from src.devices.juniper.screenos import JuniperScreenOSParser


def _parse(tmp_path, config):
    path = tmp_path / "screenos.conf"
    path.write_text(config, encoding="utf-8")
    return JuniperScreenOSParser(str(path))


def test_screenos_parses_system_users_interfaces_objects_and_management(tmp_path):
    parser = _parse(
        tmp_path,
        '''set hostname "branch-fw"
set version "6.3.0r27.0"
set chassis "SSG-140"
set admin user "ops" password "SuperSecret" privilege read-only
set admin manager-ip 192.0.2.10 255.255.255.255
set interface "ethernet0/0" zone "Untrust"
set interface "ethernet0/0" ip 198.51.100.1 255.255.255.0
set interface "ethernet0/0" manage ssh web
unset interface "ethernet0/0" manage web
set interface "ethernet0/0" manage-ip 192.0.2.20 255.255.255.255
set address "Trust" "WEB" 10.0.0.10 255.255.255.255
set service "APP" protocol tcp src-port 0-65535 dst-port 8443-8443
''',
    )

    assert parser.get_hostname() == "branch-fw"
    assert parser.get_version() == "6.3.0r27.0"
    assert parser.model == "SSG-140"
    assert parser.get_services() == {
        "telnet": False,
        "ssh": True,
        "http": False,
        "https": False,
    }
    assert parser.interfaces["ethernet0/0"].zone == "Untrust"
    assert parser.interfaces["ethernet0/0"].manager_ips == [
        "192.0.2.20 255.255.255.255"
    ]
    assert ("Trust", "WEB") in parser.address_objects
    assert "APP" in parser.service_objects
    assert parser.get_users()[0]["role"] == "read-only"
    assert "SuperSecret" not in parser.get_users()[0]["evidence"][0].text

    normalized = parser.get_normalized_config()
    ssh = normalized.management_services.items[0]
    assert ssh.protocol == "ssh"
    assert ssh.interface == "ethernet0/0"
    assert ssh.zone == "Untrust"
    assert ssh.permitted_sources == ("192.0.2.20 255.255.255.255",)
    assert normalized.users.items[0].username == "ops"
    assert normalized.interfaces.items[0].addresses == (
        "198.51.100.1 255.255.255.0",
    )


def test_screenos_policy_continuations_update_one_ordered_policy(tmp_path):
    parser = _parse(
        tmp_path,
        '''set policy id 10 from "Untrust" to "Trust" "Any" "WEB" "APP" permit log
set policy id 10
set src-address "PARTNER"
unset src-address "Any"
set service "HTTPS"
set action permit
set log session-init
exit
set policy id 20 from "Trust" to "Untrust" "Any" "Any" "ANY" permit
set policy id 20 disable
set policy id 30 from "Trust" to "Untrust" "Any" "Any" "DNS" permit
unset policy id 30
''',
    )

    assert list(parser.policies) == ["10", "20"]
    first = parser.policies["10"]
    assert first.position == 0
    assert first.sources == ["PARTNER"]
    assert first.destinations == ["WEB"]
    assert first.services == ["APP", "HTTPS"]
    assert first.action == "permit"
    assert first.tracking == "log session-init"
    assert parser.policies["20"].disabled is True

    normalized = parser.get_normalized_config()
    assert normalized.policies.items[0].state == ConfigurationState.ENABLED
    assert normalized.policies.items[1].state == ConfigurationState.DISABLED
    assert len([line for line in parser.get_native_config() if "policy id" in line]) == 1


def test_screenos_later_disable_remove_and_unset_commands_are_effective(tmp_path):
    parser = _parse(
        tmp_path,
        '''set admin telnet enable
unset admin telnet
set interface "ethernet0/1" zone "Trust"
set interface "ethernet0/1" manage ssh web
unset interface "ethernet0/1" manage ssh
set interface "ethernet0/1" disable
set address "Trust" "TEMP" 10.0.0.1 255.255.255.255
unset address "Trust" "TEMP"
set service "TEMP-SVC" protocol tcp dst-port 1-1
unset service "TEMP-SVC"
''',
    )
    assert parser.get_services() == {
        "telnet": False,
        "ssh": False,
        "http": False,
        "https": False,
    }
    assert parser.address_objects == {}
    assert parser.service_objects == {}
    assert parser.get_normalized_config().interfaces.items[0].state == ConfigurationState.DISABLED


def test_screenos_malformed_quoted_line_produces_diagnostic_without_stopping(tmp_path):
    parser = _parse(
        tmp_path,
        'set address "Trust" "broken 10.0.0.1 255.255.255.255\nset hostname recovered\n',
    )
    assert parser.get_hostname() == "recovered"
    assert any("No closing quotation" in diagnostic for diagnostic in parser.diagnostics)
