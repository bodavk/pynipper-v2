import pytest

from src.devices.fortinet.fortios import FortiOSParseError, FortiOSParser
from src.devices.common.models import ConfigurationState, KnowledgeState


FORTIOS_CONFIG = """#config-version=FGT60F-7.2.8-FW-build1639-240313:opmode=0:vdom=1:user=admin
config system global
    set hostname "branch-fw"
    set admin-https-ssl-versions "tlsv1-2" "tlsv1-3"
end
config system admin
    edit "sec-admin"
        set accprofile "super_admin"
        set remote-auth enable
    next
end
config system interface
    edit "wan1"
        set vdom "root"
        set role wan
        set ip 192.0.2.1 255.255.255.0
        set allowaccess ping
        append allowaccess "https" "ssh"
        unselect allowaccess ping
    next
end
config vdom
    edit "root"
        config firewall policy
            edit 10
                set srcintf "wan1"
                set dstintf "lan"
                set srcaddr "all"
                set dstaddr "Web Server"
                set action accept
                set service "HTTPS"
            next
            edit 20
                set srcintf "lan"
                set dstintf "wan1"
                set action accept
                set service "DNS" "HTTPS"
                set status disable
            next
            move 20 before 10
        end
        config log syslogd setting
            set status enable
            set server "198.51.100.10"
        end
    next
end
"""


def _write_config(tmp_path, content=FORTIOS_CONFIG):
    path = tmp_path / "fortigate.conf"
    path.write_text(content, encoding="utf-8")
    return path


def test_fortios_parser_tokenizes_values_and_preserves_vdom_policy_order(tmp_path):
    parser = FortiOSParser(str(_write_config(tmp_path)))
    native = parser.get_native_config()

    assert native["system global"]["hostname"] == "branch-fw"
    assert native["system interface"]["wan1"]["allowaccess"] == ["https", "ssh"]
    assert native["vdom"]["root"]["firewall policy"]["10"]["dstaddr"] == "Web Server"
    assert list(native["vdom"]["root"]["firewall policy"]) == ["20", "10"]
    assert parser.get_version() == "7.2.8"


def test_fortios_parser_populates_normalized_security_model(tmp_path):
    parser = FortiOSParser(str(_write_config(tmp_path)))
    normalized = parser.get_normalized_config()

    assert normalized.hostname.state == KnowledgeState.KNOWN
    assert normalized.hostname.value == "branch-fw"
    assert normalized.software_version.value == "7.2.8"
    assert normalized.device_model.value == "FGT60F"
    assert parser.get_model() == "FGT60F"
    assert normalized.users.state == KnowledgeState.KNOWN
    assert normalized.users.items[0].username == "sec-admin"
    assert normalized.users.items[0].scope == "root"

    services = {(item.protocol, item.interface) for item in normalized.management_services.items}
    assert services == {("https", "wan1"), ("ssh", "wan1")}
    assert normalized.interfaces.items[0].scope == "root"

    assert [policy.name for policy in normalized.policies.items] == ["20", "10"]
    assert normalized.policies.items[0].state == ConfigurationState.DISABLED
    assert normalized.policies.items[0].scope == "root"
    assert normalized.policies.items[1].destinations == ("Web Server",)

    destination = normalized.logging_destinations.items[0]
    assert destination.state == ConfigurationState.ENABLED
    assert destination.address == "198.51.100.10"
    assert destination.scope == "root"
    assert normalized.crypto_settings.items[0].value == "tlsv1-2 tlsv1-3"


@pytest.mark.parametrize(
    "content, message",
    [
        ("end\n", "no open config block"),
        ("config system global\nset hostname fw\n", "unclosed block"),
        ("config system admin\nedit admin\nend\n", "no open config block"),
        ('config system global\nset hostname "unterminated\nend\n', "Invalid quoting"),
    ],
)
def test_fortios_parser_rejects_malformed_structure_with_line_diagnostic(tmp_path, content, message):
    with pytest.raises(FortiOSParseError, match=message) as error:
        FortiOSParser(str(_write_config(tmp_path, content)))

    assert error.value.line_number >= 1
    assert error.value.source.endswith("fortigate.conf")


def test_fortios_parser_applies_unset_select_rename_and_delete(tmp_path):
    content = """config firewall address
edit "old"
set subnet 192.0.2.0 255.255.255.0
unset subnet
select comment "managed object"
next
rename "old" to "new"
edit "remove-me"
next
delete "remove-me"
end
"""
    parser = FortiOSParser(str(_write_config(tmp_path, content)))
    addresses = parser.get_native_config()["firewall address"]

    assert list(addresses) == ["new"]
    assert addresses["new"] == {"comment": "managed object"}
