"""SC-039: explicit, directly mapped local SSL-VPN password-only paths."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


RULE = "fortinet.fortios.sslvpn.password_only_local_user"
HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
USER = ('config user local\n    edit "alice"\n'
        '        set status enable\n        set type password\n'
        '        set passwd "TopSecret42"\n        set two-factor disable\n'
        '    next\nend\n')
VPN = ('config vpn ssl settings\n    set status enable\n'
       '    set source-interface "wan1"\n    set reqclientcert disable\n'
       '    config authentication-rule\n        edit 1\n'
       '            set auth local\n            set users "alice"\n'
       '            set portal "full-access"\n            set client-cert disable\n'
       '        next\n    end\nend\n')


def _scan(tmp_path, body, header=HEADER):
    source = tmp_path / "fortigate.conf"
    source.write_text(header + body, encoding="utf-8")
    parser = FortiOSParser(str(source))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = list(process_fortios_conf(parser).values())
    return parser, [item for item in findings if item.rule_id == RULE]


def test_direct_password_only_local_vpn_user(tmp_path):
    parser, findings = _scan(tmp_path, USER + VPN)
    assert len(parser.get_sslvpn_password_only_users()) == 1
    assert len(findings) == 1
    assert findings[0].basis == FindingBasis.EXPLICIT_VALUE
    assert "password-only path" in findings[0].observation
    assert "TopSecret42" not in str(findings[0])
    assert guidance_for(RULE) is not None


@pytest.mark.parametrize("body", [
    USER.replace("set status enable", "set status disable") + VPN,
    USER.replace("set type password", "set type radius") + VPN,
    USER.replace("set two-factor disable", "set two-factor fortitoken") + VPN,
    USER.replace("set two-factor disable", "") + VPN,
    USER + VPN.replace("set status enable", "set status disable"),
    USER + VPN.replace("set reqclientcert disable", "set reqclientcert enable"),
    USER + VPN.replace("set reqclientcert disable", ""),
    USER + VPN.replace("set client-cert disable", "set client-cert enable"),
    USER + VPN.replace("set client-cert disable", ""),
    USER + VPN.replace("set auth local", "set auth radius"),
    USER + VPN.replace('set users "alice"', 'set groups "vpn-users"'),
    USER + VPN.replace('set portal "full-access"', ''),
    USER + VPN.replace('set client-cert disable', 'set client-cert disable\n            set user-peer "pki"'),
    USER + VPN.replace('set client-cert disable', 'set client-cert disable\n            set source-interface "lan1"'),
])
def test_incomplete_or_protected_authentication_chain_is_ungraded(tmp_path, body):
    parser, findings = _scan(tmp_path, body)
    assert parser.get_sslvpn_password_only_users() == ()
    assert findings == []


def test_unsupported_release_is_ungraded(tmp_path):
    _, findings = _scan(tmp_path, USER + VPN, HEADER.replace("7.4.1", "7.6.0"))
    assert findings == []


def test_matching_rule_source_interface_retains_password_only_path(tmp_path):
    vpn = VPN.replace('set client-cert disable',
                      'set client-cert disable\n            set source-interface "wan1"')
    _, findings = _scan(tmp_path, USER + vpn)
    assert len(findings) == 1


@pytest.mark.parametrize("group_type", ["", "        set group-type firewall\n"])
def test_local_user_mapped_through_firewall_group(tmp_path, group_type):
    group = ('config user group\n    edit "vpn-users"\n' + group_type
             + '        set member "alice"\n    next\nend\n')
    vpn = VPN.replace('set users "alice"', 'set groups "vpn-users"')
    parser, findings = _scan(tmp_path, USER + group + vpn)
    assert len(findings) == 1
    assert parser.get_sslvpn_password_only_users()[0].group == "vpn-users"
    assert "group 'vpn-users'" in findings[0].observation
    assert "TopSecret42" not in str(findings[0])


@pytest.mark.parametrize("group", [
    'config user group\n    edit "vpn-users"\n'
    '        set group-type fsso-service\n        set member "alice"\n    next\nend\n',
    'config user group\n    edit "vpn-users"\n'
    '        set member "bob"\n    next\nend\n',
])
def test_unrelated_or_non_firewall_group_does_not_imply_local_vpn_path(tmp_path, group):
    vpn = VPN.replace('set users "alice"', 'set groups "vpn-users"')
    _, findings = _scan(tmp_path, USER + group + vpn)
    assert findings == []


def test_direct_and_group_binding_reports_one_user_once(tmp_path):
    group = ('config user group\n    edit "vpn-users"\n'
             '        set member "alice"\n    next\nend\n')
    vpn = VPN.replace('set users "alice"', 'set users "alice"\n            set groups "vpn-users"')
    _, findings = _scan(tmp_path, USER + group + vpn)
    assert len(findings) == 1


def test_group_member_is_not_borrowed_from_another_vdom(tmp_path):
    group = ('config user group\n    edit "vpn-users"\n'
             '        set member "alice"\n    next\nend\n')
    vpn = VPN.replace('set users "alice"', 'set groups "vpn-users"')
    body = ('config vdom\n    edit "other"\n' + USER + group
            + '    next\n    edit "tenant"\n' + vpn + '    next\nend\n')
    _, findings = _scan(tmp_path, body)
    assert findings == []
