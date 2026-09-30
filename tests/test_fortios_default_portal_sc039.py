"""SC-039: explicitly permissive SSL-VPN fallback portals."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


RULE = "fortinet.fortios.sslvpn.active_default_portal"
HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
VPN = ('config vpn ssl settings\n    set status enable\n'
       '    set source-interface "wan1"\n'
       '    set default-portal "fallback"\nend\n')
PORTAL = ('config vpn ssl web portal\n    edit "fallback"\n'
          '        set web-mode enable\n        set tunnel-mode disable\n'
          '        set ipv6-tunnel-mode disable\n    next\nend\n')


def _scan(tmp_path, body, header=HEADER):
    source = tmp_path / "fortigate.conf"
    source.write_text(header + body, encoding="utf-8")
    parser = FortiOSParser(str(source))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = list(process_fortios_conf(parser).values())
    return parser, [item for item in findings if item.rule_id == RULE]


def test_explicit_web_enabled_fallback_portal(tmp_path):
    parser, findings = _scan(tmp_path, VPN + PORTAL)
    assert len(parser.get_sslvpn_active_default_portals()) == 1
    assert len(findings) == 1
    assert findings[0].basis == FindingBasis.EXPLICIT_VALUE
    assert "web-mode" in findings[0].observation
    assert "does not prove successful login" in findings[0].observation
    assert guidance_for(RULE) is not None


@pytest.mark.parametrize("mode", ["tunnel-mode", "ipv6-tunnel-mode"])
def test_ipv4_and_ipv6_tunnel_modes_are_separately_resolved(tmp_path, mode):
    portal = PORTAL.replace('set web-mode enable', 'set web-mode disable')
    portal = portal.replace(f'set {mode} disable', f'set {mode} enable')
    _, findings = _scan(tmp_path, VPN + portal)
    assert len(findings) == 1
    assert mode in findings[0].observation


@pytest.mark.parametrize("body", [
    VPN.replace('set status enable', 'set status disable') + PORTAL,
    VPN.replace('set status enable', '') + PORTAL,
    VPN.replace('set source-interface "wan1"', '') + PORTAL,
    VPN.replace('set default-portal "fallback"', '') + PORTAL,
    VPN.replace('set default-portal "fallback"', 'set default-portal "missing"') + PORTAL,
    VPN + PORTAL.replace('set web-mode enable', 'set web-mode disable'),
    VPN + PORTAL.replace('set web-mode enable', ''),
])
def test_inactive_unresolved_or_nonpermissive_fallback_is_ungraded(tmp_path, body):
    parser, findings = _scan(tmp_path, body)
    assert parser.get_sslvpn_active_default_portals() == ()
    assert findings == []


def test_later_release_is_ungraded_until_agentless_semantics_are_qualified(tmp_path):
    _, findings = _scan(tmp_path, VPN + PORTAL, HEADER.replace("7.4.1", "7.6.1"))
    assert findings == []


def test_default_portal_is_not_borrowed_from_another_vdom(tmp_path):
    body = ('config vdom\n    edit "other"\n' + PORTAL
            + '    next\n    edit "tenant"\n' + VPN + '    next\nend\n')
    _, findings = _scan(tmp_path, body)
    assert findings == []
