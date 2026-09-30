"""SC-026: qualified FortiGate recursive DNS admission on an external interface."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.common.assessment import AssessmentContext
from src.devices.fortinet.fortios import FortiOSParser


RULE = "fortinet.fortios.dns.broad_resolution_service"
HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
INTERFACE = ('config system interface\n    edit "wan1"\n'
             '        set status up\n    next\nend\n')
DNS = ('config system dns-server\n    edit "wan1"\n'
       '        set mode recursive\n    next\nend\n')
ALLOW = ('config firewall local-in-policy\n    edit 1\n'
         '        set status enable\n        set intf "wan1"\n'
         '        set srcaddr "all"\n        set dstaddr "all"\n'
         '        set service "DNS"\n        set schedule "always"\n'
         '        set action accept\n'
         '        set srcaddr-negate disable\n'
         '        set dstaddr-negate disable\n'
         '        set service-negate disable\n    next\nend\n')


def _scan(tmp_path, body, *, role="external", header=HEADER):
    source = tmp_path / "fortigate.conf"
    source.write_text(header + body, encoding="utf-8")
    parser = FortiOSParser(str(source))
    parser.set_assessment_context(AssessmentContext.from_mapping({
        "interface_roles": {"wan1": role},
    }))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = list(process_fortios_conf(parser).values())
    return parser, [item for item in findings if item.rule_id == RULE]


def test_explicit_external_recursive_dns_and_broad_first_local_in_allow(tmp_path):
    parser, findings = _scan(tmp_path, INTERFACE + DNS + ALLOW)
    assert len(parser.get_dns_broad_resolvers()) == 1
    assert len(findings) == 1
    assert findings[0].basis == FindingBasis.EXPLICIT_VALUE
    assert "not proof of Internet reachability" in findings[0].observation
    assert guidance_for(RULE) is not None


def test_forward_only_dns_resolves_named_broad_source_and_udp_service(tmp_path):
    objects = ('config firewall addrgrp\n    edit "EVERYWHERE"\n'
               '        set member "all"\n    next\nend\n'
               'config firewall service custom\n    edit "DNS-UDP"\n'
               '        set udp-portrange 53\n    next\nend\n')
    policy = ALLOW.replace('set srcaddr "all"', 'set srcaddr "EVERYWHERE"')
    policy = policy.replace('set service "DNS"', 'set service "DNS-UDP"')
    _, findings = _scan(tmp_path, objects + INTERFACE + DNS.replace("recursive", "forward-only") + policy)
    assert len(findings) == 1
    assert "forward-only DNS" in findings[0].observation


def test_explicit_full_ipv4_subnet_is_broad_dns_source(tmp_path):
    policy = ALLOW.replace('set srcaddr "all"', 'set srcaddr "0.0.0.0/0"')
    _, findings = _scan(tmp_path, INTERFACE + DNS + policy)
    assert len(findings) == 1


@pytest.mark.parametrize("body,role", [
    (INTERFACE + DNS, "external"),
    (INTERFACE + DNS + ALLOW, "internal"),
    (INTERFACE + DNS.replace("recursive", "non-recursive") + ALLOW, "external"),
    (INTERFACE.replace("status up", "status down") + DNS + ALLOW, "external"),
    (INTERFACE + ALLOW, "external"),
    (INTERFACE + DNS + ALLOW.replace('set srcaddr "all"', 'set srcaddr "TRUSTED"'), "external"),
    (INTERFACE + DNS + ALLOW.replace('set schedule "always"', 'set schedule "workhours"'), "external"),
    (INTERFACE + DNS + ALLOW.replace("set service \"DNS\"", "set service \"HTTPS\""), "external"),
    (INTERFACE + DNS + ALLOW.replace("set srcaddr-negate disable", "set srcaddr-negate enable"), "external"),
])
def test_dns_broad_resolver_requires_proven_active_permission(tmp_path, body, role):
    parser, findings = _scan(tmp_path, body, role=role)
    assert parser.get_dns_broad_resolvers() == ()
    assert findings == []


def test_earlier_local_in_rule_keeps_dns_permission_unknown(tmp_path):
    earlier = ('config firewall local-in-policy\n    edit 0\n'
               '        set status enable\n        set intf "wan1"\n'
               '        set srcaddr "all"\n        set dstaddr "all"\n'
               '        set service "DNS"\n        set schedule "always"\n'
               '        set action deny\n    next\nend\n')
    _, findings = _scan(tmp_path, INTERFACE + DNS + earlier + ALLOW)
    assert findings == []


def test_dns_broad_resolver_does_not_assume_later_release_local_in_state(tmp_path):
    header = HEADER.replace("7.4.1", "7.6.1")
    _, findings = _scan(tmp_path, INTERFACE + DNS + ALLOW, header=header)
    assert findings == []
