"""SC-043: resolved source networks, not just the literal 'all' object."""

import contextlib
import io

import pytest

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
SERVICE = ('config firewall service custom\n    edit "TELNET"\n'
           '        set tcp-portrange 23\n    next\nend\n')
RULE = "fortinet.fortios.policy.risky_service_exposure"


def _scan(tmp_path, body, *, family="ipv4", extra=""):
    section = "firewall policy" if family == "ipv4" else "firewall policy6"
    source = tmp_path / "fortigate.conf"
    source.write_text(HEADER + SERVICE + body + f'config {section}\n'
                      '    edit 1\n        set srcintf "wan1"\n'
                      '        set dstintf "lan"\n        set srcaddr "SOURCES"\n'
                      '        set dstaddr "all"\n        set action accept\n'
                      '        set schedule "always"\n        set service "TELNET"\n'
                      + extra +
                      '    next\nend\n', encoding="utf-8")
    parser = FortiOSParser(str(source))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = list(process_fortios_conf(parser).values())
    return parser, [item for item in findings if item.rule_id == RULE]


@pytest.mark.parametrize("sources,expected", [
    ('config firewall address\n    edit "SOURCES"\n'
     '        set subnet 0.0.0.0 0.0.0.0\n    next\nend\n', True),
    ('config firewall address\n    edit "SOURCES"\n'
     '        set subnet 198.51.100.0 255.255.255.0\n    next\nend\n', False),
    ('config firewall addrgrp\n    edit "SOURCES"\n'
     '        set member "UNKNOWN"\n    next\nend\n', False),
])
def test_ipv4_resolved_source_is_assessed_without_literal_all(tmp_path, sources, expected):
    parser, findings = _scan(tmp_path, sources)
    assert parser.get_firewall_policy_semantics()[0].source_unrestricted is expected
    assert bool(findings) is expected


def test_union_of_ipv4_address_group_members_covers_every_source(tmp_path):
    sources = ('config firewall address\n'
               '    edit "LOW"\n        set subnet 0.0.0.0 128.0.0.0\n    next\n'
               '    edit "HIGH"\n        set subnet 128.0.0.0 128.0.0.0\n    next\nend\n'
               'config firewall addrgrp\n    edit "SOURCES"\n'
               '        set member "LOW" "HIGH"\n    next\nend\n')
    _, findings = _scan(tmp_path, sources)
    assert len(findings) == 1
    assert "every address" in findings[0].observation


def test_ipv6_resolved_full_range_source(tmp_path):
    source = ('config firewall address6\n    edit "SOURCES"\n'
              '        set ip6 ::/0\n    next\nend\n')
    parser, findings = _scan(tmp_path, source, family="ipv6")
    assert parser.get_firewall_policy_semantics()[0].source_unrestricted
    assert len(findings) == 1
    assert "ipv6" in findings[0].observation


def test_unsupported_identity_predicate_keeps_risky_service_ungraded(tmp_path):
    source = ('config firewall address\n    edit "SOURCES"\n'
              '        set subnet 0.0.0.0 0.0.0.0\n    next\nend\n')
    parser, findings = _scan(tmp_path, source, extra='        set groups "admins"\n')
    assert parser.get_firewall_policy_semantics()[0].source_unrestricted
    assert parser.get_firewall_policy_semantics()[0].unsupported_predicates == ("groups",)
    assert findings == []
