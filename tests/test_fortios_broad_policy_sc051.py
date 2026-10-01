"""SC-051: resolved IPv4/IPv6 all-address, all-service policies."""

import contextlib
import io

import pytest

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"


def _scan(tmp_path, policy, objects=""):
    source = tmp_path / "fortigate.conf"
    source.write_text(HEADER + objects + policy, encoding="utf-8")
    parser = FortiOSParser(str(source))
    with contextlib.redirect_stdout(io.StringIO()):
        findings = list(process_fortios_conf(parser).values())
    return findings


def _policy(family, source, destination, service="ALL", extra=""):
    section = "firewall policy" if family == "ipv4" else "firewall policy6"
    return (f'config {section}\n    edit 1\n'
            '        set srcintf "lan"\n        set dstintf "wan1"\n'
            f'        set srcaddr "{source}"\n        set dstaddr "{destination}"\n'
            f'        set service "{service}"\n        set schedule "always"\n'
            f'        set action accept\n{extra}    next\nend\n')


@pytest.mark.parametrize("family,any_address", [("ipv4", "all"), ("ipv6", "all_ipv6")])
def test_literal_all_addresses_have_one_broad_finding(tmp_path, family, any_address):
    findings = _scan(tmp_path, _policy(family, any_address, any_address))
    rules = [finding.rule_id for finding in findings]
    assert rules.count("fortinet.fortios.policy.broad_accept") == 1
    assert "fortinet.fortios.policy.broad_service" not in rules


@pytest.mark.parametrize("family,address_section,group_section,field,first,second", [
    ("ipv4", "address", "addrgrp", "subnet", "0.0.0.0 128.0.0.0", "128.0.0.0 128.0.0.0"),
    ("ipv6", "address6", "addrgrp6", "ip6", "::/1", "8000::/1"),
])
def test_complete_static_address_group_union_is_broad(
    tmp_path, family, address_section, group_section, field, first, second
):
    objects = (f'config firewall {address_section}\n'
               f'    edit "first"\n        set {field} {first}\n    next\n'
               f'    edit "second"\n        set {field} {second}\n    next\nend\n'
               f'config firewall {group_section}\n    edit "WHOLE"\n'
               '        set member "first" "second"\n    next\nend\n')
    findings = _scan(tmp_path, _policy(family, "WHOLE", "WHOLE"), objects)
    assert sum(f.rule_id == "fortinet.fortios.policy.broad_accept" for f in findings) == 1


@pytest.mark.parametrize("extra", [
    "        set status disable\n",
    "        set srcaddr-negate enable\n",
    '        set groups "staff"\n',
])
def test_inactive_negated_or_identity_condition_is_not_proven_broad(tmp_path, extra):
    findings = _scan(tmp_path, _policy("ipv6", "all_ipv6", "all_ipv6", extra=extra))
    assert not any(f.rule_id == "fortinet.fortios.policy.broad_accept" for f in findings)


def test_unresolved_destination_does_not_imply_broad(tmp_path):
    findings = _scan(tmp_path, _policy("ipv6", "all_ipv6", "UNKNOWN"))
    assert not any(f.rule_id == "fortinet.fortios.policy.broad_accept" for f in findings)


def test_unexported_schedule_default_is_not_inferred(tmp_path):
    policy = _policy("ipv6", "all_ipv6", "all_ipv6").replace('set schedule "always"\n', '')
    findings = _scan(tmp_path, policy)
    assert not any(f.rule_id == "fortinet.fortios.policy.broad_accept" for f in findings)
