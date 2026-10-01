"""SC-052: bounded source-union shadows and broad-allow first-match accuracy."""

import contextlib
import io

import pytest

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"


def _scan(tmp_path, body):
    source = tmp_path / "fortigate.conf"
    source.write_text(HEADER + body, encoding="utf-8")
    parser = FortiOSParser(str(source))
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_fortios_conf(parser).values())


def _rule(name, action, source, *, extra=""):
    return (f'    edit {name}\n'
            '        set srcintf "lan"\n        set dstintf "wan1"\n'
            f'        set srcaddr "{source}"\n        set dstaddr "all"\n'
            '        set service "ALL"\n        set schedule "always"\n'
            f'        set action {action}\n{extra}    next\n')


@pytest.mark.parametrize("family,all_address,first,second,gap", [
    ("ipv4", "all", "0.0.0.0 128.0.0.0", "128.0.0.0 128.0.0.0", "128.0.0.0 192.0.0.0"),
    ("ipv6", "all_ipv6", "::/1", "8000::/1", "8000::/2"),
])
def test_two_denies_shadow_broad_allow_only_when_union_complete(
    tmp_path, family, all_address, first, second, gap
):
    section = "firewall policy" if family == "ipv4" else "firewall policy6"
    object_section = "firewall address" if family == "ipv4" else "firewall address6"
    field = "subnet" if family == "ipv4" else "ip6"
    objects = (f'config {object_section}\n'
               f'    edit "LOW"\n        set {field} {first}\n    next\n'
               f'    edit "HIGH"\n        set {field} {second}\n    next\n'
               f'    edit "GAP"\n        set {field} {gap}\n    next\nend\n')
    for high, expected_shadow in (("HIGH", True), ("GAP", False)):
        policies = (f'config {section}\n' + _rule(1, "deny", "LOW")
                    + _rule(2, "deny", high) + _rule(3, "accept", all_address) + 'end\n')
        findings = _scan(tmp_path, objects + policies)
        ids = [item.rule_id for item in findings]
        assert ("fortinet.fortios.policy.shadowed_rule" in ids) is expected_shadow
        assert ("fortinet.fortios.policy.broad_accept" in ids) is not expected_shadow


def test_intervening_accept_prevents_deny_union_proof(tmp_path):
    objects = ('config firewall address\n'
               'edit LOW\nset subnet 0.0.0.0 128.0.0.0\nnext\n'
               'edit HIGH\nset subnet 128.0.0.0 128.0.0.0\nnext\nend\n')
    policies = ('config firewall policy\n' + _rule(1, "deny", "LOW")
                + _rule(2, "accept", "LOW") + _rule(3, "deny", "HIGH")
                + _rule(4, "accept", "all") + 'end\n')
    findings = _scan(tmp_path, objects + policies)
    broad = [item for item in findings if item.rule_id == "fortinet.fortios.policy.broad_accept"]
    assert len(broad) == 1 and "policy '4'" in broad[0].observation


def test_same_action_union_requires_equivalent_behavior(tmp_path):
    objects = ('config firewall address\n'
               'edit LOW\nset subnet 0.0.0.0 128.0.0.0\nnext\n'
               'edit HIGH\nset subnet 128.0.0.0 128.0.0.0\nnext\nend\n')
    policies = ('config firewall policy\n' + _rule(1, "accept", "LOW")
                + _rule(2, "accept", "HIGH", extra='        set logtraffic all\n')
                + _rule(3, "accept", "all") + 'end\n')
    findings = _scan(tmp_path, objects + policies)
    assert not any(item.rule_id == "fortinet.fortios.policy.redundant_rule"
                   and "policy '3'" in item.observation for item in findings)


def test_equivalent_same_action_source_union_is_redundant(tmp_path):
    objects = ('config firewall address\n'
               'edit LOW\nset subnet 0.0.0.0 128.0.0.0\nnext\n'
               'edit HIGH\nset subnet 128.0.0.0 128.0.0.0\nnext\nend\n')
    policies = ('config firewall policy\n' + _rule(1, "accept", "LOW")
                + _rule(2, "accept", "HIGH") + _rule(3, "accept", "all") + 'end\n')
    findings = _scan(tmp_path, objects + policies)
    redundant = [item for item in findings if item.rule_id == "fortinet.fortios.policy.redundant_rule"
                 and "policy '3'" in item.observation]
    assert len(redundant) == 1
    assert "'1', '2'" in redundant[0].observation


def test_policy_move_changes_first_match_union(tmp_path):
    objects = ('config firewall address\n'
               'edit LOW\nset subnet 0.0.0.0 128.0.0.0\nnext\n'
               'edit HIGH\nset subnet 128.0.0.0 128.0.0.0\nnext\nend\n')
    policies = ('config firewall policy\n' + _rule(1, "deny", "LOW")
                + _rule(2, "deny", "HIGH") + _rule(3, "accept", "all")
                + 'move 3 before 1\nend\n')
    findings = _scan(tmp_path, objects + policies)
    assert any(item.rule_id == "fortinet.fortios.policy.broad_accept" for item in findings)
    assert not any(item.rule_id == "fortinet.fortios.policy.shadowed_rule"
                   and item.observation.startswith(("IPv4 policy '3'", "IPV4 policy '3'"))
                   for item in findings)
