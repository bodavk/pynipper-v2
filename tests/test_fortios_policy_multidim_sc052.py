"""SC-052: bounded multi-dimensional first-match coverage."""

import contextlib
import io
import json

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser
from src.main import main


HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"


def _rule(name, action, source, destination, service="HTTPS", extra=""):
    return (f"    edit {name}\n"
            '        set srcintf "lan"\n        set dstintf "wan1"\n'
            f'        set srcaddr "{source}"\n        set dstaddr "{destination}"\n'
            f'        set service "{service}"\n        set schedule "always"\n'
            f"        set action {action}\n{extra}    next\n")


def _scan(tmp_path, body):
    source = tmp_path / "fortigate.conf"
    source.write_text(HEADER + body, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        findings = list(process_fortios_conf(FortiOSParser(str(source))).values())
    return findings


def _ids_for(findings, name):
    return {item.rule_id for item in findings if f"policy '{name}'" in item.observation}


def test_destination_union_shadows_later_allow(tmp_path):
    body = ('config firewall policy\n'
            + _rule(1, "deny", "10.0.0.0/24", "192.0.2.0/25")
            + _rule(2, "deny", "10.0.0.0/24", "192.0.2.128/25")
            + _rule(3, "accept", "10.0.0.0/24", "192.0.2.0/24") + 'end\n')
    assert "fortinet.fortios.policy.shadowed_rule" in _ids_for(_scan(tmp_path, body), "3")


def test_service_union_shadows_later_allow(tmp_path):
    group = ('config firewall service group\n    edit "WEB"\n'
             '        set member "HTTP" "HTTPS"\n    next\nend\n')
    body = (group + 'config firewall policy\n'
            + _rule(1, "deny", "10.0.0.0/24", "192.0.2.0/24", "HTTP")
            + _rule(2, "deny", "10.0.0.0/24", "192.0.2.0/24", "HTTPS")
            + _rule(3, "accept", "10.0.0.0/24", "192.0.2.0/24", "WEB") + 'end\n')
    assert "fortinet.fortios.policy.shadowed_rule" in _ids_for(_scan(tmp_path, body), "3")


def test_checkerboard_union_requires_every_cell(tmp_path):
    cells = (
        ("10.0.0.0/25", "192.0.2.0/25"),
        ("10.0.0.128/25", "192.0.2.0/25"),
        ("10.0.0.0/25", "192.0.2.128/25"),
        ("10.0.0.128/25", "192.0.2.128/25"),
    )
    for count in (3, 4):
        body = ('config firewall policy\n'
                + ''.join(_rule(number, "deny", *cell)
                          for number, cell in enumerate(cells[:count], start=1))
                + _rule(5, "accept", "10.0.0.0/24", "192.0.2.0/24") + 'end\n')
        ids = _ids_for(_scan(tmp_path, body), "5")
        assert ("fortinet.fortios.policy.shadowed_rule" in ids) is (count == 4)


def test_ipv6_destination_union_stays_in_its_own_family(tmp_path):
    body = ('config firewall policy6\n'
            + _rule(1, "deny", "2001:db8:1::/64", "2001:db8:2::/65")
            + _rule(2, "deny", "2001:db8:1::/64", "2001:db8:2:0:8000::/65")
            + _rule(3, "accept", "2001:db8:1::/64", "2001:db8:2::/64") + 'end\n')
    assert "fortinet.fortios.policy.shadowed_rule" in _ids_for(_scan(tmp_path, body), "3")


def test_udp_port_cannot_complete_tcp_service_union(tmp_path):
    objects = ('config firewall service custom\n'
               '    edit "UDP80"\n        set udp-portrange 80\n    next\nend\n'
               'config firewall service group\n    edit "WEB"\n'
               '        set member "HTTP" "HTTPS"\n    next\nend\n')
    body = (objects + 'config firewall policy\n'
            + _rule(1, "deny", "10.0.0.0/24", "192.0.2.0/24", "UDP80")
            + _rule(2, "deny", "10.0.0.0/24", "192.0.2.0/24", "HTTPS")
            + _rule(3, "accept", "10.0.0.0/24", "192.0.2.0/24", "WEB") + 'end\n')
    assert "fortinet.fortios.policy.shadowed_rule" not in _ids_for(_scan(tmp_path, body), "3")


def test_broad_allow_is_suppressed_only_for_complete_destination_union(tmp_path):
    for second, covered in (("128.0.0.0/1", True), ("128.0.0.0/2", False)):
        body = ('config firewall policy\n'
                + _rule(1, "deny", "all", "0.0.0.0/1", "ALL")
                + _rule(2, "deny", "all", second, "ALL")
                + _rule(3, "accept", "all", "all", "ALL") + 'end\n')
        ids = _ids_for(_scan(tmp_path, body), "3")
        assert ("fortinet.fortios.policy.shadowed_rule" in ids) is covered
        assert ("fortinet.fortios.policy.broad_accept" in ids) is not covered


def test_different_behavior_prevents_same_action_union(tmp_path):
    body = ('config firewall policy\n'
            + _rule(1, "accept", "10.0.0.0/24", "192.0.2.0/25")
            + _rule(2, "accept", "10.0.0.0/24", "192.0.2.128/25",
                    extra='        set logtraffic all\n')
            + _rule(3, "accept", "10.0.0.0/24", "192.0.2.0/24") + 'end\n')
    assert "fortinet.fortios.policy.redundant_rule" not in _ids_for(_scan(tmp_path, body), "3")


def test_public_json_report_contains_multidimensional_shadow(tmp_path):
    source = tmp_path / "fortigate.conf"
    source.write_text(HEADER + 'config firewall policy\n'
                      + _rule(1, "deny", "10.0.0.0/24", "192.0.2.0/25")
                      + _rule(2, "deny", "10.0.0.0/24", "192.0.2.128/25")
                      + _rule(3, "accept", "10.0.0.0/24", "192.0.2.0/24")
                      + 'end\n', encoding="utf-8")
    report = tmp_path / "report.json"
    with contextlib.redirect_stdout(io.StringIO()):
        assert main(["-d", "fortios", "-i", str(source), "-o", "JSON",
                     "-f", str(report), "-x"]) == 0
    assert "fortinet.fortios.policy.shadowed_rule" in json.dumps(
        json.loads(report.read_text(encoding="utf-8")))
