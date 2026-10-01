"""SC-046: effective management ACL source unions in first-match order."""

import contextlib
import io
import json

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.devices.cisco.ios import CiscoIOSParser
from src.main import main


LOW4 = "0.0.0.0 127.255.255.255"
HIGH4 = "128.0.0.0 127.255.255.255"


def _parser(tmp_path, acl, *, ipv6=False):
    source = tmp_path / "ios.conf"
    vty = ' ipv6 access-class MGMT6 in\n' if ipv6 else ' access-class MGMT in\n'
    web = 'ip http access-class ipv6 MGMT6\n' if ipv6 else 'ip http access-class ipv4 MGMT\n'
    source.write_text('version 17.9\nip ssh version 2\nip http secure-server\n'
                      + web + 'line vty 0 4\n transport input ssh\n' + vty
                      + acl + 'username audit secret 0 KeepThisMasked\n', encoding='utf-8')
    parser = CiscoIOSParser(str(source))
    parser.device_type = "IOS_XE"
    return parser


def _findings(parser):
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_cisco_ios_conf(parser).values())


def _ids(parser):
    return {item.rule_id for item in _findings(parser)}


def test_standard_ipv4_two_permits_cover_every_source(tmp_path):
    parser = _parser(tmp_path, 'ip access-list standard MGMT\n'
                     f' 10 permit {LOW4}\n 20 permit {HIGH4}\n')
    assert parser.get_management_ipv4_acl("MGMT").state == "permit-all"
    assert {"cisco.ios.ssh.unrestricted_sources", "cisco.ios.http.unrestricted_sources"}.issubset(
        _ids(parser))


@pytest.mark.parametrize("high,expected", [
    (HIGH4, "permit-all"),
    ("128.0.0.0 63.255.255.255", "restrictive"),
])
def test_extended_ipv4_union_requires_no_gap(tmp_path, high, expected):
    parser = _parser(tmp_path, 'ip access-list extended MGMT\n'
                     f' 10 permit tcp {LOW4} any\n 20 permit tcp {high} any\n')
    assert parser.get_management_ipv4_acl("MGMT", allow_extended=True).state == expected
    assert ("cisco.ios.ssh.unrestricted_sources" in _ids(parser)) is (expected == "permit-all")
    assert "cisco.ios.http.unrestricted_sources" not in _ids(parser)


def test_effective_deny_prevents_union_but_removed_deny_does_not(tmp_path):
    prefix = ('ip access-list standard MGMT\n'
              ' 5 deny host 192.0.2.1\n'
              f' 10 permit {LOW4}\n 20 permit {HIGH4}\n')
    assert _parser(tmp_path, prefix).get_management_ipv4_acl("MGMT").state == "restrictive"
    assert _parser(tmp_path, prefix + ' no 5\n').get_management_ipv4_acl("MGMT").state == "permit-all"


def test_deny_of_already_permitted_range_does_not_block_union(tmp_path):
    parser = _parser(tmp_path, 'ip access-list standard MGMT\n'
                     f' 10 permit {LOW4}\n 20 deny {LOW4}\n 30 permit {HIGH4}\n')
    assert parser.get_management_ipv4_acl("MGMT").state == "permit-all"


def test_ipv6_two_permits_cover_both_management_listeners(tmp_path):
    parser = _parser(tmp_path, 'ipv6 access-list MGMT6\n'
                     ' 10 permit tcp ::/1 any\n 20 permit tcp 8000::/1 any\n', ipv6=True)
    assert parser.get_management_ipv6_acl("MGMT6").state == "permit-all"
    assert {"cisco.ios.ssh.ipv6_unrestricted_sources",
            "cisco.ios.http.ipv6_unrestricted_sources"}.issubset(_ids(parser))


def test_ipv6_deny_and_unsupported_predicate_stay_ungraded(tmp_path):
    for first in ('5 deny tcp host 2001:db8::1 any',
                  '5 permit tcp ::/1 any eq 22'):
        parser = _parser(tmp_path, 'ipv6 access-list MGMT6\n'
                         f' {first}\n 10 permit tcp ::/1 any\n'
                         ' 20 permit tcp 8000::/1 any\n', ipv6=True)
        assert parser.get_management_ipv6_acl("MGMT6").state != "permit-all"
        assert "cisco.ios.ssh.ipv6_unrestricted_sources" not in _ids(parser)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_report_includes_union_without_secret(tmp_path, output_type):
    parser = _parser(tmp_path, 'ip access-list standard MGMT\n'
                     f' 10 permit {LOW4}\n 20 permit {HIGH4}\n')
    target = tmp_path / f"report.{output_type.lower()}"
    with contextlib.redirect_stdout(io.StringIO()):
        assert main(["-d", "ios-xe", "-i", parser.config_filepath,
                     "-o", output_type, "-f", str(target)]) == 0
    rendered = target.read_text(encoding="utf-8")
    assert "SSH management ACL permits every IPv4 source" in rendered
    assert "Web management ACL permits every IPv4 source" in rendered
    assert "KeepThisMasked" not in rendered
    if output_type == "JSON":
        assert json.loads(rendered)["security-audit"]
