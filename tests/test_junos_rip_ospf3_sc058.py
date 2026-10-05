"""SC-058 (CIS Juniper OS 4.4.1, 4.5.1): RIP authentication and OSPFv3 IPsec."""

import contextlib
import io

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf
from src.devices.juniper.junos import JunOSParser

BASE = "set version 22.4R1\nset system host-name r1\n"
RIP = "set protocols rip group G neighbor ge-0/0/0.0\n"


def _rules(tmp_path, body, rule):
    path = tmp_path / "junos.conf"
    path.write_text(BASE + body, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_junos_conf(JunOSParser(str(path))).values()
    return [item for item in findings if item.rule_id == rule]


def test_rip_unauthenticated(tmp_path):
    findings = _rules(tmp_path, RIP, "juniper.junos.routing.rip.authentication")
    assert len(findings) == 1 and findings[0].basis is FindingBasis.DOCUMENTED_DEFAULT
    assert findings[0].severity is Severity.HIGH and guidance_for(findings[0].rule_id)


def test_rip_simple(tmp_path):
    body = RIP + "set protocols rip authentication-type simple\nset protocols rip authentication-key \"$9$x\"\n"
    assert _rules(tmp_path, body, "juniper.junos.routing.rip.cleartext_authentication")
    assert not _rules(tmp_path, body, "juniper.junos.routing.rip.authentication")


def test_rip_md5_clean(tmp_path):
    body = RIP + "set protocols rip authentication-type md5\nset protocols rip authentication-key \"$9$x\"\n"
    for rule in ("authentication", "cleartext_authentication"):
        assert not _rules(tmp_path, body, f"juniper.junos.routing.rip.{rule}")


@pytest.mark.parametrize("body,expected", [
    ("set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0\n", True),
    ("set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0 ipsec-sa SA1\n", False),
    ("set protocols ospf3 area 0.0.0.0 interface lo0.0\n", False),
    ("set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0 passive\n", False),
])
def test_ospf3(tmp_path, body, expected):
    findings = _rules(tmp_path, body, "juniper.junos.routing.ospf3.authentication")
    assert bool(findings) is expected
    if findings:
        assert guidance_for(findings[0].rule_id)


BFD = "set protocols bgp group EXT neighbor 192.0.2.1 bfd-liveness-detection minimum-interval 300\n"


def test_bfd_default_unauthenticated(tmp_path):
    findings = _rules(tmp_path, BFD, "juniper.junos.routing.bfd.authentication")
    assert len(findings) == 1 and findings[0].basis is FindingBasis.DOCUMENTED_DEFAULT
    assert guidance_for(findings[0].rule_id)


def test_bfd_authenticated_and_loose(tmp_path):
    auth = BFD + ("set protocols bgp group EXT neighbor 192.0.2.1 bfd-liveness-detection authentication algorithm keyed-sha-1\n"
                  "set protocols bgp group EXT neighbor 192.0.2.1 bfd-liveness-detection authentication key-chain BFD\n")
    assert not _rules(tmp_path, auth, "juniper.junos.routing.bfd.authentication")
    loose = auth + "set protocols bgp group EXT neighbor 192.0.2.1 bfd-liveness-detection authentication loose-check\n"
    findings = _rules(tmp_path, loose, "juniper.junos.routing.bfd.loose_authentication")
    assert len(findings) == 1 and guidance_for(findings[0].rule_id)


def test_autoinstall_router_discovery_and_hygiene(tmp_path):
    body = "set system autoinstallation interfaces ge-0/0/0\nset protocols router-discovery interface ge-0/0/0.0\n"
    for rule in ("juniper.junos.services.autoinstallation", "juniper.junos.routing.router_discovery",
                 "juniper.junos.hardening.cis_hygiene"):
        findings = _rules(tmp_path, body, rule)
        assert findings and guidance_for(rule)
    hygiene = _rules(tmp_path, body, "juniper.junos.hardening.cis_hygiene")[0]
    assert "CIS 6.5.3" in hygiene.observation
