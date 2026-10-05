"""SC-005 EOS OSPFv2 interface authentication and IS-IS clear-text mode."""

import contextlib
import io

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis, Severity
from src.devices.arista.eos import AristaEOSParser


def _run(tmp_path, body):
    path = tmp_path / "eos.conf"
    path.write_text("! device: leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)\nhostname leaf\n" + body, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return list(process_arista_conf(AristaEOSParser(str(path))).values())


def _rules(findings, rule):
    return [finding for finding in findings if finding.rule_id == rule]


OSPF = ("interface Ethernet1\n   no switchport\n   ip address 10.0.0.1/31\n   ip ospf area 0.0.0.0\n{auth}"
        "interface Ethernet2\n   ip ospf area 0.0.0.0\n   shutdown\n"
        "interface Loopback0\n   ip ospf area 0.0.0.0\n"
        "router ospf 1\n   router-id 10.0.0.1\n{router}")


def test_unauthenticated_ospf(tmp_path):
    findings = _rules(_run(tmp_path, OSPF.format(auth="", router="")), "arista.eos.routing.ospf.authentication")
    assert len(findings) == 1
    assert findings[0].basis is FindingBasis.DOCUMENTED_DEFAULT
    assert "Ethernet1" in findings[0].observation
    assert "Ethernet2" not in findings[0].observation and "Loopback0" not in findings[0].observation
    assert guidance_for("arista.eos.routing.ospf.authentication")


def test_simple_password(tmp_path):
    findings = _run(tmp_path, OSPF.format(auth="   ip ospf authentication\n", router=""))
    assert _rules(findings, "arista.eos.routing.ospf.weak_authentication")[0].severity is Severity.MEDIUM
    assert not _rules(findings, "arista.eos.routing.ospf.authentication")
    assert guidance_for("arista.eos.routing.ospf.weak_authentication")


def test_digest_passive_and_area_auth_not_reported(tmp_path):
    for auth, router in (("   ip ospf authentication message-digest\n", ""),
                         ("", "   passive-interface Ethernet1\n"),
                         ("", "   area 0.0.0.0 authentication message-digest\n")):
        findings = _run(tmp_path, OSPF.format(auth=auth, router=router))
        assert not _rules(findings, "arista.eos.routing.ospf.authentication")
        assert not _rules(findings, "arista.eos.routing.ospf.weak_authentication")


def test_isis_text_mode(tmp_path):
    body = "router isis CORE\n   net 49.0001.0000.0000.0001.00\n   authentication mode text\n"
    findings = _rules(_run(tmp_path, body), "arista.eos.routing.isis.cleartext_authentication")
    assert len(findings) == 1
    assert guidance_for("arista.eos.routing.isis.cleartext_authentication")
    assert not _rules(_run(tmp_path, body.replace("text", "md5")), "arista.eos.routing.isis.cleartext_authentication")
