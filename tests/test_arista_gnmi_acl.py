"""SC-046/SC-026 EOS gNMI transport source restriction."""

import contextlib
import io

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.devices.arista.eos import AristaEOSParser

RULE = "arista.eos.management.unrestricted_gnmi"


def _run(tmp_path, transport_extra="", acls=""):
    body = (acls + "management api gnmi\n   transport grpc default\n      no shutdown\n"
            "      ssl profile GNMI\n" + transport_extra)
    path = tmp_path / "eos.conf"
    path.write_text("! device: leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)\nhostname leaf\n" + body, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        findings = process_arista_conf(AristaEOSParser(str(path))).values()
    return [finding for finding in findings if finding.rule_id == RULE]


def test_no_acl(tmp_path):
    findings = _run(tmp_path)
    assert len(findings) == 1 and findings[0].basis is None
    assert guidance_for(RULE)


def test_permit_all_acl(tmp_path):
    acls = "ip access-list GNMI-ACL\n   10 permit ip any any\n"
    findings = _run(tmp_path, "      ip access-group GNMI-ACL\n", acls)
    assert len(findings) == 1 and findings[0].basis is FindingBasis.EXPLICIT_VALUE


@pytest.mark.parametrize("extra,acls", [
    ("      ip access-group GNMI-ACL\n", "ip access-list GNMI-ACL\n   10 permit ip 192.0.2.0/24 any\n"),
    ("      shutdown\n", ""),
])
def test_not_reported(tmp_path, extra, acls):
    assert not _run(tmp_path, extra, acls)
