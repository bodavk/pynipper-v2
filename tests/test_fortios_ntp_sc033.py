"""SC-033: NTP exposure requires an assessed, configured-up listener."""

import pytest

from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.common.assessment import AssessmentContext
from src.devices.fortinet.fortios import FortiOSParser


RULE = "fortinet.fortios.ntp.server_exposed"
NTP = "config system ntp\nset server-mode enable\nset interface wan1\nend\n"


def _scan(tmp_path, interface, *, role=None, ntp=NTP):
    path = tmp_path / "fortios.conf"
    path.write_text(interface + ntp, encoding="utf-8")
    parser = FortiOSParser(str(path))
    if role is not None:
        parser.set_assessment_context(AssessmentContext.from_mapping({
            "interface_roles": {"wan1": role},
        }))
    findings = [item for item in process_fortios_conf(parser).values() if item.rule_id == RULE]
    return parser, findings


@pytest.mark.parametrize("interface,role,expected", [
    ("config system interface\nedit wan1\nset status up\nnext\nend\n", "external", True),
    ("config system interface\nedit wan1\nset status up\nnext\nend\n", None, False),
    ("config system interface\nedit wan1\nset role wan\nset status up\nnext\nend\n", "internal", False),
    ("config system interface\nedit wan1\nset role wan\nset status up\nnext\nend\n", None, False),
    ("config system interface\nedit wan1\nset status down\nnext\nend\n", "external", False),
    ("config system interface\nedit wan1\nnext\nend\n", "external", False),
    ("", "external", False),
])
def test_name_and_vendor_role_do_not_replace_assessed_external_scope(
    tmp_path, interface, role, expected
):
    parser, findings = _scan(tmp_path, interface, role=role)
    assert bool(findings) is expected
    assert bool(parser.get_ntp_server_exposures()) is expected
    if expected:
        assert "not prove Internet reachability" in findings[0].observation
        assert "set status up" in " ".join(findings[0].evidence)


def test_disabled_server_and_nonmatching_scope_do_not_report(tmp_path):
    interface = "config system interface\nedit wan1\nset status up\nnext\nend\n"
    _, disabled = _scan(tmp_path, interface, role="external",
                        ntp=NTP.replace("set server-mode enable", "set server-mode disable"))
    assert not disabled
    vdom = "config vdom\nedit blue\n" + NTP + "next\nend\n"
    _, mismatched = _scan(tmp_path, interface, role="external", ntp=vdom)
    assert not mismatched
