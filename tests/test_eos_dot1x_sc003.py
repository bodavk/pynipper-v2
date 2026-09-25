"""SC-003 EOS stage: explicit 802.1X bypasses on assessed access-edge ports."""

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.common.assessment import AssessmentContext
from src.devices.arista.eos import AristaEOSParser

FORCE = "arista.eos.layer2.access_edge.dot1x_force_authorized"
GLOBAL = "arista.eos.layer2.access_edge.dot1x_global_disabled"
HEADER = "! device: leaf (DCS-7050SX3-48YC8, EOS-4.30.1F)\nhostname leaf\n"


def _run(tmp_path, body, roles=(("Ethernet1", "access-edge"),)):
    path = tmp_path / "eos.conf"
    path.write_text(HEADER + body, encoding="utf-8")
    parser = AristaEOSParser(str(path))
    parser.set_assessment_context(AssessmentContext(interface_roles=tuple(roles)))
    return [item.rule_id for item in process_arista_conf(parser).values() if item.rule_id in {FORCE, GLOBAL}]


@pytest.mark.parametrize("body,expected", [
    ("dot1x system-auth-control\ninterface Ethernet1\n   dot1x pae authenticator\n   dot1x port-control force-authorized\n", [FORCE]),
    ("no dot1x system-auth-control\ninterface Ethernet1\n   dot1x pae authenticator\n   dot1x port-control auto\n", [GLOBAL]),
    ("dot1x system-auth-control\ninterface Ethernet1\n   dot1x pae authenticator\n   dot1x port-control auto\n", []),
    ("dot1x system-auth-control\ninterface Ethernet1\n   dot1x port-control force-authorized\n   no dot1x port-control\n", []),
    ("dot1x system-auth-control\ninterface Ethernet1\n   no switchport\n   dot1x port-control force-authorized\n", []),
    ("dot1x system-auth-control\ninterface Ethernet1\n   shutdown\n   dot1x port-control force-authorized\n", []),
])
def test_explicit_bypasses(tmp_path, body, expected):
    assert _run(tmp_path, body) == expected


def test_unassessed_role_is_not_reported(tmp_path):
    body = "interface Ethernet1\n   dot1x port-control force-authorized\n"
    assert _run(tmp_path, body, roles=()) == []
