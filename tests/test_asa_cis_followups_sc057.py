"""SC-057: CIS ASA follow-ups."""

import contextlib
import io

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.analyze.common.guidance import guidance_for
from src.common.assessment import AssessmentContext
from src.devices import get_parser

OUTSIDE = "interface GigabitEthernet0/0\n nameif outside\n security-level 10\n"


def _rules(tmp_path, body, roles=None):
    path = tmp_path / "asa.conf"
    path.write_text("ASA Version 9.18(4)\nhostname fw\n" + body, encoding="utf-8")
    parser = get_parser("ASA", str(path))
    if roles:
        parser.set_assessment_context(AssessmentContext.from_mapping({"interface_roles": roles}))
    with contextlib.redirect_stdout(io.StringIO()):
        return {f.rule_id: f for f in process_asa_conf(parser).values()}


def test_authorization_missing_with_remote_auth(tmp_path):
    rules = _rules(tmp_path, "aaa-server T protocol tacacs+\naaa authentication ssh console T LOCAL\n")
    assert "cisco.asa.aaa.management_authorization" in rules
    ok = _rules(tmp_path, "aaa-server T protocol tacacs+\naaa authentication ssh console T LOCAL\n"
                          "aaa authorization command T LOCAL\naaa authorization exec authentication-server\n")
    assert "cisco.asa.aaa.management_authorization" not in ok
    assert guidance_for("cisco.asa.aaa.management_authorization")


def test_routing_authentication(tmp_path):
    body = ("router ospf 1\n network 10.0.0.0 255.0.0.0 area 0\n"
            "router bgp 65000\n address-family ipv4 unicast\n  neighbor 192.0.2.1 remote-as 65001\n")
    rules = _rules(tmp_path, body)
    assert {"cisco.asa.routing.ospf.authentication", "cisco.asa.routing.bgp.authentication"} <= set(rules)
    secured = _rules(tmp_path, body.replace("area 0\n", "area 0\n area 0 authentication message-digest\n")
                     + "  neighbor 192.0.2.1 password 0 secret\n")
    assert not {"cisco.asa.routing.ospf.authentication", "cisco.asa.routing.bgp.authentication"} & set(secured)
    assert "secret" not in repr(rules["cisco.asa.routing.bgp.authentication"])


def test_external_interface_protections(tmp_path):
    rules = _rules(tmp_path, OUTSIDE + "dhcpd enable outside\nno dns-guard\n", roles={"outside": "external"})
    for rule in ("cisco.asa.interface.external_security_level", "cisco.asa.services.external_dhcp_server",
                 "cisco.asa.services.dns_guard_disabled"):
        assert rule in rules and guidance_for(rule)
    assert "cisco.asa.services.external_dhcp_server" not in _rules(tmp_path, OUTSIDE + "dhcpd enable outside\n")
