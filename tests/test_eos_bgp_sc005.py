"""SC-005 EOS stage: default-VRF IPv4 unicast BGP neighbors (Arista EOS BGP chapter)."""

import pytest

from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.common.issue import FindingBasis
from src.devices.arista.eos import AristaEOSParser

HEADER = "! device: edge (DCS-7280SR3-48YC8, EOS-4.30.1F)\nhostname edge\n"
PREFIX = "arista.eos.routing.bgp."


def _run(tmp_path, body):
    path = tmp_path / "eos.conf"
    path.write_text(HEADER + body, encoding="utf-8")
    parser = AristaEOSParser(str(path))
    findings = {f.rule_id.removeprefix(PREFIX): f for f in process_arista_conf(parser).values()
                if f.rule_id.startswith(PREFIX)}
    return parser, findings


SECURE_PEER = (
    "route-map IN permit 10\n   match ip address prefix-list CUSTOMER\n"
    "route-map OUT permit 10\n   match ip address prefix-list OURS\n"
    "router bgp 65001\n"
    "   neighbor 198.51.100.1 remote-as 65002\n"
    "   neighbor 198.51.100.1 password 7 AbCdEf==\n"
    "   neighbor 198.51.100.1 route-map IN in\n"
    "   neighbor 198.51.100.1 route-map OUT out\n"
)


def test_protected_external_peer_is_not_reported(tmp_path):
    parser, findings = _run(tmp_path, SECURE_PEER)
    peer, = parser.get_bgp_neighbors()
    assert (peer.peer_role, peer.active, peer.authentication_state) == ("external", True, "authenticated")
    assert findings == {}


def test_unprotected_external_peer(tmp_path):
    _, findings = _run(tmp_path, "router bgp 65001\n   neighbor 198.51.100.1 remote-as 65002\n")
    assert set(findings) == {"authentication", "inbound_policy", "outbound_policy"}
    assert findings["authentication"].basis is FindingBasis.REQUIRED_SETTING_MISSING
    assert findings["inbound_policy"].basis is FindingBasis.MISSING_EXPLICIT_SETTING


def test_peer_group_settings_are_inherited(tmp_path):
    body = SECURE_PEER.replace("   neighbor 198.51.100.1 remote-as 65002\n", "") \
        .replace("neighbor 198.51.100.1 ", "neighbor EXT ") + (
        "   neighbor EXT peer group\n   neighbor EXT remote-as 65002\n"
        "   neighbor 198.51.100.1 peer group EXT\n")
    parser, findings = _run(tmp_path, body)
    assert [p.address for p in parser.get_bgp_neighbors() if p.address != "EXT"] == ["198.51.100.1"]
    assert findings == {}


def test_undefined_route_map_is_permit_all_by_default(tmp_path):
    body = SECURE_PEER.replace("route-map IN permit 10\n   match ip address prefix-list CUSTOMER\n", "")
    _, findings = _run(tmp_path, body)
    assert set(findings) == {"missing_route_map"}
    assert findings["missing_route_map"].basis is FindingBasis.DOCUMENTED_DEFAULT
    _, findings = _run(tmp_path, body.replace("router bgp 65001\n",
                                              "router bgp 65001\n   bgp missing-policy direction in action deny\n"))
    assert findings == {}


def test_permit_all_route_map_and_unlimited_routes(tmp_path):
    body = SECURE_PEER.replace("   match ip address prefix-list CUSTOMER\n", "") + \
        "   neighbor 198.51.100.1 maximum-routes 0\n"
    _, findings = _run(tmp_path, body)
    assert set(findings) == {"permit_all_route_map", "prefix_limit_disabled"}


def test_absent_maximum_routes_is_not_reported(tmp_path):
    _, findings = _run(tmp_path, SECURE_PEER)
    assert "prefix_limit_disabled" not in findings


@pytest.mark.parametrize("body", [
    "router bgp 65001\n   neighbor 10.0.0.2 remote-as 65001\n   neighbor 10.0.0.2 password 7 x\n",  # iBGP: auth only
    "router bgp 65001\n   no bgp default ipv4-unicast\n   neighbor 198.51.100.1 remote-as 65002\n",
    "router bgp 65001\n   neighbor 198.51.100.1 remote-as 65002\n   neighbor 198.51.100.1 shutdown\n",
    "router bgp 65001\n   vrf CUST\n      neighbor 198.51.100.1 remote-as 65002\n",
])
def test_not_assessed(tmp_path, body):
    _, findings = _run(tmp_path, body)
    assert findings == {}


def test_address_family_activation_after_default_off(tmp_path):
    body = ("router bgp 65001\n   no bgp default ipv4-unicast\n   neighbor 198.51.100.1 remote-as 65002\n"
            "   address-family ipv4\n      neighbor 198.51.100.1 activate\n")
    _, findings = _run(tmp_path, body)
    assert "authentication" in findings
