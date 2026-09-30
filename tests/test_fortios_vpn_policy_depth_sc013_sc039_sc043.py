"""Bounded FortiOS dial-up authentication and effective exposure checks."""

import pytest

from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.common.assessment import AssessmentContext
from src.devices.fortinet.fortios import FortiOSParser


HEADER = "#config-version=FGT60F-7.4.1-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
PSK_RULE = "fortinet.fortios.vpn.dialup_psk_only"
SOURCE_RULE = "fortinet.fortios.sslvpn.unrestricted_sources"
POLICY_RULE = "fortinet.fortios.policy.risky_service_exposure"


def _scan(tmp_path, body, *, external=False):
    path = tmp_path / "fortios.conf"
    path.write_text(HEADER + body, encoding="utf-8")
    parser = FortiOSParser(str(path))
    if external:
        parser.set_assessment_context(AssessmentContext.from_mapping({
            "interface_roles": {"wan1": "external"},
        }))
    return parser, list(process_fortios_conf(parser).values())


@pytest.mark.parametrize("override,expected", [
    ("", True),
    ("set xauthtype auto\n", False),
    ("set peertype one\n", False),
    ("set authmethod signature\n", False),
    ("set ike-version 2\n", False),
    ("set type static\n", False),
    ("set peerid branch\n", False),
    ("set authmethod-remote signature\n", False),
    ("set psksecret\n", False),
    ("set psksecret ENC\n", False),
    ("set psksecret *****\n", False),
])
def test_explicit_dialup_psk_only_path(tmp_path, override, expected):
    fields = {
        "xauthtype": "disable", "peertype": "any", "authmethod": "psk",
        "authmethod-remote": "psk",
        "ike-version": "1", "type": "dynamic", "interface": '"wan1"',
        "psksecret": "ENC SYNTHETIC_SECRET",
    }
    if override:
        key, _, value = override.removeprefix("set ").partition(" ")
        key = key.strip()
        if key == "psksecret" and not value.strip():
            fields.pop(key)
        else:
            fields[key] = value.strip()
    body = ("config vpn ipsec phase1-interface\nedit dialup\n"
            + "".join(f"set {key} {value}\n" for key, value in fields.items())
            + "next\nend\n")
    parser, findings = _scan(tmp_path, body)
    matched = [item for item in findings if item.rule_id == PSK_RULE]
    assert bool(matched) is expected
    assert bool(parser.get_dialup_psk_only()) is expected
    if matched:
        assert matched[0].basis is FindingBasis.EXPLICIT_VALUE
        assert "SYNTHETIC_SECRET" not in str(matched[0])
        assert guidance_for(PSK_RULE) is not None


@pytest.mark.parametrize("interface_state,expected", [
    ("down", False), ("up", True), (None, True),
])
def test_down_listener_suppresses_external_sslvpn_source_finding(
    tmp_path, interface_state, expected
):
    interface = ("config system interface\nedit wan1\n"
                 + (f"set status {interface_state}\n" if interface_state else "")
                 + "next\nend\n") if interface_state else ""
    body = (interface + "config vpn ssl settings\nset status enable\n"
            'set source-interface "wan1"\nset source-address "all"\n'
            "set source-address-negate disable\nend\n")
    _, findings = _scan(tmp_path, body, external=True)
    assert bool([item for item in findings if item.rule_id == SOURCE_RULE]) is expected


def _policy(name, action, source="all", destination="all", service="TELNET"):
    return (f"edit {name}\nset status enable\nset srcintf wan1\nset dstintf lan\n"
            f"set srcaddr {source}\nset dstaddr {destination}\nset service {service}\n"
            f"set schedule always\nset action {action}\nnext\n")


@pytest.mark.parametrize("second_source,intervening_accept,expected", [
    ("HIGH", False, False),
    ("GAP", False, True),
    ("HIGH", True, True),
])
def test_prior_deny_source_union_must_fully_cover_risky_accept(
    tmp_path, second_source, intervening_accept, expected
):
    objects = (
        "config firewall address\n"
        "edit LOW\nset subnet 0.0.0.0 128.0.0.0\nnext\n"
        "edit HIGH\nset subnet 128.0.0.0 128.0.0.0\nnext\n"
        "edit GAP\nset subnet 128.0.0.0 192.0.0.0\nnext\nend\n"
        "config firewall service custom\nedit TELNET\nset tcp-portrange 23\nnext\nend\n"
    )
    rules = (_policy(1, "deny", "LOW")
             + (_policy(2, "accept", "LOW") if intervening_accept else "")
             + _policy(3, "deny", second_source)
             + _policy(4, "accept"))
    _, findings = _scan(tmp_path, objects + "config firewall policy\n" + rules + "end\n")
    matched = [item for item in findings if item.rule_id == POLICY_RULE]
    assert bool(matched) is expected
