"""SC-005: bounded active classic IPv4 RIPv2 authentication."""

import json
import subprocess
import sys

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.devices.cisco.ios import CiscoIOSParser


BASE = "version 17.9\nhostname edge-router\n"
RIP = "router rip\n version 2\n network 192.0.2.0\n"
PORT = "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n ip rip receive version 2\n"
NO_AUTH = "cisco.ios.routing.rip.authentication"
UNRESOLVED = "cisco.ios.routing.rip.key_resolution"
TEXT = "cisco.ios.routing.rip.cleartext_authentication"
VERSION1 = "cisco.ios.routing.rip.version1_receive"
RIP_IDS = {NO_AUTH, UNRESOLVED, TEXT, VERSION1}


def _scan(tmp_path, commands):
    path = tmp_path / "router.conf"
    path.write_text(BASE + commands, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    return parser, {item.rule_id: item for item in process_cisco_ios_conf(parser).values()}


def test_active_ripv2_without_key_chain(tmp_path):
    parser, findings = _scan(tmp_path, RIP + PORT)
    record = parser.get_rip_interfaces()[0]
    assert record.interface == "GigabitEthernet0/0"
    assert record.network == "192.0.2.0/24"
    assert record.authentication_state == "unauthenticated"
    assert NO_AUTH in findings


def test_configured_md5_chain_and_secret_redaction(tmp_path):
    parser, findings = _scan(
        tmp_path,
        RIP + "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
        + PORT + " ip rip authentication key-chain EDGE\n"
        " ip rip authentication mode md5\n",
    )
    record = parser.get_rip_interfaces()[0]
    assert record.authentication_state == "configured-md5"
    assert "syntheticprivate" not in " ".join(item.text for item in record.evidence)
    assert not RIP_IDS.intersection(findings)


@pytest.mark.parametrize("tail,state,rule", [
    (" ip rip authentication key-chain MISSING\n ip rip authentication mode md5\n", "unresolved", UNRESOLVED),
    (" ip rip authentication key-chain EDGE\n", "weak-cleartext", TEXT),
    (" ip rip authentication key-chain EDGE\n ip rip authentication mode text\n", "weak-cleartext", TEXT),
    (" ip rip authentication key-chain EDGE\n ip rip authentication mode md5\n no ip rip authentication mode\n", "weak-cleartext", TEXT),
])
def test_key_binding_and_mode_override(tmp_path, tail, state, rule):
    parser, findings = _scan(
        tmp_path,
        RIP + "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
        + PORT + tail,
    )
    assert parser.get_rip_interfaces()[0].authentication_state == state
    assert rule in findings
    assert "syntheticprivate" not in " ".join(findings[rule].evidence)


def test_version1_receive_overrides_md5(tmp_path):
    parser, findings = _scan(
        tmp_path,
        RIP + "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
        + PORT + " ip rip authentication key-chain EDGE\n"
        " ip rip authentication mode md5\n ip rip receive version 1 2\n",
    )
    assert parser.get_rip_interfaces()[0].authentication_state == "version1-accepted"
    assert VERSION1 in findings
    _, restored = _scan(
        tmp_path,
        RIP + "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
        + PORT + " ip rip authentication key-chain EDGE\n"
        " ip rip authentication mode md5\n ip rip receive version 1 2\n"
        " ip rip receive version 2\n",
    )
    assert not RIP_IDS.intersection(restored)


def test_passive_interface_still_receives_and_is_assessed(tmp_path):
    parser, findings = _scan(
        tmp_path,
        "router rip\n version 2\n network 192.0.2.0\n passive-interface default\n"
        + PORT,
    )
    assert parser.get_rip_interfaces()[0].passive is True
    assert NO_AUTH in findings
    assert "still receiving" in findings[NO_AUTH].observation


@pytest.mark.parametrize("commands", [
    RIP + PORT + " shutdown\n",
    RIP + PORT + " ip vrf forwarding CUSTOMER\n",
    RIP + "interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n",
    RIP + "no router rip\n" + PORT,
    "router rip\n version 1\n network 192.0.2.0\n" + PORT,
    "router rip\n version 2\n network 192.0.2.0\n no network 192.0.2.0\n" + PORT,
])
def test_inactive_or_unmatched_rip_is_not_flagged(tmp_path, commands):
    parser, findings = _scan(tmp_path, commands)
    assert parser.get_rip_interfaces() == []
    assert not RIP_IDS.intersection(findings)


def test_removed_chain_and_key_are_unresolved(tmp_path):
    parser, findings = _scan(
        tmp_path,
        RIP + "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
        "no key chain EDGE\n" + PORT
        + " ip rip authentication key-chain EDGE\n ip rip authentication mode md5\n",
    )
    assert parser.get_rip_interfaces()[0].authentication_state == "unresolved"
    assert UNRESOLVED in findings


def test_unknown_receive_version_or_malformed_mode_is_ungraded(tmp_path):
    chain = "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
    parser, findings = _scan(
        tmp_path,
        RIP + chain + "interface GigabitEthernet0/0\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        " ip rip authentication key-chain EDGE\n ip rip authentication mode md5\n",
    )
    assert parser.get_rip_interfaces()[0].authentication_state == "unknown"
    assert not RIP_IDS.intersection(findings)
    parser, findings = _scan(
        tmp_path,
        RIP + chain + PORT
        + " ip rip authentication key-chain EDGE\n"
        " ip rip authentication mode nonsensical\n",
    )
    assert parser.get_rip_interfaces()[0].authentication_state == "unknown"
    assert not RIP_IDS.intersection(findings)


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_cli_and_redaction(tmp_path, output_type):
    config = tmp_path / "router.conf"
    config.write_text(
        BASE + RIP + "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
        + PORT + " ip rip authentication key-chain EDGE\n",
        encoding="utf-8",
    )
    report = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "IOS_XE", "-i", str(config),
         "-o", output_type, "-f", str(report), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = report.read_text(encoding="utf-8")
    assert "RIP interface uses cleartext authentication" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == TEXT for item in data["security-audit"].values())


VRF_PORT = ("interface GigabitEthernet0/1\n vrf forwarding CUST\n"
            " ip address 198.51.100.1 255.255.255.0\n ip rip receive version 2\n")


def _vrf_rip(af_body):
    return ("router rip\n version 2\n network 192.0.2.0\n !\n address-family ipv4 vrf CUST\n"
            + af_body + " exit-address-family\n")


def test_vrf_address_family_with_its_own_version_2_is_assessed(tmp_path):
    parser, findings = _scan(tmp_path, _vrf_rip("  version 2\n  network 198.51.100.0\n") + PORT + VRF_PORT)
    records = {record.interface: record for record in parser.get_rip_interfaces()}
    assert records["GigabitEthernet0/1"].vrf == "cust"
    assert records["GigabitEthernet0/1"].authentication_state == "unauthenticated"
    assert records["GigabitEthernet0/0"].vrf == "default"
    vrf_findings = [f for f in process_cisco_ios_conf(parser).values()
                    if f.rule_id == NO_AUTH and "GigabitEthernet0/1" in f.observation]
    assert vrf_findings and "in VRF cust" in vrf_findings[0].observation


@pytest.mark.parametrize("af_body", [
    "  network 198.51.100.0\n",  # version not set inside the address family: inheritance unknown
    "  version 1\n  network 198.51.100.0\n",
    "  version 2\n",  # no network
])
def test_vrf_address_family_without_own_version_2_is_not_assessed(tmp_path, af_body):
    parser, _ = _scan(tmp_path, _vrf_rip(af_body) + PORT + VRF_PORT)
    assert [record.interface for record in parser.get_rip_interfaces()] == ["GigabitEthernet0/0"]


def test_default_vrf_is_still_assessed_next_to_a_vrf_family(tmp_path):
    parser, findings = _scan(tmp_path, _vrf_rip("  version 2\n  network 198.51.100.0\n") + PORT)
    assert [record.interface for record in parser.get_rip_interfaces()] == ["GigabitEthernet0/0"]
