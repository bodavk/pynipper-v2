"""SC-005: bounded classic IPv4 EIGRP authentication."""

import json
import subprocess
import sys

import pytest

from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf
from src.devices.cisco.ios import CiscoIOSParser


BASE = "version 17.9\nhostname edge-router\n"
EIGRP = "router eigrp 10\n network 192.0.2.0 0.0.0.255\n"
PORT = "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
CHAIN = "key chain EDGE\n key 1\n  key-string 7 syntheticprivate\n"
NO_AUTH = "cisco.ios.routing.eigrp.authentication"
UNRESOLVED = "cisco.ios.routing.eigrp.key_resolution"
EIGRP_IDS = {NO_AUTH, UNRESOLVED}


def _scan(tmp_path, commands):
    path = tmp_path / "router.conf"
    path.write_text(BASE + commands, encoding="utf-8")
    parser = CiscoIOSParser(str(path))
    findings = process_cisco_ios_conf(parser).values()
    return parser, [item for item in findings if item.rule_id in EIGRP_IDS]


def test_active_eigrp_without_authentication(tmp_path):
    parser, findings = _scan(tmp_path, EIGRP + PORT)
    record = parser.get_eigrp_interfaces()[0]
    assert (record.autonomous_system, record.interface) == ("10", "GigabitEthernet0/0")
    assert record.authentication_state == "unauthenticated"
    assert [item.rule_id for item in findings] == [NO_AUTH]


def test_configured_md5_key_chain_is_not_flagged_or_exposed(tmp_path):
    parser, findings = _scan(
        tmp_path, EIGRP + CHAIN + PORT
        + " ip authentication mode eigrp 10 md5\n"
        + " ip authentication key-chain eigrp 10 EDGE\n",
    )
    record = parser.get_eigrp_interfaces()[0]
    assert record.authentication_state == "configured-md5"
    assert findings == []
    assert "syntheticprivate" not in " ".join(item.text for item in record.evidence)


@pytest.mark.parametrize("tail,expected", [
    (" ip authentication mode eigrp 10 md5\n", "unresolved"),
    (" ip authentication mode eigrp 10 md5\n ip authentication key-chain eigrp 10 MISSING\n", "unresolved"),
    (" ip authentication mode eigrp 10 md5\n ip authentication key-chain eigrp 10 EDGE\n", "unresolved"),
])
def test_missing_key_binding_or_material(tmp_path, tail, expected):
    parser, findings = _scan(tmp_path, EIGRP + "key chain EDGE\n key 1\n" + PORT + tail)
    assert parser.get_eigrp_interfaces()[0].authentication_state == expected
    assert [item.rule_id for item in findings] == [UNRESOLVED]


def test_key_chain_without_mode_is_not_effective(tmp_path):
    parser, findings = _scan(tmp_path, EIGRP + CHAIN + PORT + " ip authentication key-chain eigrp 10 EDGE\n")
    assert parser.get_eigrp_interfaces()[0].authentication_state == "unauthenticated"
    assert [item.rule_id for item in findings] == [NO_AUTH]


@pytest.mark.parametrize("commands", [
    EIGRP + PORT + " shutdown\n",
    EIGRP + PORT + " ip vrf forwarding CUSTOMER\n",
    EIGRP + "interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n",
    EIGRP + "no router eigrp 10\n" + PORT,
    "router eigrp CAMPUS\n address-family ipv4 unicast vrf CUST autonomous-system 10\n  network 192.0.2.0 0.0.0.255\n" + PORT,
    "router eigrp 10\n network 192.0.2.0 0.0.0.255\n no network 192.0.2.0 0.0.0.255\n" + PORT,
    "router eigrp 10\n network 192.0.2.0 0.0.0.255\n passive-interface default\n" + PORT,
    "router eigrp 10\n network 192.0.2.0 0.0.0.255\n passive-interface GigabitEthernet0/0\n" + PORT,
])
def test_inactive_unmatched_or_out_of_scope_is_not_flagged(tmp_path, commands):
    parser, findings = _scan(tmp_path, commands)
    assert parser.get_eigrp_interfaces() == []
    assert findings == []


def test_passive_override_reenables_adjacency_check(tmp_path):
    commands = ("router eigrp 10\n network 192.0.2.0 0.0.0.255\n"
                " passive-interface default\n no passive-interface GigabitEthernet0/0\n" + PORT)
    parser, findings = _scan(tmp_path, commands)
    assert parser.get_eigrp_interfaces()[0].passive is False
    assert [item.rule_id for item in findings] == [NO_AUTH]


def test_multiple_as_and_authentication_overrides(tmp_path):
    commands = (EIGRP + "router eigrp 20\n network 192.0.2.0 0.0.0.255\n" + CHAIN + PORT
                + " ip authentication mode eigrp 10 md5\n"
                + " ip authentication key-chain eigrp 10 EDGE\n"
                + " ip authentication mode eigrp 20 md5\n"
                + " ip authentication key-chain eigrp 20 EDGE\n"
                + " no ip authentication key-chain eigrp 20 EDGE\n")
    parser, findings = _scan(tmp_path, commands)
    assert {item.autonomous_system: item.authentication_state for item in parser.get_eigrp_interfaces()} == {
        "10": "configured-md5", "20": "unresolved",
    }
    assert [item.rule_id for item in findings] == [UNRESOLVED]
    assert "AS 20" in findings[0].observation


def test_two_unauthenticated_as_keep_separate_findings(tmp_path):
    parser, findings = _scan(
        tmp_path, EIGRP + "router eigrp 20\n network 192.0.2.0 0.0.0.255\n" + PORT,
    )
    assert len(parser.get_eigrp_interfaces()) == 2
    assert [item.rule_id for item in findings] == [NO_AUTH, NO_AUTH]
    assert {item.observation.split(" on ")[0] for item in findings} == {"EIGRP AS 10", "EIGRP AS 20"}


def test_mode_removal_and_unknown_mode(tmp_path):
    parser, findings = _scan(
        tmp_path, EIGRP + CHAIN + PORT + " ip authentication mode eigrp 10 md5\n"
        " ip authentication key-chain eigrp 10 EDGE\n no ip authentication mode eigrp 10 md5\n",
    )
    assert parser.get_eigrp_interfaces()[0].authentication_state == "unauthenticated"
    assert [item.rule_id for item in findings] == [NO_AUTH]
    parser, findings = _scan(
        tmp_path, EIGRP + CHAIN + PORT + " ip authentication mode eigrp 10 md5\n"
        " ip authentication key-chain eigrp 10 EDGE\n no ip authentication mode eigrp 10\n",
    )
    assert parser.get_eigrp_interfaces()[0].authentication_state == "unauthenticated"
    assert [item.rule_id for item in findings] == [NO_AUTH]
    parser, findings = _scan(tmp_path, EIGRP + PORT + " ip authentication mode eigrp 10 nonsensical\n")
    assert parser.get_eigrp_interfaces()[0].authentication_state == "unknown"
    assert findings == []


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_cli_and_secret_redaction(tmp_path, output_type):
    config = tmp_path / "router.conf"
    config.write_text(
        BASE + EIGRP + CHAIN + PORT + " ip authentication mode eigrp 10 md5\n"
        " ip authentication key-chain eigrp 10 EDGE\n no ip authentication key-chain eigrp 10 EDGE\n",
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
    assert "EIGRP authentication key chain is unresolved" in rendered
    assert "syntheticprivate" not in rendered + completed.stdout + completed.stderr
    if output_type == "JSON":
        data = json.loads(rendered)
        assert any(item["rule_id"] == UNRESOLVED for item in data["security-audit"].values())
