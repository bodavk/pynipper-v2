"""SC-021 ASA stage: explicit legacy PFS groups on interface-attached crypto maps."""

import pytest

from src.analyze.cisco.asa.core.process_asa_conf import process_asa_conf
from src.devices.cisco.asa import CiscoASAParser

RULE = "cisco.asa.crypto.legacy_pfs"
BASE = """ASA Version 9.18(4)
hostname edge
interface GigabitEthernet0/0
 nameif outside
 security-level 0
crypto ipsec ikev2 ipsec-proposal STRONG
 protocol esp encryption aes-256
"""


def _findings(tmp_path, body):
    path = tmp_path / "asa.conf"
    path.write_text(BASE + body, encoding="utf-8")
    parser = CiscoASAParser(str(path))
    return parser, [item for item in process_asa_conf(parser).values() if item.rule_id == RULE]


@pytest.mark.parametrize("group", ["1", "2", "5", "14"])
def test_attached_static_map_with_legacy_pfs_group(tmp_path, group):
    parser, findings = _findings(
        tmp_path,
        f"crypto map VPN 10 set pfs group{group}\ncrypto map VPN interface outside\n",
    )
    finding, = findings
    assert f"DH group {group}" in finding.observation and "outside" in finding.observation
    assert [item.line_number for item in finding.evidence_locations] == [8, 9]


def test_dynamic_map_pfs_through_static_reference(tmp_path):
    _, findings = _findings(
        tmp_path,
        "crypto dynamic-map DYN 5 set pfs group2\n"
        "crypto map VPN 65535 ipsec-isakmp dynamic DYN\n"
        "crypto map VPN interface outside\n",
    )
    assert len(findings) == 1


@pytest.mark.parametrize(
    "body",
    [
        "crypto map VPN 10 set pfs group19\ncrypto map VPN interface outside\n",
        "crypto map VPN 10 set pfs\ncrypto map VPN interface outside\n",  # release default: not graded
        "crypto map VPN 10 set pfs group2\n",  # not attached to an interface
        "crypto map VPN 10 set pfs group2\ncrypto map VPN interface outside\nno crypto map VPN 10 set pfs\n",
        "crypto map VPN 10 set pfs group2\ncrypto map VPN interface outside\nno crypto map VPN interface outside\n",
        "crypto map VPN 10 set pfs group2\ncrypto map VPN 10 set pfs group20\ncrypto map VPN interface outside\n",
        "crypto dynamic-map DYN 5 set pfs group2\ncrypto map VPN interface outside\n",  # unreferenced dynamic map
    ],
)
def test_modern_default_unbound_and_removed_pfs_is_not_reported(tmp_path, body):
    assert _findings(tmp_path, body)[1] == []
