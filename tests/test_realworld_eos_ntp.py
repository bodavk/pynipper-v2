"""Regression cases for versionless EOS NTP exports (RV-005)."""

import json
import subprocess
import sys

import pytest

from src.analyze.arista.plugins.arista_checks_plugin import PluginAristaChecks
from src.devices.arista.eos import AristaEOSParser


def _analyze(tmp_path, config):
    path = tmp_path / "leaf.cfg"
    path.write_text(config, encoding="utf-8")
    parser = AristaEOSParser(str(path))
    plugin = PluginAristaChecks()
    plugin.check_operations(parser)
    return parser, plugin.get_issues()


@pytest.mark.parametrize("name", ["LEAF1A", "LEAF2A", "LEAF2B"])
def test_versionless_leaf_servers_without_key_or_nts_are_unauthenticated(tmp_path, name):
    parser, issues = _analyze(tmp_path, f"""!RANCID-CONTENT-TYPE: arista
hostname {name}
ntp local-interface vrf MGMT Management1
ntp server vrf MGMT 192.0.2.10 prefer
ntp server vrf MGMT 192.0.2.11
""")
    assert parser.get_version() == "?"
    associations = parser.get_ntp_associations()
    assert [(item.address, item.vrf, item.authentication_state) for item in associations] == [
        ("192.0.2.10", "mgmt", "unauthenticated"),
        ("192.0.2.11", "mgmt", "unauthenticated"),
    ]
    ntp = [item for item in issues if item.rule_id.startswith("arista.eos.ntp.")]
    assert [item.rule_id for item in ntp] == ["arista.eos.ntp.authentication"] * 2


def test_versionless_key_reference_remains_unknown_while_plain_vrf_server_is_reported(tmp_path):
    parser, issues = _analyze(tmp_path, """ntp authentication-key 7 sha1 TOPSECRET
ntp trusted-key 7
ntp server vrf MGMT 192.0.2.10 key 7
ntp server 192.0.2.11
""")
    assert [item.authentication_state for item in parser.get_ntp_associations()] == [
        "unknown", "unauthenticated",
    ]
    assert sum(item.rule_id == "arista.eos.ntp.authentication" for item in issues) == 1
    assert "TOPSECRET" not in " ".join(
        evidence.text for association in parser.get_ntp_associations() for evidence in association.evidence
    )


def test_removed_and_malformed_server_bindings_are_not_asserted_unauthenticated(tmp_path):
    parser, issues = _analyze(tmp_path, """ntp server vrf MGMT 192.0.2.10
no ntp server vrf MGMT 192.0.2.10
ntp server vrf MGMT 192.0.2.11 key
ntp server vrf MGMT 192.0.2.12 ssl
""")
    assert [(item.address, item.authentication_state) for item in parser.get_ntp_associations()] == [
        ("192.0.2.11", "unknown"),
        ("192.0.2.12", "unknown"),
    ]
    assert not any(item.rule_id == "arista.eos.ntp.authentication" for item in issues)


def test_global_and_vrf_server_overrides_remain_independent(tmp_path):
    parser, issues = _analyze(tmp_path, """! device: leaf (DCS-7050, EOS-4.29.2F)
ntp authenticate
ntp authentication-key 7 sha1 TOPSECRET
ntp trusted-key 7
ntp server 192.0.2.10 key 7
ntp server vrf MGMT 192.0.2.10
ntp server vrf MGMT 192.0.2.10 key 7
ntp server vrf MGMT 192.0.2.11
""")
    assert [(item.vrf, item.address, item.authentication_state)
            for item in parser.get_ntp_associations()] == [
        ("default", "192.0.2.10", "authenticated"),
        ("mgmt", "192.0.2.10", "authenticated"),
        ("mgmt", "192.0.2.11", "unresolved"),
    ]
    assert "arista.eos.ntp.authentication_reference" in {item.rule_id for item in issues}
    assert "arista.eos.ntp.authentication" not in {item.rule_id for item in issues}


@pytest.mark.parametrize("output_type", ["JSON", "HTML"])
def test_public_cli_discloses_each_unauthenticated_server(tmp_path, output_type):
    source = tmp_path / "leaf.cfg"
    source.write_text(
        "hostname LEAF1A\nntp server vrf MGMT 192.0.2.10\nntp server vrf MGMT 192.0.2.11\n",
        encoding="utf-8",
    )
    output = tmp_path / f"report.{output_type.lower()}"
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "-d", "ARISTA_EOS", "-i", str(source),
         "-o", output_type, "-f", str(output), "-x"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = output.read_text(encoding="utf-8")
    assert "192.0.2.10" in report and "192.0.2.11" in report
    if output_type == "JSON":
        data = json.loads(report)
        ntp = [item for item in data["security-audit"].values()
               if item["rule_id"] == "arista.eos.ntp.authentication"]
        assert len(ntp) == 2
        assert not any(item["rule_id"] == "arista.eos.ntp.servers"
                       for item in data["security-audit"].values())
    else:
        assert report.count("NTP association is unauthenticated") >= 2
