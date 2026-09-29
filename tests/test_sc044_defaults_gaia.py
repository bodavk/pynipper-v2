"""SC-044: documented Gaia defaults and explicit weak settings (Check Point).

Row IDs refer to docs/agent_notes/INSECURE_DEFAULTS_BY_RELEASE.md."""

import pytest

from src.analyze.checkpoint.core.process_checkpoint_gaia_conf import process_checkpoint_gaia_conf
from src.analyze.common.guidance import guidance_for
from src.analyze.common.issue import FindingBasis
from src.devices.checkpoint.gaia import CheckPointGaiaParser

HEADER = ("#\n# Configuration of gw1\n# Language version: 15.0v1\n#\nset hostname gw1\n"
          "set password-controls deny-on-fail enable on\n")
SAFE = "set password-controls deny-on-nonuse enable on\nset password-controls min-password-length 14\n"


def _rules(tmp_path, body):
    path = tmp_path / "gaia.conf"
    path.write_text(HEADER + body, encoding="utf-8")
    findings = process_checkpoint_gaia_conf(CheckPointGaiaParser(str(path))).values()
    assert all(guidance_for(f.rule_id) for f in findings)
    return {f.rule_id: f for f in findings}


@pytest.mark.parametrize("body,basis", [
    ("", FindingBasis.DOCUMENTED_DEFAULT),
    ("set password-controls deny-on-nonuse enable off\n", FindingBasis.EXPLICIT_VALUE),
    ("set password-controls deny-on-nonuse enable on\n", None),
])
def test_nonuse_lockout(tmp_path, body, basis):  # CP-03
    finding = _rules(tmp_path, body).get("checkpoint.gaia.password_policy.nonuse_lockout_disabled")
    assert (finding.basis if finding else None) is basis


@pytest.mark.parametrize("body,basis", [
    ("", FindingBasis.DOCUMENTED_DEFAULT),
    ("set password-controls min-password-length 6\n", FindingBasis.EXPLICIT_VALUE),
    ("set password-controls min-password-length 12\n", None),
])
def test_minimum_length_default(tmp_path, body, basis):  # CP-05
    finding = _rules(tmp_path, body).get("checkpoint.gaia.password_policy.minimum_length")
    assert (finding.basis if finding else None) is basis


@pytest.mark.parametrize("body,basis", [
    ("set ssh server permit-root-login yes\n", FindingBasis.EXPLICIT_VALUE),
    ("set ssh server mac hmac-sha2-256\n", FindingBasis.DOCUMENTED_DEFAULT),
    ("set ssh server mac hmac-sha2-256\nset ssh server permit-root-login no\n", None),
    ("", None),  # pre-R81.20 export: release unknown
])
def test_ssh_root_login(tmp_path, body, basis):  # CP-06
    finding = _rules(tmp_path, SAFE + body).get("checkpoint.gaia.ssh.root_login_permitted")
    assert (finding.basis if finding else None) is basis


def test_ccp_encryption(tmp_path):  # CP-07
    assert "checkpoint.gaia.cluster.ccp_encryption_disabled" in _rules(tmp_path, SAFE + "set cluster member ccpenc off\n")
    assert "checkpoint.gaia.cluster.ccp_encryption_disabled" not in _rules(tmp_path, SAFE + "set cluster member ccpenc on\n")


@pytest.mark.parametrize("body,basis", [
    ("add syslog log-remote-address 192.0.2.50 level info\n", FindingBasis.DOCUMENTED_DEFAULT),
    ("add syslog log-remote-address 192.0.2.50 level info protocol udp\n", FindingBasis.EXPLICIT_VALUE),
    ("add syslog log-remote-address 192.0.2.50 level info protocol tcp\n", None),
    ("add syslog log-remote-address 192.0.2.50 level info\ndelete syslog log-remote-address 192.0.2.50\n", None),
])
def test_remote_syslog_protocol(tmp_path, body, basis):  # CP-08
    finding = _rules(tmp_path, SAFE + body).get("checkpoint.gaia.syslog.remote_udp")
    assert (finding.basis if finding else None) is basis


@pytest.mark.parametrize("body,expected", [
    ("add allowed-client host any-host\n", True),
    ("add allowed-client network ipv4-address 192.0.2.0 mask-length 24\n", False),
    ("add allowed-client host any-host\ndelete allowed-client host any-host\n", False),
])
def test_allowed_client_any(tmp_path, body, expected):  # CP-11
    assert ("checkpoint.gaia.management.unrestricted_allowed_client" in _rules(tmp_path, SAFE + body)) is expected
