"""CIS Check Point 1.12, 1.13 and 2.5.2 on Gaia (documented defaults apply when omitted)."""

import pytest

from src.analyze.checkpoint.plugins.gaia_checks_plugin import PluginCheckPointGaiaChecks
from src.analyze.common.issue import FindingBasis
from src.devices.checkpoint.gaia import CheckPointGaiaParser


def _findings(tmp_path, body):
    path = tmp_path / "gaia.conf"
    path.write_text("set hostname gw\n" + body, encoding="utf-8")
    plugin = PluginCheckPointGaiaChecks()
    plugin.analyze(CheckPointGaiaParser(str(path)))
    return {f.rule_id: f for f in plugin.get_issues()}


ON = "set password-controls deny-on-fail enable on\n"


@pytest.mark.parametrize("body,basis", [
    (ON, FindingBasis.DOCUMENTED_DEFAULT),
    (ON + "set password-controls deny-on-fail failures-allowed 8\n", FindingBasis.EXPLICIT_VALUE),
    (ON + "set password-controls deny-on-fail failures-allowed 5\nset password-controls deny-on-fail allow-after 120\n",
     FindingBasis.EXPLICIT_VALUE),
])
def test_lockout_limits(tmp_path, body, basis):
    finding = _findings(tmp_path, body)["checkpoint.gaia.password_policy.lockout_threshold"]
    assert finding.basis is basis


@pytest.mark.parametrize("body", [
    ON + "set password-controls deny-on-fail failures-allowed 5\nset password-controls deny-on-fail allow-after 300\n",
    "set password-controls deny-on-fail enable off\n",  # reported by lockout_disabled instead
])
def test_lockout_limits_not_reported(tmp_path, body):
    assert "checkpoint.gaia.password_policy.lockout_threshold" not in _findings(tmp_path, body)


@pytest.mark.parametrize("body,expected", [
    ("", FindingBasis.DOCUMENTED_DEFAULT), ("set web session-timeout 30\n", FindingBasis.EXPLICIT_VALUE),
    ("set web session-timeout 10\n", None),
])
def test_web_session_timeout(tmp_path, body, expected):
    finding = _findings(tmp_path, body).get("checkpoint.gaia.web.session_timeout_excessive")
    assert (finding.basis if finding else None) is expected
