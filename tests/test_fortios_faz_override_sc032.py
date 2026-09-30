"""SC-032: FortiAnalyzer TLS checks follow active per-VDOM overrides."""

import pytest

from src.analyze.common.issue import FindingBasis
from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.devices.fortinet.fortios import FortiOSParser


WEAK = "fortinet.fortios.logging.remote_weak_tls"
IDENTITY = "fortinet.fortios.logging.remote_identity_unverified"


def _scan(tmp_path, config):
    path = tmp_path / "fortios.conf"
    path.write_text(config, encoding="utf-8")
    parser = FortiOSParser(str(path))
    return parser, [issue for issue in process_fortios_conf(parser).values()
                    if issue.rule_id in {WEAK, IDENTITY}]


def _setting(*, override=False, status="enable", server="192.0.2.60",
             encryption="low", verification="disable", tls_minimum=None):
    section = "log fortianalyzer override-setting" if override else "log fortianalyzer setting"
    return (f"config {section}\nset status {status}\n"
            + (f"set server {server}\n" if server else "")
            + f"set enc-algorithm {encryption}\n"
            + (f"set ssl-min-proto-version {tls_minimum}\n" if tls_minimum else "")
            + f"set certificate-verification {verification}\nend\n")


@pytest.mark.parametrize("override,expected", [(False, 0), (True, 2)])
def test_only_explicitly_active_vdom_override_is_assessed(tmp_path, override, expected):
    config = (
        "config vdom\nedit blue\n"
        + ("config log setting\nset faz-override enable\nend\n" if override else "")
        + _setting(override=True) + "next\nend\n"
    )
    parser, findings = _scan(tmp_path, config)
    assert len(parser.get_fortianalyzer_sinks()) == (1 if override else 0)
    assert len(findings) == expected
    if expected:
        assert {issue.rule_id for issue in findings} == {WEAK, IDENTITY}
        assert all(issue.basis == FindingBasis.EXPLICIT_VALUE for issue in findings)
        assert all("scope 'blue'" in issue.observation for issue in findings)


def test_override_uses_own_transport_not_base_settings(tmp_path):
    config = (
        _setting()
        + "config vdom\nedit blue\nconfig log setting\nset faz-override enable\nend\n"
        + _setting(override=True, encryption="high", verification="enable")
        + "next\nend\n"
    )
    _, findings = _scan(tmp_path, config)
    assert len(findings) == 2  # Root's base destination; not the VDOM override.
    assert all("scope 'root'" in issue.observation for issue in findings)


@pytest.mark.parametrize("status,server", [
    ("disable", "192.0.2.60"),
    ("enable", ""),
])
def test_inactive_or_unbound_override_is_not_assessed(tmp_path, status, server):
    config = (
        "config vdom\nedit blue\nconfig log setting\nset faz-override enable\nend\n"
        + _setting(override=True, status=status, server=server)
        + "next\nend\n"
    )
    _, findings = _scan(tmp_path, config)
    assert not findings


@pytest.mark.parametrize("tls_minimum,expected", [
    ("SSLv3", True), ("TLSv1", True), ("TLSv1-1", True),
    ("TLSv1-2", False), ("TLSv1-3", False), (None, False),
])
def test_explicit_obsolete_fortianalyzer_tls_minimum(tmp_path, tls_minimum, expected):
    config = _setting(encryption="high", verification="enable", tls_minimum=tls_minimum)
    _, findings = _scan(tmp_path, config)
    assert bool(findings) is expected
    if expected:
        assert len(findings) == 1
        assert findings[0].rule_id == WEAK
        assert tls_minimum.lower() in findings[0].observation


def test_weak_cipher_and_obsolete_protocol_are_one_destination_finding(tmp_path):
    _, findings = _scan(tmp_path, _setting(tls_minimum="TLSv1"))
    assert len([issue for issue in findings if issue.rule_id == WEAK]) == 1


def test_vdom_override_obsolete_tls_is_assessed_independently(tmp_path):
    config = (
        "config vdom\nedit blue\nconfig log setting\nset faz-override enable\nend\n"
        + _setting(override=True, encryption="high", verification="enable",
                   tls_minimum="TLSv1-1")
        + "next\nend\n"
    )
    _, findings = _scan(tmp_path, config)
    assert len(findings) == 1
    assert findings[0].rule_id == WEAK
    assert "scope 'blue'" in findings[0].observation
