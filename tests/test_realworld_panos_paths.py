"""Sanitized PAN-OS management and shared-log paths observed in RW-010."""

import pytest

from src.analyze.paloalto.core.process_panos_conf import process_panos_conf
from src.devices.paloalto.panos import PaloAltoPANOSParser


def _configuration(profile=True, bound=True, disabled=False):
    member = "<send-syslog><member>audit-syslog</member></send-syslog>" if bound else ""
    off = "<disabled>yes</disabled>" if disabled else ""
    definition = (
        "<syslog><entry name='audit-syslog'><server><entry name='collector'>"
        "<server>192.0.2.10</server></entry></server></entry></syslog>"
    ) if profile else ""
    return (
        "<config><mgt-config><password-complexity><enabled>yes</enabled>"
        "<minimum-length>12</minimum-length><minimum-uppercase-letters>1</minimum-uppercase-letters>"
        "<minimum-lowercase-letters>1</minimum-lowercase-letters>"
        "<minimum-numeric-letters>1</minimum-numeric-letters>"
        "<minimum-special-characters>1</minimum-special-characters>"
        "</password-complexity></mgt-config><shared><log-settings>"
        f"{definition}<system><match-list><entry name='audit'>{off}{member}"
        "</entry></match-list></system></log-settings></shared></config>"
    )


@pytest.mark.parametrize("profile,bound,disabled,forwarding", [
    (True, True, False, True),
    (False, True, False, False),
    (True, False, False, False),
    (True, True, True, False),
])
def test_effective_password_policy_and_system_syslog_binding(
    tmp_path, profile, bound, disabled, forwarding,
):
    path = tmp_path / "panos.xml"
    path.write_text(_configuration(profile, bound, disabled), encoding="utf-8")
    parser = PaloAltoPANOSParser(str(path))
    assert parser.get_password_policy().enabled is True
    assert bool(parser.get_system_log_forwarding_destinations()) == forwarding
    rules = {finding.rule_id for finding in process_panos_conf(parser).values()}
    assert "paloalto.panos.credentials.password_complexity" not in rules
    assert ("paloalto.panos.logging.system_forwarding" in rules) != forwarding
