"""CIS Junos follow-up: LDP, RSVP and MSDP authentication (omitted key = not configured)."""

import pytest

from src.analyze.common.issue import FindingBasis
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.devices.juniper.junos import JunOSParser

HEAD = "set version 22.4R1.10\nset system host-name r1\n"


def _findings(tmp_path, body):
    path = tmp_path / "junos.conf"
    path.write_text(HEAD + body, encoding="utf-8")
    plugin = PluginJunOSBaseline()
    plugin.check_rip_and_ospf3_authentication(JunOSParser(str(path)))
    return {f.rule_id: f for f in plugin.get_issues() if f.rule_id.split(".")[3] in {"ldp", "rsvp", "msdp"}}


@pytest.mark.parametrize("body,rule,basis", [
    ("set protocols ldp interface ge-0/0/0.0\n", "juniper.junos.routing.ldp.authentication", FindingBasis.REQUIRED_SETTING_MISSING),
    ("set protocols ldp session 192.0.2.1\n", "juniper.junos.routing.ldp.authentication", FindingBasis.REQUIRED_SETTING_MISSING),
    ("set protocols rsvp interface ge-0/0/0.0\n", "juniper.junos.routing.rsvp.authentication", FindingBasis.REQUIRED_SETTING_MISSING),
    ("set protocols msdp peer 192.0.2.9 local-address 192.0.2.1\n", "juniper.junos.routing.msdp.authentication", FindingBasis.DOCUMENTED_DEFAULT),
    ("set routing-instances VRF protocols msdp group G peer 192.0.2.9\n", "juniper.junos.routing.msdp.authentication", FindingBasis.DOCUMENTED_DEFAULT),
])
def test_omitted_keys_are_reported(tmp_path, body, rule, basis):
    findings = _findings(tmp_path, body)
    assert list(findings) == [rule]
    assert findings[rule].basis is basis and "omitted" in findings[rule].observation


@pytest.mark.parametrize("body", [
    'set protocols ldp interface ge-0/0/0.0\nset protocols ldp session 192.0.2.1 authentication-key "$9$k"\n',
    'set protocols ldp session-group 192.0.2.0/24 authentication-key "$9$k"\n',
    'set protocols rsvp interface ge-0/0/0.0 authentication-key "$9$k"\n',
    'set protocols rsvp interface ge-0/0/0.0\nset protocols rsvp authentication-key "$9$k"\n',
    'set protocols msdp peer 192.0.2.9 authentication-key "$9$k"\n',
    'set protocols msdp group G authentication-key "$9$k"\nset protocols msdp group G peer 192.0.2.9\n',
    'set protocols msdp authentication-key "$9$k"\nset protocols msdp peer 192.0.2.9\n',
    "set protocols rsvp interface ge-0/0/0.0 disable\n",
    "set protocols rsvp interface lo0.0\n",
    "deactivate protocols ldp\nset protocols ldp interface ge-0/0/0.0\n",
    "set protocols ldp interface ge-0/0/0.0\nset apply-groups G\n",
])
def test_keys_disable_and_unknown_inheritance_are_not_reported(tmp_path, body):
    assert _findings(tmp_path, body) == {}


def test_secret_value_never_in_evidence(tmp_path):
    findings = _findings(tmp_path, 'set protocols ldp interface ge-0/0/0.0\nset protocols ldp session 192.0.2.1\n'
                                   'set protocols rsvp interface ge-0/0/1.0 authentication-key "TopSecretKey"\n'
                                   'set protocols rsvp interface ge-0/0/2.0\n')
    assert "TopSecretKey" not in str([str(f) for f in findings.values()])
    assert "interface ge-0/0/2.0" in findings["juniper.junos.routing.rsvp.authentication"].observation


def _hygiene(tmp_path, body):
    path = tmp_path / "h.conf"
    path.write_text(HEAD + body, encoding="utf-8")
    plugin = PluginJunOSBaseline()
    plugin.check_cis_follow_ups(JunOSParser(str(path)))
    found = [f for f in plugin.get_issues() if f.rule_id == "juniper.junos.hardening.cis_hygiene"]
    return found[0].observation if found else ""


def test_hygiene_lists_ipv6_redirects_snmp_clients_and_password_options(tmp_path):
    text = _hygiene(tmp_path, 'set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64\n'
                              'set snmp community SECRETNAME authorization read-only\n'
                              'set system login user ops class super-user\n'
                              'set system login password minimum-length 8\n')
    for ref in ("CIS 6.22", "CIS 5.3", "CIS 5.8", "CIS 6.6.9", "CIS 6.6.10", "CIS 6.6.11"):
        assert ref in text
    assert "SECRETNAME" not in text and "1 SNMP community" in text


def test_hygiene_items_clear_when_configured(tmp_path):
    text = _hygiene(tmp_path, 'set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64\n'
                              'set system no-redirects-ipv6\n'
                              'set snmp community SECRETNAME clients 192.0.2.0/24\nset snmp interface fxp0.0\n'
                              'set system login user ops class super-user\n'
                              'set system login password minimum-length 12\nset system login password change-type character-sets\n'
                              'set system login password minimum-changes 4\n')
    for ref in ("CIS 6.22", "CIS 5.3", "CIS 5.8", "CIS 6.6.9", "CIS 6.6.10", "CIS 6.6.11"):
        assert ref not in text
