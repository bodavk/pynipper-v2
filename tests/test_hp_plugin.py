from src.analyze.hp.core.process_hp_conf import process_hp_conf
from src.analyze.hp.plugins.hp_checks_plugin import PluginHPChecks
from src.devices.common.models import ConfigurationState, KnowledgeState
from src.devices.hp.procurve import HPProCurveParser


VULNERABLE = """; J9772A Configuration Editor; Created on release #YA.16.10.0023
hostname "edge-switch"
ip ssh
password manager user-name admin plaintext unsafe-secret
snmp-server community "public" unrestricted
vlan 10 name "USERS"
"""


SECURE = """; J9772A Configuration Editor; Created on release #YA.16.10.0023
hostname "secure-switch"
no telnet-server
no web-management
ip ssh
web-management ssl
ip authorized-managers 192.0.2.0 255.255.255.0 access manager
aaa authentication ssh login radius local
aaa authentication ssh enable radius local
aaa accounting exec start-stop radius
aaa accounting command stop-only radius
radius-server host 192.0.2.10 key ciphertext
logging 192.0.2.20
timesync sntp
sntp unicast
sntp server priority 1 192.0.2.30
snmpv3 user monitor auth sha auth-secret priv aes privacy-secret
password configuration-control
vlan 10 name "USERS"
dhcp-snooping vlan 10
no ip ssh cipher 3des-cbc
no ip ssh cipher aes128-cbc
no ip ssh cipher aes192-cbc
no ip ssh cipher aes256-cbc
no ip ssh cipher rijndael-cbc@lysator.liu.se
no ip ssh kex diffie-hellman-group14-sha1
no ip ssh mac hmac-md5
no ip ssh mac hmac-md5-96
no ip ssh mac hmac-sha1
no ip ssh mac hmac-sha1-96
"""


def _parse(tmp_path, content):
    path = tmp_path / "switch.conf"
    path.write_text(content, encoding="utf-8")
    return HPProCurveParser(str(path))


def _issues(parser):
    plugin = PluginHPChecks()
    plugin.analyze(parser)
    return plugin.get_issues()


def test_parser_models_metadata_order_defaults_and_redacts_credentials(tmp_path):
    parser = _parse(tmp_path, VULNERABLE + "no ip ssh\nip ssh\n")
    assert parser.get_hostname() == "edge-switch"
    assert parser.get_model() == "J9772A"
    assert parser.get_version() == "YA.16.10.0023"
    assert parser.get_service_states()["ssh"].state == ConfigurationState.ENABLED
    assert parser.get_services()["telnet"] is True
    assert parser.get_users()[0]["username"] == "admin"
    assert "unsafe-secret" not in parser.get_normalized_config().users.items[0].evidence[0].text
    assert parser.get_normalized_config().software_version.state == KnowledgeState.KNOWN


def test_unknown_release_does_not_invent_service_defaults(tmp_path):
    parser = _parse(tmp_path, 'hostname "unknown-release"\n')
    assert parser.get_services() == {
        "telnet": None,
        "ssh": None,
        "http": None,
        "https": None,
    }
    rule_ids = {issue.rule_id for issue in _issues(parser)}
    assert "hp.procurve.management.telnet" not in rule_ids
    assert "hp.procurve.management.http" not in rule_ids


def test_vulnerable_aos_switch_has_exact_effective_findings(tmp_path):
    issues = _issues(_parse(tmp_path, VULNERABLE))
    assert [issue.rule_id for issue in issues] == [
        "hp.procurve.management.telnet",
        "hp.procurve.management.http",
        "hp.procurve.management.source_restriction",
        "hp.procurve.snmp.default_community",
        "hp.procurve.snmp.community_access",
        "hp.procurve.snmp.secure_user_missing",
        "hp.procurve.ssh.weak_algorithms",
        "hp.procurve.authentication.centralized",
        "hp.procurve.credentials.password_complexity",
        "hp.procurve.layer2.dhcp_snooping",
        "hp.procurve.logging.remote_destination",
        "hp.procurve.ntp.servers",
    ]
    assert all(issue.references for issue in issues)
    assert all("unsafe-secret" not in " ".join(issue.evidence) for issue in issues)


def test_secure_aos_switch_has_no_findings(tmp_path):
    assert _issues(_parse(tmp_path, SECURE)) == []


def test_exact_default_community_and_override_semantics(tmp_path):
    parser = _parse(
        tmp_path,
        SECURE
        + 'snmp-server community "public-readers" restricted\n'
        + 'snmp-server community "private" unrestricted\n'
        + 'no snmp-server community "private"\n',
    )
    assert [community.name for community in parser.get_snmp_communities()] == ["public-readers"]
    assert not {
        "hp.procurve.snmp.default_community",
        "hp.procurve.snmp.community_access",
        "hp.procurve.snmp.secure_user_missing",
    } & {issue.rule_id for issue in _issues(parser)}


def test_public_processor_keeps_unique_finding_identities(tmp_path):
    findings = list(process_hp_conf(_parse(tmp_path, VULNERABLE)).values())
    identities = [(finding.rule_id, finding.evidence) for finding in findings]
    assert len(identities) == len(set(identities))


def test_accounting_and_vlan_negations_are_effective(tmp_path):
    parser = _parse(
        tmp_path,
        SECURE
        + "no aaa accounting exec start-stop radius\n"
        + "no aaa accounting command stop-only radius\n"
        + "no dhcp-snooping vlan 10\n",
    )
    assert not parser.has_management_accounting()
    assert parser.get_dhcp_snooping_vlans() == ()
    rule_ids = {issue.rule_id for issue in _issues(parser)}
    assert "hp.procurve.authentication.accounting" in rule_ids
    assert "hp.procurve.layer2.dhcp_snooping" in rule_ids
