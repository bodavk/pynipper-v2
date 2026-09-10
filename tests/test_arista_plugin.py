from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.arista.plugins.arista_checks_plugin import PluginAristaChecks
from src.devices.arista.eos import AristaEOSParser
from src.devices.common.models import KnowledgeState


VULNERABLE = """! device: edge-leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)
hostname edge-leaf
username admin privilege 15 secret sha512 redacted
management api http-commands
   protocol http
   no protocol https
   no shutdown
management ssh
   authentication empty-passwords permit
   cipher 3des-cbc
   key-exchange diffie-hellman-group1-sha1
   mac hmac-sha1
snmp-server community public ro
"""


SECURE = """! device: secure-leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)
hostname secure-leaf
username breakglass role network-admin secret sha512 redacted
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
management api http-commands
   no protocol http
   protocol https
   vrf MGMT
      ip access-group EAPI-MGMT in
      ipv6 access-group EAPI-MGMT-V6 in
      no shutdown
management ssh
   authentication empty-passwords deny
   cipher aes256-ctr
   key-exchange diffie-hellman-group16-sha512
   mac hmac-sha2-256
   ip access-group SSH-MGMT in vrf MGMT
   ipv6 access-group SSH-MGMT-V6 in vrf MGMT
snmp-server user monitor SECURE v3 auth sha256 redacted priv aes256 redacted
logging host 192.0.2.20
ntp server 192.0.2.30
"""


def _parse(tmp_path, content):
    path = tmp_path / "eos.conf"
    path.write_text(content, encoding="utf-8")
    return AristaEOSParser(str(path))


def _issues(parser):
    plugin = PluginAristaChecks()
    plugin.analyze(parser)
    return plugin.get_issues()


def test_parser_reconstructs_eapi_vrf_protocol_acl_and_metadata(tmp_path):
    parser = _parse(tmp_path, SECURE)
    assert parser.get_hostname() == "secure-leaf"
    assert parser.get_version() == "4.29.2F"
    assert parser.get_model() == "DCS-7050SX3-48YC8"
    assert parser.get_users()[0]["username"] == "breakglass"
    endpoint = parser.get_eapi_endpoints()[0]
    assert (endpoint.scope, endpoint.active, endpoint.http, endpoint.https) == (
        "MGMT",
        True,
        False,
        True,
    )
    assert (endpoint.ipv4_acl, endpoint.ipv6_acl) == ("EAPI-MGMT", "EAPI-MGMT-V6")
    ssh = parser.get_ssh_settings()
    assert ssh.empty_passwords == "deny"
    assert ssh.ipv4_acls == ("SSH-MGMT",)
    assert ssh.ciphers == ("aes256-ctr",)
    assert parser.get_normalized_config().management_services.state == KnowledgeState.KNOWN


def test_vulnerable_eos_has_exact_findings_and_redacted_evidence(tmp_path):
    issues = _issues(_parse(tmp_path, VULNERABLE))
    assert [issue.rule_id for issue in issues] == [
        "arista.eos.eapi.insecure_http",
        "arista.eos.eapi.https_disabled",
        "arista.eos.eapi.source_restriction",
        "arista.eos.authentication.centralized",
        "arista.eos.ssh.empty_passwords",
        "arista.eos.ssh.weak_algorithms",
        "arista.eos.ssh.source_restriction",
        "arista.eos.snmp.default_community",
        "arista.eos.snmp.secure_user_missing",
        "arista.eos.logging.remote_destination",
        "arista.eos.ntp.servers",
    ]
    assert all(issue.references for issue in issues)
    assert all("sha512 redacted" not in " ".join(issue.evidence) for issue in issues)


def test_secure_eos_has_no_findings(tmp_path):
    assert _issues(_parse(tmp_path, SECURE)) == []


def test_shutdown_and_absent_eapi_blocks_are_not_exposed(tmp_path):
    for config in (
        "hostname absent\nprotocol https\n",
        "hostname stopped\nmanagement api http-commands\n   protocol http\n   shutdown\n",
    ):
        plugin = PluginAristaChecks()
        plugin.check_management_api(_parse(tmp_path, config))
        assert plugin.get_issues() == []


def test_http_and_https_are_independent_and_ordered_within_eapi_block(tmp_path):
    parser = _parse(
        tmp_path,
        """management api http-commands
   protocol http
   no protocol http
   no protocol https
   protocol https
   no shutdown
""",
    )
    endpoint = parser.get_eapi_endpoints()[0]
    assert endpoint.active
    assert not endpoint.http
    assert endpoint.https


def test_public_processor_preserves_unique_finding_identities(tmp_path):
    findings = list(process_arista_conf(_parse(tmp_path, VULNERABLE)).values())
    identities = [(finding.rule_id, finding.evidence) for finding in findings]
    assert len(identities) == len(set(identities))


def test_ssh_algorithm_negation_and_missing_exec_authorization(tmp_path):
    parser = _parse(
        tmp_path,
        SECURE.replace("aaa authorization exec default group tacacs+ local\n", "")
        + "management ssh\n   cipher 3des-cbc\n   no cipher 3des-cbc\n",
    )
    rule_ids = {issue.rule_id for issue in _issues(parser)}
    assert "arista.eos.authorization.exec" in rule_ids
    assert "arista.eos.ssh.weak_algorithms" not in rule_ids
