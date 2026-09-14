from src.analyze.arista.core.process_arista_conf import process_arista_conf
from src.analyze.arista.plugins.arista_checks_plugin import PluginAristaChecks
from src.devices.arista.eos import AristaEOSParser
from src.devices.common.models import KnowledgeState


VULNERABLE = """! device: edge-leaf (DCS-7050SX3-48YC8, EOS-4.29.2F)
hostname edge-leaf
username admin privilege 15 secret 0 ArbitraryUnlistedPlaintext
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
username breakglass role network-admin secret sha512 $6$salt$hash
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa authorization commands all default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
aaa accounting commands all default start-stop group tacacs+
aaa authentication policy lockout failure 5 duration 300
banner login
management api http-commands
   no protocol http
   protocol https ssl profile EAPI-TLS
   vrf MGMT
      ip access-group EAPI-MGMT in
      ipv6 access-group EAPI-MGMT-V6 in
      no shutdown
management ssh
   idle-timeout 10
   authentication empty-passwords deny
   cipher aes256-ctr
   key-exchange diffie-hellman-group16-sha512
   mac hmac-sha2-256
   ip access-group SSH-MGMT in vrf MGMT
   ipv6 access-group SSH-MGMT-V6 in vrf MGMT
management security
   ssl profile EAPI-TLS
      certificate eapi.pem
      tls versions 1.2 1.3
snmp-server view MONITOR system included
snmp-server group SECURE v3 priv read MONITOR
snmp-server ipv4 access-list SNMP-MGMT
snmp-server user monitor SECURE v3 auth sha256 redacted priv aes256 redacted
logging host 192.0.2.20
ntp authenticate
ntp authentication-key 55 sha1 ciphertext
ntp trusted-key 55
ntp server 192.0.2.30 key 55
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
        "arista.eos.authentication.lockout_disabled",
        "arista.eos.admin.idle_timeout",
        "arista.eos.admin.login_banner",
        "arista.eos.ssh.empty_passwords",
        "arista.eos.ssh.weak_algorithms",
        "arista.eos.ssh.source_restriction",
        "arista.eos.credentials.local_storage",
        "arista.eos.snmp.default_community",
        "arista.eos.snmp.secure_user_missing",
        "arista.eos.logging.remote_destination",
        "arista.eos.ntp.servers",
    ]
    assert all(issue.references for issue in issues)
    assert all("ArbitraryUnlistedPlaintext" not in " ".join(issue.evidence) for issue in issues)


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


def test_nts_and_plain_ntp_associations_are_evaluated_independently(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.35.0F)
management security
   ssl profile NTS-TRUST
      trust certificate CORP-CA
ntp server vrf MGMT time.example.net ssl profile NTS-TRUST
ntp server vrf MGMT 192.0.2.31
""",
    )
    associations = parser.get_ntp_associations()
    assert [(item.address, item.authentication_state) for item in associations] == [
        ("time.example.net", "authenticated"),
        ("192.0.2.31", "unauthenticated"),
    ]
    plugin = PluginAristaChecks()
    plugin.check_operations(parser)
    findings = [item for item in plugin.get_issues() if item.rule_id.startswith("arista.eos.ntp.")]
    assert [item.rule_id for item in findings] == ["arista.eos.ntp.authentication"]
    assert "192.0.2.31" in findings[0].observation


def test_nts_release_boundary_and_unresolved_profile_are_explicit(tmp_path):
    for version in ("4.34.2F", "4.35.0F"):
        parser = _parse(
            tmp_path,
            f"! device: leaf (DCS-7050, EOS-{version})\n"
            "management security\n   ssl profile NTS-TRUST\n"
            "ntp server time.example.net ssl profile NTS-TRUST\n",
        )
        association = parser.get_ntp_associations()[0]
        assert association.authentication_state == "unresolved"
        assert parser.supports_nts() is (version == "4.35.0F")

    unknown = _parse(
        tmp_path,
        "management security\n   ssl profile NTS-TRUST\n"
        "      trust certificate CORP-CA\n"
        "ntp server time.example.net ssl profile NTS-TRUST\n",
    )
    assert unknown.get_ntp_associations()[0].authentication_state == "unknown"


def test_ntp_key_deletion_breaks_only_referencing_association_and_redacts_secret(tmp_path):
    parser = _parse(
        tmp_path,
        """! device: leaf (DCS-7050, EOS-4.29.2F)
ntp authenticate
ntp authentication-key 1 sha1 TOPSECRET
ntp trusted-key 1
ntp server 192.0.2.1 key 1
ntp authentication-key 2 sha1 OTHERSECRET
ntp trusted-key 2
ntp server 192.0.2.2 key 2
no ntp authentication-key 2
""",
    )
    associations = parser.get_ntp_associations()
    assert [item.authentication_state for item in associations] == [
        "authenticated",
        "unresolved",
    ]
    assert all(
        secret not in " ".join(evidence.text for item in associations for evidence in item.evidence)
        for secret in ("TOPSECRET", "OTHERSECRET")
    )


def test_snmpv3_relationships_evaluate_each_user_view_and_scope(tmp_path):
    parser = _parse(
        tmp_path,
        '''! device: leaf (DCS-7050SX3-48YC8, EOS-4.36.0F)
snmp-server view LIMITED system included
snmp-server view BROAD iso included
snmp-server group SECURE v3 priv read LIMITED
snmp-server group BROAD-GROUP v3 auth read BROAD
snmp-server ipv4 access-list SNMP-MGMT
snmp-server user secure SECURE v3 auth sha AUTHSECRET priv aes PRIVSECRET
snmp-server user weak BROAD-GROUP v3 auth md5 WEAKAUTH priv des WEAKPRIV
snmp-server user orphan MISSING v3 auth sha ORPHANAUTH priv aes ORPHANPRIV
''',
    )
    _, _, users = parser.get_snmpv3_relationships()
    assert {user.name: user.source_restricted for user in users} == {
        "secure": True,
        "weak": True,
        "orphan": True,
    }
    findings = [issue for issue in _issues(parser) if issue.rule_id.startswith("arista.eos.snmp.v3_")]
    assert [(issue.rule_id, issue.observation.split("'")[1]) for issue in findings] == [
        ("arista.eos.snmp.v3_protection", "weak"),
        ("arista.eos.snmp.v3_weak_algorithm", "weak"),
        ("arista.eos.snmp.v3_access_scope", "weak"),
        ("arista.eos.snmp.v3_reference", "orphan"),
    ]
    evidence = " ".join(value for issue in findings for value in issue.evidence)
    assert all(secret not in evidence for secret in ("AUTHSECRET", "PRIVSECRET", "WEAKAUTH", "WEAKPRIV", "ORPHANAUTH", "ORPHANPRIV"))


def test_disabled_default_vrf_snmp_agent_and_removed_objects_are_inactive(tmp_path):
    parser = _parse(
        tmp_path,
        '''! device: leaf (DCS-7050SX3-48YC8, EOS-4.36.0F)
snmp-server view LIMITED system included
snmp-server group SECURE v3 priv read LIMITED
snmp-server user removed SECURE v3 auth md5 SECRET priv des OTHER
no snmp-server user removed SECURE v3
snmp-server user stale SECURE v3 auth md5 SECRET priv des OTHER
snmp-server community public ro
no snmp-server vrf default
''',
    )
    assert parser.get_snmpv3_relationships()[2] == []
    assert not [issue for issue in _issues(parser) if issue.rule_id.startswith("arista.eos.snmp.")]
