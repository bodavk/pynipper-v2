import pytest
import os
from src.devices import get_parser
from src.analyze.cisco.asa.plugins.asa_checks_plugin import PluginASAChecks
from src.analyze.cisco.asa.core.process_asa_conf import _deduplicate_findings, process_asa_conf
from src.analyze.common.issue import Finding, Severity
from src.devices.cisco.asa import CiscoASAParser


def _analyze_config(tmp_path, config):
    path = tmp_path / "asa.conf"
    path.write_text(config, encoding="utf-8")
    parser = CiscoASAParser(str(path))
    plugin = PluginASAChecks()
    plugin.analyze(parser)
    return parser, plugin.get_issues()

def test_plugin_asa_checks():
    config_file = os.path.join("tests", "test_data", "cisco_asa_vulnerable.conf")
    parser = get_parser("ASA", config_file)
    assert isinstance(parser, CiscoASAParser)
    
    plugin = PluginASAChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    assert len(issues) > 0
    # Check for a known issue in vulnerable config
    assert any("Telnet Service Enabled" in issue.title for issue in issues)


def test_public_asa_processor_emits_each_rule_once():
    config_file = os.path.join("tests", "test_data", "cisco_asa_vulnerable.conf")
    parser = get_parser("ASA", config_file)

    issues = list(process_asa_conf(parser).values())
    identities = [(issue.rule_id, issue.evidence) for issue in issues]
    rule_ids = {issue.rule_id for issue in issues}

    assert len(identities) == len(set(identities))
    assert "cisco.asa.management.telnet" in rule_ids
    assert "cisco.asa.logging.missing" in rule_ids
    assert "cisco.asa.snmp.default_community" in rule_ids


def test_asa_duplicate_guard_preserves_distinct_objects():
    common = {
        "rule_id": "cisco.asa.acl.broad_inbound_permit",
        "device": "ASA",
        "title": "Broad ACL",
        "impact": "Traffic is overly broad.",
        "recommendation": "Restrict the ACL.",
        "severity": Severity.CRITICAL,
    }
    first = Finding(
        **common,
        observation="ACL OUTSIDE permits any traffic.",
        evidence=("access-list OUTSIDE permit ip any any",),
    )
    duplicate = Finding(
        **common,
        observation="ACL OUTSIDE permits any traffic.",
        evidence=("access-list OUTSIDE permit ip any any",),
    )
    second_object = Finding(
        **common,
        observation="ACL PARTNER permits any traffic.",
        evidence=("access-list PARTNER permit ip any any",),
    )

    assert _deduplicate_findings([first, duplicate, second_object]) == [first, second_object]


def test_telnet_timeout_is_not_a_management_grant(tmp_path):
    parser, issues = _analyze_config(tmp_path, "telnet timeout 5\n")
    assert parser.get_management_grants("telnet") == []
    assert "cisco.asa.management.telnet" not in {issue.rule_id for issue in issues}


def test_management_grants_honor_removal_and_ipv6_scope(tmp_path):
    config = """interface Management0/0
 nameif mgmt-only
 security-level 0
interface GigabitEthernet0/0
 nameif outside
 security-level 0
ssh 0.0.0.0 0.0.0.0 mgmt-only
ssh ::/0 outside
ssh 192.0.2.0 255.255.255.0 outside
no ssh 192.0.2.0 255.255.255.0 outside
"""
    parser, issues = _analyze_config(tmp_path, config)
    grants = parser.get_management_grants("ssh")

    assert len(grants) == 2
    unrestricted = [issue for issue in issues if issue.rule_id == "cisco.asa.management.unrestricted_ssh"]
    assert len(unrestricted) == 1
    assert "::/0 outside" in unrestricted[0].evidence[0]


def test_logging_requires_active_host_and_suitable_severity(tmp_path):
    _, no_host = _analyze_config(tmp_path, "logging enable\n")
    assert "cisco.asa.logging.missing" in {issue.rule_id for issue in no_host}

    _, low_severity = _analyze_config(
        tmp_path,
        "logging enable\nlogging host inside 10.0.0.10\nlogging trap warnings\n",
    )
    assert "cisco.asa.logging.missing" not in {issue.rule_id for issue in low_severity}
    assert "cisco.asa.logging.severity" in {issue.rule_id for issue in low_severity}

    _, good = _analyze_config(
        tmp_path,
        "logging enable\nlogging host inside 10.0.0.10\nlogging trap informational\n",
    )
    assert not {"cisco.asa.logging.missing", "cisco.asa.logging.severity"} & {
        issue.rule_id for issue in good
    }


def test_real_asa_ssl_server_version_syntax(tmp_path):
    parser, issues = _analyze_config(tmp_path, "ssl server-version tlsv1 dtlsv1\n")
    assert parser.get_ssl_min_version() == "tlsv1"
    assert "cisco.asa.tls.minimum_version" in {issue.rule_id for issue in issues}


@pytest.mark.parametrize("protocol", ["ip", "tcp", "udp", "icmp", "object-group WEB-PROTOCOLS"])
def test_typed_acl_detects_active_broad_protocols(tmp_path, protocol):
    config = f"""interface GigabitEthernet0/0
 nameif outside
 security-level 0
access-list OUT extended permit {protocol} any any
access-list OUT remark permit ip any any
access-list OUT extended permit udp any any inactive
access-group OUT in interface outside
"""
    _, issues = _analyze_config(tmp_path, config)
    broad = [issue for issue in issues if issue.rule_id == "cisco.asa.acl.broad_inbound_permit"]
    assert len(broad) == 1
    assert "remark" not in broad[0].evidence[0]
    assert "inactive" not in broad[0].evidence[0]


def test_acl_and_binding_removals_change_effective_state(tmp_path):
    config = """interface GigabitEthernet0/0
 nameif outside
 security-level 0
access-list OUT extended permit ip any any
no access-list OUT extended permit ip any any
access-group OUT in interface outside
no access-group OUT in interface outside
"""
    parser, issues = _analyze_config(tmp_path, config)
    assert parser.get_acl_entries("OUT") == []
    assert parser.get_acl_bindings() == []
    assert "cisco.asa.acl.broad_inbound_permit" not in {issue.rule_id for issue in issues}


def test_enable_password_storage_is_classified_and_redacted(tmp_path):
    _, plaintext = _analyze_config(tmp_path, "enable password UniqueValue2026\n")
    finding = next(
        issue for issue in plaintext if issue.rule_id == "cisco.asa.credentials.weak_enable_password"
    )
    assert "UniqueValue2026" not in finding.observation
    assert "UniqueValue2026" not in " ".join(finding.evidence)

    _, encrypted = _analyze_config(tmp_path, "enable password opaquehash encrypted\n")
    assert "cisco.asa.credentials.weak_enable_password" in {
        issue.rule_id for issue in encrypted
    }


@pytest.mark.parametrize(
    ("command", "expected_storage", "expects_finding"),
    [
        ("enable password", "plaintext", True),
        ("enable password CiScO", "plaintext", True),
        ("enable password opaquehash encrypted", "encrypted", True),
        ("enable password opaquehash pbkdf2", "pbkdf2", False),
    ],
)
def test_enable_password_empty_default_and_hash_formats(
    tmp_path,
    command,
    expected_storage,
    expects_finding,
):
    parser, issues = _analyze_config(tmp_path, command + "\n")
    credential = parser.get_enable_credential()
    assert credential is not None
    assert credential.storage_type == expected_storage
    assert (
        "cisco.asa.credentials.weak_enable_password" in {issue.rule_id for issue in issues}
    ) is expects_finding


def test_snmp_defaults_use_exact_tokens_and_redact_secrets(tmp_path):
    config = """snmp-server community NotPublicButRandomized ro
snmp-server community private rw
snmp-server host inside 10.0.0.50 community NotPublicButRandomized version 2c
"""
    parser, issues = _analyze_config(tmp_path, config)
    defaults = [issue for issue in issues if issue.rule_id == "cisco.asa.snmp.default_community"]
    assert len(defaults) == 1
    assert "private" not in defaults[0].observation.casefold()
    assert "private" not in " ".join(defaults[0].evidence).casefold()
    assert "cisco.asa.snmp.write_community" in {issue.rule_id for issue in issues}
    communities, hosts, _ = parser.get_snmp_configuration()
    assert {community.name for community in communities} == {"NotPublicButRandomized", "private"}
    assert hosts[0].version == "2c"


def test_snmpv3_auth_priv_is_distinguished(tmp_path):
    _, issues = _analyze_config(
        tmp_path,
        "snmp-server user monitor GROUP v3 auth sha secret priv aes 256 secret2\n",
    )
    assert "cisco.asa.snmp.v3_protection" not in {issue.rule_id for issue in issues}


def test_snmpv3_users_resolve_groups_hosts_and_redact_each_secret(tmp_path):
    parser, issues = _analyze_config(
        tmp_path,
        '''ASA Version 9.16(4)
snmp-server group SECURE v3 priv
snmp-server group AUTHONLY v3 auth
snmp-server user monitor SECURE v3 auth sha-256 AUTHSECRET priv aes 256 PRIVSECRET
snmp-server user weak AUTHONLY v3 auth md5 WEAKAUTH priv des WEAKPRIV
snmp-server user orphan MISSING v3 auth sha-256 ORPHANAUTH priv aes 256 ORPHANPRIV
snmp-server host management 192.0.2.20 version 3 monitor
snmp-server host management 192.0.2.21 version 3 weak
snmp-server host management 192.0.2.22 version 3 orphan
''',
    )
    _, hosts, users = parser.get_snmp_configuration()
    assert hosts[0].principal == "monitor"
    assert {user.name: user.host_scopes for user in users} == {
        "monitor": ("management:192.0.2.20",),
        "weak": ("management:192.0.2.21",),
        "orphan": ("management:192.0.2.22",),
    }
    snmp = [issue for issue in issues if issue.rule_id.startswith("cisco.asa.snmp.v3_")]
    assert [(issue.rule_id, issue.observation.split("'")[1]) for issue in snmp] == [
        ("cisco.asa.snmp.v3_protection", "weak"),
        ("cisco.asa.snmp.v3_weak_algorithm", "weak"),
        ("cisco.asa.snmp.v3_reference", "orphan"),
    ]
    evidence = " ".join(value for issue in snmp for value in issue.evidence)
    assert all(secret not in evidence for secret in ("AUTHSECRET", "PRIVSECRET", "WEAKAUTH", "WEAKPRIV", "ORPHANAUTH", "ORPHANPRIV"))


def test_snmp_sha1_policy_is_release_qualified(tmp_path):
    base = '''snmp-server group SECURE v3 priv
snmp-server user monitor SECURE v3 auth sha AUTHSECRET priv aes 128 PRIVSECRET
snmp-server host management 192.0.2.20 version 3 monitor
'''
    _, old_issues = _analyze_config(tmp_path, "ASA Version 9.13(1)\n" + base)
    _, new_issues = _analyze_config(tmp_path, "ASA Version 9.14(1)\n" + base)
    assert "cisco.asa.snmp.v3_weak_algorithm" not in {issue.rule_id for issue in old_issues}
    assert "cisco.asa.snmp.v3_weak_algorithm" in {issue.rule_id for issue in new_issues}
