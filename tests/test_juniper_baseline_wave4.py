from src.analyze.juniper.core.process_screenos_conf import process_screenos_conf
from src.analyze.juniper.junos.core.process_junos_conf import process_junos_conf
from src.analyze.juniper.junos.plugins.baseline_plugin import PluginJunOSBaseline
from src.analyze.juniper.plugins.screenos_baseline_plugin import (
    PluginScreenOSBaseline,
)
from src.devices.common.models import KnowledgeState
from src.devices.juniper.junos import JunOSParser
from src.devices.juniper.screenos import JuniperScreenOSParser


def _junos(tmp_path, config):
    path = tmp_path / "junos.conf"
    path.write_text(config, encoding="utf-8")
    return JunOSParser(str(path))


def _screenos(tmp_path, config):
    path = tmp_path / "screenos.conf"
    path.write_text(config, encoding="utf-8")
    return JuniperScreenOSParser(str(path))


def _issues(plugin_class, parser):
    plugin = plugin_class()
    plugin.analyze(parser)
    return plugin.get_issues()


def test_junos_vulnerable_baseline_has_exact_high_value_rule_ids(tmp_path):
    parser = _junos(
        tmp_path,
        '''## Model: SRX345
set version 22.4R1.10
set system host-name weak-srx
set system login user ops class super-user
set system login user legacy class super-user
set system login user legacy authentication encrypted-password "$1$secret"
set system login retry-options tries-before-disconnect 8
set system services ssh root-login deny
set system services ssh ciphers [ aes256-ctr 3des-cbc ]
set system services ssh macs [ hmac-sha2-256 hmac-md5 ]
set system services ssh key-exchange [ curve25519-sha256 group-exchange-sha1 ]
set system services ssh hostkey-algorithm [ ssh-ed25519 ssh-dss ]
set system services ftp
set snmp community public authorization read-write
set snmp v3 usm local-engine user monitor authentication-md5 authentication-password "$9$auth"
set snmp v3 usm local-engine user monitor privacy-des privacy-password "$9$priv"
set system ntp server 192.0.2.20
set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/24
''',
    )

    issues = _issues(PluginJunOSBaseline, parser)
    rule_ids = {issue.rule_id for issue in issues}

    assert {
        "juniper.junos.authentication.centralized",
        "juniper.junos.authentication.login_attempts",
        "juniper.junos.authentication.lockout",
        "juniper.junos.authentication.super_user",
        "juniper.junos.authentication.weak_storage",
        "juniper.junos.ssh.weak_ciphers",
        "juniper.junos.ssh.weak_macs",
        "juniper.junos.ssh.weak_key_exchange",
        "juniper.junos.ssh.weak_hostkey_algorithm",
        "juniper.junos.services.legacy",
        "juniper.junos.snmp.legacy_community",
        "juniper.junos.snmp.v3_security",
        "juniper.junos.logging.remote_destination",
        "juniper.junos.ntp.authentication",
        "juniper.junos.control_plane.lo0_filter",
        "juniper.junos.interfaces.redirects",
    }.issubset(rule_ids)
    assert all(issue.references for issue in issues)
    assert all("$1$secret" not in item for issue in issues for item in issue.evidence)
    assert all("$9$auth" not in item for issue in issues for item in issue.evidence)


def test_junos_secure_baseline_is_clean(tmp_path):
    parser = _junos(
        tmp_path,
        '''## Model: SRX345
set version 22.4R1.10
set system host-name secure-srx
set system authentication-order [ tacplus password ]
set system tacplus-server 192.0.2.5 secret "$9$redacted"
set system login retry-options tries-before-disconnect 3
set system login retry-options lockout-period 30
set system login user ops class super-user
set system login user ops authentication ssh-ed25519 "ssh-ed25519 AAAAredacted"
set system services ssh root-login deny
set system services ssh ciphers [ aes256-ctr aes256-gcm@openssh.com ]
set system services ssh macs [ hmac-sha2-256 hmac-sha2-512 ]
set system services ssh key-exchange [ curve25519-sha256 ecdh-sha2-nistp384 ]
set system services ssh hostkey-algorithm [ ssh-ed25519 rsa-sha2-512 ]
set snmp v3 usm local-engine user monitor authentication-sha authentication-password "$9$auth"
set snmp v3 usm local-engine user monitor privacy-aes128 privacy-password "$9$priv"
set system syslog host 192.0.2.30 any informational
set system ntp authentication-key 1 type sha256 value "$9$key"
set system ntp trusted-key 1
set system ntp server 192.0.2.20 key 1
set system no-redirects
set interfaces lo0 unit 0 family inet address 192.0.2.1/32
set interfaces lo0 unit 0 family inet filter input PROTECT-RE
set firewall family inet filter PROTECT-RE term allow-ssh from source-address 192.0.2.0/24
set firewall family inet filter PROTECT-RE term allow-ssh from protocol tcp
set firewall family inet filter PROTECT-RE term allow-ssh then accept
set firewall family inet filter PROTECT-RE term deny-rest then discard
''',
    )

    assert _issues(PluginJunOSBaseline, parser) == []
    normalized = parser.get_normalized_config()
    assert normalized.logging_destinations.state == KnowledgeState.KNOWN
    assert normalized.logging_destinations.items[0].address == "192.0.2.30"
    assert normalized.crypto_settings.state == KnowledgeState.KNOWN


def test_junos_unknown_version_does_not_infer_missing_baseline_state(tmp_path):
    parser = _junos(
        tmp_path,
        "set system services ssh ciphers [ aes256-ctr ]\n",
    )
    assert _issues(PluginJunOSBaseline, parser) == []


def test_junos_ntp_requires_matching_configured_and_trusted_key(tmp_path):
    parser = _junos(
        tmp_path,
        '''set version 22.4R1.10
set system ntp authentication-key 1 type sha256 value "$9$key"
set system ntp trusted-key 2
set system ntp server 192.0.2.20 key 2
''',
    )
    assert "juniper.junos.ntp.authentication" in {
        issue.rule_id for issue in _issues(PluginJunOSBaseline, parser)
    }


def test_junos_deleted_and_inactive_weak_definitions_do_not_trigger(tmp_path):
    parser = _junos(
        tmp_path,
        '''set version 22.4R1.10
set system services ssh
set system services ssh ciphers [ aes256-ctr 3des-cbc ]
delete system services ssh ciphers
set system services ssh ciphers [ aes256-ctr ]
set system services ftp
deactivate system services ftp
set snmp community public authorization read-write
delete snmp community public
''',
    )
    explicit_rule_ids = {
        issue.rule_id for issue in _issues(PluginJunOSBaseline, parser)
    }
    assert not {
        "juniper.junos.ssh.weak_ciphers",
        "juniper.junos.services.legacy",
        "juniper.junos.snmp.legacy_community",
    }.intersection(explicit_rule_ids)


def test_screenos_vulnerable_baseline_has_effective_scoped_findings(tmp_path):
    parser = _screenos(
        tmp_path,
        '''set version "6.3.0r27.0"
set chassis "SSG-140"
set hostname "legacy-edge"
set admin name "admin"
set admin password "password"
set admin access attempts 7
set console timeout 0
set interface "ethernet0/0" zone "Untrust"
set interface "ethernet0/0" manage ssh ssl snmp
set ssh version v1
set ssl enable
set ssl encrypt rc4 md5
set snmp community "public" read-write version any
set policy id 10 from "Untrust" to "Trust" "Any" "Any" "ANY" permit
set ike p1-proposal "LEGACY-P1" preshare pre-g2 3des md5 second 28800
set ike gateway "PARTNER" address 192.0.2.50 Main outgoing-interface ethernet0/0 proposal "LEGACY-P1"
''',
    )

    issues = _issues(PluginScreenOSBaseline, parser)
    rule_ids = {issue.rule_id for issue in issues}

    assert {
        "juniper.screenos.lifecycle.end_of_life",
        "juniper.screenos.administration.manager_sources",
        "juniper.screenos.administration.session_timeout",
        "juniper.screenos.administration.login_attempts",
        "juniper.screenos.ssh.protocol_version",
        "juniper.screenos.https.legacy_cipher",
        "juniper.screenos.credentials.default_or_empty",
        "juniper.screenos.administration.login_banner",
        "juniper.screenos.logging.remote_destination",
        "juniper.screenos.snmp.legacy_community",
        "juniper.screenos.ntp.servers",
        "juniper.screenos.policy.unlogged_permit",
        "juniper.screenos.vpn.weak_proposal",
    }.issubset(rule_ids)
    assert all(issue.references for issue in issues)
    assert all("password password" not in item.casefold() for issue in issues for item in issue.evidence)
    assert all("community public" not in item.casefold() for issue in issues for item in issue.evidence)


def test_screenos_hardened_interim_config_only_reports_eol(tmp_path):
    parser = _screenos(
        tmp_path,
        '''set version "6.3.0r27.0"
set chassis "SSG-140"
set hostname "legacy-edge"
set admin name "ops-admin"
set admin password "nKVUM2rwMUzPcrkG5sWIHm8FPNASNW"
set admin access attempts 3
set admin manager-ip 192.0.2.10 255.255.255.255
set admin auth banner telnet login "Authorized use only"
set console timeout 10
set interface "ethernet0/0" zone "Trust"
set interface "ethernet0/0" manage ssh ssl
set ssh version v2
set ssl enable
set syslog config 192.0.2.30 facilities local0 local0
set syslog enable
set ntp server 192.0.2.20
set policy id 10 from "Untrust" to "Trust" "Any" "Any" "ANY" deny log
set ike p1-proposal "MODERN-P1" preshare pre-g14 aes256 sha-256 second 28800
set ike gateway "PARTNER" address 192.0.2.50 Main outgoing-interface ethernet0/0 proposal "MODERN-P1"
''',
    )

    issues = _issues(PluginScreenOSBaseline, parser)
    assert [issue.rule_id for issue in issues] == [
        "juniper.screenos.lifecycle.end_of_life"
    ]
    normalized = parser.get_normalized_config()
    assert normalized.logging_destinations.items[0].address == "192.0.2.30"
    assert normalized.logging_destinations.items[0].state.value == "enabled"
    assert normalized.crypto_settings.state == KnowledgeState.KNOWN


def test_screenos_unset_state_and_unused_vpn_proposals_do_not_trigger(tmp_path):
    parser = _screenos(
        tmp_path,
        '''set interface "ethernet0/0" manage ssl
unset interface "ethernet0/0" manage ssl
set ssl enable
unset ssl enable
set snmp community "public" read-write
unset snmp community "public"
set ike p1-proposal "UNUSED" preshare pre-g2 3des md5 second 28800
''',
    )
    issues = _issues(PluginScreenOSBaseline, parser)
    assert not {
        "juniper.screenos.https.global_activation",
        "juniper.screenos.snmp.legacy_community",
        "juniper.screenos.vpn.weak_proposal",
    }.intersection(issue.rule_id for issue in issues)


def test_screenos_known_encrypted_default_password_is_detected_and_redacted(tmp_path):
    parser = _screenos(
        tmp_path,
        '''set version "6.3.0r27.0"
set admin password "nKVUM2rwMUzPcrkG5sWIHdCtqkAibn"
''',
    )
    findings = [
        issue
        for issue in _issues(PluginScreenOSBaseline, parser)
        if issue.rule_id == "juniper.screenos.credentials.default_or_empty"
    ]
    assert len(findings) == 1
    assert "nKVUM2" not in " ".join(findings[0].evidence)


def test_public_juniper_pipelines_include_baselines_without_duplicate_rule_evidence(tmp_path):
    junos = _junos(tmp_path, "set version 22.4R1.10\n")
    junos_findings = list(process_junos_conf(junos).values())
    junos_keys = [(item.rule_id, item.evidence) for item in junos_findings]
    assert len(junos_keys) == len(set(junos_keys))
    assert "juniper.junos.logging.remote_destination" in {
        item.rule_id for item in junos_findings
    }

    screenos = _screenos(tmp_path, 'set version "6.3.0r27.0"\n')
    screenos_findings = list(process_screenos_conf(screenos).values())
    screenos_keys = [(item.rule_id, item.evidence) for item in screenos_findings]
    assert len(screenos_keys) == len(set(screenos_keys))
    assert "juniper.screenos.lifecycle.end_of_life" in {
        item.rule_id for item in screenos_findings
    }
