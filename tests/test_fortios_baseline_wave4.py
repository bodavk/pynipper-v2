from src.analyze.fortinet.core.process_fortios_conf import process_fortios_conf
from src.analyze.fortinet.plugins.fortios_baseline_plugin import PluginFortiOSBaseline
from src.devices.fortinet.fortios import FortiOSParser


def _parser(tmp_path, config):
    path = tmp_path / "fortigate-wave4.conf"
    path.write_text(config, encoding="utf-8")
    return FortiOSParser(str(path))


def _issues(tmp_path, config):
    parser = _parser(tmp_path, config)
    plugin = PluginFortiOSBaseline()
    plugin.analyze(parser)
    return parser, plugin.get_issues()


SECURE_CONFIG = '''#config-version=FGT100F-7.2.11-FW-build0001-240101:opmode=0:vdom=1:user=admin
config system global
set hostname edge-fw
set strong-crypto enable
set ssl-static-key-ciphers disable
set dh-params 4096
set admin-ssh-v1 disable
set ssh-cbc-cipher disable
set ssh-enc-algo aes256-ctr chacha20-poly1305@openssh.com
set ssh-kex-algo curve25519-sha256
set ssh-mac-algo hmac-sha2-256
set admin-server-cert corp-edge-fw
set admin-lockout-threshold 3
set admin-lockout-duration 120
set admintimeout 5
end
config system admin
edit remote-ops
set accprofile super_admin
set remote-auth enable
set remote-group FortiAdmins
set trusthost1 192.0.2.0 255.255.255.0
next
edit breakglass
set accprofile super_admin
set two-factor fortitoken
set trusthost1 192.0.2.10 255.255.255.255
next
end
config system password-policy
set status enable
set apply-to admin-password
set minimum-length 14
set min-lower-case-letter 1
set min-upper-case-letter 1
set min-non-alphanumeric 1
set min-number 1
set reuse-password disable
end
config system interface
edit wan1
set role wan
set ip 198.51.100.1 255.255.255.0
set allowaccess ping https ssh snmp
next
edit lan
set role lan
set ip 10.0.0.1 255.255.255.0
next
end
config system snmp user
edit monitor
set security-level auth-priv
set auth-proto sha256
set auth-pwd ENC secret-auth
set priv-proto aes256
set priv-pwd ENC secret-priv
next
end
config system ntp
set ntpsync enable
set type fortiguard
end
config log syslogd setting
set status enable
set server 192.0.2.20
end
config log syslogd filter
set anomaly enable
set forward-traffic enable
set local-traffic enable
set system enable
set user enable
end
config system autoupdate schedule
set status enable
set frequency automatic
end
config system fortiguard
set auto-firmware-upgrade enable
end
config firewall policy
edit 1
set srcintf lan
set dstintf wan1
set srcaddr CorpNet
set dstaddr all
set service HTTPS DNS
set action accept
set logtraffic all
set utm-status enable
set ips-sensor default
set ssl-ssh-profile certificate-inspection
next
end
config firewall DoS-policy
edit 1
set interface wan1
config anomaly
edit tcp_syn_flood
set status enable
set log enable
set action block
set threshold 2000
next
end
next
end
'''


def test_secure_known_release_has_no_wave4_baseline_findings(tmp_path):
    _, issues = _issues(tmp_path, SECURE_CONFIG)

    assert issues == []


def test_vulnerable_release_emits_stable_rule_set_with_references(tmp_path):
    config = '''#config-version=FGT60F-7.2.8-FW-build0001-240101:opmode=0:vdom=0:user=admin
config system global
set strong-crypto disable
set ssl-static-key-ciphers enable
set dh-params 1024
set admin-ssh-v1 enable
set ssh-enc-algo aes128-cbc aes256-ctr
set admin-lockout-threshold 8
set admin-lockout-duration 20
set admintimeout 30
end
config system admin
edit admin
set accprofile super_admin
set password ENC never-report-this-password
next
edit remote-broken
set accprofile super_admin
set remote-auth enable
set trusthost1 192.0.2.0 255.255.255.0
next
end
config system password-policy
set status enable
set apply-to ipsec-preshared-key
set minimum-length 8
set min-lower-case-letter 0
set min-upper-case-letter 0
set min-non-alphanumeric 0
set min-number 0
set reuse-password enable
end
config system interface
edit wan1
set status up
set role wan
set ip 198.51.100.1 255.255.255.0
set allowaccess https snmp fgfm
next
edit spare1
set status up
next
edit lan
set role lan
set ip 10.0.0.1 255.255.255.0
next
end
config system snmp community
edit public
set status enable
next
end
config system snmp user
edit monitor
set security-level auth-priv
set auth-proto md5
set auth-pwd ENC never-report-auth
set priv-proto des
set priv-pwd ENC never-report-priv
next
end
config system ntp
set ntpsync enable
set type custom
config ntpserver
edit 1
set server 192.0.2.30
set authentication enable
set key-id 1
set key ENC never-report-key
set key-type md5
next
end
end
config log syslogd setting
set status enable
set server 192.0.2.20
end
config log syslogd filter
set anomaly disable
set local-traffic disable
end
config system autoupdate schedule
set status disable
set frequency manual
end
config system fortiguard
set auto-firmware-upgrade disable
end
config firewall policy
edit 10
set srcintf lan
set dstintf wan1
set srcaddr CorpNet
set dstaddr all
set service ALL
set action accept
next
end
'''
    _, issues = _issues(tmp_path, config)
    rule_ids = {issue.rule_id for issue in issues}

    assert {
        "fortinet.fortios.admin.trusted_hosts",
        "fortinet.fortios.admin.remote_group",
        "fortinet.fortios.admin.mfa",
        "fortinet.fortios.admin.centralized_authentication",
        "fortinet.fortios.password_policy.weak",
        "fortinet.fortios.admin.lockout",
        "fortinet.fortios.admin.session_timeout",
        "fortinet.fortios.crypto.strong_crypto",
        "fortinet.fortios.crypto.ssl_static_key_ciphers",
        "fortinet.fortios.crypto.admin_ssh_v1",
        "fortinet.fortios.crypto.dh_parameters",
        "fortinet.fortios.ssh.weak_enc_algo",
        "fortinet.fortios.https.management_certificate",
        "fortinet.fortios.snmp.legacy_community",
        "fortinet.fortios.snmp.v3_security",
        "fortinet.fortios.snmp.secure_user_missing",
        "fortinet.fortios.ntp.authentication",
        "fortinet.fortios.logging.events_filtered",
        "fortinet.fortios.policy.logging",
        "fortinet.fortios.policy.security_profiles",
        "fortinet.fortios.fortiguard.automatic_updates",
        "fortinet.fortios.firmware.automatic_updates",
        "fortinet.fortios.management.auxiliary_services",
        "fortinet.fortios.interface.unused_enabled",
        "fortinet.fortios.dos.wan_policy_missing",
    } <= rule_ids
    assert all(issue.references for issue in issues)
    combined_evidence = " ".join(
        evidence for issue in issues for evidence in issue.evidence
    )
    assert "never-report" not in combined_evidence


def test_unknown_release_does_not_infer_absent_defaults(tmp_path):
    _, issues = _issues(tmp_path, "")

    assert issues == []


def test_explicit_weak_state_is_detected_without_version_header(tmp_path):
    config = '''config system global
set strong-crypto disable
end
config system password-policy
set status disable
end
config system ntp
set ntpsync disable
end
'''
    _, issues = _issues(tmp_path, config)

    assert {issue.rule_id for issue in issues} == {
        "fortinet.fortios.crypto.strong_crypto",
        "fortinet.fortios.password_policy.disabled",
        "fortinet.fortios.ntp.synchronization",
    }


def test_global_snmpv3_user_applies_to_vdom_interface_and_disabled_objects_are_ignored(tmp_path):
    config = '''config global
config system snmp user
edit monitor
set security-level auth-priv
set auth-proto sha256
set auth-pwd ENC secure-auth
set priv-proto aes256
set priv-pwd ENC secure-priv
next
edit disabled-weak
set status disable
set security-level no-auth-no-priv
next
end
config system admin
edit disabled-admin
set status disable
set accprofile super_admin
next
end
end
config vdom
edit blue
config system interface
edit wan1
set role wan
set allowaccess snmp
next
end
next
end
'''
    _, issues = _issues(tmp_path, config)
    ids = {issue.rule_id for issue in issues}

    assert "fortinet.fortios.snmp.secure_user_missing" not in ids
    assert "fortinet.fortios.snmp.v3_security" not in ids
    assert "fortinet.fortios.admin.trusted_hosts" not in ids


def test_fortios_parser_redacts_secret_evidence_and_normalizes_crypto(tmp_path):
    parser = _parser(
        tmp_path,
        '''config system global
set strong-crypto disable
set admin-server-cert factory
end
config system admin
edit admin
set password ENC sensitive-value
next
end
''',
    )

    assert parser.evidence[("system admin", "admin", "password")].text == "set password <redacted>"
    crypto = {setting.name: setting.value for setting in parser.get_normalized_config().crypto_settings.items}
    assert crypto == {"strong-crypto": "disable", "admin-server-cert": "factory"}


def test_public_pipeline_has_stable_unique_finding_identities(tmp_path):
    parser = _parser(tmp_path, SECURE_CONFIG.replace("set logtraffic all", "set logtraffic disable"))
    findings = list(process_fortios_conf(parser).values())
    identities = [(finding.rule_id, finding.evidence) for finding in findings]

    assert "fortinet.fortios.policy.logging" in {finding.rule_id for finding in findings}
    assert len(identities) == len(set(identities))


def test_documented_7x_defaults_are_inferred_but_older_releases_are_explicit_only(tmp_path):
    seven = '''#config-version=FGT60F-7.4.5-FW-build0001-240101:opmode=0:vdom=0:user=admin
config system interface
edit wan1
set role wan
next
end
'''
    _, seven_issues = _issues(tmp_path, seven)
    seven_ids = {issue.rule_id for issue in seven_issues}
    assert {
        "fortinet.fortios.password_policy.disabled",
        "fortinet.fortios.ntp.synchronization",
        "fortinet.fortios.dos.wan_policy_missing",
    } <= seven_ids

    six = seven.replace("7.4.5", "6.4.15").replace(
        "config system interface",
        "config system global\nset strong-crypto disable\nend\nconfig system interface",
    )
    _, six_issues = _issues(tmp_path, six)
    six_ids = {issue.rule_id for issue in six_issues}
    assert six_ids == {"fortinet.fortios.crypto.strong_crypto"}


def test_disabled_snmp_agent_and_fortimanager_owned_firmware_are_not_reported(tmp_path):
    config = '''config system interface
edit wan1
set role wan
set allowaccess snmp
next
end
config system snmp sysinfo
set status disable
end
config system snmp community
edit private
next
end
config system central-management
set type fortimanager
set fmg 192.0.2.10
end
config system fortiguard
set auto-firmware-upgrade disable
end
'''
    _, issues = _issues(tmp_path, config)
    ids = {issue.rule_id for issue in issues}

    assert not any(rule_id.startswith("fortinet.fortios.snmp.") for rule_id in ids)
    assert "fortinet.fortios.firmware.automatic_updates" not in ids


def test_dos_policy_distinguishes_nonblocking_and_unlogged_protection(tmp_path):
    nonblocking = '''config system interface
edit wan1
set role wan
next
end
config firewall DoS-policy
edit 1
set interface wan1
config anomaly
edit tcp_syn_flood
set status enable
set action pass
set log disable
next
end
next
end
'''
    _, nonblocking_issues = _issues(tmp_path, nonblocking)
    nonblocking_ids = {issue.rule_id for issue in nonblocking_issues}
    assert "fortinet.fortios.dos.no_blocking_anomaly" in nonblocking_ids
    assert "fortinet.fortios.dos.wan_policy_missing" not in nonblocking_ids

    blocking = nonblocking.replace("set action pass", "set action block")
    _, blocking_issues = _issues(tmp_path, blocking)
    blocking_ids = {issue.rule_id for issue in blocking_issues}
    assert "fortinet.fortios.dos.no_blocking_anomaly" not in blocking_ids
    assert "fortinet.fortios.dos.logging" in blocking_ids


def test_password_default_scope_custom_ntp_and_inactive_utm_are_resolved(tmp_path):
    config = '''#config-version=FGT60F-7.2.11-FW-build0001-240101:opmode=0:vdom=0:user=admin
config system password-policy
set status enable
set minimum-length 14
set min-lower-case-letter 1
set min-upper-case-letter 1
set min-non-alphanumeric 1
set min-number 1
set reuse-password disable
end
config system ntp
set ntpsync enable
set type custom
end
config system interface
edit wan1
set role wan
next
edit lan
set role lan
next
end
config firewall policy
edit 1
set srcintf lan
set dstintf wan1
set srcaddr CorpNet
set dstaddr all
set service HTTPS
set action accept
set logtraffic all
set utm-status disable
set ips-sensor default
next
end
'''
    _, issues = _issues(tmp_path, config)
    ids = {issue.rule_id for issue in issues}

    assert "fortinet.fortios.password_policy.weak" not in ids
    assert "fortinet.fortios.ntp.custom_server_missing" in ids
    assert "fortinet.fortios.policy.security_profiles" in ids


def test_local_log_filter_is_checked_only_when_its_destination_is_enabled(tmp_path):
    enabled = '''config log disk setting
set status enable
end
config log disk filter
set local-traffic disable
end
'''
    _, enabled_issues = _issues(tmp_path, enabled)
    assert "fortinet.fortios.logging.events_filtered" in {
        issue.rule_id for issue in enabled_issues
    }

    disabled = enabled.replace("set status enable", "set status disable")
    _, disabled_issues = _issues(tmp_path, disabled)
    assert "fortinet.fortios.logging.events_filtered" not in {
        issue.rule_id for issue in disabled_issues
    }
